/*-
 * SSLproxy
 *
 * Copyright (c) 2017-2026, Soner Tari <sonertari@gmail.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PROTOHTTP3_H
#define PROTOHTTP3_H

/*
 * HTTP/3 reverse-proxy connection handler.
 *
 * Design overview
 * ---------------
 *  - QUIC runs over raw UDP sockets; Libevent bufferevents cannot be used for
 *    UDP QUIC because they do not expose the per-datagram recvmsg() metadata
 *    (ECN, local address) that ngtcp2 requires.  We therefore use a plain
 *    'struct event' that tracks EV_READ | EV_WRITE readiness on the UDP fd.
 *
 *  - One protohttp3_conn_ctx_t represents the QUIC/H3 session between
 *    SSLproxy and a single client.  A parallel "upstream" ctx (dst side)
 *    would be added in the same way.
 *
 *  - Each QUIC stream is tracked by a stream_h3_ctx_t.  Streams are linked
 *    in a singly-linked list hanging off protohttp3_conn_ctx_t.
 *
 *  - nghttp3 framing sits on top of ngtcp2 transport.  The glue is:
 *      ngtcp2_conn_read_pkt  ->  ngtcp2 fires stream-data callbacks
 *      nghttp3_conn_read_stream  ->  nghttp3 fires header/data callbacks
 *      nghttp3_conn_writev_stream  ->  fills iovecs for ngtcp2_conn_writev_stream
 *      ngtcp2_conn_write_pkt  ->  serialises QUIC packets onto the UDP socket
 *
 *  - Session demultiplexing: The UDP listener callback uses a khash-based
 *    session hash table keyed by the QUIC Destination Connection ID (DCID)
 *    extracted from each incoming packet.  New Initial packets create a new
 *    session; all other packets are routed to the existing session.
 */

#include "pxyconn.h"
#include "attrib.h"
#include "khash.h"
// #include <sys/queue.h>

#include <stdint.h>
#include <sys/socket.h>

#include <event2/event.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

/* =========================================================================
 * Datagram receive buffer size.
 * QUIC datagrams are bounded by the path MTU (typically <= 1500 bytes) but
 * we use a generous buffer to accommodate jumbo frames on LAN segments.
 * ====================================================================== */
#define H3_DGRAM_BUFSZ  65536

typedef struct protohttp3_conn_ctx protohttp3_conn_ctx_t;

/* -------------------------------------------------------------------------
 * Session hash table key: 5-tuple key structure
 * ---------------------------------------------------------------------- */
typedef struct {
    struct sockaddr_storage src_addr;
    struct sockaddr_storage dst_addr;
    socklen_t src_len;
    socklen_t dst_len;
} quic_tuple_key_t;

#define H3_CID_KEYLEN  (NGTCP2_MAX_CIDLEN * 2 + 1)

/* -------------------------------------------------------------------------
 * Session hash table (khash based on 5-tuple).
 * ---------------------------------------------------------------------- */

static kh_inline khint_t
kh_quic_tuple_hash_func(quic_tuple_key_t k)
{
    khint_t h = 0;
    const uint8_t *p = (const uint8_t *)&k;
    for (size_t i = 0; i < sizeof(quic_tuple_key_t); i++) {
        h = (h * 31) + p[i];
    }
    return h;
}

static kh_inline int
kh_quic_tuple_hash_equal(quic_tuple_key_t a, quic_tuple_key_t b)
{
    if (a.src_len != b.src_len || a.dst_len != b.dst_len) {
        return 0;
    }
    return (memcmp(&a.src_addr, &b.src_addr, a.src_len) == 0 &&
            memcmp(&a.dst_addr, &b.dst_addr, a.dst_len) == 0);
}

KHASH_INIT(h3_conn_map, quic_tuple_key_t, protohttp3_conn_ctx_t *, 1,
           kh_quic_tuple_hash_func, kh_quic_tuple_hash_equal)

typedef struct h3_session_map {
    khash_t(h3_conn_map) *map;
    pthread_mutex_t lock;
} h3_session_map_t;

h3_session_map_t *h3_session_map_new(void);
void h3_session_map_free(h3_session_map_t *smap);

protohttp3_conn_ctx_t *h3_session_map_get(h3_session_map_t *smap, const quic_tuple_key_t *key);
int h3_session_map_insert(h3_session_map_t *smap, const quic_tuple_key_t *key, protohttp3_conn_ctx_t *conn);
void h3_session_map_remove(h3_session_map_t *smap, const quic_tuple_key_t *key);

/* -------------------------------------------------------------------------
 * Per-stream state  (mirrors stream_ctx_t from protohttp2.h)
 * ---------------------------------------------------------------------- */

typedef struct stream_h3_ctx {
    int64_t stream_id;         /* ngtcp2/QUIC stream id                   */

    /* Accumulated request headers (filled by on_recv_header callback).    */
    nghttp3_nv  *headers;
    size_t       headers_count;
    size_t       headers_capacity;

    /* Body staging buffer - data received before we can forward it.       */
    uint8_t     *body_buf;
    size_t       body_len;
    size_t       body_cap;

    /* Flags (same bit-field idiom used throughout sslproxy)               */
    unsigned int headers_complete : 1; /* 1 after END_HEADERS equivalent   */
    unsigned int end_stream       : 1; /* 1 after FIN/END_STREAM           */
    unsigned int closed           : 1; /* 1 after stream_close callback    */
    unsigned int term             : 1; /* 1 when safe to free              */

    /* Deferred-free support (same pattern as protohttp2.c)                */
    int ref_count;
    int deferred_free_pending;
    struct event *ev_free;

    struct stream_h3_ctx *next;
} stream_h3_ctx_t;

typedef struct pkt_node {
    uint8_t *buf;
    size_t len;
    int ecn;
    struct pkt_node *next;
} pkt_node_t;

/* -------------------------------------------------------------------------
 * Per-connection (QUIC session) state
 * ---------------------------------------------------------------------- */

struct protohttp3_conn_ctx {
    /*
     * The QUIC transport layer.  src_conn faces the client (server mode),
     * dst_conn faces the upstream server (client mode).
     */
    ngtcp2_conn  *src_conn;
    ngtcp2_conn  *dst_conn;

    /*
     * The HTTP/3 framing layer on top of each QUIC conn.
     */
    nghttp3_conn *src_h3;
    nghttp3_conn *dst_h3;

    /* TLS/SSL instances for the QUIC connections */
    void *src_ssl; /* (SSL *) */
    void *dst_ssl; /* (SSL *) */
    ngtcp2_crypto_conn_ref src_conn_ref;
    ngtcp2_crypto_conn_ref dst_conn_ref;

    /*
     * Raw UDP sockets.  We cannot use Libevent bufferevents here because
     * ngtcp2 needs recvmsg() to extract per-datagram ancillary data (ECN
     * bits, destination IP for path validation).
     */
    int dst_fd;   /* connected UDP fd towards the upstream server    */

    /* Libevent 'struct event' wrappers around the raw fds.               */
    struct event *src_rev;   /* read-ready event on src_fd               */
    struct event *src_wev;   /* write-ready event on src_fd (armed on    */
                             /* demand when ngtcp2 has output queued)    */
    struct event *dst_rev;
    struct event *dst_wev;

    struct event *src_process_pkt_ev; /* event to process a received packet on client side */

    /* Timer event that drives ngtcp2's loss-detection / keep-alive.       */
    struct event *timer_ev;

    /* Event base of the connection handling thread this h3 conn is assigned to,
     * borrowed from the proxy thread (never freed here).  */
    struct event_base *evbase;

    /* Back-pointer to the owning SSLproxy connection context.             */
    pxy_conn_ctx_t *ctx;

    /* Peer addresses cached from the first recvmsg() call.                */
    struct sockaddr_storage dst_peer_addr;
    socklen_t               dst_peer_addrlen;

    struct sockaddr_storage dst_local_addr;
	socklen_t dst_local_addrlen;

    /* Local and peer addresses on client side (needed by ngtcp2 path tracking). */
    ngtcp2_path src_path;
    ngtcp2_path dst_path;

    ngtcp2_crypto_ossl_ctx *src_ossl_ctx;
    ngtcp2_crypto_ossl_ctx *dst_ossl_ctx;

    /* Linked list of active H3 streams.                                   */
    stream_h3_ctx_t *streams;

    /* Termination flag.                                                    */
    unsigned int term : 1;

    /* Session hash table key (5-tuple) & container reference.             */
    quic_tuple_key_t key;
    h3_session_map_t *h3_sessions;

    int udp_listener_fd;

    struct pkt_node *pkt_queue;
    pthread_mutex_t pkt_queue_mutex;
};

/* -------------------------------------------------------------------------
 * Public interface
 * ---------------------------------------------------------------------- */

protohttp3_conn_ctx_t *protohttp3_new(struct event_base *evbase,
                                      pxy_conn_ctx_t    *ctx,
                                      ngtcp2_version_cid vc) WUNRES;

/* Tear down all sessions, free all streams, delete all events.           */
void protohttp3_free(protohttp3_conn_ctx_t *h3_ctx) NONNULL(1);

/*
 * Receive helper for raw UDP sockets.
 */
ssize_t protohttp3_recvmsg(int fd,
                           uint8_t *buf, size_t bufsz,
                           struct sockaddr_storage *peer_addr, socklen_t *peer_addrlen,
                           int *ecn);

/*
 * Process a raw UDP datagram through an existing QUIC session.
 * Called by the packet demuxer when a session is found in the hash table.
 * Returns 0 on success, -1 on error.
 */
void protohttp3_process_packet_cb(evutil_socket_t fd, short what, void *arg) NONNULL(3);

/*
 * Safely schedule a stream_h3_ctx_t for freeing.
 */
void protohttp3_request_free_stream_ctx(stream_h3_ctx_t      *s,
                                         protohttp3_conn_ctx_t *h3_ctx) NONNULL(1,2);

/*
 * Set up the HTTP/3 protocol handler in the given proxy connection context.
 */
protocol_t protohttp3_setup(pxy_conn_ctx_t *) NONNULL(1) WUNRES;

/*
 * Build a hex-encoded CID key string from raw CID bytes.
 */
void protohttp3_cid_to_hex(char *key, const uint8_t *cid, size_t cidlen) NONNULL(1,2);

#endif /* !PROTOHTTP3_H */

/* vim: set noet ft=c: */
