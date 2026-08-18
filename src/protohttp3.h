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

#ifndef WITHOUT_HTTP3

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
 *    is added in the same way.
 *
 *  - Each QUIC stream is tracked by a protohttp3_stream_ctx.  Streams are linked
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
#include "icap.h"

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

typedef struct protohttp3_conn_ctx protohttp3_ctx_t;

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

KHASH_INIT(h3_conn_map, quic_tuple_key_t, protohttp3_ctx_t *, 1,
           kh_quic_tuple_hash_func, kh_quic_tuple_hash_equal)

typedef struct h3_session_map {
    khash_t(h3_conn_map) *map;
    pthread_mutex_t lock;
} h3_session_map_t;

h3_session_map_t *h3_session_map_new(void);
void h3_session_map_free(h3_session_map_t *);

protohttp3_ctx_t *h3_session_map_get(h3_session_map_t *, const quic_tuple_key_t *);
int h3_session_map_insert(h3_session_map_t *, const quic_tuple_key_t *, protohttp3_ctx_t *);
void h3_session_map_remove(h3_session_map_t *, const quic_tuple_key_t *);

/* -------------------------------------------------------------------------
 * Per-stream state  (mirrors stream_ctx_t from protohttp2.h)
 * ---------------------------------------------------------------------- */

typedef struct protohttp3_stream_ctx {
    int64_t src_stream_id;     /* ngtcp2/QUIC stream id on the client side */
    int64_t dst_stream_id;     /* ngtcp2/QUIC stream id on the server side */
    pxy_conn_ctx_t *ctx;

    nghttp3_nv  *headers;
    size_t       headers_count;
    size_t       headers_capacity;

    struct evbuffer *data_buf;
    // Persistent buffer for evbuffer_pullup() to survive until the data is sent or the stream is freed
    uint8_t     *body_buf;
    size_t       body_len;
    nghttp3_data_reader dr;

#ifndef WITHOUT_ICAP
	icap_ctx_t *icap_ctx;
#endif /* !WITHOUT_ICAP */

    protohttp_ctx_t *http_ctx;

    /* Flags (same bit-field idiom used throughout sslproxy)               */
    unsigned int src_end_stream   : 1; /* 1 after FIN/END_STREAM           */
    unsigned int dst_end_stream   : 1; /* 1 after FIN/END_STREAM           */
    unsigned int closed           : 1; /* 1 after stream_close callback    */
    unsigned int term             : 1; /* 1 when safe to free              */

    // Deferred-free support (same pattern as protohttp2.c)
    int ref_count;
    int deferred_free_pending;
    struct event *ev_free;

    conn_opts_t *conn_opts;

    struct protohttp3_stream_ctx *next;
} protohttp3_stream_ctx_t;

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

    ngtcp2_crypto_conn_ref src_conn_ref;
    ngtcp2_crypto_conn_ref dst_conn_ref;

    /*
     * The HTTP/3 framing layer on top of each QUIC conn.
     */
    nghttp3_conn *src_h3;
    nghttp3_conn *dst_h3;

    /* max cummulative bidi streams on src side,
     * incremented each time a bidi stream is closed,
     * to allow new streams to be opened. */
    uint64_t src_max_streams_bidi;

    int64_t src_ctrl_stream_id, src_qenc_stream_id, src_qdec_stream_id;
    int64_t dst_ctrl_stream_id, dst_qenc_stream_id, dst_qdec_stream_id;

    // TODO: Use the pxy_conn_desc src.ssl and dst.ssl in pxy_conn_ctx_t, instead of these two SSL pointers?
    /* TLS/SSL instances for the QUIC connections */
    SSL *src_ssl;
    SSL *dst_ssl;

    /*
     * Raw UDP sockets.  We cannot use Libevent bufferevents here because
     * ngtcp2 needs recvmsg() to extract per-datagram ancillary data (ECN
     * bits, destination IP for path validation).
     */
    int src_fd;   /* listener fd for QUIC UDP server    */
    int dst_fd;   /* connected UDP fd towards the upstream server    */

    /* Libevent 'struct event' wrappers around the raw fds.               */
    struct event *src_wev;   /* write-ready event on src_fd (armed on    */
                             /* demand when ngtcp2 has output queued)    */
    struct event *dst_rev;
    struct event *dst_wev;

    struct event *src_process_pkt_ev; /* event to process a received packet on client side */

    /* Timer event that drives ngtcp2's loss-detection / keep-alive.       */
    struct event *timer_ev;

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
    protohttp3_stream_ctx_t *streams;

    /* Termination flag.                                                    */
    unsigned int term : 1;

    /* Session hash table key (5-tuple) & container reference.             */
    quic_tuple_key_t key;
    h3_session_map_t *h3_sessions;

    struct pkt_node *pkt_queue;
    pthread_mutex_t pkt_queue_mutex;
    unsigned int wait_server_connected : 1;
    unsigned int proxying : 1;
};

/* -------------------------------------------------------------------------
 * Public interface
 * ---------------------------------------------------------------------- */

#ifndef WITHOUT_ICAP
// Forward declaration
struct icap_service_ctx;

void protohttp3_icap_send_data_to_src_cb(icap_ctx_t *) NONNULL(1);
void protohttp3_icap_send_data_to_dst_cb(icap_ctx_t *) NONNULL(1);
void protohttp3_icap_failopen_to_dest_cb(struct icap_service_ctx *) NONNULL(1);

void protohttp3_close_stream(protohttp3_stream_ctx_t *);

#endif /* !WITHOUT_ICAP */

protohttp3_ctx_t *protohttp3_new(pxy_conn_ctx_t *, ngtcp2_version_cid) WUNRES;
protocol_t protohttp3_setup(pxy_conn_ctx_t *) NONNULL(1) WUNRES;

void protohttp3_free(protohttp3_ctx_t *) NONNULL(1);
void protohttp3_request_free_stream_ctx(protohttp3_stream_ctx_t *) NONNULL(1);

ssize_t protohttp3_recvmsg(int, uint8_t *, size_t, struct sockaddr_storage *, socklen_t *, int *);
void protohttp3_process_packet_cb(evutil_socket_t, short, void *) NONNULL(3);

void protohttp3_cid_to_hex(char *, const uint8_t *, size_t) NONNULL(1,2);

#endif /* !PROTOHTTP3_H */
#endif /* !WITHOUT_HTTP3 */

/* vim: set noet ft=c: */
