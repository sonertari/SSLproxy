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
 * HTTP/3 reverse-proxy connection handler prototype.
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
 */

#include "pxyconn.h"
#include "attrib.h"

#include <stdint.h>
#include <sys/socket.h>

#include <event2/event.h>

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

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

/* -------------------------------------------------------------------------
 * Per-connection (QUIC session) state
 * ---------------------------------------------------------------------- */

typedef struct protohttp3_conn_ctx {
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

    /*
     * Raw UDP sockets.  We cannot use Libevent bufferevents here because
     * ngtcp2 needs recvmsg() to extract per-datagram ancillary data (ECN
     * bits, destination IP for path validation).
     */
    int src_fd;   /* listening/connected UDP fd for the client side  */
    int dst_fd;   /* connected UDP fd towards the upstream server    */

    /* Libevent 'struct event' wrappers around the raw fds.               */
    struct event *src_rev;   /* read-ready event on src_fd               */
    struct event *src_wev;   /* write-ready event on src_fd (armed on    */
                             /* demand when ngtcp2 has output queued)    */
    struct event *dst_rev;
    struct event *dst_wev;

    /* Timer event that drives ngtcp2's loss-detection / keep-alive.       */
    struct event *timer_ev;

    /* Libevent base - borrowed from the proxy thread (never freed here).  */
    struct event_base *evbase;

    /* Back-pointer to the owning SSLproxy connection context.             */
    pxy_conn_ctx_t *ctx;

    /* Peer addresses cached from the first recvmsg() call.                */
    struct sockaddr_storage src_peer_addr;
    socklen_t               src_peer_addrlen;
    struct sockaddr_storage dst_peer_addr;
    socklen_t               dst_peer_addrlen;

    /* Local addresses (needed by ngtcp2 path tracking).                   */
    struct sockaddr_storage src_local_addr;
    socklen_t               src_local_addrlen;

    /* Linked list of active H3 streams.                                   */
    stream_h3_ctx_t *streams;

    /* Termination flag.                                                    */
    unsigned int term : 1;
} protohttp3_conn_ctx_t;

/* -------------------------------------------------------------------------
 * Public interface
 * ---------------------------------------------------------------------- */

/*
 * Allocate and initialise a protohttp3_conn_ctx_t, wire up all ngtcp2 and
 * nghttp3 callbacks, and arm the Libevent UDP read events.
 *
 * 'src_fd'   - already-bound, connected UDP socket facing the client.
 * 'evbase'   - Libevent event_base owned by the proxy thread.
 * 'ctx'      - the parent SSLproxy connection context.
 *
 * Returns the new context on success, NULL on OOM / fatal error.
 */
protohttp3_conn_ctx_t *protohttp3_new(int src_fd,
                                      struct event_base *evbase,
                                      pxy_conn_ctx_t    *ctx) WUNRES;

/* Tear down all sessions, free all streams, delete all events.           */
void protohttp3_free(protohttp3_conn_ctx_t *h3_ctx) NONNULL(1);

/*
 * Safely schedule a stream_h3_ctx_t for freeing.  If the stream is
 * currently on the C call stack (ref_count > 0) the actual free is
 * deferred via a zero-timeout Libevent timer, matching the technique used
 * in protohttp2_request_free_stream_ctx().
 */
void protohttp3_request_free_stream_ctx(stream_h3_ctx_t      *s,
                                        protohttp3_conn_ctx_t *h3_ctx) NONNULL(1,2);

/*
 * Set up the HTTP/3 protocol handler in the given proxy connection context.
 * This is the integration point called from proxy_setup_proto().
 *
 * For HTTP/3, the socket fd is a UDP socket.  The setup function
 * configures the protoctx callbacks so that the QUIC/H3 session can
 * be initiated from the init_conn callback.
 */
protocol_t protohttp3_setup(pxy_conn_ctx_t *) NONNULL(1) WUNRES;

#endif /* !PROTOHTTP3_H */

/* vim: set noet ft=c: */
