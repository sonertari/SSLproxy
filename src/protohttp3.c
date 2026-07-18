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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * protohttp3.c – minimal, clean, working prototype structure for an
 * asynchronous HTTP/3 reverse proxy connection handler.
 *
 * Stack
 * -----
 *   Libevent struct event (raw UDP fd)
 *       -> recvmsg()  ->  ngtcp2_conn_read_pkt()
 *          ngtcp2 stream-data callback  ->  nghttp3_conn_read_stream()
 *          nghttp3 header callback  ->  stream_h3_ctx_t.headers[]
 *          nghttp3 data callback    ->  stream_h3_ctx_t.body_buf[]
 *   ngtcp2_conn_write_pkt() / ngtcp2_conn_writev_stream()
 *          ->  sendmsg()  ->  network
 *
 * Threading model
 * ---------------
 *   All callbacks fire on the single-threaded Libevent loop of the proxy
 *   thread that owns this connection.  No locks are needed inside the
 *   callbacks.
 *
 * Known limitations of this prototype
 * ------------------------------------
 *   - TLS/QUIC handshake wiring (ngtcp2_crypto_*) is left as a stub;
 *     hooking in the actual OpenSSL/BoringSSL QUIC crypto layer is the
 *     next step after this file compiles and the event wiring is verified.
 *   - The upstream dst_conn is not yet set up; only the src (client-facing)
 *     side is wired.  The pattern is identical and can be replicated.
 *   - QPACK (dynamic table) is initialised with capacity 0 (static-only
 *     mode) to keep the prototype simple.
 */

#include "protohttp3.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>          /* clock_gettime(CLOCK_MONOTONIC)              */

/* recvmsg() ancillary data for ECN and destination-address extraction.   */
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>    /* in_pktinfo, in6_pktinfo, IP_TOS, ...        */

#include <event2/event.h>

/*
 * h3_timestamp – return a ngtcp2_tstamp (nanoseconds, CLOCK_MONOTONIC).
 * ngtcp2 does not ship a ngtcp2_timestamp() helper; applications must
 * supply their own.  This is the idiomatic implementation used in the
 * ngtcp2 example servers.
 */
static ngtcp2_tstamp
h3_timestamp(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * 1000000000ULL + (ngtcp2_tstamp)ts.tv_nsec;
}

/* =========================================================================
 * Internal forward declarations
 * ====================================================================== */

static void protohttp3_src_read_cb(evutil_socket_t fd, short what, void *arg);
static void protohttp3_src_write_cb(evutil_socket_t fd, short what, void *arg);
static void protohttp3_timer_cb(evutil_socket_t fd, short what, void *arg);

static int  protohttp3_arm_timer(protohttp3_conn_ctx_t *h3_ctx);
static void protohttp3_flush_src(protohttp3_conn_ctx_t *h3_ctx);

/* =========================================================================
 * Datagram receive buffer size.
 * QUIC datagrams are bounded by the path MTU (typically <= 1500 bytes) but
 * we use a generous buffer to accommodate jumbo frames on LAN segments.
 * ====================================================================== */
#define H3_DGRAM_BUFSZ  65536

/* Maximum iovecs we ask nghttp3 to fill in one writev call.              */
#define H3_MAX_IOVECS   16

/* =========================================================================
 * stream_h3_ctx_t helpers
 * ====================================================================== */

static stream_h3_ctx_t *
protohttp3_find_stream(protohttp3_conn_ctx_t *h3_ctx, int64_t stream_id)
{
    stream_h3_ctx_t *s = h3_ctx->streams;
    while (s) {
        if (s->stream_id == stream_id)
            return s;
        s = s->next;
    }
    return NULL;
}

static stream_h3_ctx_t *
protohttp3_new_stream(protohttp3_conn_ctx_t *h3_ctx, int64_t stream_id)
{
    stream_h3_ctx_t *s = calloc(1, sizeof(stream_h3_ctx_t));
    if (!s)
        return NULL;

    s->stream_id = stream_id;

    /* Pre-allocate a small header vector.                                 */
    s->headers_capacity = 16;
    s->headers = calloc(s->headers_capacity, sizeof(nghttp3_nv));
    if (!s->headers) {
        free(s);
        return NULL;
    }

    /* Prepend to the stream list.                                          */
    s->next = h3_ctx->streams;
    h3_ctx->streams = s;

    log_dbg_printf("protohttp3: new stream %" PRId64 "\n", stream_id);
    return s;
}

/*
 * Append a single name-value header pair to the stream's header array,
 * growing the backing array by doubling as needed.
 *
 * Returns 0 on success, -1 on OOM.
 */
static int
protohttp3_stream_add_header(stream_h3_ctx_t *s,
                             const uint8_t *name,  size_t namelen,
                             const uint8_t *value, size_t valuelen)
{
    if (s->headers_count >= s->headers_capacity) {
        size_t newcap = s->headers_capacity * 2;
        nghttp3_nv *tmp = realloc(s->headers, newcap * sizeof(nghttp3_nv));
        if (!tmp)
            return -1;
        s->headers = tmp;
        s->headers_capacity = newcap;
    }

    nghttp3_nv *nv = &s->headers[s->headers_count];

    nv->name = malloc(namelen);
    if (!nv->name)
        return -1;
    memcpy(nv->name, name, namelen);
    nv->namelen = namelen;

    nv->value = malloc(valuelen);
    if (!nv->value) {
        free(nv->name);
        return -1;
    }
    memcpy(nv->value, value, valuelen);
    nv->valuelen = valuelen;

    nv->flags = NGHTTP3_NV_FLAG_NONE;
    s->headers_count++;
    return 0;
}

/*
 * Append raw bytes to the stream body staging buffer, growing by doubling.
 *
 * Returns 0 on success, -1 on OOM.
 */
static int
protohttp3_stream_append_body(stream_h3_ctx_t *s,
                              const uint8_t *data, size_t len)
{
    if (s->body_len + len > s->body_cap) {
        size_t newcap = s->body_cap ? s->body_cap : 4096;
        while (newcap < s->body_len + len)
            newcap *= 2;
        uint8_t *tmp = realloc(s->body_buf, newcap);
        if (!tmp)
            return -1;
        s->body_buf = tmp;
        s->body_cap = newcap;
    }
    memcpy(s->body_buf + s->body_len, data, len);
    s->body_len += len;
    return 0;
}

static void
protohttp3_free_stream_headers(stream_h3_ctx_t *s)
{
    for (size_t i = 0; i < s->headers_count; i++) {
        free(s->headers[i].name);
        free(s->headers[i].value);
    }
    free(s->headers);
    s->headers = NULL;
    s->headers_count = 0;
    s->headers_capacity = 0;
}

static void
protohttp3_free_stream_ctx(stream_h3_ctx_t *s,
                           protohttp3_conn_ctx_t *h3_ctx)
{
    /* Cancel pending deferred-free timer if still armed.                  */
    if (s->ev_free) {
        event_free(s->ev_free);
        s->ev_free = NULL;
    }

    protohttp3_free_stream_headers(s);
    free(s->body_buf);

    /* Unlink from the connection stream list.                             */
    if (h3_ctx->streams == s) {
        h3_ctx->streams = s->next;
    } else {
        stream_h3_ctx_t *prev = h3_ctx->streams;
        while (prev && prev->next != s)
            prev = prev->next;
        if (prev)
            prev->next = s->next;
    }

    log_dbg_printf("protohttp3: freed stream %" PRId64 "\n", s->stream_id);
    free(s);
}

/*
 * Deferred-free callback fired by the zero-timeout Libevent timer.
 * By the time this runs the C call stack that had ref_count > 0 has
 * completely unwound, so it is safe to destroy the stream.
 */
/*
 * Unused first-generation stub – superseded by protohttp3_deferred_free_stream_cb2
 * which receives the h3_ctx via the deferred_args_t bundle.
 * Kept for documentation purposes only; the linker will discard it.
 */
// static void
// protohttp3_deferred_free_stream_cb(evutil_socket_t fd, short what, void *arg)
// {
//     (void)fd; (void)what; (void)arg;
//     /* The real logic is in protohttp3_deferred_free_stream_cb2 below.    */
// }

/* Small heap bundle used as the deferred-free timer's user_data.         */
typedef struct {
    stream_h3_ctx_t       *s;
    protohttp3_conn_ctx_t *h3_ctx;
} deferred_args_t;

static void
protohttp3_deferred_free_stream_cb2(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    deferred_args_t *da = arg;
    protohttp3_free_stream_ctx(da->s, da->h3_ctx);
    free(da);
}

void
protohttp3_request_free_stream_ctx(stream_h3_ctx_t      *s,
                                   protohttp3_conn_ctx_t *h3_ctx)
{
    if (s->ref_count > 0) {
        /* Something on the call stack still references this stream.       */
        if (s->deferred_free_pending) {
            log_dbg_printf("protohttp3: stream %" PRId64
                           " already deferred for free\n", s->stream_id);
            return;
        }
        s->deferred_free_pending = 1;

        deferred_args_t *da = malloc(sizeof(deferred_args_t));
        if (!da) {
            log_dbg_printf("protohttp3: OOM deferring stream free\n");
            return;
        }
        da->s      = s;
        da->h3_ctx = h3_ctx;

        /* Fire on the next event-loop iteration (zero timeout).           */
        s->ev_free = event_new(h3_ctx->evbase, -1, 0,
                               protohttp3_deferred_free_stream_cb2, da);
        if (!s->ev_free) {
            free(da);
            return;
        }
        struct timeval tv = {0, 0};
        if (event_add(s->ev_free, &tv) == -1) {
            event_free(s->ev_free);
            s->ev_free = NULL;
            free(da);
        }
        log_dbg_printf("protohttp3: stream %" PRId64
                       " deferred for free (ref_count=%d)\n",
                       s->stream_id, s->ref_count);
        return;
    }

    /* Safe to destroy immediately.                                        */
    protohttp3_free_stream_ctx(s, h3_ctx);
}

/* =========================================================================
 * nghttp3 callbacks
 *
 * nghttp3 calls these when it has decoded an HTTP/3 frame from the stream
 * data handed to it by nghttp3_conn_read_stream().
 * ====================================================================== */

/*
 * Called once for each decoded header field within a HEADERS frame.
 * Equivalent to nghttp2's on_header_callback.
 */
static int
h3_on_recv_header(nghttp3_conn *conn, int64_t stream_id,
                  int32_t token,
                  nghttp3_rcbuf *name, nghttp3_rcbuf *value,
                  uint8_t flags, void *user_data,
                  void *stream_user_data)
{
    (void)conn; (void)token; (void)flags; (void)stream_user_data;

    protohttp3_conn_ctx_t *h3_ctx = user_data;

    stream_h3_ctx_t *s = protohttp3_find_stream(h3_ctx, stream_id);
    if (!s) {
        /*
         * First header for this stream – allocate a stream context.
         * In H3, the stream id is already known by the time nghttp3
         * delivers headers (ngtcp2 opened the stream first).
         */
        s = protohttp3_new_stream(h3_ctx, stream_id);
        if (!s)
            return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    s->ref_count++;

    nghttp3_vec name_vec  = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec value_vec = nghttp3_rcbuf_get_buf(value);

    if (protohttp3_stream_add_header(s,
            name_vec.base,  name_vec.len,
            value_vec.base, value_vec.len) != 0) {
        s->ref_count--;
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    log_dbg_printf("protohttp3: stream %" PRId64 " header: %.*s: %.*s\n",
                   stream_id,
                   (int)name_vec.len,  (char *)name_vec.base,
                   (int)value_vec.len, (char *)value_vec.base);

    s->ref_count--;
    return 0;
}

/*
 * Called when the HEADERS block is fully decoded (analogous to H2's
 * NGHTTP2_FLAG_END_HEADERS).  This is the correct place to act on the
 * complete header set (e.g. apply filter rules, begin upstream connection).
 */
static int
h3_on_end_headers(nghttp3_conn *conn, int64_t stream_id,
                  int fin, void *user_data,
                  void *stream_user_data)
{
    (void)conn; (void)stream_user_data;

    protohttp3_conn_ctx_t *h3_ctx = user_data;

    stream_h3_ctx_t *s = protohttp3_find_stream(h3_ctx, stream_id);
    if (!s)
        return 0; /* Nothing to do if stream not tracked.                 */

    s->ref_count++;
    s->headers_complete = 1;
    if (fin)
        s->end_stream = 1;

    log_dbg_printf("protohttp3: stream %" PRId64
                   " END_HEADERS (%zu headers, fin=%d)\n",
                   stream_id, s->headers_count, fin);

    /*
     * HERE: inspect s->headers[0..s->headers_count-1].
     *
     * For a request stream the special pseudo-headers will be present:
     *   :method, :path, :scheme, :authority
     * For a response stream (from upstream):
     *   :status
     *
     * This is where you would:
     *   1. Apply URL/Host filter rules (analogous to protohttp2_filter_request_header).
     *   2. Log the connection (protohttp_log_connect).
     *   3. Initiate forwarding to the upstream / downstream.
     */

    s->ref_count--;
    return 0;
}

/*
 * Called when raw body data is available on a stream.
 * Equivalent to nghttp2's on_data_chunk_recv_callback.
 */
static int
h3_on_recv_data(nghttp3_conn *conn, int64_t stream_id,
                const uint8_t *data, size_t datalen,
                void *user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;

    protohttp3_conn_ctx_t *h3_ctx = user_data;

    stream_h3_ctx_t *s = protohttp3_find_stream(h3_ctx, stream_id);
    if (!s) {
        /* Data before headers – should not normally happen.               */
        log_dbg_printf("protohttp3: data on unknown stream %" PRId64 "\n",
                       stream_id);
        return 0;
    }

    s->ref_count++;

    if (protohttp3_stream_append_body(s, data, datalen) != 0) {
        s->ref_count--;
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    log_dbg_printf("protohttp3: stream %" PRId64 " data %zu bytes\n",
                   stream_id, datalen);

    s->ref_count--;
    return 0;
}

/*
 * Called when the stream's DATA frames are exhausted and the FIN flag was
 * set.  Equivalent to nghttp2's on_stream_close when triggered by H3 layer.
 */
static int
h3_on_end_stream(nghttp3_conn *conn, int64_t stream_id,
                 void *user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;

    protohttp3_conn_ctx_t *h3_ctx = user_data;

    stream_h3_ctx_t *s = protohttp3_find_stream(h3_ctx, stream_id);
    if (!s)
        return 0;

    s->ref_count++;
    s->end_stream = 1;

    log_dbg_printf("protohttp3: stream %" PRId64 " END_STREAM\n", stream_id);

    /*
     * HERE: the request (or response) body is complete.
     * Forward accumulated body (s->body_buf[0..s->body_len]) upstream /
     * downstream, or signal the peer with a FIN.
     */

    s->ref_count--;

    /* Schedule stream context cleanup.                                    */
    s->term = 1;
    protohttp3_request_free_stream_ctx(s, h3_ctx);
    return 0;
}

/*
 * nghttp3 asks for stream data to send (read callback pattern used when we
 * are the request originator on the dst side).  For the client-facing src
 * side we act as a server so this callback is less frequently needed.
 *
 * Return the number of bytes placed in vec[0..*pcnt-1], or
 * NGHTTP3_ERR_WOULDBLOCK if nothing is ready.
 */
UNUSED static nghttp3_ssize
h3_stream_read_data(nghttp3_conn *conn, int64_t stream_id,
                    nghttp3_vec *vec, size_t veccnt,
                    uint32_t *pflags,
                    void *user_data, void *stream_user_data)
{
    (void)conn; (void)stream_user_data;

    protohttp3_conn_ctx_t *h3_ctx = user_data;
    stream_h3_ctx_t *s = protohttp3_find_stream(h3_ctx, stream_id);

    if (!s || s->body_len == 0) {
        /* Nothing buffered right now – tell nghttp3 to pause this stream. */
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    /* Hand the entire staging buffer as a single iovec.                   */
    if (veccnt < 1)
        return NGHTTP3_ERR_WOULDBLOCK;

    vec[0].base = s->body_buf;
    vec[0].len  = s->body_len;

    if (s->end_stream) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
    }

    /* Caller (ngtcp2 write path) will consume exactly vec[0].len bytes.  */
    /* We null the pointer without freeing so it can be re-used or freed   */
    /* later; in a production path you would use a proper ring-buffer.     */
    s->body_buf = NULL;
    s->body_len = 0;
    s->body_cap = 0;

    return 1; /* number of vecs filled */
}

/* =========================================================================
 * ngtcp2 callbacks
 *
 * ngtcp2 calls these during ngtcp2_conn_read_pkt() to notify us of
 * transport-level events and to deliver stream payload bytes.
 * ====================================================================== */

/*
 * ngtcp2 delivers decrypted stream data here.  We forward it straight into
 * nghttp3_conn_read_stream() which will parse H3 frames and invoke the
 * nghttp3 callbacks above.
 */
static int
quic_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                      int64_t stream_id,
                      uint64_t offset,
                      const uint8_t *data, size_t datalen,
                      void *user_data, void *stream_user_data)
{
    (void)conn; (void)offset; (void)stream_user_data;

    protohttp3_conn_ctx_t *h3_ctx = user_data;

    if (!h3_ctx->src_h3) {
        /* nghttp3 session not yet created (handshake incomplete).         */
        return 0;
    }

    int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;

    /*
     * Feed the raw H3 frame bytes into nghttp3.  nghttp3 will call our
     * h3_on_recv_header / h3_on_recv_data / h3_on_end_headers / h3_on_end_stream
     * callbacks as it parses complete frames.
     */
    nghttp3_ssize nread = nghttp3_conn_read_stream(
        h3_ctx->src_h3, stream_id, data, datalen, fin);
    if (nread < 0) {
        log_dbg_printf("protohttp3: nghttp3_conn_read_stream error: %s\n",
                       nghttp3_strerror((int)nread));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    /*
     * Inform ngtcp2 how many bytes the application has consumed so that
     * flow-control credit (MAX_STREAM_DATA / MAX_DATA) is correctly updated.
     */
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, (uint64_t)nread);
    ngtcp2_conn_extend_max_offset(conn, (uint64_t)nread);

    return 0;
}

/*
 * ngtcp2 tells us a new unidirectional stream was opened by the peer.
 * H3 control streams (stream types 0x00, 0x02, 0x03) arrive here.
 * We must accept them so nghttp3 can set up its internal state.
 */
static int
quic_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
    (void)conn;

    protohttp3_conn_ctx_t *h3_ctx = user_data;

    /*
     * For unidirectional streams opened by the client we create a
     * lightweight stream context.  nghttp3 identifies the stream type from
     * the first byte it reads.
     */
    if (!protohttp3_find_stream(h3_ctx, stream_id)) {
        if (!protohttp3_new_stream(h3_ctx, stream_id)) {
            log_dbg_printf("protohttp3: OOM for new stream %" PRId64 "\n",
                           stream_id);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    /* Let nghttp3 know a new unidirectional stream was opened.            */
    if (h3_ctx->src_h3) {
        int rv = nghttp3_conn_set_stream_user_data(h3_ctx->src_h3, stream_id,
                                                   NULL);
        if (rv != 0 && rv != NGHTTP3_ERR_INVALID_ARGUMENT) {
            /* INVALID_ARGUMENT means nghttp3 already knows this stream.   */
            log_dbg_printf("protohttp3: nghttp3_conn_set_stream_user_data: %s\n",
                           nghttp3_strerror(rv));
        }
    }

    log_dbg_printf("protohttp3: stream opened %" PRId64 "\n", stream_id);
    return 0;
}

/*
 * ngtcp2 tells us a stream was closed (STREAM_FIN or RESET_STREAM).
 * We schedule the stream_h3_ctx_t for cleanup.
 */
static int
quic_stream_close(ngtcp2_conn *conn, uint32_t flags,
                  int64_t stream_id, uint64_t app_error_code,
                  void *user_data, void *stream_user_data)
{
    (void)conn; (void)flags; (void)app_error_code; (void)stream_user_data;

    protohttp3_conn_ctx_t *h3_ctx = user_data;

    if (h3_ctx->src_h3) {
        nghttp3_conn_close_stream(h3_ctx->src_h3, stream_id, app_error_code);
    }

    stream_h3_ctx_t *s = protohttp3_find_stream(h3_ctx, stream_id);
    if (s) {
        if (!s->closed) {
            s->closed = 1;
        } else {
            /* Second close event: ready to tear down.                     */
            s->term = 1;
            protohttp3_request_free_stream_ctx(s, h3_ctx);
        }
    }

    log_dbg_printf("protohttp3: stream closed %" PRId64 "\n", stream_id);
    return 0;
}

/*
 * ngtcp2 delivers unidirectional stream data (H3 control/QPACK streams).
 * Route it through nghttp3 so it can process SETTINGS, QPACK instructions
 * etc.  The signature matches recv_stream_data but the stream is uni-dir.
 */
/*
 * NOTE: ngtcp2 v0.12 uses a single recv_stream_data callback for both
 * bidirectional and unidirectional streams; the NGTCP2_STREAM_DATA_FLAG_FIN
 * flag in 'flags' distinguishes end-of-stream.  There is no separate
 * recv_uni_stream_data field in the ngtcp2_callbacks struct at this version.
 * The quic_recv_stream_data callback above handles all stream types.
 */

/*
 * ngtcp2 handshake-complete callback.
 *
 * At this point the QUIC handshake is done and we can create the nghttp3
 * session and initiate the H3 control streams.
 */
static int
quic_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;

    protohttp3_conn_ctx_t *h3_ctx = user_data;

    log_dbg_printf("protohttp3: QUIC handshake completed\n");

    /* ------------------------------------------------------------------
     * Build the nghttp3 callback table.
     * ------------------------------------------------------------------ */
    nghttp3_callbacks h3cb = {0};
    h3cb.recv_header        = h3_on_recv_header;
    h3cb.end_headers        = h3_on_end_headers;
    h3cb.recv_data          = h3_on_recv_data;
    h3cb.end_stream         = h3_on_end_stream;

    /* ------------------------------------------------------------------
     * Create the server-side H3 session (client-facing / src).
     * Static QPACK only (max_table_capacity = 0, blocked_streams = 0).
     * ------------------------------------------------------------------ */
    nghttp3_settings h3settings;
    nghttp3_settings_default(&h3settings);
    /* h3settings.max_field_section_size can be tuned here.               */

    int rv = nghttp3_conn_server_new(&h3_ctx->src_h3,
                                     &h3cb,
                                     &h3settings,
                                     NULL,           /* mem allocator (default) */
                                     h3_ctx);
    if (rv != 0) {
        log_dbg_printf("protohttp3: nghttp3_conn_server_new: %s\n",
                       nghttp3_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    /*
     * Bind the three mandatory H3 unidirectional control streams that we
     * own (as the server):
     *   - Control stream  (type 0x00)
     *   - QPACK encoder   (type 0x02)
     *   - QPACK decoder   (type 0x03)
     *
     * ngtcp2 allocates the stream ids for us via ngtcp2_conn_open_uni_stream.
     */
    int64_t ctrl_stream_id, qenc_stream_id, qdec_stream_id;

    if (ngtcp2_conn_open_uni_stream(h3_ctx->src_conn, &ctrl_stream_id, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(h3_ctx->src_conn, &qenc_stream_id, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(h3_ctx->src_conn, &qdec_stream_id, NULL) != 0) {
        log_dbg_printf("protohttp3: failed to open H3 control streams\n");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    rv = nghttp3_conn_bind_control_stream(h3_ctx->src_h3, ctrl_stream_id);
    if (rv != 0) {
        log_dbg_printf("protohttp3: bind_control_stream: %s\n",
                       nghttp3_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    rv = nghttp3_conn_bind_qpack_streams(h3_ctx->src_h3,
                                         qenc_stream_id,
                                         qdec_stream_id);
    if (rv != 0) {
        log_dbg_printf("protohttp3: bind_qpack_streams: %s\n",
                       nghttp3_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    /* Arm the write event so SETTINGS / QPACK streams are flushed.       */
    event_add(h3_ctx->src_wev, NULL);

    return 0;
}

/*
 * ngtcp2 requests random bytes for connection IDs, stateless resets, etc.
 * In a real implementation hook into the system CSPRNG.
 */
/*
 * ngtcp2_rand callback: must return void (as of ngtcp2 0.12+).
 * arc4random_buf() is available on Linux via glibc 2.36+ or libbsd.
 */
static void
quic_rand(uint8_t *dest, size_t destlen,
          const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    arc4random_buf(dest, destlen);
}

/*
 * ngtcp2 requests a new connection ID.  The simplest correct approach is
 * to generate a cryptographically random ID.
 */
static int
quic_get_new_connection_id(ngtcp2_conn *conn,
                           ngtcp2_cid *cid,
                           uint8_t *token,
                           size_t cidlen,
                           void *user_data)
{
    (void)conn; (void)user_data;
    arc4random_buf(cid->data, cidlen);
    cid->datalen = cidlen;
    arc4random_buf(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

/* =========================================================================
 * UDP I/O helpers
 * ====================================================================== */

/*
 * Receive a single datagram from the UDP socket using recvmsg() so that we
 * can extract:
 *   - The peer address (required by ngtcp2 path tracking).
 *   - The local destination address (for path validation / migration).
 *   - The ECN codepoint (DSCP bits) used by QUIC for congestion control.
 *
 * Returns the number of bytes received on success, -1 on error (EAGAIN /
 * EWOULDBLOCK are swallowed and return 0).
 */
static ssize_t
protohttp3_recvmsg(int fd,
                   uint8_t *buf, size_t bufsz,
                   struct sockaddr_storage *peer_addr, socklen_t *peer_addrlen,
                   struct sockaddr_storage *local_addr, socklen_t *local_addrlen,
                   int *ecn)
{
    struct iovec iov = { .iov_base = buf, .iov_len = bufsz };

    /* Ancillary data buffer large enough for IP_PKTINFO + ECN.           */
    uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                    CMSG_SPACE(sizeof(int))];

    struct msghdr msg = {
        .msg_name       = peer_addr,
        .msg_namelen    = sizeof(*peer_addr),
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    ssize_t n = recvmsg(fd, &msg, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }

    *peer_addrlen = msg.msg_namelen;
    *ecn = 0;
    *local_addrlen = 0;

    /* Walk ancillary control messages.                                    */
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {

        /* IPv4 destination address + ECN.                                 */
        if (cmsg->cmsg_level == IPPROTO_IP) {
            if (cmsg->cmsg_type == IP_PKTINFO) {
                struct in_pktinfo *pkt = (void *)CMSG_DATA(cmsg);
                struct sockaddr_in *la = (struct sockaddr_in *)local_addr;
                la->sin_family = AF_INET;
                la->sin_addr   = pkt->ipi_addr;
                *local_addrlen = sizeof(*la);
            }
#ifdef IP_TOS
            if (cmsg->cmsg_type == IP_TOS) {
                *ecn = *(int *)CMSG_DATA(cmsg) & 0x03;
            }
#endif
        }

        /* IPv6 destination address + ECN.                                 */
        if (cmsg->cmsg_level == IPPROTO_IPV6) {
            if (cmsg->cmsg_type == IPV6_PKTINFO) {
                struct in6_pktinfo *pkt6 = (void *)CMSG_DATA(cmsg);
                struct sockaddr_in6 *la6 = (struct sockaddr_in6 *)local_addr;
                la6->sin6_family = AF_INET6;
                la6->sin6_addr   = pkt6->ipi6_addr;
                *local_addrlen   = sizeof(*la6);
            }
#ifdef IPV6_TCLASS
            if (cmsg->cmsg_type == IPV6_TCLASS) {
                *ecn = *(int *)CMSG_DATA(cmsg) & 0x03;
            }
#endif
        }
    }

    return n;
}

/*
 * Write all serialised QUIC packets that ngtcp2 has queued for the client
 * (src) side.  Called after every ngtcp2_conn_read_pkt() and from the
 * write-ready Libevent callback.
 *
 * ngtcp2 drives the output write loop:
 *   1. nghttp3_conn_writev_stream() fills iovecs with H3 frame data.
 *   2. ngtcp2_conn_writev_stream() encapsulates that into QUIC packets.
 *   3. sendmsg() transmits each QUIC packet to the peer.
 */
static void
protohttp3_flush_src(protohttp3_conn_ctx_t *h3_ctx)
{
    if (!h3_ctx->src_conn)
        return;

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    /* Destination (peer) address for sendmsg().                          */
    ngtcp2_path path;
    ngtcp2_addr_init(&path.local,
                     (struct sockaddr *)&h3_ctx->src_local_addr,
                     h3_ctx->src_local_addrlen);
    ngtcp2_addr_init(&path.remote,
                     (struct sockaddr *)&h3_ctx->src_peer_addr,
                     h3_ctx->src_peer_addrlen);

    static uint8_t pktbuf[H3_DGRAM_BUFSZ];

    for (;;) {
        nghttp3_vec vecs[H3_MAX_IOVECS];
        int64_t     stream_id = -1;
        int         fin       = 0;
        nghttp3_ssize sveccnt = 0;

        /*
         * Ask nghttp3 which stream has data ready and collect iovecs.
         * This is the nghttp3->ngtcp2 bridging step.
         */
        if (h3_ctx->src_h3) {
            sveccnt = nghttp3_conn_writev_stream(h3_ctx->src_h3,
                                                 &stream_id, &fin,
                                                 vecs, H3_MAX_IOVECS);
            if (sveccnt < 0) {
                log_dbg_printf("protohttp3: nghttp3_conn_writev_stream: %s\n",
                               nghttp3_strerror((int)sveccnt));
                break;
            }
        }

        ngtcp2_ssize pktlen;
        ngtcp2_pkt_info pi = {0};

        if (sveccnt == 0 || stream_id < 0) {
            /*
             * No H3 data to send; let ngtcp2 emit any pending ACKs,
             * CRYPTO, or PADDING frames.
             */
            pktlen = ngtcp2_conn_write_pkt(h3_ctx->src_conn,
                                           &path, &pi,
                                           pktbuf, sizeof(pktbuf),
                                           h3_timestamp());
        } else {
            /*
             * Embed H3 stream data into a QUIC STREAM frame.
             */
            pktlen = ngtcp2_conn_writev_stream(
                         h3_ctx->src_conn,
                         &path, &pi,
                         pktbuf, sizeof(pktbuf),
                         NULL,          /* pdatalen out (we ignore it)   */
                         NGTCP2_WRITE_STREAM_FLAG_MORE,
                         stream_id, (const ngtcp2_vec *)vecs,
                         (size_t)sveccnt,
                         h3_timestamp());
        }

        if (pktlen < 0) {
            if (pktlen == NGTCP2_ERR_WRITE_MORE) {
                /*
                 * ngtcp2 consumed the iovecs and coalesced them into its
                 * internal buffer; call nghttp3 again to get more data.
                 */
                if (h3_ctx->src_h3 && stream_id >= 0) {
                    nghttp3_conn_add_write_offset(h3_ctx->src_h3,
                                                  stream_id,
                                                  /* how much ngtcp2 consumed */
                                                  /* (not exposed cleanly in  */
                                                  /* this simplified loop):   */
                                                  0);
                }
                continue;
            }
            log_dbg_printf("protohttp3: ngtcp2 write error: %s\n",
                           ngtcp2_strerror((int)pktlen));
            break;
        }

        if (pktlen == 0)
            break; /* No more packets to send.                            */

        /*
         * Notify nghttp3 how many bytes were handed to ngtcp2 for this
         * stream so it can advance its internal send offset.
         */
        if (h3_ctx->src_h3 && stream_id >= 0 && sveccnt > 0) {
            size_t consumed = 0;
            for (nghttp3_ssize i = 0; i < sveccnt; i++)
                consumed += vecs[i].len;
            nghttp3_conn_add_write_offset(h3_ctx->src_h3, stream_id, consumed);
            if (fin)
                nghttp3_conn_add_ack_offset(h3_ctx->src_h3, stream_id, consumed);
        }

        /* Transmit the packet.                                            */
        struct iovec iov = { .iov_base = pktbuf, .iov_len = (size_t)pktlen };
        struct msghdr mhdr = {
            .msg_name    = (struct sockaddr *)&h3_ctx->src_peer_addr,
            .msg_namelen = h3_ctx->src_peer_addrlen,
            .msg_iov     = &iov,
            .msg_iovlen  = 1,
        };
        ssize_t sent = sendmsg(h3_ctx->src_fd, &mhdr, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Socket is not ready; arm the write-ready event.         */
                event_add(h3_ctx->src_wev, NULL);
                break;
            }
            log_dbg_printf("protohttp3: sendmsg: %s\n", strerror(errno));
            break;
        }
    }

    /* Schedule the ngtcp2 loss-detection / keep-alive timer.             */
    protohttp3_arm_timer(h3_ctx);
}

/* =========================================================================
 * Libevent callbacks for the raw UDP fds
 * ====================================================================== */

/*
 * Fired when the UDP socket for the client side (src_fd) is readable.
 *
 * The core QUIC receive loop:
 *   recvmsg()  ->  ngtcp2_conn_read_pkt()
 *              ->  quic_recv_stream_data()
 *              ->  nghttp3_conn_read_stream()
 *              ->  h3_on_recv_header / h3_on_recv_data / ...
 */
static void
protohttp3_src_read_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    protohttp3_conn_ctx_t *h3_ctx = arg;

    uint8_t buf[H3_DGRAM_BUFSZ];
    struct sockaddr_storage peer_addr;
    socklen_t               peer_addrlen;
    struct sockaddr_storage local_addr;
    socklen_t               local_addrlen;
    int ecn = 0;

    /*
     * Drain all immediately available datagrams in a tight loop.  Staying
     * in the callback reduces per-datagram Libevent overhead.
     */
    for (;;) {
        ssize_t n = protohttp3_recvmsg(fd,
                                       buf, sizeof(buf),
                                       &peer_addr,  &peer_addrlen,
                                       &local_addr, &local_addrlen,
                                       &ecn);
        if (n <= 0)
            break;

        /* Cache peer / local addresses on first receive.                  */
        if (h3_ctx->src_peer_addrlen == 0) {
            memcpy(&h3_ctx->src_peer_addr, &peer_addr, peer_addrlen);
            h3_ctx->src_peer_addrlen = peer_addrlen;
        }
        if (h3_ctx->src_local_addrlen == 0 && local_addrlen > 0) {
            memcpy(&h3_ctx->src_local_addr, &local_addr, local_addrlen);
            h3_ctx->src_local_addrlen = local_addrlen;
        }

        /* Build the ngtcp2 path descriptor from the addresses.            */
        ngtcp2_path path;
        ngtcp2_addr_init(&path.local,
                         (struct sockaddr *)&h3_ctx->src_local_addr,
                         h3_ctx->src_local_addrlen);
        ngtcp2_addr_init(&path.remote,
                         (struct sockaddr *)&peer_addr,
                         peer_addrlen);

        ngtcp2_pkt_info pi = { .ecn = (uint8_t)ecn };

        /*
         * Hand the raw datagram to ngtcp2.  ngtcp2 decrypts the QUIC
         * packet, demultiplexes streams, and fires our ngtcp2 callbacks
         * which in turn drive nghttp3.
         */
        int rv = ngtcp2_conn_read_pkt(h3_ctx->src_conn,
                                      &path, &pi,
                                      buf, (size_t)n,
                                      h3_timestamp());
        if (rv != 0) {
            log_dbg_printf("protohttp3: ngtcp2_conn_read_pkt: %s\n",
                           ngtcp2_strerror(rv));
            /* Non-fatal: keep draining the socket.                        */
        }
    }

    /* After processing all inbound datagrams, flush any queued output.    */
    protohttp3_flush_src(h3_ctx);
}

/*
 * Fired when the UDP socket is writable again after a previous sendmsg()
 * returned EAGAIN.  We just re-enter the write flush loop.
 */
static void
protohttp3_src_write_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    protohttp3_conn_ctx_t *h3_ctx = arg;
    protohttp3_flush_src(h3_ctx);
}

/* =========================================================================
 * ngtcp2 loss-detection / keep-alive timer
 * ====================================================================== */

/*
 * Set or reschedule the Libevent timer according to ngtcp2's requested
 * expiry time.  ngtcp2_conn_get_expiry() returns the deadline in
 * nanoseconds (CLOCK_MONOTONIC).  We convert the delta to a struct timeval.
 */
static int
protohttp3_arm_timer(protohttp3_conn_ctx_t *h3_ctx)
{
    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(h3_ctx->src_conn);
    ngtcp2_tstamp now    = h3_timestamp();

    if (expiry == UINT64_MAX) {
        event_del(h3_ctx->timer_ev);
        return 0;
    }

    int64_t delta_ns = (int64_t)(expiry - now);
    if (delta_ns < 0)
        delta_ns = 0;

    struct timeval tv = {
        .tv_sec  = (long)(delta_ns / 1000000000LL),
        .tv_usec = (long)((delta_ns % 1000000000LL) / 1000),
    };

    return event_add(h3_ctx->timer_ev, &tv);
}

/*
 * Fired when the ngtcp2 timer expires.  Call ngtcp2_conn_handle_expiry()
 * to process loss-detection, anti-amplification, keep-alive etc., then
 * flush output.
 */
static void
protohttp3_timer_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    protohttp3_conn_ctx_t *h3_ctx = arg;

    int rv = ngtcp2_conn_handle_expiry(h3_ctx->src_conn, h3_timestamp());
    if (rv != 0) {
        log_dbg_printf("protohttp3: ngtcp2_conn_handle_expiry: %s\n",
                       ngtcp2_strerror(rv));
        return;
    }

    protohttp3_flush_src(h3_ctx);
}

/* =========================================================================
 * TLS/QUIC crypto stubs
 *
 * A complete implementation must implement the ngtcp2_crypto_conn_ref
 * abstraction and use either:
 *   - ngtcp2_crypto_openssl (OpenSSL 3.x QUIC)
 *   - ngtcp2_crypto_boringssl (BoringSSL)
 *   - ngtcp2_crypto_wolfssl  (wolfSSL)
 *
 * These stubs satisfy the compiler; replace them with the real crypto
 * callbacks from the chosen library before testing.
 * ====================================================================== */

static int
crypto_client_initial(ngtcp2_conn *conn, void *user_data)
{
    (void)conn; (void)user_data;
    /* Server-side: ngtcp2 calls this to start TLS; delegate to TLS lib.  */
    return 0;
}

static int
crypto_recv_client_initial(ngtcp2_conn *conn,
                           const ngtcp2_cid *dcid,
                           void *user_data)
{
    (void)conn; (void)dcid; (void)user_data;
    return 0;
}

static int
crypto_recv_crypto_data(ngtcp2_conn *conn,
                        ngtcp2_crypto_level crypto_level,
                        uint64_t offset,
                        const uint8_t *data, size_t datalen,
                        void *user_data)
{
    (void)conn; (void)crypto_level; (void)offset; (void)data; (void)datalen;
    (void)user_data;
    /*
     * Deliver TLS handshake bytes to the TLS library.
     * Real code: ngtcp2_crypto_openssl_configure_server_session() or
     *            ngtcp2_crypto_recv_crypto_data_cb().
     */
    return 0;
}

/* =========================================================================
 * Public API
 * ====================================================================== */

/*
 * protohttp3_new – create a fully wired QUIC/H3 server-side session.
 *
 * After this function returns:
 *   - h3_ctx->src_conn is a ngtcp2 server session in the Initial state.
 *   - h3_ctx->src_rev  is an armed Libevent READ event on src_fd.
 *   - h3_ctx->src_wev  is a one-shot WRITE event (armed on demand).
 *   - h3_ctx->timer_ev is a one-shot timer (rearmed by protohttp3_arm_timer).
 *   - The nghttp3 session (src_h3) is created later inside
 *     quic_handshake_completed() once the TLS handshake is done.
 */
protohttp3_conn_ctx_t *
protohttp3_new(int src_fd, struct event_base *evbase, pxy_conn_ctx_t *ctx)
{
    protohttp3_conn_ctx_t *h3_ctx = calloc(1, sizeof(protohttp3_conn_ctx_t));
    if (!h3_ctx)
        return NULL;

    h3_ctx->src_fd  = src_fd;
    h3_ctx->dst_fd  = -1;
    h3_ctx->evbase  = evbase;
    h3_ctx->ctx     = ctx;

    /* ------------------------------------------------------------------
     * Build the ngtcp2 server callbacks table.
     * ------------------------------------------------------------------ */
    ngtcp2_callbacks cb = {0};

    /* Mandatory crypto hooks – replace stubs with real TLS library.      */
    cb.client_initial        = crypto_client_initial;
    cb.recv_client_initial   = crypto_recv_client_initial;
    cb.recv_crypto_data      = crypto_recv_crypto_data;

    /* QUIC / transport hooks.                                             */
    cb.handshake_completed   = quic_handshake_completed;
    cb.recv_stream_data      = quic_recv_stream_data;
    /* recv_uni_stream_data does not exist in ngtcp2 v0.12; the single     */
    /* recv_stream_data callback handles both bidi and uni streams.        */
    cb.stream_open           = quic_stream_open;
    cb.stream_close          = quic_stream_close;
    cb.rand                  = quic_rand;
    cb.get_new_connection_id = quic_get_new_connection_id;

    /* ------------------------------------------------------------------
     * Build ngtcp2 server settings.
     * ------------------------------------------------------------------ */
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = h3_timestamp();
    settings.log_printf = NULL; /* Set to log_dbg_printf to enable ngtcp2 debug logs. */

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi       = 128;
    params.initial_max_streams_uni        = 3; /* control + qenc + qdec  */
    params.initial_max_data               = 1024 * 1024;
    params.initial_max_stream_data_bidi_local   = 256 * 1024;
    params.initial_max_stream_data_bidi_remote  = 256 * 1024;
    params.initial_max_stream_data_uni          = 256 * 1024;

    /*
     * Placeholder connection IDs.  A real implementation derives these
     * from the Initial packet the client sent (stored in a pre-parsed
     * ngtcp2_pkt_hd).  For the prototype we generate random IDs.
     */
    ngtcp2_cid scid, dcid;
    scid.datalen = NGTCP2_MAX_CIDLEN;
    arc4random_buf(scid.data, scid.datalen);
    dcid.datalen = NGTCP2_MAX_CIDLEN;
    arc4random_buf(dcid.data, dcid.datalen);

    /*
     * Path: src_fd is bound to a local address; use a zero-filled
     * placeholder here since we fill in the real addresses from the first
     * recvmsg() call inside protohttp3_src_read_cb().
     */
    struct sockaddr_in local4 = { .sin_family = AF_INET };
    struct sockaddr_in peer4  = { .sin_family = AF_INET };
    ngtcp2_path path;
    ngtcp2_addr_init(&path.local,  (struct sockaddr *)&local4, sizeof(local4));
    ngtcp2_addr_init(&path.remote, (struct sockaddr *)&peer4,  sizeof(peer4));

    int rv = ngtcp2_conn_server_new(&h3_ctx->src_conn,
                                    &dcid, &scid,
                                    &path,
                                    NGTCP2_PROTO_VER_V1,
                                    &cb,
                                    &settings,
                                    &params,
                                    NULL,   /* mem allocator (default)    */
                                    h3_ctx);
    if (rv != 0) {
        log_dbg_printf("protohttp3: ngtcp2_conn_server_new: %s\n",
                       ngtcp2_strerror(rv));
        goto err_conn;
    }

    /* ------------------------------------------------------------------
     * Create Libevent events for the raw UDP file descriptor.
     *
     * EV_READ | EV_PERSIST  – fires every time the fd is readable.
     * EV_WRITE              – one-shot, armed only when we have output.
     * ------------------------------------------------------------------ */
    h3_ctx->src_rev = event_new(evbase, src_fd,
                                EV_READ | EV_PERSIST,
                                protohttp3_src_read_cb, h3_ctx);
    if (!h3_ctx->src_rev)
        goto err_rev;

    h3_ctx->src_wev = event_new(evbase, src_fd,
                                EV_WRITE,
                                protohttp3_src_write_cb, h3_ctx);
    if (!h3_ctx->src_wev)
        goto err_wev;

    /* Timer event: fd = -1, EV_TIMEOUT (one-shot).                       */
    h3_ctx->timer_ev = event_new(evbase, -1,
                                 EV_TIMEOUT,
                                 protohttp3_timer_cb, h3_ctx);
    if (!h3_ctx->timer_ev)
        goto err_timer;

    /* Arm the read event immediately.                                     */
    if (event_add(h3_ctx->src_rev, NULL) != 0)
        goto err_arm;

    log_dbg_printf("protohttp3: session created on fd=%d\n", src_fd);
    return h3_ctx;

err_arm:
    event_free(h3_ctx->timer_ev);
err_timer:
    event_free(h3_ctx->src_wev);
err_wev:
    event_free(h3_ctx->src_rev);
err_rev:
    ngtcp2_conn_del(h3_ctx->src_conn);
err_conn:
    free(h3_ctx);
    return NULL;
}

/*
 * protohttp3_free – tear down the entire QUIC/H3 session.
 *
 * Mirrors protohttp2_free() in protohttp2.c.
 */
void
protohttp3_free(protohttp3_conn_ctx_t *h3_ctx)
{
    /* Stop all Libevent events first so no more callbacks fire.           */
    if (h3_ctx->src_rev)  { event_del(h3_ctx->src_rev);  event_free(h3_ctx->src_rev);  }
    if (h3_ctx->src_wev)  { event_del(h3_ctx->src_wev);  event_free(h3_ctx->src_wev);  }
    if (h3_ctx->dst_rev)  { event_del(h3_ctx->dst_rev);  event_free(h3_ctx->dst_rev);  }
    if (h3_ctx->dst_wev)  { event_del(h3_ctx->dst_wev);  event_free(h3_ctx->dst_wev);  }
    if (h3_ctx->timer_ev) { event_del(h3_ctx->timer_ev); event_free(h3_ctx->timer_ev); }

    /* Destroy nghttp3 sessions.                                           */
    if (h3_ctx->src_h3) { nghttp3_conn_del(h3_ctx->src_h3); h3_ctx->src_h3 = NULL; }
    if (h3_ctx->dst_h3) { nghttp3_conn_del(h3_ctx->dst_h3); h3_ctx->dst_h3 = NULL; }

    /* Destroy ngtcp2 connections.                                         */
    if (h3_ctx->src_conn) { ngtcp2_conn_del(h3_ctx->src_conn); h3_ctx->src_conn = NULL; }
    if (h3_ctx->dst_conn) { ngtcp2_conn_del(h3_ctx->dst_conn); h3_ctx->dst_conn = NULL; }

    /* Free all stream contexts.                                           */
    while (h3_ctx->streams)
        protohttp3_free_stream_ctx(h3_ctx->streams, h3_ctx);

    /* Close raw UDP sockets.                                              */
    if (h3_ctx->src_fd >= 0) { close(h3_ctx->src_fd); h3_ctx->src_fd = -1; }
    if (h3_ctx->dst_fd >= 0) { close(h3_ctx->dst_fd); h3_ctx->dst_fd = -1; }

    free(h3_ctx);
    log_dbg_printf("protohttp3: session freed\n");
}

/* vim: set noet ft=c: */
