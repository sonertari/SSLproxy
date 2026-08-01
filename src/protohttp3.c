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

#include "protohttp.h"
#include "protohttp3.h"
#include "log.h"

#ifndef WITHOUT_ICAP
#include "icap.h"
#endif /* !WITHOUT_ICAP */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>          /* clock_gettime(CLOCK_MONOTONIC)              */
// #include <ctype.h>      /* for tolower() in header filtering, but not used yet */

/* recvmsg() ancillary data for ECN and destination-address extraction.   */
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>    /* in_pktinfo, in6_pktinfo, IP_TOS, ...        */

#include <event2/event.h>

// For debugging, we need to include arpa/inet.h for inet_ntop() to print IP addresses.
#include <arpa/inet.h>

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

static void protohttp3_src_write_cb(evutil_socket_t fd, short what, void *arg);
static void protohttp3_timer_cb(evutil_socket_t fd, short what, void *arg);

static int  protohttp3_arm_timer(protohttp3_ctx_t *h3_ctx);

static nghttp3_ssize
h3_stream_read_data(nghttp3_conn *conn, int64_t stream_id,
                    nghttp3_vec *vec, size_t veccnt,
                    uint32_t *pflags,
                    void *user_data, void *stream_user_data);

/* Maximum iovecs we ask nghttp3 to fill in one writev call.              */
#define H3_MAX_IOVECS   16

/* =========================================================================
 * stream_h3_ctx_t helpers
 * ====================================================================== */

static protohttp3_stream_ctx_t *
protohttp3_get_stream_ctx(protohttp3_ctx_t *h3_ctx, int64_t stream_id, int reqmod)
{
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;

    protohttp3_stream_ctx_t *s = h3_ctx->streams;
    while (s) {
        if (reqmod ? s->src_stream_id == stream_id : s->dst_stream_id == stream_id) {
            // log_finest_va("Found %s stream id=%" PRId64 " fd=%d", reqmod ? "src" : "dst", reqmod ? s->src_stream_id : s->dst_stream_id, h3_ctx->dst_fd);
            return s;
        }
        s = s->next;
    }

    log_finest_va("Cannot find stream context for stream_id=%" PRId64 ", reqmod=%d", stream_id, reqmod);
    return NULL;
}

static protohttp3_stream_ctx_t *
protohttp3_new_stream_ctx(protohttp3_ctx_t *h3_ctx, int64_t stream_id)
{
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;

    log_finest_va("ENTER, stream_id=%" PRId64, stream_id);

    protohttp3_stream_ctx_t *s = malloc(sizeof(protohttp3_stream_ctx_t));
    if (!s)
        return NULL;
    memset(s, 0, sizeof(protohttp3_stream_ctx_t));

    s->src_stream_id = stream_id;

    // Not yet assigned by ngtcp2_conn_open_bidi_stream()
    // Set to -1 to indicate that the dst_stream_id is not yet known.
    s->dst_stream_id = -1;
    s->ctx = ctx;

    // Set up the data reader hook
    s->dr.read_data = h3_stream_read_data;

    s->http_ctx = malloc(sizeof(protohttp_ctx_t));
	if (!s->http_ctx) {
        free(s);
		return NULL;
	}
	memset(s->http_ctx, 0, sizeof(protohttp_ctx_t));

#ifndef WITHOUT_ICAP
    s->icap_ctx = icap_init(ctx, PROTO_HTTP3, s, h3_ctx);
	if (!s->icap_ctx) {
        free(s->http_ctx);
        free(s);
		return NULL;
    }
    // s->icap_ctx->send_data_to_src_cb = protohttp2_icap_send_data_to_src_cb;
    // s->icap_ctx->send_data_to_dst_cb = protohttp2_icap_send_data_to_dst_cb;
    // s->icap_ctx->failopen_to_dest_cb = protohttp2_icap_failopen_to_dest_cb;
#endif /* !WITHOUT_ICAP */

    // Prepend to the stream list
    s->next = h3_ctx->streams;
    h3_ctx->streams = s;
    return s;
}

static void
protohttp3_free_stream_headers(protohttp3_stream_ctx_t *s)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
#ifndef WITHOUT_ICAP
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx->reqmod);
#else /* !WITHOUT_ICAP */
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);
#endif /* !WITHOUT_ICAP */

    for (size_t i = 0; i < s->headers_count; i++) {
        if (s->headers[i].name) {
            free((void *)s->headers[i].name);
            s->headers[i].name = NULL;
        }
        if (s->headers[i].value) {
            free((void *)s->headers[i].value);
            s->headers[i].value = NULL;
        }
    }
    s->headers_count = 0;
    s->headers_capacity = 0;

    free(s->headers);
    s->headers = NULL;
}

static void NONNULL(1)
protohttp3_free_stream_ctx(protohttp3_stream_ctx_t *s)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    UNUSED protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp3_ctx_t *h3_ctx = http_ctx->arg;
#ifndef WITHOUT_ICAP
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx ? s->icap_ctx->reqmod : -1);
#else /* !WITHOUT_ICAP */
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);
#endif /* !WITHOUT_ICAP */

    // Cancel pending deferred-free timer if still armed
    if (s->ev_free) {
        event_free(s->ev_free);
        s->ev_free = NULL;
    }

    if (s->headers) {
        protohttp3_free_stream_headers(s);
    }

    free(s->body_buf);

#ifndef WITHOUT_ICAP
    if (s->icap_ctx) {
        // Disconnect the ICAP chain to stop any further event callbacks,
        // but do not terminate the icap services here, icap_ctx_free() should do that
        // TODO: Can we term the icap services here?
    	icap_disconnect(s->icap_ctx, 0);

        s->icap_ctx->stream_ctx = NULL;
        if (icap_enabled(s->icap_ctx) && !icap_is_finished(s->icap_ctx)) {
            log_finest("ICAP not finished, set icap_ctx term flag");
            s->icap_ctx->term = 1;
        } else {
            log_finest("ICAP finished or not enabled, free icap_ctx");
            // Do not term owner, we are already freeing the owner stream here
            icap_ctx_free(s->icap_ctx, 0);
            s->icap_ctx = NULL;
        }
    }
    else {
        log_finest("No ICAP context");
    }
#endif /* !WITHOUT_ICAP */

    if (s->http_ctx) {
        protohttp_free_ctx(s->http_ctx);
        s->http_ctx = NULL;
    }

    // Unlink from the connection stream list
    if (h3_ctx->streams == s) {
        h3_ctx->streams = s->next;
    } else {
        protohttp3_stream_ctx_t *prev = h3_ctx->streams;
        while (prev && prev->next != s)
            prev = prev->next;
        if (prev)
            prev->next = s->next;
    }

    free(s);
}

/*
 * Deferred-free callback fired by the zero-timeout Libevent timer.
 * By the time this runs the C call stack that had ref_count > 0 has
 * completely unwound, so it is safe to destroy the stream.
 */
static void
protohttp3_deferred_free_stream_ctx_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
    protohttp3_stream_ctx_t *s = arg;
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("Execute deferred free of stream_ctx, src_stream=%" PRId64 ", dst_stream=%" PRId64, s->src_stream_id, s->dst_stream_id);

    // Perform the actual, complete teardown
    protohttp3_free_stream_ctx(s);
}

void
protohttp3_request_free_stream_ctx(protohttp3_stream_ctx_t *s, int reqmod)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("stream %" PRId64 " free requested", s->src_stream_id);

    if (s->ref_count > 0) {
        // Something on the call stack still references this stream
        if (s->deferred_free_pending) {
            log_finest_va("stream %" PRId64 " already deferred for free", s->src_stream_id);
            return;
        }
        s->deferred_free_pending = 1;

        // Fire on the next event-loop iteration (zero timeout)
        s->ev_free = event_new(ctx->thr->evbase, -1, 0, protohttp3_deferred_free_stream_ctx_cb, s);
        if (!s->ev_free) {
            return;
        }
        struct timeval tv = {0, 0};
        if (event_add(s->ev_free, &tv) == -1) {
            event_free(s->ev_free);
            s->ev_free = NULL;
        }
        log_finest_va("stream %" PRId64 " deferred for free (ref_count=%d)",
                       s->src_stream_id, s->ref_count);
        return;
    }

    if (!reqmod) {
        log_finest_va("stream %" PRId64 " is server-side, free immediately", s->src_stream_id);
        // Safe to destroy immediately
        protohttp3_free_stream_ctx(s);
    } else {
        log_finest_va("stream %" PRId64 " is client-side, wait for server side", s->src_stream_id);
    }
}

/*
 * Append a single name-value header pair to the stream's header array,
 * growing the backing array by doubling as needed.
 *
 * Returns 0 on success, -1 on OOM.
 */
static int
protohttp3_add_nv_header(protohttp3_stream_ctx_t *s,
                         const uint8_t *name,  size_t namelen,
                         const uint8_t *value, size_t valuelen)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("%.*s: %.*s", (int)namelen, name, (int)valuelen, value);

    if (s->headers_count >= s->headers_capacity) {
        size_t new_capacity = s->headers_capacity == 0 ? 16 : s->headers_capacity * 2;
        nghttp3_nv *tmp = realloc(s->headers, new_capacity * sizeof(nghttp3_nv));
        if (!tmp) {
            log_fine("Failed reallocating headers");
            return -1;
        }
        s->headers = tmp;
        s->headers_capacity = new_capacity;
    }

    nghttp3_nv *nv = &s->headers[s->headers_count];

    nv->name = malloc(namelen);
    if (!nv->name) return -1;
    // Cast to void* to avoid warnings about discarding const qualifier
    memcpy((void *)nv->name, name, namelen);
    nv->namelen = namelen;

    // TODO: HTTP/3 mandates strict lowercase header names?
    // for (size_t i = 0; i < nv->namelen; i++) {
    //     nv->name[i] = tolower(nv->name[i]);
    // }

    nv->value = malloc(valuelen);
    if (!nv->value) {
        free((void *)nv->name);
        return -1;
    }
    memcpy((void *)nv->value, value, valuelen);
    nv->valuelen = valuelen;

    nv->flags = NGHTTP3_NV_FLAG_NONE;
    s->headers_count++;
    return 0;
}

/* =========================================================================
 * UDP read/write loops
 * ====================================================================== */

static pthread_mutex_t sendmsg_mutex = PTHREAD_MUTEX_INITIALIZER;

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
protohttp3_trigger_write_loop(protohttp3_ctx_t *h3_ctx, int reqmod)
{
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest_va("ENTER, fd=%d", h3_ctx->dst_fd);

    // TODO: Consider using a static buffer to avoid stack allocation on each call.
    // But static buffer may not be thread-safe if multiple threads call this function simultaneously.
    // static uint8_t pktbuf[H3_DGRAM_BUFSZ];
    uint8_t pktbuf[H3_DGRAM_BUFSZ];

    for (;;) {
        ngtcp2_ssize pktlen = -1;
        ngtcp2_pkt_info pi = {0};

        nghttp3_vec vecs[H3_MAX_IOVECS];
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_ssize sveccnt = 0;

        /* 1. Pull H3 data if present */
        if ((reqmod && h3_ctx->src_h3) || (!reqmod && h3_ctx->dst_h3)) {
            sveccnt = nghttp3_conn_writev_stream(reqmod ? h3_ctx->src_h3 : h3_ctx->dst_h3,
                                                 &stream_id, &fin,
                                                 vecs, H3_MAX_IOVECS);
            if (sveccnt < 0) {
                log_finest_va("nghttp3_conn_writev_stream: %s", nghttp3_strerror((int)sveccnt));
                break;
            }
        }
        else {
            log_finest_va("No upstream H3 session; skipping nghttp3_conn_writev_stream, fd=%d", h3_ctx->dst_fd);
        }

        /* 2. Write either Stream packet or standard QUIC packet (Crypto/ACK) */
        if (sveccnt > 0 && stream_id >= 0) {
            ngtcp2_ssize pdatalen = 0;
            pktlen = ngtcp2_conn_writev_stream(
                         reqmod ? h3_ctx->src_conn : h3_ctx->dst_conn,
                         reqmod ? &h3_ctx->src_path : &h3_ctx->dst_path,
                         &pi,
                         pktbuf, sizeof(pktbuf),
                         &pdatalen,
                         // TODO: Is this enough? The ngtcp2_write_stream_flag enum has changed in recent versions.
                         // The NGTCP2_WRITE_STREAM_FLAG_MORE flag is now deprecated and replaced with NGTCP2_WRITE_STREAM_FLAG_FIN for the FIN flag.
                         // We need to check the version of ngtcp2 we are using and adjust accordingly.
                         fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_MORE,
                         stream_id, (const ngtcp2_vec *)vecs,
                         (size_t)sveccnt,
                         h3_timestamp());

            if (pdatalen > 0) {
                nghttp3_conn_add_write_offset(reqmod ? h3_ctx->src_h3 : h3_ctx->dst_h3, stream_id, (size_t)pdatalen);
            }
        } else {
            log_finest_va("Write pending  ACKs, Handshake CRYPTO, etc., fd=%d", h3_ctx->dst_fd);
            /* No stream data; write pending ACKs, Handshake CRYPTO, etc. */
            pktlen = ngtcp2_conn_write_pkt(reqmod ? h3_ctx->src_conn : h3_ctx->dst_conn,
                                           reqmod ? &h3_ctx->src_path : &h3_ctx->dst_path,
                                           &pi, pktbuf, sizeof(pktbuf),
                                           h3_timestamp());
        }

        /* 3. Handle write status */
        if (pktlen == NGTCP2_ERR_WRITE_MORE) {
            log_finest_va("Write more, pktlen=%zd, fd=%d", pktlen, h3_ctx->dst_fd);
            continue;
        }

        if (pktlen <= 0) {
            if (pktlen < 0 && pktlen != NGTCP2_ERR_WRITE_MORE) {
                log_finest_va("ngtcp2 write error: %s", ngtcp2_strerror((int)pktlen));
            }
            log_finest_va("Drained all pending packets, pktlen=%zd, fd=%d", pktlen, h3_ctx->dst_fd);
            break; /* Drained all pending packets */
        }

        log_finest_va("Transmit packet, pktlen=%zd, fd=%d", pktlen, h3_ctx->dst_fd);

        /* 4. Transmit via UDP socket */
        struct iovec iov = { .iov_base = pktbuf, .iov_len = (size_t)pktlen };
        struct msghdr mhdr = {
            .msg_name    = reqmod ? (struct sockaddr *)&h3_ctx->ctx->srcaddr : (struct sockaddr *)&h3_ctx->dst_peer_addr,
            .msg_namelen = reqmod ? h3_ctx->ctx->srcaddrlen : h3_ctx->dst_peer_addrlen,
            .msg_iov     = &iov,
            .msg_iovlen  = 1,
        };

        ssize_t sent = 0;

        if (reqmod) {
		    // QUIC server should send from the common UDP listener fd, not a connected socket.
		    // hence the global mutex to serialize sendmsg() calls across multiple threads.
		    pthread_mutex_lock(&sendmsg_mutex);
		    sent = sendmsg(h3_ctx->src_fd, &mhdr, 0);
		    pthread_mutex_unlock(&sendmsg_mutex);
		}
		else {
	        sent = sendmsg(h3_ctx->dst_fd, &mhdr, 0);
		}

        log_finest_va("sendmsg fd=%d returned %zd (errno=%d: %s)",
                    reqmod ? h3_ctx->src_fd : h3_ctx->dst_fd, sent, errno, strerror(errno));        
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (reqmod ? h3_ctx->src_wev : h3_ctx->dst_wev)
					event_add(reqmod ? h3_ctx->src_wev : h3_ctx->dst_wev, NULL);
            } else {
                log_finest_va("sendmsg error on fd %d: %s", 
                               reqmod ? h3_ctx->src_fd : h3_ctx->dst_fd, strerror(errno));
            }
            break;
        }
    }

    protohttp3_arm_timer(h3_ctx);
}

static int
protohttp3_submit_data(protohttp3_ctx_t *h3_ctx, protohttp3_stream_ctx_t *s, int reqmod)
{
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int rv = 0;

    if (s->headers_count > 0) {
        log_finest_va("Submit headers, headers_count=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->headers_count, s->src_stream_id, s->dst_stream_id, reqmod);

        if (reqmod) {
            rv = nghttp3_conn_submit_request(h3_ctx->dst_h3, s->dst_stream_id, s->headers, s->headers_count, &s->dr, s);
            if (rv < 0) {
                log_finest_va("Fatal: nghttp3_conn_submit_request failed: %s", nghttp3_strerror(rv));
                return -1;
            }

            // Set the stream id assigned by nghttp2 for the destination session
            s->dst_stream_id = rv;
        }
        else {
            rv = nghttp3_conn_submit_response(h3_ctx->src_h3, s->src_stream_id, s->headers, s->headers_count, &s->dr);
            if (rv < 0) {
                log_finest_va("Fatal: nghttp3_conn_submit_response failed: %s", nghttp3_strerror(rv));
                return -1;
            }
        }
        protohttp3_free_stream_headers(s);

#ifndef WITHOUT_ICAP
        s->icap_ctx->made_progress = 1;
#endif /* !WITHOUT_ICAP */
    }

    if (s->body_len > 0) {
        log_finest_va("Submit data, data_len=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->body_len, s->src_stream_id, s->dst_stream_id, reqmod);

        rv = nghttp3_conn_resume_stream(reqmod ? h3_ctx->dst_h3 : h3_ctx->src_h3, reqmod ? s->dst_stream_id : s->src_stream_id);

        if (rv == NGHTTP3_ERR_INVALID_ARGUMENT) {
            // Clean operational bypass: The engine is already active and polling
            log_finest_va("Stream %" PRId64 " already active, continuing to explicit write execution.", s->src_stream_id);
        }
        else if (rv < 0) {
            log_finest_va("Fatal: nghttp3_conn_resume_stream failed: %s", nghttp3_strerror(rv));
            return -1;
        }

#ifndef WITHOUT_ICAP
        s->icap_ctx->made_progress = 1;
#endif /* !WITHOUT_ICAP */
    }

    // Clean Data Wakeup Flush
    log_finest_va("Executing scheduled session frame serialization loop for stream, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
    protohttp3_trigger_write_loop(h3_ctx, reqmod);

    return 0;
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
    (void)token; (void)flags; (void)stream_user_data;

    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0; /* 1=client-side, 0=server-side */

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s) {
        /*
         * First header for this stream – allocate a stream context.
         * In H3, the stream id is already known by the time nghttp3
         * delivers headers (ngtcp2 opened the stream first).
         */
        s = protohttp3_new_stream_ctx(h3_ctx, stream_id);
        if (!s) {
            log_fine_va("Failed to create new stream context for stream_id=%" PRId64, stream_id);
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }
    }

    nghttp3_vec name_vec  = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec value_vec = nghttp3_rcbuf_get_buf(value);

    if (protohttp3_add_nv_header(s, name_vec.base,  name_vec.len, value_vec.base, value_vec.len) != 0) {
        log_fine_va("Failed to add header for stream_id=%" PRId64, stream_id);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
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
    (void)stream_user_data;

    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s)
        return 0; /* Nothing to do if stream not tracked.*/

    s->ref_count++;
    s->headers_complete = 1;
    if (fin)
        s->end_stream = 1;

    log_finest_va("stream %" PRId64 " END_HEADERS (%zu headers, fin=%d)",
                   stream_id, s->headers_count, fin);

    /*
     * Stream Forwarding:
     * We forward headers between src and dst sides. For this prototype,
     * we assume that dst_h3 is available (handshake completed).
     */
    if (reqmod) {
        /* Client request headers received; forward to upstream. */
        if (h3_ctx->dst_h3) {
            if (s->dst_stream_id == -1) {
                ngtcp2_conn_open_bidi_stream(h3_ctx->dst_conn, &s->dst_stream_id, s);
            }
        }
        else {
            log_finest("WARNING: upstream H3 session not ready");
        }
    }

    protohttp3_submit_data(h3_ctx, s, reqmod);

    s->ref_count--;
    return 0;
}

/*
 * Append raw bytes to the stream body staging buffer, growing by doubling.
 *
 * Returns 0 on success, -1 on OOM.
 */
static int
protohttp3_stream_append_body(protohttp3_stream_ctx_t *s, const uint8_t *data, size_t len)
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

/*
 * Called when raw body data is available on a stream.
 * Equivalent to nghttp2's on_data_chunk_recv_callback.
 */
static int
h3_on_recv_data(nghttp3_conn *conn, int64_t stream_id,
                const uint8_t *data, size_t datalen,
                void *user_data, void *stream_user_data)
{
    (void)stream_user_data;

    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s) {
        /* Data before headers – should not normally happen.               */
        log_finest_va("data on unknown stream %" PRId64 " (fd=%d)", stream_id, h3_ctx->dst_fd);
        return 0;
    }

    s->ref_count++;

#ifdef DEBUG_PROXY
	/* Log first 400 bytes for debugging */
	size_t log_len = datalen < 400 ? datalen : 400;
	char log_buf[401];  // Stack allocation
	memcpy(log_buf, data, log_len);
	log_buf[log_len] = '\0';
	log_finest_va("DATA (first %zu bytes, orig %zu bytes): %s", log_len, datalen, log_buf);
#endif /* DEBUG_PROXY */

    if (protohttp3_stream_append_body(s, data, datalen) != 0) {
        log_finest_va("protohttp3_stream_append_body() failed for stream %" PRId64 " received %zu bytes of DATA", stream_id, datalen);
        s->ref_count--;
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    /* Forward payload data (assuming simple buffered forwarding for prototype) */
    log_finest_va("stream %" PRId64 " received %zu bytes of DATA", stream_id, datalen);

    // Resume nghttp3 stream so it calls h3_stream_read_data
    protohttp3_submit_data(h3_ctx, s, reqmod);

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
    (void)stream_user_data;

    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s)
        return 0;

    s->end_stream = 1;

    log_finest_va("stream %" PRId64 " END_STREAM", stream_id);

    // Do NOT free the stream here
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
static nghttp3_ssize
h3_stream_read_data(nghttp3_conn *conn, int64_t stream_id,
                    nghttp3_vec *vec, size_t veccnt,
                    uint32_t *pflags,
                    void *user_data, void *stream_user_data)
{
    (void)stream_user_data;

    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    // TODO: Casting the stream pointer in stream_user_data does not work correctly
    // stream_h3_ctx_t *s = stream_user_data;
    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);

    if (!s || s->body_len == 0) {
        /* Nothing buffered right now – tell nghttp3 to pause this stream. */
        log_finest_va("s->body_len == 0, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    /* Hand the entire staging buffer as a single iovec.                   */
    if (veccnt < 1) {
        log_finest_va("veccnt < 1, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    vec[0].base = s->body_buf;
    vec[0].len  = s->body_len;

    if (s->end_stream) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
    }

    log_finest_va("stream %" PRId64 " READ, reqmod=%d, fd=%d, len=%zu", stream_id, reqmod, h3_ctx->dst_fd, s->body_len);

    /*
     * Zero body_len so a second call to this callback (e.g. after a
     * WOULDBLOCK / resume cycle) does not re-submit the same data.
     * body_buf is kept alive until the stream is freed; ngtcp2 copies
     * the payload into its own packet buffer within the same flush loop
     * before we ever return here again.
     */
    s->body_len = 0;

    return 1; // Number of vectors filled
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
    (void)offset; (void)stream_user_data;

    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_conn ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;

    /*
     * Feed the raw H3 frame bytes into nghttp3.  nghttp3 will call our
     * h3_on_recv_header / h3_on_recv_data / h3_on_end_headers / h3_on_end_stream
     * callbacks as it parses complete frames.
     */
    nghttp3_ssize nread = nghttp3_conn_read_stream(reqmod ? h3_ctx->src_h3 : h3_ctx->dst_h3, stream_id, data, datalen, fin);

    if (nread < 0) {
        log_finest_va("nghttp3_conn_read_stream error: %s", nghttp3_strerror((int)nread));
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
    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_conn ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    /*
     * For unidirectional streams opened by the client we create a
     * lightweight stream context.  nghttp3 identifies the stream type from
     * the first byte it reads.
     */
    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);

    if (!s) {
        s = protohttp3_new_stream_ctx(h3_ctx, stream_id);
        if (!s) {
            log_finest_va("OOM for new stream %" PRId64, stream_id);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    /* Let nghttp3 know a new unidirectional stream was opened.            */
    if (reqmod) {
        if (h3_ctx->src_h3) {
            int rv = nghttp3_conn_set_stream_user_data(h3_ctx->src_h3, stream_id, s);
            if (rv != 0 && rv != NGHTTP3_ERR_INVALID_ARGUMENT) {
                /* INVALID_ARGUMENT means nghttp3 already knows this stream.   */
                log_finest_va("nghttp3_conn_set_stream_user_data: %s", nghttp3_strerror(rv));
            }
        }
    }
    else {
        if (h3_ctx->dst_h3) {
            int rv = nghttp3_conn_set_stream_user_data(h3_ctx->dst_h3, stream_id, s);
            if (rv != 0 && rv != NGHTTP3_ERR_INVALID_ARGUMENT) {
                log_finest_va("nghttp3_conn_set_stream_user_data: %s", nghttp3_strerror(rv));
            }
        }
    }

    log_finest_va("stream opened %" PRId64, stream_id);
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
    (void)flags; (void)app_error_code; (void)stream_user_data;

    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_conn ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (s) {
        if (reqmod) {
            if (h3_ctx->src_h3) {
                nghttp3_conn_close_stream(h3_ctx->src_h3, s->src_stream_id, app_error_code);
            }
        }
        else {
            if (h3_ctx->dst_h3) {
                nghttp3_conn_close_stream(h3_ctx->dst_h3, s->dst_stream_id, app_error_code);
            }
        }

        if (!s->closed) {
            log_finest_va("stream first close, stream id %" PRId64, stream_id);
            s->closed = 1;
        } else {
            /* Second close event: ready to tear down.                     */
            log_finest_va("stream second close, request free, stream id %" PRId64, stream_id);
            s->term = 1;
            protohttp3_request_free_stream_ctx(s, reqmod);
        }
    }

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
    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest_va("%s QUIC handshake completed, fd=%d", conn == h3_ctx->src_conn ? "Client side" : "Server side", h3_ctx->dst_fd);

    /* ------------------------------------------------------------------
     * Build the nghttp3 callback table.
     * ------------------------------------------------------------------ */
    nghttp3_callbacks h3cb = {0};
    h3cb.recv_header        = h3_on_recv_header;
    h3cb.end_headers        = h3_on_end_headers;
    h3cb.recv_data          = h3_on_recv_data;
    h3cb.end_stream         = h3_on_end_stream;

    nghttp3_settings h3settings;
    nghttp3_settings_default(&h3settings);

    int reqmod = (conn == h3_ctx->src_conn);
    nghttp3_conn **h3_conn_ptr = reqmod ? &h3_ctx->src_h3 : &h3_ctx->dst_h3;

    int rv;
    if (reqmod) {
        rv = nghttp3_conn_server_new(h3_conn_ptr, &h3cb, &h3settings, NULL, h3_ctx);
    } else {
        rv = nghttp3_conn_client_new(h3_conn_ptr, &h3cb, &h3settings, NULL, h3_ctx);
    }

    if (rv != 0) {
        log_finest_va("nghttp3_conn_new: %s", nghttp3_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    /*
     * Bind the three mandatory H3 unidirectional control streams that we
     * own:
     *   - Control stream  (type 0x00)
     *   - QPACK encoder   (type 0x02)
     *   - QPACK decoder   (type 0x03)
     */
    int64_t ctrl_stream_id, qenc_stream_id, qdec_stream_id;

    if (ngtcp2_conn_open_uni_stream(conn, &ctrl_stream_id, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(conn, &qenc_stream_id, NULL) != 0 ||
        ngtcp2_conn_open_uni_stream(conn, &qdec_stream_id, NULL) != 0) {
        log_finest("failed to open H3 control streams");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    rv = nghttp3_conn_bind_control_stream(*h3_conn_ptr, ctrl_stream_id);
    if (rv != 0) {
        log_finest_va("bind_control_stream: %s", nghttp3_strerror(rv));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    rv = nghttp3_conn_bind_qpack_streams(*h3_conn_ptr, qenc_stream_id, qdec_stream_id);
    if (rv != 0) {
        log_finest_va("bind_qpack_streams: %s", nghttp3_strerror(rv));
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
 *   - The ECN codepoint (DSCP bits) used by QUIC for congestion control.
 *
 * Returns the number of bytes received on success, -1 on error (EAGAIN /
 * EWOULDBLOCK are swallowed and return 0).
 */
ssize_t
protohttp3_recvmsg(int fd,
                   uint8_t *buf, size_t bufsz,
                   struct sockaddr_storage *peer_addr, socklen_t *peer_addrlen,
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

    /* Walk ancillary control messages.                                    */
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {

        /* IPv4 destination address + ECN.                                 */
        if (cmsg->cmsg_level == IPPROTO_IP) {
#ifdef IP_TOS
            if (cmsg->cmsg_type == IP_TOS) {
                *ecn = *(int *)CMSG_DATA(cmsg) & 0x03;
            }
#endif
        }

        /* IPv6 destination address + ECN.                                 */
        if (cmsg->cmsg_level == IPPROTO_IPV6) {
#ifdef IPV6_TCLASS
            if (cmsg->cmsg_type == IPV6_TCLASS) {
                *ecn = *(int *)CMSG_DATA(cmsg) & 0x03;
            }
#endif
        }
    }

	log_finest_main_va("EXIT, fd=%d, bytes received=%zd, ecn=%d", fd, n, *ecn);
    return n;
}

void
protohttp3_debug_print_addr(const struct sockaddr_storage *peer_addr, char *label)
{
    char hostbuf[INET6_ADDRSTRLEN] = "unknown";
    uint16_t port = 0;

    if (peer_addr->ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)peer_addr;
        inet_ntop(AF_INET, &s->sin_addr, hostbuf, sizeof(hostbuf));
        port = ntohs(s->sin_port);
    } else if (peer_addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)peer_addr;
        inet_ntop(AF_INET6, &s->sin6_addr, hostbuf, sizeof(hostbuf));
        port = ntohs(s->sin6_port);
    }

    log_finest_main_va("%s=%s:%u", label, hostbuf, port);
}

/* =========================================================================
 * Libevent callbacks for the raw UDP fds
 * ====================================================================== */

/*
 * Fired when the UDP socket is writable again after a previous sendmsg()
 * returned EAGAIN.  We just re-enter the write flush loop.
 */
static void
protohttp3_src_write_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    protohttp3_ctx_t *h3_ctx = arg;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest("ENTER");
    protohttp3_trigger_write_loop(h3_ctx, 1);
}

static void
protohttp3_dst_read_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)what;
    protohttp3_ctx_t *h3_ctx = arg;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest_va("ENTER, fd=%d", h3_ctx->dst_fd);

	uint8_t buf[H3_DGRAM_BUFSZ];
	struct sockaddr_storage peer_addr;
	socklen_t peer_addrlen = sizeof(peer_addr);
	int ecn = 0;

    // TODO: The port in local_addr returned by protohttp3_recvmsg2() is always 0, why?
    ssize_t n = protohttp3_recvmsg(fd, buf, sizeof(buf), &peer_addr, &peer_addrlen, &ecn);
	if (n <= 0) {
		if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
			log_err_level_printf(LOG_CRIT,
				"Error reading from server-side UDP socket: %s\n",
				strerror(errno));
		}
		else {
			log_finest("No data read from server-side UDP socket (EAGAIN/EWOULDBLOCK)");
		}
		return;
	}

    log_finest_va("Read %zd bytes from server-side UDP socket", n);

    protohttp3_debug_print_addr(&peer_addr, "pkt dst_peer_addr");

    ngtcp2_pkt_info pi = { .ecn = (uint8_t)ecn };

    int rv = ngtcp2_conn_read_pkt(h3_ctx->dst_conn,
                                &h3_ctx->dst_path, &pi,
                                buf, (size_t)n,
                                h3_timestamp());

    log_finest_va("ngtcp2_conn_read_pkt returns: %s", ngtcp2_strerror(rv));
    if (rv != 0) {
        if (rv == NGTCP2_ERR_CRYPTO) {
            unsigned long err;
            while ((err = ERR_get_error())) {
                char err_buf[256];
                ERR_error_string_n(err, err_buf, sizeof(err_buf));
                // TODO: Log the TLS alert code from ngtcp2 if available
                // ngtcp2_conn_get_tls_alert(h3_ctx->src_conn);
                log_finest_va("OpenSSL error during ngtcp2_conn_read_pkt: %s", err_buf);
            }
        }
        // TODO: See ngtcp2_conn_read_pkt() for specific error codes that indicate the connection should be closed
        return;
    }

    protohttp3_trigger_write_loop(h3_ctx, 0);
}

static void
protohttp3_dst_write_cb(evutil_socket_t fd, short what, void *arg)
{
    (void)fd; (void)what;
    protohttp3_ctx_t *h3_ctx = arg;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest_va("ENTER, fd=%d", h3_ctx->dst_fd);
    protohttp3_trigger_write_loop(h3_ctx, 0);
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
protohttp3_arm_timer(protohttp3_ctx_t *h3_ctx)
{
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest("ENTER");

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
    protohttp3_ctx_t *h3_ctx = arg;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest("ENTER");

    int rv = ngtcp2_conn_handle_expiry(h3_ctx->src_conn, h3_timestamp());
    if (rv != 0) {
        log_finest_va("ngtcp2_conn_handle_expiry: %s", ngtcp2_strerror(rv));
        return;
    }

    protohttp3_trigger_write_loop(h3_ctx, 1);
}

/* =========================================================================
 * TLS/QUIC crypto integration (ngtcp2_crypto_ossl)
 *
 * This implementation relies on a QUIC-enabled OpenSSL build (like quictls)
 * which provides the necessary ngtcp2_crypto callbacks out of the box.
 * ====================================================================== */


/* =========================================================================
 * Public API
 * ====================================================================== */

/*
 * Build a hex-encoded CID key string from raw CID bytes.
 */
void
protohttp3_cid_to_hex(char *key, const uint8_t *cid, size_t cidlen)
{
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < cidlen && i < NGTCP2_MAX_CIDLEN; i++) {
        key[i * 2]     = hex[(cid[i] >> 4) & 0xf];
        key[i * 2 + 1] = hex[cid[i] & 0xf];
    }
    key[cidlen * 2] = '\0';
}

/* =========================================================================
 * Session Hash Table (5-tuple lookup) Implementation
 * ====================================================================== */

h3_session_map_t *
h3_session_map_new(void)
{
    h3_session_map_t *smap = calloc(1, sizeof(*smap));
    if (!smap)
        return NULL;
    smap->map = kh_init(h3_conn_map);
    if (!smap->map) {
        free(smap);
        return NULL;
    }
    pthread_mutex_init(&smap->lock, NULL);
    return smap;
}

void
h3_session_map_free(h3_session_map_t *smap)
{
    if (!smap)
        return;
    pthread_mutex_lock(&smap->lock);
    if (smap->map) {
        kh_destroy(h3_conn_map, smap->map);
        smap->map = NULL;
    }
    pthread_mutex_unlock(&smap->lock);
    pthread_mutex_destroy(&smap->lock);
    free(smap);
}

protohttp3_ctx_t *
h3_session_map_get(h3_session_map_t *smap, const quic_tuple_key_t *key)
{
    if (!smap || !smap->map)
        return NULL;
    protohttp3_ctx_t *h3_ctx = NULL;
    pthread_mutex_lock(&smap->lock);
    khiter_t k = kh_get(h3_conn_map, smap->map, *key);
    if (k != kh_end(smap->map) && kh_exist(smap->map, k)) {
        h3_ctx = kh_val(smap->map, k);
    }
    pthread_mutex_unlock(&smap->lock);
    return h3_ctx;
}

int
h3_session_map_insert(h3_session_map_t *smap, const quic_tuple_key_t *key, protohttp3_ctx_t *h3_ctx)
{
    if (!smap || !smap->map)
        return -1;
    int ret;
    pthread_mutex_lock(&smap->lock);
    khiter_t k = kh_put(h3_conn_map, smap->map, *key, &ret);
    if (ret >= 0) {
        kh_val(smap->map, k) = h3_ctx;
        h3_ctx->h3_sessions = smap;
        h3_ctx->key = *key;
    }
    pthread_mutex_unlock(&smap->lock);
    return ret >= 0 ? 0 : -1;
}

void
h3_session_map_remove(h3_session_map_t *smap, const quic_tuple_key_t *key)
{
    if (!smap || !smap->map)
        return;
    pthread_mutex_lock(&smap->lock);
    khiter_t k = kh_get(h3_conn_map, smap->map, *key);
    if (k != kh_end(smap->map) && kh_exist(smap->map, k)) {
        kh_del(h3_conn_map, smap->map, k);
    }
    pthread_mutex_unlock(&smap->lock);
}

void
protohttp3_process_packet_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
    protohttp3_ctx_t *h3_ctx = arg;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest("ENTER");

    pthread_mutex_lock(&h3_ctx->pkt_queue_mutex);
    // ATTENTION: We should never need to check if h3_ctx->src_process_pkt_ev is not NULL here,
    // because this callback is not scheduled again if one is already scheduled.
    // Otherwise would mean a memory leak, as src_process_pkt_ev would have been overwritten.
    // But protohttp3_init_conn directly calls this function without scheduling it, so we need to check here.
    if (h3_ctx->src_process_pkt_ev) {
        event_free(h3_ctx->src_process_pkt_ev);
        h3_ctx->src_process_pkt_ev = NULL;
    }
    pthread_mutex_unlock(&h3_ctx->pkt_queue_mutex);

    if (!h3_ctx->src_conn) {
        log_finest("src_conn is NULL");
        return;
    }

    protohttp3_debug_print_addr(&h3_ctx->ctx->srcaddr, "src_peer_addr");
    protohttp3_debug_print_addr(&h3_ctx->ctx->spec->listen_addr, "src_local_addr");

    size_t total_bytes_processed = 0;
    int pkt_count = 0;

    for (;;) {
        pthread_mutex_lock(&h3_ctx->pkt_queue_mutex);
        if (!h3_ctx->pkt_queue) {
            pthread_mutex_unlock(&h3_ctx->pkt_queue_mutex);
            break;
        }

        pkt_node_t *pkt = h3_ctx->pkt_queue;
        h3_ctx->pkt_queue = pkt->next;
        pthread_mutex_unlock(&h3_ctx->pkt_queue_mutex);

        ngtcp2_pkt_info pi = { .ecn = (uint8_t)pkt->ecn };

        log_finest_va("Processing packet %d of %zu bytes", pkt_count, pkt->len);
        total_bytes_processed += pkt->len;
        pkt_count++;

        int rv = ngtcp2_conn_read_pkt(h3_ctx->src_conn,
                                    &h3_ctx->src_path, &pi,
                                    pkt->buf, pkt->len,
                                    h3_timestamp());

        free(pkt);

        if (rv != 0) {
            log_finest_va("ngtcp2_conn_read_pkt returns: %s", ngtcp2_strerror(rv));
            if (rv == NGTCP2_ERR_CRYPTO) {
                unsigned long err;
                while ((err = ERR_get_error())) {
                    char err_buf[256];
                    ERR_error_string_n(err, err_buf, sizeof(err_buf));
                    // TODO: Log the TLS alert code from ngtcp2 if available
                    // ngtcp2_conn_get_tls_alert(h3_ctx->src_conn);
                    log_finest_va("OpenSSL error during ngtcp2_conn_read_pkt: %s", err_buf);
                }
            }
            else if (rv == NGTCP2_ERR_DRAINING) {
                log_finest("Connection is draining, no more packets will be processed");
            }
            // TODO: See ngtcp2_conn_read_pkt() for specific error codes that indicate the connection should be closed
            return;
        }
    }

    log_finest_va("Processed total of %d packets and %zu bytes", pkt_count, total_bytes_processed);
    protohttp3_trigger_write_loop(h3_ctx, 1);
}

static ngtcp2_conn *
get_src_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
    protohttp3_ctx_t *h3_ctx = conn_ref->user_data;
    return h3_ctx->src_conn;
}

static ngtcp2_conn *
get_dst_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
    protohttp3_ctx_t *h3_ctx = conn_ref->user_data;
    return h3_ctx->dst_conn;
}

static int
alpn_select_cb(SSL *ssl, const unsigned char **out,
                          unsigned char *outlen, const unsigned char *in,
                          unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;

    /* Wire format: 1 byte length (2) followed by "h3" */
    static const unsigned char h3_alpn[] = "\x02h3";

    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              h3_alpn, sizeof(h3_alpn) - 1,
                              in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;
}

// Debug logging callbacks for ngtcp2.  These are set in ngtcp2_settings.log_printf.
void
debug_log_src(UNUSED void *user_data, const char *fmt, ...) {
    fprintf(stderr, "Client-side: ");
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void
debug_log_dst(UNUSED void *user_data, const char *fmt, ...) {
    fprintf(stderr, "Server-side: ");
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void
keylog_callback(UNUSED const SSL *ssl, const char *line)
{
    log_dbg_printf("keylog_callback: %s\n", line);
}

/*
 * protohttp3_new – create a fully wired QUIC/H3 server-side session.
 *
 * After this function returns:
 *   - h3_ctx->src_conn is a ngtcp2 server session in the Initial state.
 *   - h3_ctx->src_wev  is a one-shot WRITE event (armed on demand).
 *   - h3_ctx->timer_ev is a one-shot timer (rearmed by protohttp3_arm_timer).
 *   - The nghttp3 session (src_h3) is created later inside
 *     quic_handshake_completed() once the TLS handshake is done.
 *
 * 'dcid' / 'dcidlen' are the client's Initial Destination Connection ID
 * extracted from the first Initial packet.  They are used to set
 * params.original_dcid, which ngtcp2 requires for server connections.
 */
protohttp3_ctx_t *
protohttp3_new(pxy_conn_ctx_t *ctx, ngtcp2_version_cid vc)
{
    protohttp3_ctx_t *h3_ctx = malloc(sizeof(protohttp3_ctx_t));
    if (!h3_ctx) {
        return NULL;
    }
    memset(h3_ctx, 0, sizeof(protohttp3_ctx_t));

    h3_ctx->dst_fd  = -1;
    h3_ctx->ctx     = ctx;

	ctx->protoctx->arg = malloc(sizeof(protohttp_ctx_t));
	if (!ctx->protoctx->arg) {
        free(h3_ctx);
		return NULL;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protohttp_ctx_t));

    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    http_ctx->arg = h3_ctx;

    /* ------------------------------------------------------------------
     * Build the ngtcp2 server callbacks table.
     * ------------------------------------------------------------------ */
    ngtcp2_callbacks cb = {0};

    /* Real OpenSSL crypto hooks provided by ngtcp2_crypto_ossl.        */
    cb.client_initial           = ngtcp2_crypto_client_initial_cb;
    cb.recv_client_initial      = ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt                  = ngtcp2_crypto_encrypt_cb;
    cb.decrypt                  = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask                  = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry               = ngtcp2_crypto_recv_retry_cb;
    cb.update_key               = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation      = ngtcp2_crypto_version_negotiation_cb;

    /* QUIC / transport hooks.                                             */
    cb.handshake_completed      = quic_handshake_completed;
    cb.recv_stream_data         = quic_recv_stream_data;
    /* recv_uni_stream_data does not exist in ngtcp2 v0.12; the single     */
    /* recv_stream_data callback handles both bidi and uni streams.        */
    cb.stream_open              = quic_stream_open;
    cb.stream_close             = quic_stream_close;
    cb.rand                     = quic_rand;
    cb.get_new_connection_id    = quic_get_new_connection_id;

    /* ------------------------------------------------------------------
     * Build ngtcp2 server settings.
     * ------------------------------------------------------------------ */
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = h3_timestamp();

    // Set to log_dbg_printf to enable ngtcp2 debug logs
    settings.log_printf = NULL;

    // TODO: Do we need this param?
    // settings.max_tx_udp_payload_size = 1472;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);

    // TODO: Tune these parameters for better performance and resource usage.
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 10 * 1024 * 1024; // 10MB
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.active_connection_id_limit = 2; // Must be >= 2
    params.max_udp_payload_size                = 1472;
    params.max_idle_timeout = 30 * NGTCP2_SECONDS;

    /*
     * 'scid' is the server-chosen initial Source Connection ID (will be used
     * as the DCID in server-to-client packets).  We generate it randomly.
     *
     * 'initial_dcid' is the *client's* initial Source Connection ID,
     * extracted from the client's first QUIC Initial packet.
     * 
     * ngtcp2 requires client's initial Destination Connection ID to be set in 
     * params.original_dcid for server connections.
     */

    ngtcp2_cid initial_scid;
    char dcid_hex[H3_CID_KEYLEN];

    initial_scid.datalen = NGTCP2_MAX_CIDLEN;
    arc4random_buf(initial_scid.data, initial_scid.datalen);

    protohttp3_cid_to_hex(dcid_hex, initial_scid.data, initial_scid.datalen);
    log_finest_va("Assign a random cid as initial_scid=0x%s", dcid_hex);

    ngtcp2_cid initial_dcid;
    initial_dcid.datalen = vc.scidlen < NGTCP2_MAX_CIDLEN ? (size_t)vc.scidlen : NGTCP2_MAX_CIDLEN;
    memcpy(initial_dcid.data, vc.scid, initial_dcid.datalen);

    protohttp3_cid_to_hex(dcid_hex, initial_dcid.data, initial_dcid.datalen);
    log_finest_va("Assign initial pkt client scid as initial_dcid=0x%s", dcid_hex);

    ngtcp2_cid client_dcid;
    client_dcid.datalen = vc.dcidlen < NGTCP2_MAX_CIDLEN ? (size_t)vc.dcidlen : NGTCP2_MAX_CIDLEN;
    memcpy(client_dcid.data, vc.dcid, client_dcid.datalen);

    protohttp3_cid_to_hex(dcid_hex, client_dcid.data, client_dcid.datalen);
    log_finest_va("Assign initial pkt client dcid as params.original_dcid=0x%s", dcid_hex);

    // Set original_dcid to the Destination Connection ID extracted from the Initial packet from client
    params.original_dcid = client_dcid;
    params.original_dcid_present = 1;

    // Set initial_scid to the scid randomly generated above, which is the server's initial Source Connection ID
    params.initial_scid = initial_scid;

    ngtcp2_addr_init(&h3_ctx->src_path.local,  (struct sockaddr *)&ctx->spec->listen_addr, ctx->spec->listen_addrlen);
    ngtcp2_addr_init(&h3_ctx->src_path.remote, (struct sockaddr *)&ctx->srcaddr,  ctx->srcaddrlen);

    settings.log_printf = debug_log_src;

    int rv = ngtcp2_conn_server_new(&h3_ctx->src_conn, &initial_dcid, &initial_scid, &h3_ctx->src_path,
                                    NGTCP2_PROTO_VER_V1, &cb, &settings,
                                    &params, NULL, h3_ctx);
    if (rv != 0) {
        log_finest_va("ngtcp2_conn_server_new: %s", ngtcp2_strerror(rv));
        protohttp3_free(h3_ctx);
        return NULL;
    }

    // TODO: Set params for server only, to update params, otherwise ngtcp2_conn_server_new() already sets them
    // ngtcp2_conn_set_local_transport_params(h3_ctx->src_conn, &params);

    /* ------------------------------------------------------------------
     * TLS OpenSSL setup (src side).
     * ------------------------------------------------------------------ */
    /* Note: For SSLproxy, we should derive the SSL_CTX from the proxyspec.
     * We'll use a local TLS method block for the QUIC prototype. */
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

    // QUIC requires TLS 1.3
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    // Enable ALPN selection on OpenSSL server context
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, NULL);

    // TODO: Do we need to call SSL_CTX_use_certificate_chain_file()? Load by calling ssl_x509chain_load()?
    // TODO: Load ca.crt/key from the proxy spec, not hardcoded path
    if (SSL_CTX_use_certificate_file(ssl_ctx, "./tests/testproxy/ca.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_ctx, "./tests/testproxy/ca.key", SSL_FILETYPE_PEM) <= 0) {
        log_finest("failed to load server cert/key!");
        // Clear OpenSSL error queue so old errors don't pollute runtime
        ERR_clear_error();
        return NULL;
    }

    // Enable key logging for debugging purposes
    SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);

    h3_ctx->src_ssl = SSL_new(ssl_ctx);

    SSL_set_accept_state(h3_ctx->src_ssl);

    ngtcp2_crypto_ossl_configure_server_session(h3_ctx->src_ssl);

    h3_ctx->src_conn_ref.get_conn = get_src_conn;
    h3_ctx->src_conn_ref.user_data = h3_ctx;
    SSL_set_app_data(h3_ctx->src_ssl, &h3_ctx->src_conn_ref);

    h3_ctx->src_ossl_ctx = NULL;
    if (ngtcp2_crypto_ossl_ctx_new(&h3_ctx->src_ossl_ctx, h3_ctx->src_ssl) != 0) {
        log_finest("failed to create ngtcp2_crypto_ossl_ctx");
        return NULL;
    }

    ngtcp2_conn_set_tls_native_handle(h3_ctx->src_conn, h3_ctx->src_ossl_ctx);

    // TODO: Call ngtcp2_conn_get_tls_native_handle() if needed?
    // ngtcp2_crypto_ossl_ctx *ossl_ctx = ngtcp2_conn_get_tls_native_handle(h3_ctx->src_conn);

    /* ------------------------------------------------------------------
     * Create Libevent events for the raw UDP file descriptor.
     * EV_WRITE              – one-shot, armed only when we have output.
     * ------------------------------------------------------------------ */
    h3_ctx->src_wev = event_new(ctx->thr->evbase, -1,
                                EV_WRITE,
                                protohttp3_src_write_cb, h3_ctx);
    if (!h3_ctx->src_wev)
        goto err_wev;

    /* Timer event: fd = -1, EV_TIMEOUT (one-shot).                       */
    h3_ctx->timer_ev = event_new(ctx->thr->evbase, -1,
                                 EV_TIMEOUT,
                                 protohttp3_timer_cb, h3_ctx);
    if (!h3_ctx->timer_ev)
        goto err_timer;

    log_finest("Session created");
    return h3_ctx;

err_timer:
    event_free(h3_ctx->src_wev);
err_wev:
    ngtcp2_conn_del(h3_ctx->src_conn);
    free(h3_ctx);
    return NULL;
}

/* =========================================================================
 * proxy.c integration: protohttp3_setup and protohttp3_init_conn
 *
 * These functions adapt the raw protohttp3.c internals to the SSLproxy
 * protocol handler interface expected by proxy.c.
 * ====================================================================== */

/*
 * Forward declarations.
 */
static int  protohttp3_conn_connect(pxy_conn_ctx_t *ctx);
static void protohttp3_init_conn(evutil_socket_t fd, short what, void *arg);
static void protohttp3_conn_free(pxy_conn_ctx_t *ctx);

/*
 * Called by proxy_setup_proto() in proxy.c to register HTTP/3 callbacks.
 * 
 * Since HTTP/3 uses raw UDP and ngtcp2 rather than libevent bufferevents,
 * most of the standard callback fields (bev_readcb, bev_writecb, etc.)
 * are left as NULL.  The actual I/O is driven by the libevent events
 * created inside protohttp3_new().
 */
protocol_t
protohttp3_setup(pxy_conn_ctx_t *ctx)
{
    ctx->protoctx->proto = PROTO_HTTP3;
    ctx->protoctx->connectcb = protohttp3_conn_connect;
    ctx->protoctx->init_conn = protohttp3_init_conn;
    ctx->protoctx->proto_free = protohttp3_conn_free;

    /*
     * UDP bufferevent callbacks are not used – protohttp3 manages its
     * own raw UDP events.  Set them to the default tcp implementations
     * just so that they are never NULL (harmless since they won't be
     * called for HTTP/3).
     */
    ctx->protoctx->bev_readcb = NULL;
    ctx->protoctx->bev_writecb = NULL;
    ctx->protoctx->bev_eventcb = NULL;

    /*
     * Watermark and discard callbacks are for bufferevent-based protocols.
     * HTTP/3 handles its own flow control via ngtcp2, so we set these to
     * no-ops.
     */
    ctx->protoctx->set_watermarkcb = NULL;
    ctx->protoctx->unset_watermarkcb = NULL;
    ctx->protoctx->discard_inbufcb = NULL;
    ctx->protoctx->discard_outbufcb = NULL;

    log_finest_va("EXIT, ctx->fd=%d", ctx->fd);

    return PROTO_HTTP3;
}

/*
 * init_conn callback – called from proxy_listener_acceptcb() after the
 * connection has been handed off to the connection handling thread.
 * We create the QUIC/H3 server session here.
 */
static void
protohttp3_init_conn(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
    pxy_conn_ctx_t *ctx = arg;

    log_finest_va("ENTER, ctx->fd=%d, fd=%d", ctx->fd, fd);

    if (ctx->ev) {
        event_free(ctx->ev);
        ctx->ev = NULL;
    }

    /*
     * pxy_conn_init sets up the connection for use with the generic
     * SSLproxy framework.  For HTTP/3 we don't use bufferevents, so
     * we bypass the bufferevent parts.
     */
    if (pxy_conn_init(ctx) == -1)
        return;

    log_finest_va("Session initialised on fd=%d", ctx->fd);

    /* Initiate upstream QUIC connection immediately for reverse proxy */
    pxy_conn_connect(ctx);

    // We create the h3 context in proxy_listener_acceptcb_udp()
    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp3_ctx_t *h3_ctx = http_ctx->arg;

    // Directly call the packet processing callback to handle the first queued packet
    protohttp3_process_packet_cb(h3_ctx->src_fd, 0, h3_ctx);
}

/*
 * connectcb callback – called from pxy_conn_connect().
 * For HTTP/3 we need to determine the upstream server address and
 * initiate a QUIC connection to it.
 *
 * In split mode, we connect the upstream (dst) UDP socket and create
 * a client-mode ngtcp2 session for the upstream direction.
 */
static int
protohttp3_conn_connect(pxy_conn_ctx_t *ctx)
{
    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp3_ctx_t *h3_ctx = http_ctx->arg;

    log_finest("ENTER");

    if (!h3_ctx || !h3_ctx->src_conn) {
        log_fine("No src session");
        return -1;
    }

    /*
     * Determine the upstream (dst) address.
     * If we have a static target address, use it.  Otherwise fall back
     * to NAT lookup.
     */
    if (!ctx->dstaddrlen) {
        if (ctx->spec->connect_addrlen) {
            memcpy(&ctx->dstaddr, &ctx->spec->connect_addr,
                   ctx->spec->connect_addrlen);
            ctx->dstaddrlen = ctx->spec->connect_addrlen;
        } else if (ctx->spec->natlookup) {
            if (ctx->spec->natlookup((struct sockaddr *)&ctx->dstaddr,
                                     &ctx->dstaddrlen,
                                     ctx->fd,
                                     (struct sockaddr *)&ctx->srcaddr,
                                     ctx->srcaddrlen) == -1) {
                log_finest("NAT lookup failed");
                return -1;
            }
        }
    }

    if (!ctx->dstaddrlen) {
        log_finest("No upstream destination address");
        pxy_conn_term(ctx, 1);
        return -1;
    }

    /*
     * Create the upstream UDP socket and connect it to the target.
     */
    int dst_fd = socket(ctx->dstaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (dst_fd == -1) {
        log_finest_va("Failed to create dst UDP socket: %s", strerror(errno));
        return -1;
    }

    // TODO: Do we need to set IP_PKTINFO for the dst socket?
    // int val = 1;
    // if (setsockopt(dst_fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val)) < 0) {
    //     log_finest_va("Failed to set IP_PKTINFO: %s", strerror(errno));
    // }

    // TODO: Do we need to bind to the dst socket?

    if (connect(dst_fd, (struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen) == -1) {
        log_finest_va("Failed to connect dst UDP socket: %s", strerror(errno));
        close(dst_fd);
        return -1;
    }

    /* Make the socket non-blocking. */
    evutil_make_socket_nonblocking(dst_fd);

    h3_ctx->dst_fd = dst_fd;

    /*
     * Cache the peer address for the upstream.
     */
    memcpy(&h3_ctx->dst_peer_addr, &ctx->dstaddr, ctx->dstaddrlen);
    h3_ctx->dst_peer_addrlen = ctx->dstaddrlen;

    /*
     * Instantiate the upstream QUIC client session.
     */
    ngtcp2_callbacks cb = {0};

    cb.client_initial           = ngtcp2_crypto_client_initial_cb;
    cb.recv_client_initial      = ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt                  = ngtcp2_crypto_encrypt_cb;
    cb.decrypt                  = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask                  = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry               = ngtcp2_crypto_recv_retry_cb;
    cb.update_key               = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation      = ngtcp2_crypto_version_negotiation_cb;

    cb.handshake_completed      = quic_handshake_completed; /* In a real client this would be a client handshake cb */
    cb.recv_stream_data         = quic_recv_stream_data;
    cb.stream_open              = quic_stream_open;
    cb.stream_close             = quic_stream_close;
    cb.rand                     = quic_rand;
    cb.get_new_connection_id    = quic_get_new_connection_id;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = h3_timestamp();

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);

    // TODO: Tune these parameters for better performance and resource usage.
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 10 * 1024 * 1024; // 10MB
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.active_connection_id_limit = 2; // Must be >= 2
    params.max_udp_payload_size                = 1472;
    params.max_idle_timeout = 30 * NGTCP2_SECONDS;

    ngtcp2_cid scid, dcid;
    scid.datalen = NGTCP2_MAX_CIDLEN;
    arc4random_buf(scid.data, scid.datalen);
    dcid.datalen = NGTCP2_MAX_CIDLEN;
    arc4random_buf(dcid.data, dcid.datalen);

    // ATTENTION: We need a persistent var for dst_local_addr, hence h3_ctx->dst_local_addr,
    // because ngtcp2_addr_init() does not copy the sockaddr, it just stores a pointer to it.
	h3_ctx->dst_local_addrlen = sizeof(h3_ctx->dst_local_addr);
	if (getsockname(dst_fd, (struct sockaddr *)&h3_ctx->dst_local_addr, &h3_ctx->dst_local_addrlen) < 0) {
		log_err_level_printf(LOG_CRIT, "Error in getsockname: %s\n", strerror(errno));
		goto err;
	}

    ngtcp2_addr_init(&h3_ctx->dst_path.local,  (struct sockaddr *)&h3_ctx->dst_local_addr, h3_ctx->dst_local_addrlen);
    ngtcp2_addr_init(&h3_ctx->dst_path.remote, (struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen);

    protohttp3_debug_print_addr((struct sockaddr_storage *)h3_ctx->dst_path.remote.addr, "dst_path.remote");
    protohttp3_debug_print_addr((struct sockaddr_storage *)h3_ctx->dst_path.local.addr, "dst_path.local");

    settings.log_printf = debug_log_dst;

    int rv = ngtcp2_conn_client_new(&h3_ctx->dst_conn, &dcid, &scid, &h3_ctx->dst_path,
                               NGTCP2_PROTO_VER_V1, &cb, &settings,
                               &params, NULL, h3_ctx);
    if (rv != 0) {
        log_finest("Failed to create dst QUIC session");
        goto err;
    }

    /* ------------------------------------------------------------------
     * TLS OpenSSL setup (dst side).
     * ------------------------------------------------------------------ */
    /* Note: For SSLproxy, we should derive the SSL_CTX from the proxyspec.
     * We'll use a local TLS method block for the QUIC prototype. */

    // TODO: Use the SSL method from conn_opts if available, otherwise default to TLS_method()
    // SSL_CTX *ssl_ctx = SSL_CTX_new(ctx->conn_opts->sslmethod());
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());

    // QUIC requires TLS 1.3
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    // TODO: Enable ALPN selection on OpenSSL client context?
    // SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, NULL);

    // Enable key logging for debugging purposes
    SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);

    h3_ctx->dst_ssl = SSL_new(ssl_ctx);

    // Set ALPN on client SSL instance (e.g. \x02h3)
    unsigned char alpn[] = {0x02, 'h', '3'};
    SSL_set_alpn_protos(h3_ctx->dst_ssl, alpn, sizeof(alpn));

    /* Set SNI on the client SSL object */
    // TODO: Get the hostname of the upstream server from the SNI in ClientHello on the client side,
    // or from the proxyspec, if the target server is specified.
    // For now we hardcode "localhost" for testing.
    // if (ctx->hostname && strlen(ctx->hostname) > 0) {
    //     SSL_set_tlsext_host_name(h3_ctx->dst_ssl, ctx->hostname);
    // } else {
        // Fallback if proxying by raw IP — e.g. "localhost" or target IP domain
        SSL_set_tlsext_host_name(h3_ctx->dst_ssl, "localhost"); 
    // }

    SSL_set_connect_state(h3_ctx->dst_ssl);

    ngtcp2_crypto_ossl_configure_client_session(h3_ctx->dst_ssl);

    h3_ctx->dst_conn_ref.get_conn = get_dst_conn;
    h3_ctx->dst_conn_ref.user_data = h3_ctx;
    SSL_set_app_data(h3_ctx->dst_ssl, &h3_ctx->dst_conn_ref);

    h3_ctx->dst_ossl_ctx = NULL;
    if (ngtcp2_crypto_ossl_ctx_new(&h3_ctx->dst_ossl_ctx, h3_ctx->dst_ssl) != 0) {
        log_finest("failed to create ngtcp2_crypto_ossl_ctx");
        return -1;
    }

    ngtcp2_conn_set_tls_native_handle(h3_ctx->dst_conn, h3_ctx->dst_ossl_ctx);

    /*
     * Set up the libevent read/write events for the upstream UDP socket.
     */
    h3_ctx->dst_rev = event_new(ctx->thr->evbase, dst_fd,
                                EV_READ | EV_PERSIST,
                                protohttp3_dst_read_cb, h3_ctx);
    if (!h3_ctx->dst_rev)
        goto err;

    h3_ctx->dst_wev = event_new(ctx->thr->evbase, dst_fd,
                                EV_WRITE,
                                protohttp3_dst_write_cb, h3_ctx);
    if (!h3_ctx->dst_wev)
        goto err;

    if (event_add(h3_ctx->dst_rev, NULL) != 0)
        goto err;

    if (event_add(h3_ctx->dst_wev, NULL) != 0)
        goto err;

    /*
     * Mark the connection as connected so the proxy framework considers
     * it ready.  HTTP/3 will still need to perform the QUIC handshake
     * via the existing ngtcp2 events.
     */
    // ctx->connected = 1;

    log_finest_va("Upstream connection configured to dst_fd=%d", dst_fd);

    protohttp3_trigger_write_loop(h3_ctx, 0);

    return 0;

err:
    if (h3_ctx->dst_rev) { event_free(h3_ctx->dst_rev); h3_ctx->dst_rev = NULL; }
    if (h3_ctx->dst_wev) { event_free(h3_ctx->dst_wev); h3_ctx->dst_wev = NULL; }
    close(dst_fd);
    h3_ctx->dst_fd = -1;
    return -1;
}

/*
 * proto_free callback – called during connection teardown.
 * Delegates to protohttp3_free() which cleans up the QUIC/H3 session.
 */
static void
protohttp3_conn_free(pxy_conn_ctx_t *ctx)
{
    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp3_ctx_t *h3_ctx = http_ctx->arg;
    if (h3_ctx) {
        log_finest("freeing session");
        protohttp3_free(h3_ctx);
        http_ctx->arg = NULL;
    }
}

/*
 * protohttp3_free – tear down the entire QUIC/H3 session.
 *
 * Mirrors protohttp2_free() in protohttp2.c.
 */
void
protohttp3_free(protohttp3_ctx_t *h3_ctx)
{
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest("Free session");

    /* Stop all Libevent events first so no more callbacks fire.           */
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
        protohttp3_free_stream_ctx(h3_ctx->streams);

    /* Remove from session hash table if present.                          */
    if (h3_ctx->h3_sessions) {
        h3_session_map_remove((h3_session_map_t *)h3_ctx->h3_sessions, &h3_ctx->key);
        h3_ctx->h3_sessions = NULL;
    }

    /* Close raw UDP sockets.                                              */
    if (h3_ctx->dst_fd >= 0) { close(h3_ctx->dst_fd); h3_ctx->dst_fd = -1; }

    pthread_mutex_lock(&h3_ctx->pkt_queue_mutex);
    while (h3_ctx->pkt_queue) {
        pkt_node_t *pkt = h3_ctx->pkt_queue;
        h3_ctx->pkt_queue = pkt->next;
        if (pkt->buf) {
            free(pkt->buf);
            pkt->buf = NULL;
        }
        free(pkt);
    }
    pthread_mutex_unlock(&h3_ctx->pkt_queue_mutex);

    pthread_mutex_destroy(&h3_ctx->pkt_queue_mutex);

    free(h3_ctx);
}

/* vim: set noet ft=c: */
