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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * protohttp3.c – asynchronous HTTP/3 reverse proxy connection handler.
 *
 * Stack
 * -----
 *   Libevent struct event (raw UDP fd)
 *       -> recvmsg()  ->  ngtcp2_conn_read_pkt()
 *          ngtcp2 stream-data callback  ->  nghttp3_conn_read_stream2()
 *          nghttp3 header callback  ->  protohttp3_stream_ctx.headers[]
 *          nghttp3 data callback    ->  protohttp3_stream_ctx.body_buf[]
 *   ngtcp2_conn_write_pkt() / ngtcp2_conn_writev_stream()
 *          ->  sendmsg()  ->  network
 *
 * Threading model
 * ---------------
 *   All callbacks fire on the single-threaded Libevent loop of the proxy
 *   thread assigned to this connection.  No locks are needed inside the
 *   callbacks.
 *
 * Known limitations of this prototype
 * ------------------------------------
 *   - QPACK (dynamic table) is initialised with capacity 0 (static-only
 *     mode) to keep the prototype simple.
 */

#include "protossl.h"
#include "protohttp.h"
#include "protohttp3.h"
#include "log.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>       /* clock_gettime(CLOCK_MONOTONIC) */
#include <ctype.h>      /* for tolower() in header filtering */

/* recvmsg() ancillary data for ECN and destination-address extraction */
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h> /* in_pktinfo, in6_pktinfo, IP_TOS, ... */

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

static int
protohttp3_conn_connect(pxy_conn_ctx_t *ctx);

/* Maximum iovecs we ask nghttp3 to fill in one writev call.              */
#define H3_MAX_IOVECS   16

/* =========================================================================
 * protohttp3_stream_ctx helpers
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
    s->data_buf = evbuffer_new();

    // Set up the data reader hook
    s->dr.read_data = h3_stream_read_data;

    s->http_ctx = malloc(sizeof(protohttp_ctx_t));
	if (!s->http_ctx) {
        free(s);
		return NULL;
	}
	memset(s->http_ctx, 0, sizeof(protohttp_ctx_t));

	s->http_ctx->ctx = ctx;

#ifndef WITHOUT_ICAP
    s->icap_ctx = icap_init(ctx, PROTO_HTTP3, (protohttpx_stream_ctx_t *)s, h3_ctx, ctx->conn_opts->icap_chain);
	if (!s->icap_ctx) {
        free(s->http_ctx);
        free(s);
		return NULL;
    }
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
    pxy_conn_ctx_t *ctx = s->ctx;
    protohttp3_ctx_t *h3_ctx = ctx->protoctx->arg;
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

    if (s->data_buf) {
        evbuffer_free(s->data_buf);
        s->data_buf = NULL;
    }

    if (s->body_buf) {
        free(s->body_buf);
        s->body_buf = NULL;
    }

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
protohttp3_request_free_stream_ctx(protohttp3_stream_ctx_t *s)
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

    log_finest_va("stream %" PRId64 " free immediately", s->src_stream_id);
    // Safe to destroy immediately
    protohttp3_free_stream_ctx(s);
}

/*
 * Append a single name-value header pair to the stream's header array,
 * growing the backing array by doubling as needed.
 *
 * Returns 0 on success, -1 on OOM.
 */
static int
protohttp3_add_nv_header(protohttp3_stream_ctx_t *s,
                         const char *name,  size_t namelen,
                         const char *value, size_t valuelen)
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
    if (!nv->name)
        return -1;

    // TODO: HTTP/3 mandates strict lowercase header names?
    // Note that nghttp3 seems to convert to lowercase automatically, but we will do it here for safety.
    char name_lower[namelen];
    memcpy(name_lower, name, namelen);
    for (size_t i = 0; i < namelen; i++) {
        name_lower[i] = tolower(name[i]);
    }

    // Cast to void* to avoid warnings about discarding const qualifier
    memcpy((void *)nv->name, name_lower, namelen);
    nv->namelen = namelen;

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

#ifndef WITHOUT_ICAP
int
protohttp3_get_h3_headers(protohttp3_stream_ctx_t *s, struct evbuffer *h1_buf, int init)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx->reqmod);

    // Clean slate for this stream context's header holder
    if (init == 1 && s->headers) {
        protohttp3_free_stream_headers(s);
    }

    size_t line_len;
    char *line;
    int is_first_line = 1;

    while ((line = evbuffer_readln(h1_buf, &line_len, EVBUFFER_EOL_CRLF)) != NULL) {
        if (line_len == 0) {
            free(line);
            break;
        }

        if (is_first_line) {
            is_first_line = 0;

            // Request Line
            if (memcmp(line, "HTTP/", 5) != 0) {
                char *method = line;
                char *path = strchr(line, ' ');
                if (path) {
                    *path = '\0';
                    path++;
                    char *version = strchr(path, ' ');
                    if (version) {
                        *version = '\0';
                    }

                    // Strip absolute uri scheme and authority
                    // If path starts with "http://" or "https://", skip to the relative path component
                    if (strncasecmp(path, "http://", 7) == 0) {
                        char *relative_path = strchr(path + 7, '/');
                        if (relative_path) {
                            path = relative_path;
                        } else {
                            path = "/"; // Fallback if no trailing slash was provided
                        }
                    } else if (strncasecmp(path, "https://", 8) == 0) {
                        char *relative_path = strchr(path + 8, '/');
                        if (relative_path) {
                            path = relative_path;
                        } else {
                            path = "/"; // Fallback if no trailing slash was provided
                        }
                    }

                    size_t m_len = strlen(method);
                    size_t p_len = strlen(path);

                    log_finest_va("Translate Request Line: :method=%.*s, :path=%.*s, and add :scheme=https", (int)m_len, method, (int)p_len, path);
                    if (protohttp3_add_nv_header(s, ":method", 7, method, m_len) < 0 ||
                        protohttp3_add_nv_header(s, ":path", 5, path, p_len) < 0 ||
                        protohttp3_add_nv_header(s, ":scheme", 7, "https", 5) < 0) {
                        free(line);
                        return -1;
                    }
                }
            }
            // Status Line
            else {
                char *status = strchr(line, ' ');
                if (status) {
                    while (*status == ' ') status++; // Skip spaces
                    char *phrase = strchr(status, ' ');
                    if (phrase) {
                        // We only want the status digit group (e.g. "200"), not the reason phrase (e.g. "OK")
                        *phrase = '\0';
                    }
                    size_t s_len = strlen(status);
                    log_finest_va("Translate Status Line: :status=%.*s", (int)s_len, status);
                    if (protohttp3_add_nv_header(s, ":status", 7, status, s_len) < 0) {
                        free(line);
                        return -1;
                    }
                }
            }
            free(line);
            continue;
        }

        // Process regular headers "Name: Value"
        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            char *h_name = line;
            char *h_value = colon + 1;

            size_t n_len = 0;
            size_t v_len = 0;
            h_name = trim_whitespace(h_name, &n_len);
            h_value = trim_whitespace(h_value, &v_len);

            if (n_len == 4 && !strncasecmp(h_name, "Host", 4)) {
                log_finest_va("Translate Host to :authority: %.*s", (int)v_len, h_value);
                if (protohttp3_add_nv_header(s, ":authority", 10, h_value, v_len) < 0) {
                    free(line);
                    return -1;
                }
            }
            // Filter out Connection headers that are forbidden or invalid in H2
            else if ((n_len == 10 && !strncasecmp(h_name, "Connection", 10)) ||
                     (n_len == 17 && !strncasecmp(h_name, "Transfer-Encoding", 17)) ||
                     (n_len == 10 && !strncasecmp(h_name, "Keep-Alive", 10)) ||
                     (n_len == 5  && !strncasecmp(h_name, "Proxy", 5))) {
                log_finest_va("Skip H1 specific connection header: %s", h_name);
            }
            // Regular Header Pass-through
            else {
                if (protohttp3_add_nv_header(s, h_name, n_len, h_value, v_len) < 0) {
                    free(line);
                    return -1;
                }
            }
        }
        free(line);
    }

    return 0;
}
#endif /* !WITHOUT_ICAP */

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
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest_va("ENTER, fd=%d", h3_ctx->dst_fd);

    if (reqmod && h3_ctx->wait_server_connected) {
        log_finest_va("Wait for server connection, skipping write loop, fd=%d", h3_ctx->dst_fd);
        return;
    }

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
        // Note that we do send fin packets without data to signal the end of a stream.
        if ((sveccnt > 0 || fin) && stream_id >= 0) {
            ngtcp2_ssize pdatalen = 0;
            pktlen = ngtcp2_conn_writev_stream(
                         reqmod ? h3_ctx->src_conn : h3_ctx->dst_conn,
                         reqmod ? &h3_ctx->src_path : &h3_ctx->dst_path,
                         &pi,
                         pktbuf, sizeof(pktbuf),
                         &pdatalen,
                         // TODO: Is this enough? The ngtcp2_write_stream_flag enum has changed in recent versions.
                         // The NGTCP2_WRITE_STREAM_FLAG_MORE flag is now deprecated and replaced with NGTCP2_WRITE_STREAM_FLAG_FIN for the FIN flag.
                         // Or should we pass NGTCP2_WRITE_STREAM_FLAG_NONE, instead of NGTCP2_WRITE_STREAM_FLAG_MORE?
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

        /* Handle write status */
        if (pktlen == NGTCP2_ERR_WRITE_MORE) {
            log_finest_va("Write more, pktlen=%zd, fd=%d", pktlen, h3_ctx->dst_fd);
            continue;
        }

        if (pktlen <= 0) {
            if (pktlen < 0 && pktlen != NGTCP2_ERR_WRITE_MORE) {
                log_finest_va("ngtcp2 write error: %s", ngtcp2_strerror((int)pktlen));

                if (pktlen == NGTCP2_ERR_STREAM_SHUT_WR || pktlen == NGTCP2_ERR_STREAM_NOT_FOUND) {
                    log_finest_va("ngtcp2 write error with ERR_STREAM_SHUT_WR, stream_id=%" PRId64 ", fd=%d", stream_id, h3_ctx->dst_fd);
                    nghttp3_conn_close_stream(reqmod ? h3_ctx->src_h3 : h3_ctx->dst_h3, stream_id, NGHTTP3_H3_INTERNAL_ERROR);
                }

                // TODO: Check if this is enough on fatal errors
                if (ngtcp2_err_is_fatal((int)pktlen)) {
                    log_finest_va("Fatal ngtcp2 write error, terminating connection, fd=%d", h3_ctx->dst_fd);
                    const ngtcp2_ccerr ccerr = {
                        .type = NGTCP2_CCERR_TYPE_TRANSPORT,
                        .error_code = (int)pktlen,
                    };
                    ngtcp2_conn_write_connection_close(reqmod ? h3_ctx->src_conn : h3_ctx->dst_conn,
                        reqmod ? &h3_ctx->src_path : &h3_ctx->dst_path, &pi, pktbuf, sizeof(pktbuf),
                        &ccerr, h3_timestamp());
                    // TODO: Should we call ngtcp2_conn_del() here to free the connection?
                    // ngtcp2_conn_del(reqmod ? h3_ctx->src_conn : h3_ctx->dst_conn);
                    return;
                }
            }
            log_finest_va("Drained all pending packets, pktlen=%zd, fd=%d", pktlen, h3_ctx->dst_fd);
            break; /* Drained all pending packets */
        }

        log_finest_va("Transmit packet, pktlen=%zd, fd=%d", pktlen, h3_ctx->dst_fd);
        if (reqmod) {
            ctx->thr->intif_out_bytes += pktlen;
        } else {
            ctx->thr->extif_out_bytes += pktlen;
        }

        /* 3. Transmit via UDP socket */
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

    // ATTENTION: This function submits data to the opposite side of the connection (src or dst) based on the reqmod flag.
    // So, if reqmod is 1, we are submitting data to the dst side (server), and if reqmod is 0, we are submitting data to the src side (client).
    if (s->headers_count > 0) {
        log_finest_va("Submit headers, headers_count=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->headers_count, s->src_stream_id, s->dst_stream_id, reqmod);

        if (reqmod) {
            rv = nghttp3_conn_submit_request(h3_ctx->dst_h3, s->dst_stream_id, s->headers, s->headers_count, &s->dr, s);
            if (rv < 0) {
                log_finest_va("Fatal: nghttp3_conn_submit_request failed: %s", nghttp3_strerror(rv));
                return -1;
            }

            // TODO: Set the stream id assigned by nghttp3 for the destination session, as in h2?
            // But in h3 the dst_stream_id is assigned by ngtcp2_conn_open_bidi_stream() before calling this function.
            // s->dst_stream_id = rv;
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

#ifndef WITHOUT_ICAP
    // TODO: What about fin packets without data? Should we set made_progress for those as well?
    if (evbuffer_get_length(s->data_buf) > 0) {
        s->icap_ctx->made_progress = 1;
    }
#endif /* !WITHOUT_ICAP */

    // ATTENTION: We should not check for data_buf length here, because we may have a zero-length data submission (e.g., end of stream).
    // if (evbuffer_get_length(s->data_buf) > 0) {
        log_finest_va("Submit data, data_len=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", evbuffer_get_length(s->data_buf), s->src_stream_id, s->dst_stream_id, reqmod);

        rv = nghttp3_conn_resume_stream(reqmod ? h3_ctx->dst_h3 : h3_ctx->src_h3, reqmod ? s->dst_stream_id : s->src_stream_id);

        if (rv == NGHTTP3_ERR_INVALID_ARGUMENT) {
            // Clean operational bypass: The engine is already active and polling
            log_finest_va("Stream already active, continuing to explicit write execution, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
        }
        else if (rv < 0) {
            log_finest_va("Fatal: nghttp3_conn_resume_stream failed: %s", nghttp3_strerror(rv));
            return -1;
        }

// #ifndef WITHOUT_ICAP
//         s->icap_ctx->made_progress = 1;
// #endif /* !WITHOUT_ICAP */
    // }

    // Clean Data Wakeup Flush
    log_finest_va("Executing scheduled session frame serialization loop for stream, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
    // ATTENTION: We pass !reqmod here because the write loop is triggered on the opposite side of the connection from where the data is being submitted.
    // The proxying flag is for the h3_stream_read_data callback to know which side of the connection is being written to.
    h3_ctx->proxying = 1;
    protohttp3_trigger_write_loop(h3_ctx, !reqmod);
    h3_ctx->proxying = 0;

    return 0;
}

#ifndef WITHOUT_ICAP
void NONNULL(1)
protohttp3_icap_send_data_to_src_cb(icap_ctx_t *icap_ctx)
{
    protohttp3_stream_ctx_t *s = icap_ctx->stream_ctx;
    protohttp3_ctx_t *h3_ctx = icap_ctx->hx_ctx;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;

    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", veto_hdr=%zu, veto_body=%zu, data_buf=%zu", s->src_stream_id, s->dst_stream_id,
        evbuffer_get_length(icap_ctx->veto_hdr), evbuffer_get_length(icap_ctx->veto_body), evbuffer_get_length(s->data_buf));

    protohttp3_get_h3_headers(s, icap_ctx->veto_hdr, 1);

    evbuffer_add_buffer(s->data_buf, icap_ctx->veto_body);

    // ATTENTION: We pass 0 for reqmod because we are sending data to the src (client) side, not the dst (server) side.
    // So, protohttp3_submit_data() will use !reqmod, when triggering the write loop.
    // Send block page to src (client), not dst (server)
    if (protohttp3_submit_data(h3_ctx, s, 0 /*respmod*/) < 0) {
        log_finest_va("Failed to submit data for src_stream_id=%" PRId64, s->src_stream_id);
        return;
    }
}

void NONNULL(1)
protohttp3_icap_send_data_to_dst_cb(icap_ctx_t *icap_ctx)
{
    protohttp3_stream_ctx_t *s = icap_ctx->stream_ctx;
    if (!s) {
		// log_dbg_printf("protohttp3_icap_send_data_to_dst_cb: No stream context\n");
        return;
    }

    protohttp3_ctx_t *h3_ctx = icap_ctx->hx_ctx;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;

    struct evbuffer *out_hdr = icap_get_last_service_out_hdr(icap_ctx);
    protohttp3_get_h3_headers(s, out_hdr, 1);

    struct evbuffer *out_body = icap_get_last_service_out_body(icap_ctx);
    evbuffer_add_buffer(s->data_buf, out_body);

    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", data_buf=%zu", s->src_stream_id, s->dst_stream_id, evbuffer_get_length(s->data_buf));

    if (protohttp3_submit_data(h3_ctx, s, icap_ctx->reqmod) < 0) {
        log_finest_va("Failed to submit data, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, icap_ctx->reqmod);
        return;
    }

    if (icap_enabled(s->icap_ctx) && icap_is_finished(s->icap_ctx) && s->closed) {
        if (!s->closed) {
            // Do not close the stream here, just set the flag (first close)
            log_finest_va("ICAP finished, set stream closed, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, icap_ctx->reqmod);
            s->closed = 1;
        }
        else {
            log_finest_va("Stream already closed, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", fd=%d", s->src_stream_id, s->dst_stream_id, h3_ctx->dst_fd);
        }
    }
}

void NONNULL(1)
protohttp3_icap_failopen_to_dest_cb(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
    protohttp3_stream_ctx_t *s = icap_ctx->stream_ctx;

    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d, headers_count=%zu, data_buf=%zu", s->src_stream_id, s->dst_stream_id,
        icap_ctx->reqmod, s->headers_count, evbuffer_get_length(s->data_buf));

	struct evbuffer *in_hdr = ICAP_STATE(service_ctx, icap_ctx->reqmod)->in_hdr;
	struct evbuffer *in_body = ICAP_STATE(service_ctx, icap_ctx->reqmod)->in_body;
	struct evbuffer *sent_hdr = ICAP_STATE(service_ctx, icap_ctx->reqmod)->sent_hdr;
	struct evbuffer *sent_body = ICAP_STATE(service_ctx, icap_ctx->reqmod)->sent_body;

    // On failopen, s->headers may contain headers, as we may not have submitted them by protohttp2_submit_data()
    protohttp3_free_stream_headers(s);

    // TODO: Non-http protocols do not have hdr
	if (evbuffer_get_length(sent_hdr) > 0) {
        protohttp3_get_h3_headers(s, sent_hdr, 1);
		icap_ctx->made_progress = 1;
	}
	if (evbuffer_get_length(sent_body) > 0) {
        evbuffer_add_buffer(s->data_buf, sent_body);
		icap_ctx->made_progress = 1;
	}
	if (evbuffer_get_length(in_hdr) > 0) {
        // Do not init h3 headers, just append to existing headers from sent_hdr, if any
        protohttp3_get_h3_headers(s, in_hdr, 0);
		icap_ctx->made_progress = 1;
	}
	if (evbuffer_get_length(in_body) > 0) {
        evbuffer_add_buffer(s->data_buf, in_body);
		icap_ctx->made_progress = 1;
	}

    log_finest_va("After copy, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d, headers_count=%zu, data_buf=%zu", s->src_stream_id, s->dst_stream_id,
        icap_ctx->reqmod, s->headers_count, evbuffer_get_length(s->data_buf));

    protohttp3_ctx_t *h3_ctx = icap_ctx->hx_ctx;
    if (protohttp3_submit_data(h3_ctx, s, icap_ctx->reqmod) < 0) {
        log_finest_va("Failed to submit data for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, icap_ctx->reqmod);
        return;
    }
}
#endif /* !WITHOUT_ICAP */

/* =========================================================================
 * nghttp3 callbacks
 *
 * nghttp3 calls these when it has decoded an HTTP/3 frame from the stream
 * data handed to it by nghttp3_conn_read_stream2().
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
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0; /* 1=client-side, 0=server-side */

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    // TODO: Uni streams are control streams and do not carry HTTP headers, do we ever get here for uni streams?
    if (!ngtcp2_is_bidi_stream(stream_id)) {
        log_finest_va("Ignoring uni stream header, stream_id=%" PRId64, stream_id);
        return 0;
    }

    // TODO: Is it possible we don't have a stream ctx yet for this stream_id? quic_stream_open() should have created one already.
    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s) {
        log_fine_va("ERROR: No stream context for stream_id=%" PRId64, stream_id);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    nghttp3_vec name_vec  = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec value_vec = nghttp3_rcbuf_get_buf(value);

    if (protohttp3_add_nv_header(s, (char *)name_vec.base,  name_vec.len, (char *)value_vec.base, value_vec.len) != 0) {
        log_fine_va("Failed to add header for stream_id=%" PRId64, stream_id);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static void
protohttp3_delete_nv_header(protohttp3_stream_ctx_t *s, size_t idx)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", remove idx=%zu", s->src_stream_id, s->dst_stream_id, idx);

    if (s->headers_count == 0 || idx >= s->headers_count) {
        return; // Invalid index or empty headers
    }

    // TODO: How to free the name and value buffers properly? They are allocated with malloc in protohttp3_add_nv_header.
    free((void *)s->headers[idx].name);
    free((void *)s->headers[idx].value);

    // Move the remaining headers up to fill the gap left by the removed header
    for (size_t i = idx; i < s->headers_count - 1; i++) {
        memcpy(&s->headers[i], &s->headers[i + 1], sizeof(nghttp3_nv));
    }

    memset(&s->headers[s->headers_count - 1], 0, sizeof(nghttp3_nv));
    s->headers_count--;
}

static int WUNRES NONNULL(1)
protohttp3_filter_request_header(protohttp3_stream_ctx_t *s)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);

    nghttp3_nv *headers = s->headers;
    size_t count = s->headers_count;
    protohttp_ctx_t *http_ctx = s->http_ctx;
    conn_opts_t *conn_opts = s->conn_opts ? s->conn_opts : ctx->conn_opts;

    for (size_t i = 0; i < count; i++) {
        log_finest_va("Processing header '%.*s=%.*s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
            (int)headers[i].namelen, headers[i].name, (int)headers[i].valuelen, headers[i].value, i, s->src_stream_id, s->dst_stream_id);

        if (headers[i].namelen == 7 && !memcmp(headers[i].name, ":method", 7)) {
            if (http_ctx->http_method) {
                free(http_ctx->http_method);
            }
            http_ctx->http_method = malloc(headers[i].valuelen + 1);
            if (!http_ctx->http_method) {
                s->ctx->enomem = 1;
                return -1;
            }
            memcpy(http_ctx->http_method, headers[i].value, headers[i].valuelen);
            http_ctx->http_method[headers[i].valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http method '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_method, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (headers[i].namelen == 5 && !memcmp(headers[i].name, ":path", 5)) {
            if (http_ctx->http_uri) {
                free(http_ctx->http_uri);
            }
            http_ctx->http_uri = malloc(headers[i].valuelen + 1);
            if (!http_ctx->http_uri) {
                s->ctx->enomem = 1;
                return -1;
            }
            memcpy(http_ctx->http_uri, headers[i].value, headers[i].valuelen);
            http_ctx->http_uri[headers[i].valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http URI '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_uri, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (headers[i].namelen == 10 && !memcmp(headers[i].name, ":authority", 10)) {
            if (http_ctx->http_host) {
                free(http_ctx->http_host);
            }
            http_ctx->http_host = malloc(headers[i].valuelen + 1);
            if (!http_ctx->http_host) {
                s->ctx->enomem = 1;
                return -1;
            }
            memcpy(http_ctx->http_host, headers[i].value, headers[i].valuelen);
            http_ctx->http_host[headers[i].valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http host '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_host, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (headers[i].namelen == 14 && !memcmp(headers[i].name, "content-length", 14)) {
			if (http_ctx->http_content_length) {
				free(http_ctx->http_content_length);
			}
			http_ctx->http_content_length = malloc(headers[i].valuelen + 1);
			if (!http_ctx->http_content_length) {
				s->ctx->enomem = 1;
				return -1;
			}
			memcpy(http_ctx->http_content_length, headers[i].value, headers[i].valuelen);
			http_ctx->http_content_length[headers[i].valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http content-length '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_content_length, i, s->src_stream_id, s->dst_stream_id);
		}
        else if (headers[i].namelen == 12 && !memcmp(headers[i].name, "content-type", 12)) {
			if (http_ctx->http_content_type) {
				free(http_ctx->http_content_type);
			}
			http_ctx->http_content_type = malloc(headers[i].valuelen + 1);
			if (!http_ctx->http_content_type) {
				s->ctx->enomem = 1;
				return -1;
			}
            memcpy(http_ctx->http_content_type, headers[i].value, headers[i].valuelen);
            http_ctx->http_content_type[headers[i].valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http content-type '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_content_type, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (conn_opts->remove_http_accept_encoding && (headers[i].namelen == 15 && !memcmp(headers[i].name, "accept-encoding", 15))) {
            protohttp3_delete_nv_header(s, i);
			http_ctx->seen_keyword_count++;
        }
        else if (conn_opts->remove_http_referer && (headers[i].namelen == 7 && !memcmp(headers[i].name, "referer", 7))) {
            protohttp3_delete_nv_header(s, i);
			http_ctx->seen_keyword_count++;
		}
		         // Not possible in HTTP/2
        else if ((headers[i].namelen == 4 && !memcmp(headers[i].name, "host", 4)) ||
                 (headers[i].namelen == 10 && !memcmp(headers[i].name, "connection", 10)) ||
                 (headers[i].namelen == 8 && !memcmp(headers[i].name, "keep-alive", 8)) ||
                 (headers[i].namelen == 7 && !memcmp(headers[i].name, "upgrade", 7)) ||
		         // ATTENTION: flickr keeps redirecting to https with 301 unless we remove the Via line of squid
                 // Apparently flickr assumes the existence of Via header field or squid keyword a sign of plain http, even if we are using https
		         (headers[i].namelen == 4 && !memcmp(headers[i].name, "via", 4)) ||
				 // Also do not send the loopback address to the Internet
		         (headers[i].namelen == 15 && !memcmp(headers[i].name, "x-forwarded-for", 15))) {
            protohttp3_delete_nv_header(s, i);
        }
    }

	if (http_ctx->seen_req_header) {
        // ATTENTION: Do not return -1 if protohttpx_apply_filter() fails, ignore the retval.
        // Otherwise, the caller h3_on_end_headers() returns NGHTTP3_ERR_CALLBACK_FAILURE,
        // which is a fatal error after ngtcp2_conn_read_pkt() in protohttp3_process_packet_cb(),
        // a reason to close the connection altogether
        protohttpx_apply_filter(s, PROTO_HTTP3);

        // TODO: Implement deny OCSP at TLS level in HTTP/3?
        // if (ctx->conn_opts->deny_ocsp) {
        //     protohttp_ocsp_deny(ctx, http_ctx);
        // }
	}

    if (s->ctx->enomem) {
        return -1;
    }
	return 0;
}

static int WUNRES NONNULL(1)
protohttp3_filter_response_header(protohttp3_stream_ctx_t *s)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);

    nghttp3_nv *headers = s->headers;
    size_t count = s->headers_count;
    protohttp_ctx_t *http_ctx = s->http_ctx;
    conn_opts_t *conn_opts = s->conn_opts ? s->conn_opts : ctx->conn_opts;

    for (size_t i = 0; i < count; i++) {
        log_finest_va("Processing header '%.*s=%.*s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
            (int)headers[i].namelen, headers[i].name, (int)headers[i].valuelen, headers[i].value, i, s->src_stream_id, s->dst_stream_id);

        if (headers[i].namelen == 7 && !memcmp(headers[i].name, ":status", 7)) {
            if (http_ctx->http_status_code) {
                free(http_ctx->http_status_code);
            }
            http_ctx->http_status_code = malloc(headers[i].valuelen + 1);
            if (!http_ctx->http_status_code) {
                s->ctx->enomem = 1;
                return -1;
            }
            memcpy(http_ctx->http_status_code, headers[i].value, headers[i].valuelen);
            http_ctx->http_status_code[headers[i].valuelen] = '\0';

            log_finest_va("Http status '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_status_code, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (headers[i].namelen == 14 && !memcmp(headers[i].name, "content-length", 14)) {
			if (http_ctx->http_content_length) {
				free(http_ctx->http_content_length);
			}
			http_ctx->http_content_length = malloc(headers[i].valuelen + 1);
			if (!http_ctx->http_content_length) {
				s->ctx->enomem = 1;
				return -1;
			}
			memcpy(http_ctx->http_content_length, headers[i].value, headers[i].valuelen);
			http_ctx->http_content_length[headers[i].valuelen] = '\0';

            log_finest_va("Http content-length '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_content_length, i, s->src_stream_id, s->dst_stream_id);
		}
        else if (headers[i].namelen == 12 && !memcmp(headers[i].name, "content-type", 12)) {
			if (http_ctx->http_content_type) {
				free(http_ctx->http_content_type);
			}
			http_ctx->http_content_type = malloc(headers[i].valuelen + 1);
			if (!http_ctx->http_content_type) {
				s->ctx->enomem = 1;
				return -1;
			}
            memcpy(http_ctx->http_content_type, headers[i].value, headers[i].valuelen);
            http_ctx->http_content_type[headers[i].valuelen] = '\0';

            log_finest_va("Http content-type '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_content_type, i, s->src_stream_id, s->dst_stream_id);
        }
        // Normally not possible in response
        else if (conn_opts->remove_http_referer && (headers[i].namelen == 7 && !memcmp(headers[i].name, "referer", 7))) {
            protohttp3_delete_nv_header(s, i);
		}
        else if ((headers[i].namelen == 15 && !memcmp(headers[i].name, "public-key-pins", 15)) ||
                 (headers[i].namelen == 27 && !memcmp(headers[i].name, "public-key-pins-report-only", 27)) ||
                 (headers[i].namelen == 26 && !memcmp(headers[i].name, "strict-transport-security", 26)) ||
                 (headers[i].namelen == 9 && !memcmp(headers[i].name, "expect-ct", 9)) ||
                 (headers[i].namelen == 18 && !memcmp(headers[i].name, "alternate-protocol", 18)) ||
                 (headers[i].namelen == 7 && !memcmp(headers[i].name, "upgrade", 7))) {
            protohttp3_delete_nv_header(s, i);
        }
        // We should not receive alt-svc on an already h3 stream, but if we do, rewrite it to the configured port
        // And h3 proxyspecs should not be configured to rewrite alt-svc anyway
        else if (conn_opts->rewrite_alt_svc_port && !memcmp(headers[i].name, "alt-svc", 7)) {
            // TODO: Rewrite only the port number in the alt-svc header, keep the rest
            protohttp3_delete_nv_header(s, i);

            size_t len = strlen("h3=\"\":") + strlen(conn_opts->rewrite_alt_svc_port) + strlen("; ma=86400") + 1;
			char *new_value = malloc(len);
			if (!new_value) {
				s->ctx->enomem = 1;
				return -1;
			}
			snprintf(new_value, len, "h3=\":%s\"; ma=86400", conn_opts->rewrite_alt_svc_port);

            protohttp3_add_nv_header(s, "alt-svc", strlen("alt-svc"), new_value, strlen(new_value));
            free(new_value);
        }
    }

    if (s->ctx->enomem) {
        return -1;
    }
	return 0;
}

#ifndef WITHOUT_ICAP
static struct evbuffer *
protohttp3_get_h1_headers(protohttp3_stream_ctx_t *s)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx->reqmod);

    struct evbuffer *buf = evbuffer_new();
    if (!buf)
        return NULL;

    int method_idx = -1, path_idx = -1, status_idx = -1, authority_idx = -1;

    nghttp3_nv *headers = s->headers;
    size_t count = s->headers_count;

    for (size_t i = 0; i < count; i++) {
        if (headers[i].namelen == 7 && !memcmp(headers[i].name, ":method", 7))
            method_idx = (int)i;
        else if (headers[i].namelen == 5 && !memcmp(headers[i].name, ":path", 5))
            path_idx = (int)i;
        else if (headers[i].namelen == 7 && !memcmp(headers[i].name, ":status", 7))
            status_idx = (int)i;
        else if (headers[i].namelen == 10 && !memcmp(headers[i].name, ":authority", 10))
            authority_idx = (int)i;
    }

    if (method_idx != -1) {
        // log_finest_va("method_idx=%d", method_idx);
        log_finest_va("%.*s %.*s HTTP/1.1", (int)headers[method_idx].valuelen, (char *)headers[method_idx].value,
            (path_idx != -1) ? (int)headers[path_idx].valuelen : 1, (path_idx != -1) ? (char *)headers[path_idx].value : "/");

        evbuffer_add_printf(buf, "%.*s %.*s HTTP/1.1\r\n", (int)headers[method_idx].valuelen, (char *)headers[method_idx].value,
            (path_idx != -1) ? (int)headers[path_idx].valuelen : 1, (path_idx != -1) ? (char *)headers[path_idx].value : "/");

        if (authority_idx != -1) {
            evbuffer_add_printf(buf, "Host: %.*s\r\n", (int)headers[authority_idx].valuelen, (char *)headers[authority_idx].value);
        }
    }

    if (status_idx != -1 && headers[status_idx].valuelen == 3) {
        // log_finest_va("status_idx=%d", status_idx);
        log_finest_va("HTTP/1.1 %.*s", (int)headers[status_idx].valuelen, (char *)headers[status_idx].value);

        int status_code = http_parse_status_3dig(headers[status_idx].value);
        const char *reason = http_get_reason_phrase(status_code);

        // Add the correct reason phrase, otherwise E2Guardian icap service does not respond
        evbuffer_add_printf(buf, "HTTP/1.1 %d %s\r\n", status_code, reason);
    }

    for (size_t i = 0; i < count; i++) {
        if (headers[i].name[0] == ':')
            continue;
        // Skip Host to avoid duplicates
        if (headers[i].namelen == 4 && !strncasecmp((char *)headers[i].name, "Host", 4))
            continue;
        log_finest_va("%.*s: %.*s", (int)headers[i].namelen, headers[i].name, (int)headers[i].valuelen, headers[i].value);
        evbuffer_add_printf(buf, "%.*s: %.*s\r\n", (int)headers[i].namelen, headers[i].name, (int)headers[i].valuelen, headers[i].value);
    }

    // Do not append Transfer-Encoding, otherwise we have to wait for body of GET requests too
    // see protohttp2_bev_readcb_src()
    // evbuffer_add_printf(buf, "Transfer-Encoding: chunked\r\n\r\n");

    // Add an extra CRLF to signal end of headers.
    evbuffer_add_printf(buf, "\r\n");

    return buf;
}
#endif /* !WITHOUT_ICAP */

/*
 * Called when the HEADERS block is fully decoded (analogous to H2's
 * NGHTTP2_FLAG_END_HEADERS).  This is the correct place to act on the
 * complete header set (e.g. apply filter rules, begin upstream connection).
 */
static int
h3_on_end_headers(nghttp3_conn *conn, int64_t stream_id,
                  UNUSED int fin, void *user_data,
                  UNUSED void *stream_user_data)
{
    protohttp3_ctx_t *h3_ctx = user_data;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    // TODO: Uni streams are control streams and do not carry HTTP headers, do we ever get here for uni streams?
    if (!ngtcp2_is_bidi_stream(stream_id)) {
        log_finest_va("Ignoring uni stream end headers, stream_id=%" PRId64, stream_id);
        return 0;
    }

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s) {
        log_finest_va("No stream context found for stream_id=%" PRId64, stream_id);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    // No need to set the *_end_stream flags here, because we set them in h3_on_end_stream() when the stream is actually closed
    log_finest_va("stream %" PRId64 " END_HEADERS (%zu headers, fin=%d)", stream_id, s->headers_count, fin);

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
        log_finest_va("Request headers complete, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);
        s->http_ctx->seen_req_header = 1;
    }
    else {
        log_finest_va("Response headers complete, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);
        s->http_ctx->seen_resp_header = 1;
    }

    // TODO: We get to this point only once per stream, when the headers are complete. So, do we need seen_header_on_entry?
    // int seen_header_on_entry = reqmod ? s->http_ctx->seen_req_header : s->http_ctx->seen_resp_header;

    int (*filter_header)(protohttp3_stream_ctx_t *) = reqmod ? protohttp3_filter_request_header : protohttp3_filter_response_header;
    if (filter_header(s) == -1) {
        return -1;
    }

    // TODO: Should we log when we get the response only?
    // if (!seen_header_on_entry && ((reqmod && s->http_ctx->seen_req_header) || (!reqmod && s->http_ctx->seen_resp_header))) {
    if ((reqmod && s->http_ctx->seen_req_header) || (!reqmod && s->http_ctx->seen_resp_header)) {
        /* header complete: log connection */
        if (WANT_CONNECT_LOG(ctx->conn)) {
            // TODO: Implement h3 specific logging with stream info
            protohttp_log_connect(ctx, s->http_ctx, s->log_connect);
        }
    }

#ifndef WITHOUT_ICAP
    if (icap_enabled(s->icap_ctx)) {
        s->icap_ctx->reqmod = reqmod;

        struct evbuffer *outbuf_ptr = icap_get_first_service_in_hdr(s->icap_ctx);
        struct evbuffer *header_buf = protohttp3_get_h1_headers(s);

        evbuffer_add_buffer(outbuf_ptr, header_buf);
        evbuffer_free(header_buf);

        icap_process_data(s->data_buf, s->icap_ctx);
        return 0;
    }
#endif /* !WITHOUT_ICAP */

    return protohttp3_submit_data(h3_ctx, s, reqmod);
}

/*
 * Called when raw body data is available on a stream.
 * Equivalent to nghttp2's on_data_chunk_recv_callback.
 */
static int
h3_on_recv_data(nghttp3_conn *conn, int64_t stream_id,
                const uint8_t *data, size_t datalen,
                void *user_data, UNUSED void *stream_user_data)
{
    protohttp3_ctx_t *h3_ctx = user_data;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s) {
        // Data before headers – should not normally happen
        log_finest_va("Data on unknown stream %" PRId64 ", fd=%d, reqmod=%d", stream_id, h3_ctx->dst_fd, reqmod);
        return 0;
    }

#ifdef DEBUG_PROXY
	/* Log first 400 bytes for debugging */
	size_t log_len = datalen < 400 ? datalen : 400;
	char log_buf[401];  // Stack allocation
	memcpy(log_buf, data, log_len);
	log_buf[log_len] = '\0';
	log_finest_va("DATA (first %zu bytes, orig %zu bytes): %s", log_len, datalen, log_buf);
#endif /* DEBUG_PROXY */

    evbuffer_add(s->data_buf, data, datalen);

#ifndef WITHOUT_ICAP
    if (icap_enabled(s->icap_ctx)) {
        s->icap_ctx->reqmod = reqmod;
        icap_process_data(s->data_buf, s->icap_ctx);
        return 0;
    }
#endif /* !WITHOUT_ICAP */

    // Resume nghttp3 stream so it calls h3_stream_read_data
    return protohttp3_submit_data(h3_ctx, s, reqmod);
}

/*
 * Called when the stream's DATA frames are exhausted and the FIN flag was
 * set.  Equivalent to nghttp2's on_stream_close when triggered by H3 layer.
 */
static int
h3_on_end_stream(nghttp3_conn *conn, int64_t stream_id,
                 void *user_data, UNUSED void *stream_user_data)
{
    protohttp3_ctx_t *h3_ctx = user_data;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0;

    log_finest_va("ENTER, stream_id=%" PRId64 ", reqmod=%d, fd=%d", stream_id, reqmod, h3_ctx->dst_fd);

    if (!ngtcp2_is_bidi_stream(stream_id)) {
        log_finest_va("Ignoring uni stream end, stream_id=%" PRId64, stream_id);
        return 0;
    }

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s) {
        // TODO: Is this fatal? Should we return an error code to nghttp3?
        log_fine_va("No stream context found for stream_id=%" PRId64 ", reqmod=%d, fd=%d", stream_id, reqmod, h3_ctx->dst_fd);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    if (reqmod) {
        // Extend the max stream limit for the client-facing side to allow more streams
        ngtcp2_conn_extend_max_streams_bidi(h3_ctx->src_conn, 1);

        // Update HTTP/3 layer max stream boundary
        h3_ctx->src_max_streams_bidi += 1;
        nghttp3_conn_set_max_client_streams_bidi(h3_ctx->src_h3, h3_ctx->src_max_streams_bidi);

        protohttp3_trigger_write_loop(h3_ctx, 1);

        log_finest_va("Extend max bidi stream limit by 1, src_max_streams_bidi=%lu", (unsigned long)h3_ctx->src_max_streams_bidi);

        // WAKE UP the server-facing stream in nghttp3 to signal that the stream is closed and no more data will be sent
        log_finest_va("Request stream %" PRId64 " END_STREAM", stream_id);
        s->src_end_stream = 1;

        nghttp3_conn_resume_stream(h3_ctx->dst_h3, s->dst_stream_id);

        protohttp3_trigger_write_loop(h3_ctx, 0);
    }
    else {
        // WAKE UP the client-facing stream in nghttp3 to signal that the stream is closed and no more data will be sent
        log_finest_va("Response stream %" PRId64 " END_STREAM", stream_id);
        s->dst_end_stream = 1;

        /* WAKE UP the client-facing stream in nghttp3! */
        nghttp3_conn_resume_stream(h3_ctx->src_h3, s->src_stream_id);

        protohttp3_trigger_write_loop(h3_ctx, 1);
    }

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
                    void *user_data, UNUSED void *stream_user_data)
{
    protohttp3_ctx_t *h3_ctx = user_data;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;

    // ATTENTION: h3_stream_read_data is called by the trigger function called in protohttp3_submit_data(), for proxying in either direction
    // So we use the h3_ctx->proxying flag to determine which side we are proxying, and the reqmod flag to determine if we are reading from the request or response side
    int reqmod = conn == h3_ctx->src_h3 ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, proxying=%d, fd=%d", reqmod, h3_ctx->proxying, h3_ctx->dst_fd);

    // TODO: Uni streams are control streams and do not carry HTTP data, do we ever get here for uni streams?
    if (!ngtcp2_is_bidi_stream(stream_id)) {
        log_finest_va("Ignoring uni stream data read, stream_id=%" PRId64, stream_id);
        return 0;
    }

    // TODO: Casting the stream pointer in stream_user_data does not work here
    // protohttp3_stream_ctx *s = stream_user_data;
    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s) {
        log_fine_va("No stream context found for stream_id=%" PRId64 ", reqmod=%d, fd=%d", stream_id, reqmod, h3_ctx->dst_fd);
        return NGHTTP3_ERR_CALLBACK_FAILURE;
    }

    // TODO: Do we need to check the len of s->data_buf too? But we drain it below anyway, so it should be empty after this callback.
    // Flag the end of stream
    if (evbuffer_get_length(s->data_buf) == 0) {
        log_finest_va("evbuffer_get_length(s->data_buf) == 0, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);

        if ((h3_ctx->proxying ? !reqmod : reqmod) ? s->src_end_stream : s->dst_end_stream) {
            log_finest_va("End of stream reached, set NGHTTP3_DATA_FLAG_EOF for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d",
                s->src_stream_id, s->dst_stream_id, reqmod);
#ifndef WITHOUT_ICAP
            if (s->icap_ctx && icap_enabled(s->icap_ctx) && !icap_is_finished(s->icap_ctx)) {
                log_finest_va("Do not set NGHTTP3_DATA_FLAG_EOF for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx->reqmod);
                return NGHTTP3_ERR_WOULDBLOCK;
            }
#endif /* !WITHOUT_ICAP */

            log_finest_va("Set NGHTTP3_DATA_FLAG_EOF for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
            *pflags |= NGHTTP3_DATA_FLAG_EOF;
            return 0;
        }

        /* Nothing buffered right now – tell nghttp3 to pause this stream. */
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    /* Hand the entire staging buffer as a single iovec.                   */
    if (veccnt < 1) {
        log_finest_va("veccnt < 1, reqmod=%d, fd=%d", reqmod, h3_ctx->dst_fd);
        return NGHTTP3_ERR_WOULDBLOCK;
    }

    // ATTENTION: We should have a persistent buffer for evbuffer_pullup() to survive until the data is sent or the stream is freed,
    // we drain s->data_buf below, so the pointer returned by evbuffer_pullup() will be invalid after that.
    // And vec[0].base just saves the pointer, it does not copy the data.
    // vec[0].base = evbuffer_pullup(s->data_buf, evbuffer_get_length(s->data_buf));
    // vec[0].len  = evbuffer_get_length(s->data_buf);

    if (s->body_buf) {
        free(s->body_buf);
        s->body_buf = NULL;
    }

    size_t data_len = evbuffer_get_length(s->data_buf);
    s->body_buf = malloc(data_len);
    memcpy(s->body_buf, evbuffer_pullup(s->data_buf, data_len), data_len);

    // TODO: Do we need to fill more than one vector? For now, we just fill one vector with the entire body.
    vec[0].base = s->body_buf;
    vec[0].len  = data_len;

    // TODO: Do we need to double check the *_end_stream flags here, as we already check them above?
    // But this sets the NGHTTP3_DATA_FLAG_EOF flag asap, instead of waiting for the next call to h3_stream_read_data() to set it.
    // Flag the end of stream
    if ((h3_ctx->proxying ? !reqmod : reqmod) ? s->src_end_stream : s->dst_end_stream) {
        log_finest_va("End of stream reached, set NGHTTP3_DATA_FLAG_EOF for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d",
            s->src_stream_id, s->dst_stream_id, reqmod);
#ifndef WITHOUT_ICAP
        if (s->icap_ctx && icap_enabled(s->icap_ctx) && !icap_is_finished(s->icap_ctx)) {
            log_finest_va("Do not set NGHTTP3_DATA_FLAG_EOF for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx->reqmod);
            goto out;
        }
#endif /* !WITHOUT_ICAP */

        log_finest_va("Set NGHTTP3_DATA_FLAG_EOF for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
    }
#ifndef WITHOUT_ICAP
out:
#endif /* !WITHOUT_ICAP */
    log_finest_va("stream %" PRId64 " READ, reqmod=%d, fd=%d, len=%zu", stream_id, reqmod, h3_ctx->dst_fd, data_len);

    /*
     * Drain data_buf so a second call to this callback (e.g. after a
     * WOULDBLOCK / resume cycle) does not re-submit the same data.
     * body_buf is kept alive until the stream is freed; ngtcp2 copies
     * the payload into its own packet buffer within the same flush loop
     * before we ever return here again.
     */
    evbuffer_drain(s->data_buf, data_len);

    // ATTENTION: Return the number of vectors filled, not the number of bytes placed in vec[0..*pcnt-1].
    // return s->body_len; // Number of bytes placed in vec[0..*pcnt-1]
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
 * nghttp3_conn_read_stream2() which will parse H3 frames and invoke the
 * nghttp3 callbacks above.
 */
static int
quic_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                      int64_t stream_id,
                      UNUSED uint64_t offset,
                      const uint8_t *data, size_t datalen,
                      void *user_data, UNUSED void *stream_user_data)
{
    protohttp3_ctx_t *h3_ctx = user_data;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_conn ? 1 : 0;

    log_finest_va("ENTER, reqmod=%d, fd=%d, stream_id=%" PRId64 ", datalen=%zu, flags=%x",
                  reqmod, h3_ctx->dst_fd, stream_id, datalen, flags);

    if (!ngtcp2_is_bidi_stream(stream_id)) {
        log_finest_va("Ignoring uni stream recv data, stream_id=%" PRId64, stream_id);
        return 0;
    }

    // ATTENTION: We cannot set *_end_stream flags here, because we need to wait for h3 callbacks
    int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;

    if (WANT_CONTENT_LOG(ctx)) {
        protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
        if (!s) {
            log_fine_va("No stream context found for stream_id=%" PRId64 ", reqmod=%d, fd=%d", stream_id, reqmod, h3_ctx->dst_fd);
            return NGHTTP3_ERR_CALLBACK_FAILURE;
        }

        struct evbuffer *inbuf = evbuffer_new();
        evbuffer_add(inbuf, data, datalen);
        pxy_log_content_inbuf(ctx, inbuf, reqmod, IPPROTO_UDP, s->log_content, s->log_pcap
#ifndef WITHOUT_MIRROR
            , s->log_mirror
#endif /* !WITHOUT_MIRROR */
            );
        evbuffer_free(inbuf);
    }

    /*
     * Feed the raw H3 frame bytes into nghttp3.  nghttp3 will call our
     * h3_on_recv_header / h3_on_recv_data / h3_on_end_headers / h3_on_end_stream
     * callbacks as it parses complete frames.
     */

     /* Get current timestamp in nanoseconds for nghttp3 */
    struct timeval tv;
    evutil_gettimeofday(&tv, NULL);
    nghttp3_tstamp ts = (nghttp3_tstamp)tv.tv_sec * 1000000000 + tv.tv_usec * 1000;

    /* Feed the non-zero raw H3 frame bytes into nghttp3 */
    nghttp3_ssize nread = nghttp3_conn_read_stream2(reqmod ? h3_ctx->src_h3 : h3_ctx->dst_h3, stream_id, data, datalen, fin, ts);

    if (nread < 0) {
        log_finest_va("nghttp3_conn_read_stream2 error: %s", nghttp3_strerror((int)nread));
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
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_conn ? 1 : 0;

    log_finest_va("ENTER, stream_id=%" PRId64 ", reqmod=%d, fd=%d", stream_id, reqmod, h3_ctx->dst_fd);

    if (!ngtcp2_is_bidi_stream(stream_id)) {
        /* Uni stream opened by peer.  nghttp3 will read the
         * stream type and set up its internal state.  We don't need to
         * track it in our stream ctx list.
         */
        log_finest_va("Ignoring uni stream open, stream_id=%" PRId64, stream_id);
        return 0;
    }

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (!s) {
        s = protohttp3_new_stream_ctx(h3_ctx, stream_id);
        if (!s) {
            log_finest_va("OOM for new stream %" PRId64, stream_id);
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    // Let nghttp3 know a new unidirectional stream was opened
    if (reqmod) {
        if (h3_ctx->src_h3) {
            int rv = nghttp3_conn_set_stream_user_data(h3_ctx->src_h3, stream_id, s);
            if (rv != 0 && rv != NGHTTP3_ERR_INVALID_ARGUMENT) {
                // INVALID_ARGUMENT means nghttp3 already knows this stream
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

    return 0;
}

/*
 * ngtcp2 tells us a stream was closed (STREAM_FIN or RESET_STREAM).
 * We schedule the protohttp3_stream_ctx for cleanup.
 */
static int
quic_stream_close(ngtcp2_conn *conn, UNUSED uint32_t flags,
                  int64_t stream_id, UNUSED uint64_t app_error_code,
                  void *user_data, UNUSED void *stream_user_data)
{
    protohttp3_ctx_t *h3_ctx = user_data;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    int reqmod = conn == h3_ctx->src_conn ? 1 : 0;

    log_finest_va("ENTER, stream_id=%" PRId64 ", reqmod=%d, fd=%d", stream_id, reqmod, h3_ctx->dst_fd);

    if (!ngtcp2_is_bidi_stream(stream_id)) {
        log_finest_va("Ignoring uni stream close, stream_id=%" PRId64, stream_id);
        return 0;
    }

    protohttp3_stream_ctx_t *s = protohttp3_get_stream_ctx(h3_ctx, stream_id, reqmod);
    if (s) {
#ifndef WITHOUT_ICAP
        if (icap_enabled(s->icap_ctx)) {
            if (!icap_is_finished(s->icap_ctx)) {
                log_finest_va("ICAP not finished yet, do not terminate stream, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
                if (!s->closed) {
                    log_finest_va("Set stream closed, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
                    s->closed = 1;
                }
                return 0;
            }
            else {
                log_finest_va("ICAP finished, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
            }
        }
#endif /* !WITHOUT_ICAP */

        if (!s->closed) {
            log_finest_va("Set stream closed, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
            s->closed = 1;
        } else {
            /* Second close event: ready to tear down.                     */
            log_finest_va("Stream closed before, free completely and remove, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
            s->term = 1;
            protohttp3_request_free_stream_ctx(s);
        }
    }
    else {
        log_finest_va("No stream context found for stream_id=%" PRId64 ", reqmod=%d, fd=%d", stream_id, reqmod, h3_ctx->dst_fd);
        return NGTCP2_ERR_CALLBACK_FAILURE;
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
    int reqmod = (conn == h3_ctx->src_conn);
    log_finest_va("%s QUIC handshake completed, fd=%d", reqmod ? "Client side" : "Server side", h3_ctx->dst_fd);

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

    /*
     * Bind the three mandatory H3 unidirectional control streams that we
     * own:
     *   - Control stream  (type 0x00)
     *   - QPACK encoder   (type 0x02)
     *   - QPACK decoder   (type 0x03)
     */

    if (!reqmod) {
        int rv = nghttp3_conn_client_new(&h3_ctx->dst_h3, &h3cb, &h3settings, NULL, h3_ctx);
        if (rv != 0) {
            log_finest_va("nghttp3_conn_client_new: %s", nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        if (ngtcp2_conn_open_uni_stream(conn, &h3_ctx->dst_ctrl_stream_id, NULL) != 0 ||
            ngtcp2_conn_open_uni_stream(conn, &h3_ctx->dst_qenc_stream_id, NULL) != 0 ||
            ngtcp2_conn_open_uni_stream(conn, &h3_ctx->dst_qdec_stream_id, NULL) != 0) {
            log_finest("failed to open H3 control streams");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        rv = nghttp3_conn_bind_control_stream(h3_ctx->dst_h3, h3_ctx->dst_ctrl_stream_id);
        if (rv != 0) {
            log_finest_va("bind_control_stream: %s", nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        rv = nghttp3_conn_bind_qpack_streams(h3_ctx->dst_h3, h3_ctx->dst_qenc_stream_id, h3_ctx->dst_qdec_stream_id);
        if (rv != 0) {
            log_finest_va("bind_qpack_streams: %s", nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        protohttp3_trigger_write_loop(h3_ctx, 0);

        log_finest_va("Forge server cert and resume handshake with client, fd=%d", h3_ctx->dst_fd);

        if (ctx->sslctx->alpn_protos_len > 0) {
            protossl_set_alpn_selected(h3_ctx->dst_ssl, ctx);
        }
        else {
            log_finest("Will not set ALPN protocols enabled with server, client did not provide ALPN protocols to negotiate");
        }

        // protossl_srcssl_create() forges the server cert
        h3_ctx->src_ssl = protossl_srcssl_create(ctx, h3_ctx->dst_ssl, h3_ctx->src_ssl);

        // Now we can continue with the deferred handshake
        h3_ctx->wait_server_connected = 0;

        // OpenSSL now resumes and generates ServerHello using the forged cert
        ERR_clear_error();
        rv = SSL_do_handshake(h3_ctx->src_ssl);
        if (rv <= 0) {
            int err = SSL_get_error(h3_ctx->src_ssl, rv);
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE &&
                err != SSL_ERROR_WANT_X509_LOOKUP) {
                log_finest_va("SSL_do_handshake failed after resuming cert_cb: %d", err);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
        }

        // Tell ngtcp2 to drain OpenSSL's newly generated TLS 1.3 Handshake 
        // payload (ServerHello, EncryptedExtensions, Certificate, Finished)
        // and write QUIC packets to the client socket fd.
        ngtcp2_conn_handle_expiry(h3_ctx->src_conn, h3_timestamp());

        // Flush the client socket to send the handshake payload to the client
        protohttp3_trigger_write_loop(h3_ctx, 1);
    }
    else {
        int rv = nghttp3_conn_server_new(&h3_ctx->src_h3, &h3cb, &h3settings, NULL, h3_ctx);
        if (rv != 0) {
            log_finest_va("nghttp3_conn_server_new: %s", nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        /* ATTENTION: Set max client streams from QUIC transport params so nghttp3
         * can validate stream IDs in PRIORITY_UPDATE frames. Without this,
         * max_client_streams defaults to 0, causing ERR_H3_ID_ERROR and
         * eventual assertion failure in nghttp3_conn_read_control. */

        // TODO: Should we use local or remote transport params? We are the server, so we should use the remote params from the client.
        // But the client may not have sent them yet, so we may need to wait until we receive them. For now, we use local params as a workaround.
        // const ngtcp2_transport_params *params = ngtcp2_conn_get_remote_transport_params(h3_ctx->src_conn);
        const ngtcp2_transport_params *params = ngtcp2_conn_get_local_transport_params(h3_ctx->src_conn);
        if (params) {
            h3_ctx->src_max_streams_bidi = params->initial_max_streams_bidi;
            nghttp3_conn_set_max_client_streams_bidi(h3_ctx->src_h3, h3_ctx->src_max_streams_bidi);
            log_finest_va("Initialized H3 server stream quota from QUIC transport params, src_max_streams_bidi=%lu", (unsigned long)h3_ctx->src_max_streams_bidi);

            // TODO: Do we need to set max concurrent streams too?
            // nghttp3_conn_set_max_concurrent_streams(h3_ctx->src_h3, params->initial_max_streams_bidi);
        }

        if ((rv = ngtcp2_conn_open_uni_stream(h3_ctx->src_conn, &h3_ctx->src_ctrl_stream_id, NULL)) != 0 ||
            (rv = ngtcp2_conn_open_uni_stream(h3_ctx->src_conn, &h3_ctx->src_qenc_stream_id, NULL)) != 0 ||
            (rv = ngtcp2_conn_open_uni_stream(h3_ctx->src_conn, &h3_ctx->src_qdec_stream_id, NULL)) != 0) {
            log_finest_va("failed to open H3 control streams: %s", nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        log_finest_va("Successfully opened H3 control streams, h3_ctx->src_ctrl_stream_id=%" PRId64 " h3_ctx->src_qenc_stream_id=%" PRId64 " h3_ctx->src_qdec_stream_id=%" PRId64,
                      h3_ctx->src_ctrl_stream_id, h3_ctx->src_qenc_stream_id, h3_ctx->src_qdec_stream_id);

        rv = nghttp3_conn_bind_control_stream(h3_ctx->src_h3, h3_ctx->src_ctrl_stream_id);
        if (rv != 0) {
            log_finest_va("bind_control_stream: %s", nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        rv = nghttp3_conn_bind_qpack_streams(h3_ctx->src_h3, h3_ctx->src_qenc_stream_id, h3_ctx->src_qdec_stream_id);
        if (rv != 0) {
            log_finest_va("bind_qpack_streams: %s", nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        protohttp3_trigger_write_loop(h3_ctx, 1);

        // The connected flag does not seem useful with h3, but we set for completeness
        ctx->connected = 1;
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

    // Ancillary data buffer large enough for IP_PKTINFO + ECN.           */
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

    // Walk ancillary control messages
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {

        // IPv4 destination address + ECN.
        if (cmsg->cmsg_level == IPPROTO_IP) {
#ifdef IP_TOS
            if (cmsg->cmsg_type == IP_TOS) {
                *ecn = *(int *)CMSG_DATA(cmsg) & 0x03;
            }
#endif
        }

        // IPv6 destination address + ECN.
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
protohttp3_close_stream(protohttp3_stream_ctx_t *s)
{
    pxy_conn_ctx_t *ctx = s->ctx;
    protohttp3_ctx_t *h3_ctx = ctx->protoctx->arg;
    log_finest_va("Close src stream, stream_id=%" PRId64 ", fd=%d", s->src_stream_id, h3_ctx->dst_fd);

    /* Tell nghttp3 the stream is closed locally */
    nghttp3_conn_close_stream(h3_ctx->src_h3, s->src_stream_id, NGHTTP3_H3_REQUEST_CANCELLED);

    /* Instruct ngtcp2 (QUIC layer) to immediately reset transmission on QUIC stream */
    ngtcp2_conn_shutdown_stream_write(h3_ctx->src_conn, 0, s->src_stream_id, NGHTTP3_H3_REQUEST_CANCELLED);

    /* Tell the client to stop sending any remaining request body */
    ngtcp2_conn_shutdown_stream_read(h3_ctx->src_conn, 0, s->src_stream_id, NGHTTP3_H3_REQUEST_CANCELLED);

    // TODO: Should we or can we flush the stream buffers after the shutdown calls above?
    // protohttp3_trigger_write_loop(h3_ctx, 1);

    // ATTENTION: Do not free the stream here, otherwise Brave hangs
    // s->ref_count++;
    // protohttp3_request_free_stream_ctx(s);
    // s->ref_count--;
}

#ifdef DEBUG_PROXY
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
#endif /* DEBUG_PROXY */

/* =========================================================================
 * Libevent callbacks for the raw UDP fds
 * ====================================================================== */

/*
 * Fired when the UDP socket is writable again after a previous sendmsg()
 * returned EAGAIN.  We just re-enter the write flush loop.
 */
static void
protohttp3_src_write_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
    protohttp3_ctx_t *h3_ctx = arg;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
    log_finest("ENTER");
    protohttp3_trigger_write_loop(h3_ctx, 1);
}

static void
protohttp3_dst_read_cb(evutil_socket_t fd, UNUSED short what, void *arg)
{
    protohttp3_ctx_t *h3_ctx = arg;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
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
    ctx->thr->extif_in_bytes += n;

#ifdef DEBUG_PROXY
    protohttp3_debug_print_addr(&peer_addr, "pkt dst_peer_addr");
#endif /* DEBUG_PROXY */

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
        if (rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_DROP_CONN) {
            // TODO: pxy_conn_term() set the term flag only, do as TCP proxyspecs do
            pxy_conn_term(h3_ctx->ctx, 1);
        }
        return;
    }

    protohttp3_trigger_write_loop(h3_ctx, 0);
}

static void
protohttp3_dst_write_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
    protohttp3_ctx_t *h3_ctx = arg;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
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
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
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
        if (rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_DROP_CONN) {
            pxy_conn_term(ctx, 1);
        }
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

/*
 * Process a raw UDP datagram through an existing QUIC session.
 * Called by the packet demuxer when a session is found in the hash table.
 * Returns 0 on success, -1 on error.
 */
void
protohttp3_process_packet_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
    protohttp3_ctx_t *h3_ctx = arg;
    UNUSED pxy_conn_ctx_t *ctx = h3_ctx->ctx;
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

#ifdef DEBUG_PROXY
    protohttp3_debug_print_addr(&h3_ctx->ctx->srcaddr, "src_peer_addr");
    protohttp3_debug_print_addr(&h3_ctx->ctx->spec->listen_addr, "src_local_addr");
#endif /* DEBUG_PROXY */

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
            if (rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_DROP_CONN) {
                pxy_conn_term(h3_ctx->ctx, 1);
            }
            return;
        }
    }

    log_finest_va("Processed total of %d packets and %zu bytes", pkt_count, total_bytes_processed);
    ctx->thr->intif_in_bytes += total_bytes_processed;

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

#ifdef DEBUG_PROXY
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
#endif /* DEBUG_PROXY */

/*
 * We need the SNI and ALPN protos from the client's ClientHello before we can connect to the server.
 * But we also need the server cert and forge it, before we can continue with the TLS handshake with the client.
 * We break this deadlock by this quic_client_hello_cb() and then suspending and deferring the TLS handshake with the client,
 * until we have connected to the server and obtained and forged its cert.
 * See quic_handshake_completed() for where we resume the TLS handshake with the client.
 */
static int
quic_client_hello_cb(SSL *ssl, UNUSED int *al, void *arg)
{
    protohttp3_ctx_t *h3_ctx = (protohttp3_ctx_t *)arg;
    pxy_conn_ctx_t *ctx = h3_ctx->ctx;

    log_finest("ENTER");

    // SSL_get_servername() and SSL_get0_alpn_selected() may not return the SNI and ALPN values at this point in the handshake,
    // so we get them from quic_sni_cert_cb() instead.
    const unsigned char *alpn_list = NULL;
    size_t alpn_list_len = 0;

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_application_layer_protocol_negotiation, &alpn_list, &alpn_list_len) == 1) {
        log_finest_va("Found ALPN protos in ClientHello, alpn_list_len=%zu", alpn_list_len);
        if (alpn_list_len >= 2) {
            uint16_t list_len = (alpn_list[0] << 8) | alpn_list[1];

            /* Sanity check outer list length */
            if ((size_t)(list_len + 2) <= alpn_list_len) {
                if (ctx->sslctx->alpn_protos) {
                    log_finest_va("Overwriting ALPN protos: %s", ssl_wire_to_printable(ctx->sslctx->alpn_protos, ctx->sslctx->alpn_protos_len));
                    free((void *)ctx->sslctx->alpn_protos);
                }
                ctx->sslctx->alpn_protos = malloc(list_len);
                ctx->sslctx->alpn_protos_len = list_len;
                /* Skip the 2-byte header to get to the vector of length-prefixed strings */
                memcpy(ctx->sslctx->alpn_protos, alpn_list + 2, list_len);

                log_finest_va("ALPN protos in ClientHello: %s", ssl_wire_to_printable(ctx->sslctx->alpn_protos, ctx->sslctx->alpn_protos_len));
            }
        }
    }
    else {
        log_finest("Cannot find ALPN protos in ClientHello");
    }

    const unsigned char *sni = NULL;
    size_t sni_len = 0;

    if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &sni, &sni_len)) {
        log_finest_va("Found SNI in ClientHello, sni_len=%zu", sni_len);
        /* Minimum valid SNI extension payload length: 
        * 2 (list len) + 1 (type) + 2 (name len) + at least 1 byte name = 6 bytes */
        if (sni_len >= 5) {
            uint16_t list_len = (sni[0] << 8) | sni[1];

            /* Sanity check outer list length */
            if ((size_t)(list_len + 2) <= sni_len) {
                uint8_t name_type = sni[2];
                uint16_t name_len = (sni[3] << 8) | sni[4];

                /* TLSEXT_NAMETYPE_host_name is 0 */
                if (name_type == TLSEXT_NAMETYPE_host_name && (size_t)(name_len + 5) <= sni_len) {
                    if (ctx->sslctx->sni) {
                        log_finest_va("Overwriting SNI: %s", ctx->sslctx->sni);
                        free(ctx->sslctx->sni);
                    }

                    /* Hostname string starts at offset sni + 5 */
                    ctx->sslctx->sni = strndup((const char *)(sni + 5), name_len);

                    log_finest_va("Extracted SNI from ClientHello: %s", ctx->sslctx->sni);
                }
            }
        }
    } else {
        log_finest("Cannot find SNI in ClientHello");
    }

    // Now that we have the SNI and ALPN protos, we can proceed to connect to the server
    h3_ctx->wait_server_connected = 1;
    pxy_conn_connect(ctx);

    // ATTENTION: Return -1 so OpenSSL pauses handshake
    return -1;
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

	ctx->protoctx->arg = h3_ctx;

    // TODO: Do we need these stream IDs? They are not useful in the current implementation.
    h3_ctx->src_ctrl_stream_id = -1;
    h3_ctx->src_qenc_stream_id = -1;
    h3_ctx->src_qdec_stream_id = -1;
    h3_ctx->dst_ctrl_stream_id = -1;
    h3_ctx->dst_qenc_stream_id = -1;
    h3_ctx->dst_qdec_stream_id = -1;

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

#ifdef DEBUG_PROXY
    settings.log_printf = debug_log_src;
#endif /* DEBUG_PROXY */

    int rv = ngtcp2_conn_server_new(&h3_ctx->src_conn, &initial_dcid, &initial_scid, &h3_ctx->src_path,
                                    NGTCP2_PROTO_VER_V1, &cb, &settings,
                                    &params, NULL, h3_ctx);
    if (rv != 0) {
        log_finest_va("Failed to create ngtcp2_conn_server_new: %s", ngtcp2_strerror(rv));
        goto err;
    }

    // TODO: Set params for server only, to update params, otherwise ngtcp2_conn_server_new() already sets them
    // ngtcp2_conn_set_local_transport_params(h3_ctx->src_conn, &params);

    /* ------------------------------------------------------------------
     * TLS OpenSSL setup (src side).
     * ------------------------------------------------------------------ */
    /* Note: For SSLproxy, we derive the SSL_CTX from the proxyspec.
     * We'll use a local TLS method block for minimal initialization. */
    SSL_CTX *sslctx = SSL_CTX_new(TLS_method());

    // QUIC requires TLS 1.3
    SSL_CTX_set_min_proto_version(sslctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);

    SSL_CTX_set_client_hello_cb(sslctx, quic_client_hello_cb, h3_ctx);

    // We will set the alpn_select_cb when we create a new SSL_CTX and replace the one here,
    // after completing the TLS handshake with the server and forging the server cert
    // SSL_CTX_set_alpn_select_cb(sslctx, protossl_alpn_select_cb, ctx);

    // ATTENTION: We do not load a cert/key here, because we will forge the server cert

#if OPENSSL_VERSION_NUMBER >= 0x10101000L && !defined(LIBRESSL_VERSION_NUMBER)
	if (ctx->global->masterkeylog) {
		SSL_CTX_set_keylog_callback(sslctx, protossl_keylog_callback);
	}
#endif

    h3_ctx->src_ssl = SSL_new(sslctx);

    SSL_set_accept_state(h3_ctx->src_ssl);

    ngtcp2_crypto_ossl_configure_server_session(h3_ctx->src_ssl);

    h3_ctx->src_conn_ref.get_conn = get_src_conn;
    h3_ctx->src_conn_ref.user_data = h3_ctx;
    SSL_set_app_data(h3_ctx->src_ssl, &h3_ctx->src_conn_ref);

    h3_ctx->src_ossl_ctx = NULL;
    if (ngtcp2_crypto_ossl_ctx_new(&h3_ctx->src_ossl_ctx, h3_ctx->src_ssl) != 0) {
        log_finest("Failed to create ngtcp2_crypto_ossl_ctx");
        goto err;
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
err:
    protohttp3_free(h3_ctx);
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
    log_finest_va("ENTER, ctx->fd=%d", ctx->fd);

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

	ctx->sslctx = malloc(sizeof(ssl_ctx_t));
	if (!ctx->sslctx) {
		return PROTO_ERROR;
	}
	memset(ctx->sslctx, 0, sizeof(ssl_ctx_t));

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

// No need to check for OPENSSL_NO_TLSEXT here, since h3 requires ALPN and TLS 1.3,
// which are not available if OPENSSL_NO_TLSEXT is defined.
// #ifdef OPENSSL_NO_TLSEXT
// 	pxy_conn_connect(ctx);
// 	return;
// #endif /* !OPENSSL_NO_TLSEXT */

    // We create the h3 context in proxy_listener_acceptcb_udp()
    protohttp3_ctx_t *h3_ctx = ctx->protoctx->arg;

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
    log_finest("ENTER");

    protohttp3_ctx_t *h3_ctx = ctx->protoctx->arg;
    if (!h3_ctx || !h3_ctx->src_conn) {
        log_fine("No src session");
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

#ifdef DEBUG_PROXY
    protohttp3_debug_print_addr((struct sockaddr_storage *)h3_ctx->dst_path.remote.addr, "dst_path.remote");
    protohttp3_debug_print_addr((struct sockaddr_storage *)h3_ctx->dst_path.local.addr, "dst_path.local");
#endif /* DEBUG_PROXY */

#ifdef DEBUG_PROXY
    settings.log_printf = debug_log_dst;
#endif /* DEBUG_PROXY */

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

    // TODO: QUIC requires TLS 1.3
    // SSL_CTX_set_min_proto_version(sslctx, TLS1_3_VERSION);
    // SSL_CTX_set_max_proto_version(sslctx, TLS1_3_VERSION);

	h3_ctx->dst_ssl = protossl_dstssl_create(ctx);

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

    log_finest_va("Upstream connection configured to dst_fd=%d", dst_fd);

    if (pxy_prepare_logging(ctx) == -1) {
        goto err;
    }

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
    log_finest("ENTER");
    protohttp3_ctx_t *h3_ctx = ctx->protoctx->arg;
    if (h3_ctx) {
        protohttp3_free(h3_ctx);
    }
}

static void
protohttp3_ssl_shutdown(pxy_conn_ctx_t *ctx, SSL *ssl)
{
	SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
	SSL_shutdown(ssl);

	if (OPTS_DEBUG(ctx->global)) {
		char *str = ssl_ssl_state_to_str(ssl, "SSL_free() in state ", 1);
		if (str)
			log_dbg_print_free(str);
	}
#ifdef DEBUG_PROXY
	char *str = ssl_ssl_state_to_str(ssl, "SSL_free() in state ", 0);
	if (str) {
		log_finer_va("fd=%d, %s", ctx->fd, str);
		free(str);
	}
#endif /* DEBUG_PROXY */

	SSL_free(ssl);
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
    log_finest("ENTER");

    if (h3_ctx->src_ossl_ctx) {
        ngtcp2_crypto_ossl_ctx_del(h3_ctx->src_ossl_ctx);
        h3_ctx->src_ossl_ctx = NULL;
    }
    protohttp3_ssl_shutdown(ctx, h3_ctx->src_ssl);

    if (h3_ctx->dst_ossl_ctx) {
        ngtcp2_crypto_ossl_ctx_del(h3_ctx->dst_ossl_ctx);
        h3_ctx->dst_ossl_ctx = NULL;
    }
    protohttp3_ssl_shutdown(ctx, h3_ctx->dst_ssl);

    // Stop all Libevent events first so no more callbacks fire
    if (h3_ctx->src_wev)  { event_del(h3_ctx->src_wev);  event_free(h3_ctx->src_wev);  }
    if (h3_ctx->dst_rev)  { event_del(h3_ctx->dst_rev);  event_free(h3_ctx->dst_rev);  }
    if (h3_ctx->dst_wev)  { event_del(h3_ctx->dst_wev);  event_free(h3_ctx->dst_wev);  }
    if (h3_ctx->timer_ev) { event_del(h3_ctx->timer_ev); event_free(h3_ctx->timer_ev); }
    if (h3_ctx->src_process_pkt_ev) { event_del(h3_ctx->src_process_pkt_ev); event_free(h3_ctx->src_process_pkt_ev); }

    // Destroy nghttp3 sessions
    if (h3_ctx->src_h3) { nghttp3_conn_del(h3_ctx->src_h3); h3_ctx->src_h3 = NULL; }
    if (h3_ctx->dst_h3) { nghttp3_conn_del(h3_ctx->dst_h3); h3_ctx->dst_h3 = NULL; }

    /* Destroy ngtcp2 connections.                                         */
    if (h3_ctx->src_conn) { ngtcp2_conn_del(h3_ctx->src_conn); h3_ctx->src_conn = NULL; }
    if (h3_ctx->dst_conn) { ngtcp2_conn_del(h3_ctx->dst_conn); h3_ctx->dst_conn = NULL; }

    // Free all stream contexts
    while (h3_ctx->streams)
        protohttp3_free_stream_ctx(h3_ctx->streams);

    // Remove from session hash table if present
    if (h3_ctx->h3_sessions) {
        h3_session_map_remove((h3_session_map_t *)h3_ctx->h3_sessions, &h3_ctx->key);
        h3_ctx->h3_sessions = NULL;
    }

    // Close raw UDP sockets
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
    ctx->protoctx->arg = NULL;
}

#endif /* !WITHOUT_HTTP3 */

typedef int dummy_declaration_to_avoid_empty_translation_unit;

/* vim: set noet ft=c: */
