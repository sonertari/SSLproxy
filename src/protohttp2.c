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

#include "protohttp.h"
#include "protohttp2.h"
#include "prototcp.h"
#include "protossl.h"
#include "pxyconn.h"
#include "util.h"

#include <event2/bufferevent.h>
#include <nghttp2/nghttp2.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>

static ssize_t
protohttp2_provider_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
    uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
static void protohttp2_trigger_write_loop(protohttp2_ctx_t *h2_ctx, int reqmod);

static protohttp2_stream_ctx_t *
protohttp2_get_stream_ctx(protohttp2_ctx_t *h2_ctx, int32_t stream_id, int reqmod)
{
    UNUSED pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    protohttp2_stream_ctx_t *s = h2_ctx->streams;
    while (s) {
        if (reqmod ? s->src_stream_id == stream_id : s->dst_stream_id == stream_id)
            return s;
        s = s->next;
    }

    log_finest_va("Cannot find stream context for stream_id=%d, reqmod=%d", stream_id, reqmod);
    return NULL;
}

static protohttp2_stream_ctx_t *
protohttp2_new_stream_ctx(protohttp2_ctx_t *h2_ctx, int32_t stream_id)
{
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    log_finest_va("ENTER, stream_id=%d", stream_id);
    protohttp2_stream_ctx_t *s = malloc(sizeof(protohttp2_stream_ctx_t));
    if (!s)
        return NULL;
    memset(s, 0, sizeof(protohttp2_stream_ctx_t));

    // New streams are always reqmod streams, so we set src_stream_id here
    // The dst_stream_id will be assigned by nghttp2 when the request header is first sent to the destination
    s->src_stream_id = stream_id;
    s->ctx = ctx;
    s->data_buf = evbuffer_new();

    // Set up the data provider hook
    s->provider.source.ptr = s;
    s->provider.read_callback = protohttp2_provider_read_callback;

    s->http_ctx = malloc(sizeof(protohttp_ctx_t));
	if (!s->http_ctx) {
        evbuffer_free(s->data_buf);
        free(s);
		return NULL;
	}
	memset(s->http_ctx, 0, sizeof(protohttp_ctx_t));

	s->http_ctx->ctx = ctx;

#ifndef WITHOUT_ICAP
    s->icap_ctx = icap_init(ctx, (protohttpx_stream_ctx_t *)s, h2_ctx, ctx->conn_opts->icap_chain);
	if (!s->icap_ctx) {
        evbuffer_free(s->data_buf);
        free(s->http_ctx);
        free(s);
		return NULL;
    }
#endif /* !WITHOUT_ICAP */

    s->next = h2_ctx->streams;
    h2_ctx->streams = s;
    return s;
}

void NONNULL(1)
protohttp2_free_stream_ctx(protohttp2_stream_ctx_t *s)
{
    pxy_conn_ctx_t *ctx = s->ctx;
    protohttp2_ctx_t *h2_ctx = ctx->protoctx->arg;
#ifndef WITHOUT_ICAP
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx ? s->icap_ctx->reqmod : -1);
#else /* !WITHOUT_ICAP */
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 "", s->src_stream_id, s->dst_stream_id);
#endif /* !WITHOUT_ICAP */

    if (s->ev_free) {
        event_free(s->ev_free);
        s->ev_free = NULL;
    }

    if (s->headers) {
        protohttpx_free_nv_headers((protohttpx_stream_ctx_t *)s);
    }

    if (s->data_buf) {
        evbuffer_free(s->data_buf);
        s->data_buf = NULL;
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

    if (h2_ctx->streams == s) {
        h2_ctx->streams = s->next;
    } else {
        protohttp2_stream_ctx_t *prev = h2_ctx->streams;
        while (prev && prev->next != s) prev = prev->next;
        if (prev) prev->next = s->next;
    }

    free(s);
}

static void
protohttp2_deferred_free_stream_ctx_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
    protohttp2_stream_ctx_t *s = arg;
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("Execute deferred free of stream_ctx, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);

    // Perform the actual, complete teardown
    protohttp2_free_stream_ctx(s);
}

void
protohttp2_request_free_stream_ctx(protohttp2_stream_ctx_t *s)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;

    if (s->ref_count > 0) {
        // We are currently processing this stream higher up on the stack!
        if (s->deferred_free_pending) {
            log_finest_va("Stream is already deferred for stream_ctx free, return, src_stream_id=%" PRId64 " dst_stream_id=%" PRId64 ", ref_count=%d",
                          s->src_stream_id, s->dst_stream_id, s->ref_count);
            return;
        }

        log_finest_va("Stream is being used, defer stream_ctx free, src_stream_id=%" PRId64 " dst_stream_id=%" PRId64 ", ref_count=%d",
                      s->src_stream_id, s->dst_stream_id, s->ref_count);

        s->deferred_free_pending = 1;

        // Schedule the free on the event loop (0s timeout)
        s->ev_free = event_new(ctx->thr->evbase, -1, 0, protohttp2_deferred_free_stream_ctx_cb, s);
		if (!s->ev_free) {
			log_fine_va("Error creating deferred free event for stream_ctx, src_stream_id=%" PRId64 " dst_stream_id=%" PRId64 "", s->src_stream_id, s->dst_stream_id);
			return;
		}

		// Do not immediately dispatch with event_active(),
		// instead use a zero timeout to prevent reentrant callback issues
		struct timeval tv = {0, 0};
		if (event_add(s->ev_free, &tv) == -1) {
			log_fine_va("Error adding deferred free event for stream_ctx, src_stream_id=%" PRId64 " dst_stream_id=%" PRId64 "", s->src_stream_id, s->dst_stream_id);
			event_free(s->ev_free);
			s->ev_free = NULL;
		}
        return;
    }

    log_finest_va("Stream is safe to destroy, free immediately, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", ref_count=%d",
                    s->src_stream_id, s->dst_stream_id, s->ref_count);
    protohttp2_free_stream_ctx(s);
}

void
protohttp2_close_stream(protohttp2_stream_ctx_t *s)
{
    pxy_conn_ctx_t *ctx = s->ctx;
    protohttp2_ctx_t *h2_ctx = ctx->protoctx->arg;
    log_finest_va("Close src stream, src_stream_id=%" PRId64 " dst_stream_id=%" PRId64 "", s->src_stream_id, s->dst_stream_id);

    /* Send an H2 RST_STREAM frame to the client */
    // We send NGHTTP2_CANCEL, because if we send the NGHTTP2_REFUSED_STREAM errorcode, curl tries 4 more times.
    nghttp2_submit_rst_stream(h2_ctx->src_session, NGHTTP2_FLAG_NONE, s->src_stream_id, NGHTTP2_CANCEL);

    /* Flush outbound H2 buffer to send the RST_STREAM frame down the socket */
    protohttp2_trigger_write_loop(h2_ctx, 1);

    // ATTENTION: Do not free the stream here, otherwise Brave hangs
    // s->ref_count++;
    // protohttp2_request_free_stream_ctx(s);
    // s->ref_count--;
}

static void NONNULL(1, 2)
protohttp2_bev_writecb(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
    pxy_conn_ctx_t *ctx = arg;
    log_finest("ENTER");

    protohttp2_ctx_t *h2_ctx = ctx->protoctx->arg;

    // Always call nghttp2_session_send() to flush any remaining data in the session's output buffer
    nghttp2_session_send(h2_ctx->src_session);

    // ATTENTION: Triggering the write loop here is necessary to ensure that any pending data in the nghttp2 session is flushed out to the underlying bufferevent.
    // This is especially important when dealing with HTTP/2 streams, as the protocol requires proper framing and flow control.
    // By calling protohttp2_trigger_write_loop, we ensure that the nghttp2 session processes any queued frames and sends them out through the appropriate bufferevent (either src or dst).
    protohttp2_trigger_write_loop(h2_ctx, 0);

    nghttp2_session_send(h2_ctx->dst_session);
    protohttp2_trigger_write_loop(h2_ctx, 1);
}

static ssize_t
protohttp2_send_callback_src(UNUSED nghttp2_session *session, const uint8_t *data, size_t length, UNUSED int flags, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = user_data;
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest("ENTER");

    if (ctx->src.bev == NULL) {
        log_finest("No src.bev to send data");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (bufferevent_write(ctx->src.bev, data, length) == -1)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return (ssize_t)length;
}

static ssize_t
protohttp2_send_callback_dst(UNUSED nghttp2_session *session, const uint8_t *data, size_t length, UNUSED int flags, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest("ENTER");

    if (ctx->dst.bev == NULL) {
        log_finest("No dst.bev to send data");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    if (bufferevent_write(ctx->dst.bev, data, length) == -1)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return (ssize_t)length;
}

static int
protohttp2_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
    const uint8_t *value, size_t valuelen, UNUSED uint8_t flags, void *user_data)
{
    // ATTENTION: NGHTTP2_FLAG_END_HEADERS is never set on the on_header_callback,
    // it is only set on the on_frame_recv_callback when the entire frame has been received.
    // That's why we filter and process the headers in the on_frame_recv_callback.
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;
    UNUSED pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    log_finest_va("ENTER, stream_id=%d, session=%s", frame->hd.stream_id, session == h2_ctx->src_session ? "src" : "dst");

    int reqmod = (session == h2_ctx->src_session) ? 1 : 0;

    protohttp2_stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id, reqmod);
    if (!s) {
        s = protohttp2_new_stream_ctx(h2_ctx, frame->hd.stream_id);
        if (!s) {
            log_fine_va("Failed to create new stream context for stream_id=%d", frame->hd.stream_id);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    if (protohttpx_add_nv_header((protohttpx_stream_ctx_t *)s, (const char *)name, namelen, (const char *)value, valuelen) < 0) {
        log_fine_va("Failed to add header for stream_id=%d: %.*s=%.*s", frame->hd.stream_id, (int)namelen, name, (int)valuelen, value);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static void
protohttp2_trigger_write_loop(protohttp2_ctx_t *h2_ctx, int reqmod)
{
    const uint8_t *binary_payload;

    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest_va("ENTER, reqmod=%d", reqmod);

    // ATTENTION: The other side of the connection (client or server) is the session for sending data
    nghttp2_session *session = reqmod ? h2_ctx->dst_session : h2_ctx->src_session;
    struct bufferevent *bev = reqmod ? ctx->dst.bev : ctx->src.bev;

    if (bev == NULL) {
        log_finest_va("No %s.bev to send data", reqmod ? "dst" : "src");
        return;
    }

    // Ask nghttp2 to serialize the pending header queue into a raw byte stream
    ssize_t payload_len = nghttp2_session_mem_send(session, &binary_payload);

    while (payload_len > 0) {
        // Write the raw binary frames directly into the bufferevent
        bufferevent_write(bev, binary_payload, payload_len);
        // struct evbuffer *outbuf = bufferevent_get_output(bev);
        // evbuffer_add(outbuf, binary_payload, payload_len);

        // Check if there is more data waiting in the memory queue loop
        payload_len = nghttp2_session_mem_send(session, &binary_payload);
    }
}

static ssize_t
protohttp2_provider_read_callback(UNUSED nghttp2_session *session, UNUSED int32_t stream_id,
    uint8_t *buf, size_t length, UNUSED uint32_t *data_flags, // data_flags is UNUSED if WITHOUT_ICAP is set
    nghttp2_data_source *source, UNUSED void *user_data)
{
    protohttp2_stream_ctx_t *s = source->ptr;
    size_t available = evbuffer_get_length(s->data_buf);

    if (available == 0) {
        // No data ready right now. Tell nghttp2 to pause writing DATA frames
        // for this stream until we explicitly resume it.
        return NGHTTP2_ERR_DEFERRED;
    }

    // Read only up to what nghttp2 can fit or what we have
    size_t to_read = (available < length) ? available : length;
    evbuffer_remove(s->data_buf, buf, to_read);

#ifndef WITHOUT_ICAP
    // TODO: Do we need to set NGHTTP2_DATA_FLAG_EOF when icap is disabled too? But how to know the end of stream in that case?
    // Flag the end of stream
    if (evbuffer_get_length(s->data_buf) == 0 && icap_enabled(s->icap_ctx) && icap_is_finished(s->icap_ctx)) {
        protohttp2_ctx_t *h2_ctx = s->icap_ctx->hx_ctx;
        UNUSED pxy_conn_ctx_t *ctx = h2_ctx->ctx;
        log_finest_va("Set NGHTTP2_DATA_FLAG_EOF for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx->reqmod);

        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
#endif /* !WITHOUT_ICAP */

    return to_read;
}

static int
protohttp2_submit_data(protohttp2_ctx_t *h2_ctx, protohttp2_stream_ctx_t *s, int reqmod)
{
    UNUSED pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    int rv = 0;

    if (s->headers_count > 0) {
        log_finest_va("Submit headers, headers_count=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->headers_count, s->src_stream_id, s->dst_stream_id, reqmod);

        if (reqmod) {
            rv = nghttp2_submit_request(h2_ctx->dst_session, NULL, s->headers, s->headers_count, &s->provider, h2_ctx);
            if (rv < 0) {
                log_finest_va("Fatal: nghttp2_submit_request failed: %s", nghttp2_strerror(rv));
                return -1;
            }

            // Set the stream id assigned by nghttp2 for the destination session
            s->dst_stream_id = rv;
        }
        else {
            rv = nghttp2_submit_response(h2_ctx->src_session, s->src_stream_id, s->headers, s->headers_count, &s->provider);
            if (rv < 0) {
                log_finest_va("Fatal: nghttp2_submit_response failed: %s", nghttp2_strerror(rv));
                return -1;
            }
        }
        protohttpx_free_nv_headers((protohttpx_stream_ctx_t *)s);

#ifndef WITHOUT_ICAP
        if (s->icap_ctx) {
            s->icap_ctx->made_progress = 1;
        }
#endif /* !WITHOUT_ICAP */
    }

    if (evbuffer_get_length(s->data_buf) > 0) {
        log_finest_va("Submit data, data_len=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", evbuffer_get_length(s->data_buf), s->src_stream_id, s->dst_stream_id, reqmod);

        rv = nghttp2_session_resume_data(reqmod ? h2_ctx->dst_session : h2_ctx->src_session, reqmod ? s->dst_stream_id : s->src_stream_id);

        if (rv == NGHTTP2_ERR_INVALID_ARGUMENT) {
            // Clean operational bypass: The engine is already active and polling
            log_finest_va("Stream already active, continuing to explicit write execution, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 "", s->src_stream_id, s->dst_stream_id);
        }
        else if (rv < 0) {
            log_finest_va("Fatal: nghttp2_session_resume_data failed: %s", nghttp2_strerror(rv));
            return -1;
        }

#ifndef WITHOUT_ICAP
        if (s->icap_ctx) {
            s->icap_ctx->made_progress = 1;
        }
#endif /* !WITHOUT_ICAP */
    }

    // Clean Data Wakeup Flush
    log_finest_va("Executing scheduled session frame serialization loop for stream, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
    protohttp2_trigger_write_loop(h2_ctx, reqmod);

    return 0;
}

#ifndef WITHOUT_ICAP
void NONNULL(1)
protohttp2_icap_send_data_to_src_cb(icap_ctx_t *icap_ctx)
{
    protohttp2_stream_ctx_t *s = (protohttp2_stream_ctx_t *)icap_ctx->stream_ctx;
    protohttp2_ctx_t *h2_ctx = icap_ctx->hx_ctx;
    UNUSED pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", veto_hdr=%zu, veto_body=%zu, data_buf=%zu", s->src_stream_id, s->dst_stream_id,
        evbuffer_get_length(icap_ctx->veto_hdr), evbuffer_get_length(icap_ctx->veto_body), evbuffer_get_length(s->data_buf));

    if (protohttpx_get_hx_headers((protohttpx_stream_ctx_t *)s, icap_ctx->veto_hdr, 1) < 0) {
        log_finest_va("Failed to add veto headers for src_stream_id=%" PRId64 "", s->src_stream_id);
        return;
    }

    evbuffer_add_buffer(s->data_buf, icap_ctx->veto_body);

    // Send block page to src (client), not dst (server)
    if (protohttp2_submit_data(h2_ctx, s, 0 /*respmod*/) < 0) {
        log_finest_va("Failed to submit data for src_stream_id=%" PRId64 "", s->src_stream_id);
        return;
    }
}

void NONNULL(1)
protohttp2_icap_send_data_to_dst_cb(icap_ctx_t *icap_ctx)
{
    protohttp2_stream_ctx_t *s = (protohttp2_stream_ctx_t *)icap_ctx->stream_ctx;
    if (!s) {
		// log_dbg_printf("protohttp2_icap_send_data_to_dst_cb: No stream context\n");
        return;
    }

    protohttp2_ctx_t *h2_ctx = icap_ctx->hx_ctx;
    UNUSED pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    struct evbuffer *out_hdr = icap_get_last_service_out_hdr(icap_ctx);
    if (protohttpx_get_hx_headers((protohttpx_stream_ctx_t *)s, out_hdr, 1) < 0) {
        log_finest_va("Failed to add out headers for src_stream_id=%" PRId64 "", s->src_stream_id);
        return;
    }

    struct evbuffer *out_body = icap_get_last_service_out_body(icap_ctx);
    evbuffer_add_buffer(s->data_buf, out_body);

    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", data_buf=%zu", s->src_stream_id, s->dst_stream_id, evbuffer_get_length(s->data_buf));

    if (protohttp2_submit_data(h2_ctx, s, icap_ctx->reqmod) < 0) {
        log_finest_va("Failed to submit data, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, icap_ctx->reqmod);
        return;
    }

    if (icap_enabled(s->icap_ctx) && icap_is_finished(s->icap_ctx) && s->closed) {
        log_finest_va("ICAP finished and stream closed, send RST_STREAM, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, icap_ctx->reqmod);
        nghttp2_submit_rst_stream(icap_ctx->reqmod ? h2_ctx->dst_session : h2_ctx->src_session, NGHTTP2_FLAG_NONE, icap_ctx->reqmod ? s->dst_stream_id : s->src_stream_id, NGHTTP2_NO_ERROR);
        nghttp2_session_send(icap_ctx->reqmod ? h2_ctx->dst_session : h2_ctx->src_session);
    }
}

void NONNULL(1)
protohttp2_icap_failopen_to_dest_cb(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
    protohttp2_stream_ctx_t *s = (protohttp2_stream_ctx_t *)icap_ctx->stream_ctx;

    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d, headers_count=%zu, data_buf=%zu", s->src_stream_id, s->dst_stream_id,
        icap_ctx->reqmod, s->headers_count, evbuffer_get_length(s->data_buf));

	struct evbuffer *in_hdr = ICAP_STATE(service_ctx, icap_ctx->reqmod)->in_hdr;
	struct evbuffer *in_body = ICAP_STATE(service_ctx, icap_ctx->reqmod)->in_body;
	struct evbuffer *sent_hdr = ICAP_STATE(service_ctx, icap_ctx->reqmod)->sent_hdr;
	struct evbuffer *sent_body = ICAP_STATE(service_ctx, icap_ctx->reqmod)->sent_body;

    // On failopen, s->headers may contain headers, as we may not have submitted them by protohttp2_submit_data()
    protohttpx_free_nv_headers((protohttpx_stream_ctx_t *)s);

    // TODO: Non-http protocols do not have hdr
	if (evbuffer_get_length(sent_hdr) > 0) {
        if (protohttpx_get_hx_headers((protohttpx_stream_ctx_t *)s, sent_hdr, 1) < 0) {
            log_finest_va("Failed to add sent headers for src_stream_id=%" PRId64 "", s->src_stream_id);
            return;
        }
		icap_ctx->made_progress = 1;
	}
	if (evbuffer_get_length(sent_body) > 0) {
        evbuffer_add_buffer(s->data_buf, sent_body);
		icap_ctx->made_progress = 1;
	}
	if (evbuffer_get_length(in_hdr) > 0) {
        // Do not init h2 headers, just append to existing headers from sent_hdr, if any
        if (protohttpx_get_hx_headers((protohttpx_stream_ctx_t *)s, in_hdr, 0) < 0) {
            log_finest_va("Failed to add in headers for src_stream_id=%" PRId64 "", s->src_stream_id);
            return;
        }
		icap_ctx->made_progress = 1;
	}
	if (evbuffer_get_length(in_body) > 0) {
		evbuffer_add_buffer(s->data_buf, in_body);
		icap_ctx->made_progress = 1;
	}

    log_finest_va("After copy, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d, headers_count=%zu, data_buf=%zu", s->src_stream_id, s->dst_stream_id,
        icap_ctx->reqmod, s->headers_count, evbuffer_get_length(s->data_buf));

    protohttp2_ctx_t *h2_ctx = icap_ctx->hx_ctx;
    if (protohttp2_submit_data(h2_ctx, s, icap_ctx->reqmod) < 0) {
        log_finest_va("Failed to submit data for src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, icap_ctx->reqmod);
        return;
    }
}
#endif /* !WITHOUT_ICAP */

static int
protohttp2_on_frame_recv(UNUSED nghttp2_session *session, const nghttp2_frame *frame, void *user_data, int reqmod)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest_va("ENTER, frame_type=0x%02x, stream_id=%d, reqmod=%d", frame->hd.type, frame->hd.stream_id, reqmod);

    // TODO: Check "frame->hd.flags & NGHTTP2_FLAG_END_STREAM" to determine if the stream has ended, and set an s->end_stream flag.
    // And use that flag in protohttp2_provider_read_callback() to set NGHTTP2_DATA_FLAG_EOF, if icap is not enabled for that stream.

    if (frame->hd.type == NGHTTP2_GOAWAY) {
        log_finest_va("NGHTTP2_GOAWAY received, stream_id=%d", frame->hd.stream_id);
        // Forward the GOAWAY frame to the other side of the connection
        nghttp2_submit_goaway(reqmod ? h2_ctx->dst_session : h2_ctx->src_session, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR, NULL, 0);
    }

    if (frame->hd.type == NGHTTP2_RST_STREAM) {
        log_finest_va("NGHTTP2_RST_STREAM received, stream_id=%d", frame->hd.stream_id);
        // ATTENTION: Forward the RST_STREAM frame to the other side of the connection to ensure proper stream termination
        protohttp2_stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id, reqmod);
        if (s) {
#ifndef WITHOUT_ICAP
            if (icap_enabled(s->icap_ctx)) {
                if (!icap_is_finished(s->icap_ctx)) {
                    log_finest_va("ICAP not finished yet, do not send RST_STREAM, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
                    return 0;
                }
                else {
                    log_finest_va("ICAP finished, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
                }

                log_finest_va("Set stream closed, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
                s->closed = 1;
            }
#endif /* !WITHOUT_ICAP */

            log_finest_va("Forward RST_STREAM to other end, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
            // Send to the other end of the connection to ensure proper stream termination
            nghttp2_submit_rst_stream(reqmod ? h2_ctx->dst_session : h2_ctx->src_session, NGHTTP2_FLAG_NONE, reqmod ? s->dst_stream_id : s->src_stream_id, NGHTTP2_NO_ERROR);

            // Never call nghttp2_session_send() in nghttp2 callbacks, as it may cause state corruption
            // Instead, we call it in libevent read and write callbacks
            // nghttp2_session_send(reqmod ? h2_ctx->dst_session : h2_ctx->src_session);
        }
    }

    if (frame->hd.type == NGHTTP2_WINDOW_UPDATE) {
        log_finest_va("NGHTTP2_WINDOW_UPDATE received, stream_id=%d", frame->hd.stream_id);
    }

    if (frame->hd.type == NGHTTP2_SETTINGS) {
        if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
            log_finest_va("NGHTTP2_SETTINGS ACK received from client/server, stream_id=%d", frame->hd.stream_id);
        } else {
            log_finest_va("NGHTTP2_SETTINGS parameter adjustments received, stream_id=%d", frame->hd.stream_id);
        }
    }

    if (frame->hd.type == NGHTTP2_HEADERS) {
        log_finest_va("NGHTTP2_HEADERS received, stream_id=%d", frame->hd.stream_id);

        protohttp2_stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id, reqmod);
        if (s) {
            // TODO: We get to this point only once per stream, when the headers are complete. So, do we need seen_header_on_entry?
            // int seen_header_on_entry = reqmod ? s->http_ctx->seen_req_header : s->http_ctx->seen_resp_header;

            if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS) {
                if (reqmod) {
                    log_finest_va("Request headers complete, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 "", s->src_stream_id, s->dst_stream_id);
                    s->http_ctx->seen_req_header = 1;
                }
                else {
                    log_finest_va("Response headers complete, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 "", s->src_stream_id, s->dst_stream_id);
                    s->http_ctx->seen_resp_header = 1;
                }
            }

            filter_header_t filter_header = reqmod ? protohttpx_filter_request_header : protohttpx_filter_response_header;

            int rv = filter_header((protohttpx_stream_ctx_t *)s);
            if (rv < 0) {
                log_finest_va("Return fatal error, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
                return -1;
            }
            // ATTENTION: Do not return -1 if protohttpx_apply_filter() returns 1 with block action.
            // see h3_on_end_headers().
            else if (rv == 1) /* Block action */ {
                log_finest_va("Return 0 with block action, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
                return 0;
            }

            // TODO: Should we log when we get the response only?
            // if (!seen_header_on_entry && ((reqmod && s->http_ctx->seen_req_header) || (!reqmod && s->http_ctx->seen_resp_header))) {
            if ((reqmod && s->http_ctx->seen_req_header) || (!reqmod && s->http_ctx->seen_resp_header)) {
                /* header complete: log connection */
                if (WANT_CONNECT_LOG(ctx->conn)) {
                    // TODO: Implement h2 specific logging with stream info
                    protohttp_log_connect(ctx, s->http_ctx, s->log_connect);
                }
            }

#ifndef WITHOUT_ICAP
            if (icap_enabled(s->icap_ctx)) {
                s->icap_ctx->reqmod = reqmod;

                struct evbuffer *outbuf_ptr = icap_get_first_service_in_hdr(s->icap_ctx);
                struct evbuffer *header_buf = protohttpx_get_h1_headers((protohttpx_stream_ctx_t *)s);

                evbuffer_add_buffer(outbuf_ptr, header_buf);
                evbuffer_free(header_buf);

                icap_process_data(s->data_buf, s->icap_ctx);
                return 0;
            }
#endif /* !WITHOUT_ICAP */

            return protohttp2_submit_data(h2_ctx, s, reqmod);
        }
        else {
            log_finest_va("No stream context found for stream_id=%d", frame->hd.stream_id);
            return -1;
        }
    }
    return 0;
}

static int
protohttp2_on_frame_recv_callback_src(UNUSED nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    return protohttp2_on_frame_recv(session, frame, user_data, 1);
}

static int
protohttp2_on_frame_recv_callback_dst(UNUSED nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    return protohttp2_on_frame_recv(session, frame, user_data, 0);
}

static int
protohttp2_on_data_chunk_recv(nghttp2_session *session, UNUSED uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data, int reqmod)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;
    UNUSED pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest_va("ENTER, stream_id=%d, len=%zu", stream_id, len);

    protohttp2_stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, stream_id, reqmod);
    if (!s) {
        nghttp2_session_consume(session, stream_id, len);
        return 0;
    }

    log_finest_va("src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);

#ifdef DEBUG_PROXY
	/* Log first 400 bytes for debugging */
	size_t log_len = len < 400 ? len : 400;
	char log_buf[401];  // Stack allocation
	memcpy(log_buf, data, log_len);
	log_buf[log_len] = '\0';
	log_finest_va("Chunk (first %zu bytes, orig %zu bytes): %s", log_len, len, log_buf);
#endif /* DEBUG_PROXY */

    // Queue pristine payload data straight into the staging buffer
    evbuffer_add(s->data_buf, data, len);

#ifndef WITHOUT_ICAP
    if (icap_enabled(s->icap_ctx)) {
        s->icap_ctx->reqmod = reqmod;
        icap_process_data(s->data_buf, s->icap_ctx);
        return 0;
    }
#endif /* !WITHOUT_ICAP */

    return protohttp2_submit_data(h2_ctx, s, reqmod);
}

static int
protohttp2_on_data_chunk_recv_callback_src(nghttp2_session *session, UNUSED uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    return protohttp2_on_data_chunk_recv(session, flags, stream_id, data, len, user_data, 1);
}

static int
protohttp2_on_data_chunk_recv_callback_dst(nghttp2_session *session, UNUSED uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    return protohttp2_on_data_chunk_recv(session, flags, stream_id, data, len, user_data, 0);
}

static int
protohttp2_on_stream_close(UNUSED nghttp2_session *session, int32_t stream_id, UNUSED uint32_t error_code, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = user_data;
    UNUSED pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    int reqmod = (session == h2_ctx->src_session) ? 1 : 0;

    log_finest_va("ENTER, stream_id=%d, reqmod=%d", stream_id, reqmod);

    protohttp2_stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, stream_id, reqmod);
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
        }
        else {
            log_finest_va("Stream closed before, free completely and remove, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, reqmod);
            // ATTENTION: Do not directly free the stream ctx here, otherwise may cause use-after-free issues in the nghttp2 callbacks
            // nghttp2 does not have a concept of deferred callbacks, so set the term flag and schedule the stream context for cleanup in the next event loop iteration
            // protohttp2_free_stream_ctx(s);
            s->term = 1;
            protohttp2_request_free_stream_ctx(s);
        }
        return 0;
    }

    log_finest_va("No stream context found for stream_id=%d, reqmod=%d", stream_id, reqmod);
    return -1;
}

static int
protohttp2_on_stream_close_callback_src(UNUSED nghttp2_session *session, int32_t stream_id, UNUSED uint32_t error_code, void *user_data)
{
    return protohttp2_on_stream_close(session, stream_id, error_code, user_data);
}

static int
protohttp2_on_stream_close_callback_dst(UNUSED nghttp2_session *session, int32_t stream_id, UNUSED uint32_t error_code, void *user_data)
{
    return protohttp2_on_stream_close(session, stream_id, error_code, user_data);
}

/*
 * Interface
 */

#ifndef WITHOUT_ICAP
int
protohttp2_icap_is_finished(pxy_conn_ctx_t *ctx)
{
    protohttp2_ctx_t *h2_ctx = ctx->protoctx->arg;
    protohttp2_stream_ctx_t *s = h2_ctx->streams;
    while (s) {
        if (icap_enabled(s->icap_ctx) && !icap_is_finished(s->icap_ctx)) {
            log_finest_va("ICAP not finished for stream, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64 ", reqmod=%d", s->src_stream_id, s->dst_stream_id, s->icap_ctx->reqmod);
            return 0;
        }
        s = s->next;
    }
    return 1;
}
#endif /* !WITHOUT_ICAP */

void
protohttp2_free(pxy_conn_ctx_t *ctx)
{
    log_finest("ENTER");

    protohttp2_ctx_t *h2_ctx = ctx->protoctx->arg;
    if (h2_ctx) {
        if (h2_ctx->src_session) {
            nghttp2_session_del(h2_ctx->src_session);
            h2_ctx->src_session = NULL;
        }
        if (h2_ctx->dst_session) {
            nghttp2_session_del(h2_ctx->dst_session);
            h2_ctx->dst_session = NULL;
        }
        while (h2_ctx->streams)
            protohttp2_free_stream_ctx(h2_ctx->streams);
        free(h2_ctx);
        ctx->protoctx->arg = NULL;
    }
    protohttps_free(ctx);
}

static void NONNULL(1)
protohttp2_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev || bev == ctx->dst.bev) {
        int reqmod = bev == ctx->src.bev;
        log_finest_va("ENTER, reqmod=%d", reqmod);

        protohttp2_ctx_t *h2_ctx = ctx->protoctx->arg;
        if (!h2_ctx) {
            log_finest("h2_ctx is NULL");
            return;
        }

        struct evbuffer *inbuf = bufferevent_get_input(bev);
        size_t len = evbuffer_get_length(inbuf);
        if (!len) {
            log_finest("No data to read");
            return;
        }

        unsigned char *data = malloc(len);
        if (!data) {
            log_finest("malloc failed");
            return;
        }
        evbuffer_remove(inbuf, data, len);

        if (nghttp2_session_mem_recv(reqmod ? h2_ctx->src_session : h2_ctx->dst_session, data, len) < 0) {
            log_finest("nghttp2_session_mem_recv failed");
        }
        else {
            // Always call nghttp2_session_send() to process pending frames
            // This is to ensure the HTTP/2 state machine is properly stepped
            // But never if nghttp2_session_mem_recv() returned an error
            nghttp2_session_send(reqmod ? h2_ctx->src_session : h2_ctx->dst_session);
            protohttp2_trigger_write_loop(h2_ctx, reqmod);
        }

        // Call nghttp2_session_send() for the opposite session to ensure any pending frames are sent
        nghttp2_session_send(reqmod ? h2_ctx->dst_session : h2_ctx->src_session);
        protohttp2_trigger_write_loop(h2_ctx, !reqmod);

        free(data);
	} else if (bev == ctx->srvdst.bev) {
        log_fine("readcb called on srvdst");
	} else {
		log_finest("protohttp2_bev_readcb: UNKWN conn end\n");
		return;
	}

	if (ctx->enomem) {
		return;
	}
}

protocol_t protohttp2_setup(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

    // TODO: Send GOAWAY frame to gracefully close the session and wait for it sent, but not here
    // nghttp2_submit_goaway(h2_ctx->session, NGHTTP2_FLAG_NONE, 1, NGHTTP2_NO_ERROR, NULL, 0);
    // nghttp2_session_send(h2_ctx->session);

    ctx->protoctx->bev_readcb = protohttp2_bev_readcb;
    ctx->protoctx->bev_writecb = protohttp2_bev_writecb;
    ctx->protoctx->proto_free = protohttp2_free;

    protohttp2_ctx_t *h2_ctx = malloc(sizeof(protohttp2_ctx_t));
    if (!h2_ctx) {
        ctx->enomem = 1;
        return PROTO_ERROR;
    }
    memset(h2_ctx, 0, sizeof(protohttp2_ctx_t));

    h2_ctx->ctx = ctx;

    // protoctx->arg is assigned to protohttp_ctx_t by protohttp_setup() initially,
    // after ALPN negotiation to h2, we need to free it before reassigning to protohttp2_ctx_t
    if (ctx->protoctx->arg) {
        log_finest("protoctx->arg is not NULL, freeing previous arg");
        protohttp_free_ctx((protohttp_ctx_t *)ctx->protoctx->arg);
    }
    ctx->protoctx->arg = h2_ctx;

    // Initialize session for H2 connections
    nghttp2_session_callbacks *cb;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_send_callback(cb, protohttp2_send_callback_src);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, protohttp2_on_frame_recv_callback_src);
    nghttp2_session_callbacks_set_on_header_callback(cb, protohttp2_on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, protohttp2_on_data_chunk_recv_callback_src);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, protohttp2_on_stream_close_callback_src);
    nghttp2_session_server_new(&h2_ctx->src_session, cb, h2_ctx);

	log_finest("Sending initial SETTINGS frame from client session");
    nghttp2_submit_settings(h2_ctx->src_session, NGHTTP2_FLAG_NONE, NULL, 0);

    nghttp2_session_callbacks_del(cb);

    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_send_callback(cb, protohttp2_send_callback_dst);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, protohttp2_on_frame_recv_callback_dst);
    nghttp2_session_callbacks_set_on_header_callback(cb, protohttp2_on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, protohttp2_on_data_chunk_recv_callback_dst);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, protohttp2_on_stream_close_callback_dst);
    nghttp2_session_client_new(&h2_ctx->dst_session, cb, h2_ctx);

	log_finest("Sending initial SETTINGS frame from server session");
    // No need to send max concurrent streams - let nghttpd decide based on its own config
    // nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    // nghttp2_submit_settings(h2_ctx->session, NGHTTP2_FLAG_NONE, iv, 1);
    // No need to send initial window update - we'll let nghttpd manage flow control and just respond to its WINDOW_UPDATE frames
    // nghttp2_submit_window_update(h2_ctx->session, NGHTTP2_FLAG_NONE, 0, 65535);
    nghttp2_submit_settings(h2_ctx->dst_session, NGHTTP2_FLAG_NONE, NULL, 0);

    nghttp2_session_callbacks_del(cb);

    nghttp2_session_send(h2_ctx->src_session);
    nghttp2_session_send(h2_ctx->dst_session);

    return PROTO_HTTP2;
}
