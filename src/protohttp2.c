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

#include <event2/bufferevent.h>
#include <nghttp2/nghttp2.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>

/*
 * Struct definitions
 */

typedef struct stream_ctx {
    int32_t stream_id;
    evutil_socket_t fd; // Used to match responses to requests

    nghttp2_nv *headers;
    size_t headers_count;
    size_t headers_capacity;

    struct evbuffer *data_buf;
    int h1_body_finished;
    struct stream_ctx *next;
} stream_ctx_t;

typedef struct protohttp2_ctx {
    nghttp2_session *session;
    void *ctx; /* Points to either pxy_conn_ctx_t or pxy_conn_child_ctx_t */
    
    stream_ctx_t *streams;

    enum {
        H1_STATE_STATUS_LINE,
        H1_STATE_HEADERS,
        H1_STATE_BODY_IDENTITY,
        H1_STATE_BODY_CHUNK_HEAD,
        H1_STATE_BODY_CHUNK_DATA,
        H1_STATE_BODY_CHUNK_TRAILER
    } h1_state;
    long long h1_content_length;
    int h1_chunked;
    size_t h1_chunk_left;
    stream_ctx_t *h1_active_stream;

    unsigned int h2_handshake_done : 1;
} protohttp2_ctx_t;


static stream_ctx_t *
protohttp2_get_stream_ctx(protohttp2_ctx_t *h2_ctx, int32_t stream_id)
{
    stream_ctx_t *s = h2_ctx->streams;
    while (s)
    {
        if (s->stream_id == stream_id)
            return s;
        s = s->next;
    }
    return NULL;
}

static int32_t
protohttp2_get_stream_id_from_fd(protohttp2_ctx_t *h2_ctx, evutil_socket_t fd)
{
    stream_ctx_t *s = h2_ctx->streams;
    while (s) {
        log_dbg_printf("protohttp2_get_stream_id_from_fd: fd: %d, stream_id: %d\n", fd, s->stream_id);
        if (s->fd == fd) {
            return s->stream_id;
        }
        s = s->next;
    }
    return -1;
}

static stream_ctx_t *
protohttp2_new_stream_ctx(protohttp2_ctx_t *h2_ctx, int32_t stream_id, evutil_socket_t fd)
{
    log_dbg_printf("protohttp2_new_stream_ctx: fd: %d, stream_id: %d\n", fd, stream_id);
    stream_ctx_t *s = malloc(sizeof(stream_ctx_t));
    if (!s)
        return NULL;
    memset(s, 0, sizeof(stream_ctx_t));
    s->stream_id = stream_id;
    s->fd = fd;
    s->data_buf = evbuffer_new();
    s->next = h2_ctx->streams;
    h2_ctx->streams = s;
    return s;
}

static void
protohttp2_add_header(stream_ctx_t *s, const char *name, const char *value)
{
    if (s->headers_count == s->headers_capacity) {
        s->headers_capacity = s->headers_capacity ? s->headers_capacity * 2 : 16;
        s->headers = realloc(s->headers, s->headers_capacity * sizeof(nghttp2_nv));
        if (!s->headers) {
            // Handle allocation failure
            return;
        }
    }
    nghttp2_nv *nv = &s->headers[s->headers_count++];
    nv->name = (uint8_t *)strdup(name);
    nv->namelen = strlen(name);
    // H2 requires lowercase header names
    for (size_t i = 0; i < nv->namelen; i++) {
        if (nv->name[i] >= 'A' && nv->name[i] <= 'Z') {
            nv->name[i] += 'a' - 'A';
        }
    }
    nv->value = (uint8_t *)strdup(value);
    nv->valuelen = strlen(value);
    nv->flags = NGHTTP2_NV_FLAG_NONE;
    log_dbg_printf("protohttp2_add_header: H2 Header: %s: %s\n", name, value);
}

static void
protohttp2_free_stream_ctx(protohttp2_ctx_t *h2_ctx, stream_ctx_t *s)
{
    if (h2_ctx->streams == s) {
        h2_ctx->streams = s->next;
    } else {
        stream_ctx_t *prev = h2_ctx->streams;
        while (prev && prev->next != s) prev = prev->next;
        if (prev) prev->next = s->next;
    }
    if (s->headers) {
        for (size_t i = 0; i < s->headers_count; i++) {
            if (s->headers[i].name) free(s->headers[i].name);
            if (s->headers[i].value) free(s->headers[i].value);
        }
        free(s->headers);
    }
    if (s->data_buf) evbuffer_free(s->data_buf);
    free(s);
}

static struct evbuffer *
protohttp2_h1_headers(nghttp2_nv *headers, size_t count, int child)
{
    log_err_printf("protohttp2_h1_headers: ENTER\n");

    struct evbuffer *buf = evbuffer_new();
    if (!buf)
        return NULL;
    int method_idx = -1, path_idx = -1, status_idx = -1, authority_idx = -1;
    for (size_t i = 0; i < count; i++)
    {
        if (headers[i].namelen == 7 && !memcmp(headers[i].name, ":method", 7))
            method_idx = (int)i;
        else if (headers[i].namelen == 5 && !memcmp(headers[i].name, ":path", 5))
            path_idx = (int)i;
        else if (headers[i].namelen == 7 && !memcmp(headers[i].name, ":status", 7))
            status_idx = (int)i;
        else if (headers[i].namelen == 10 && !memcmp(headers[i].name, ":authority", 10))
            authority_idx = (int)i;
    }
    if ((method_idx != -1) && !child)
    {
        log_err_printf("protohttp2_h1_headers: method_idx=%d\n", method_idx);
        log_err_printf("protohttp2_h1_headers: %.*s %.*s HTTP/1.1\r\n",
                            (int)headers[method_idx].valuelen, (char *)headers[method_idx].value,
                            (path_idx != -1) ? (int)headers[path_idx].valuelen : 1, (path_idx != -1) ? (char *)headers[path_idx].value : "/");

        evbuffer_add_printf(buf, "%.*s %.*s HTTP/1.1\r\n",
                            (int)headers[method_idx].valuelen, (char *)headers[method_idx].value,
                            (path_idx != -1) ? (int)headers[path_idx].valuelen : 1, (path_idx != -1) ? (char *)headers[path_idx].value : "/");
        if (authority_idx != -1)
        {
            evbuffer_add_printf(buf, "Host: %.*s\r\n", (int)headers[authority_idx].valuelen, (char *)headers[authority_idx].value);
        }
    }
    if ((status_idx != -1) && child)
    {
        log_err_printf("protohttp2_h1_headers: status_idx=%d\n", status_idx);
        log_err_printf("protohttp2_h1_headers: HTTP/1.1 %.*s\r\n", (int)headers[status_idx].valuelen, (char *)headers[status_idx].value);

        evbuffer_add_printf(buf, "HTTP/1.1 %.*s\r\n", (int)headers[status_idx].valuelen, (char *)headers[status_idx].value);
    }
    for (size_t i = 0; i < count; i++)
    {
        if (headers[i].name[0] == ':')
            continue;
        // Skip Host to avoid duplicates
        if (headers[i].namelen == 4 && !strncasecmp((char *)headers[i].name, "Host", 4))
            continue;
        log_err_printf("protohttp2_h1_headers: %.*s: %.*s\r\n", (int)headers[i].namelen, headers[i].name, (int)headers[i].valuelen, headers[i].value);
        evbuffer_add_printf(buf, "%.*s: %.*s\r\n", (int)headers[i].namelen, headers[i].name, (int)headers[i].valuelen, headers[i].value);
    }

    // Do not append Transfer-Encoding, otherwise we have to wait for body of GET requests too
    // see protohttp2_bev_readcb_src_child()
    // evbuffer_add_printf(buf, "Transfer-Encoding: chunked\r\n\r\n");

    // Add an extra CRLF to signal end of headers.
    evbuffer_add_printf(buf, "\r\n");
    return buf;
}

/*
 * Callbacks
 */

static ssize_t
protohttp2_data_source_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags, nghttp2_data_source *source, void *user_data)
{
    log_err_printf("protohttp2_data_source_read_callback: ENTER\n");

    stream_ctx_t *s = (stream_ctx_t *)source->ptr;
    size_t len = evbuffer_get_length(s->data_buf);
    if (len == 0) {
        if (s->h1_body_finished) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        return NGHTTP2_ERR_DEFERRED;
    }
    size_t n = MIN(len, length);
    evbuffer_remove(s->data_buf, buf, n);
    if (evbuffer_get_length(s->data_buf) == 0 && s->h1_body_finished) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    (void)session; (void)stream_id; (void)user_data;
    return (ssize_t)n;
}

static void NONNULL(1, 2)
protohttp2_bev_writecb(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
    // TODO: Remove this callback and use the callback in https code
	pxy_conn_ctx_t *ctx = arg;
	log_finest("ENTER (Nothing to do)");
}

/*
 * nghttp2 callbacks
 */

static ssize_t
protohttp2_send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
    log_err_printf("protohttp2_send_callback: ");
    for (size_t i = 0; i < (length > 24 ? 24 : length); i++)
    {
        log_err_printf("%02x ", data[i]);
    }
    log_err_printf("\n");

    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;
    struct bufferevent *bev = ((pxy_conn_ctx_t *)(h2_ctx->ctx))->src.bev;
    if (bufferevent_write(bev, data, length) == -1)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    (void)session;
    (void)flags;
    return (ssize_t)length;
}

static ssize_t
protohttp2_send_callback_child(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
    log_err_printf("protohttp2_send_callback_child: ");
    for (size_t i = 0; i < (length > 24 ? 24 : length); i++)
    {
        log_err_printf("%02x ", data[i]);
    }
    log_err_printf("\n");

    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;
    struct bufferevent *bev = ((pxy_conn_child_ctx_t *)(h2_ctx->ctx))->dst.bev;
    if (bufferevent_write(bev, data, length) == -1)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    (void)session;
    (void)flags;
    return (ssize_t)length;
}

static int
protohttp2_on_header_callback(UNUSED nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, UNUSED uint8_t flags, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_ctx_t *ctx = (pxy_conn_ctx_t *)h2_ctx->ctx;
    log_finest("ENTER");
    
    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;
    stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id);
    if (!s)
        s = protohttp2_new_stream_ctx(h2_ctx, frame->hd.stream_id, ctx->fd);
    if (s)
    {
        if (s->headers_count == s->headers_capacity)
        {
            s->headers_capacity = s->headers_capacity ? s->headers_capacity * 2 : 16;
            s->headers = realloc(s->headers, s->headers_capacity * sizeof(nghttp2_nv));
        }
        nghttp2_nv *nv = &s->headers[s->headers_count++];
        nv->name = malloc(namelen);
        memcpy(nv->name, name, namelen);
        nv->namelen = namelen;
        nv->value = malloc(valuelen);
        memcpy(nv->value, value, valuelen);
        nv->valuelen = valuelen;
        nv->flags = NGHTTP2_NV_FLAG_NONE;
    }
    return 0;
}

static int
protohttp2_on_header_callback_child(UNUSED nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, UNUSED uint8_t flags, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_child_ctx_t *ctx = (pxy_conn_child_ctx_t *)h2_ctx->ctx;
    log_finest("ENTER");

    if (frame->hd.type != NGHTTP2_HEADERS)
        return 0;
    stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id);
    if (s)
    {
        if (s->headers_count == s->headers_capacity)
        {
            s->headers_capacity = s->headers_capacity ? s->headers_capacity * 2 : 16;
            s->headers = realloc(s->headers, s->headers_capacity * sizeof(nghttp2_nv));
        }
        nghttp2_nv *nv = &s->headers[s->headers_count++];
        nv->name = malloc(namelen);
        memcpy(nv->name, name, namelen);
        nv->namelen = namelen;
        nv->value = malloc(valuelen);
        memcpy(nv->value, value, valuelen);
        nv->valuelen = valuelen;
        nv->flags = NGHTTP2_NV_FLAG_NONE;
    }
    return 0;
}

static int
protohttp2_on_frame_recv_callback(UNUSED nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_ctx_t *ctx = (pxy_conn_ctx_t *)h2_ctx->ctx;
    log_finest("ENTER");

    if (frame->hd.type == NGHTTP2_HEADERS)
    {
        stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id);
        if (s)
        {
            struct evbuffer *h1buf = protohttp2_h1_headers(s->headers, s->headers_count, 0);
            if (h1buf)
            {
                struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);
                // In http, we add SSLproxy header after the request line and before the headers
                // Client side: sending to lp (H2 -> H1)
                // pxy_try_prepend_sslproxy_header(h2_ctx->ctx, h1buf, outbuf);
	            protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
                if (protohttp_filter_request_header(h1buf, outbuf, http_ctx, ctx->type, ctx) == -1) {
                    // TODO: Handle error
                    // return;
                }
                evbuffer_free(h1buf);
            }
        }
    }
    return 0;
}

static int
protohttp2_on_frame_recv_callback_child(UNUSED nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_child_ctx_t *ctx = (pxy_conn_child_ctx_t *)h2_ctx->ctx;
    log_finest("ENTER");

    // Check if we received the SETTINGS ACK from the server
    if (frame->hd.type == NGHTTP2_SETTINGS && (frame->hd.flags & NGHTTP2_FLAG_ACK))
    {
        log_finest("SETTINGS ACK received");
        h2_ctx->h2_handshake_done = 1;

        // NOW it is safe to enable reading from lp on server side
        // and process any buffered data.
        bufferevent_enable(ctx->src.bev, EV_READ | EV_WRITE);

        // If we were manually holding data, trigger a write now
        // nghttp2_session_send(session);
    }

    if (frame->hd.type == NGHTTP2_HEADERS)
    {
        log_finest("HEADERS received");

        stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id);
        if (s)
        {
            struct evbuffer *h1buf = protohttp2_h1_headers(s->headers, s->headers_count, 1);
            if (h1buf)
            {
                log_finest("Sending to lp");
                struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);
                evbuffer_add_buffer(outbuf, h1buf);
                evbuffer_free(h1buf);
            }
        }
    }
    return 0;
}

static int
protohttp2_on_data_chunk_recv_callback(UNUSED nghttp2_session *session, UNUSED uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_ctx_t *ctx = (pxy_conn_ctx_t *)h2_ctx->ctx;
    log_finest_va("stream_id=%d, len=%zu", stream_id, len);

    // For client side, we're receiving data from H2 client
    // This is where we send the chunked data to the H1 lp (e.g. POST body)
    struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);
    evbuffer_add(outbuf, data, len);
    return 0;
}

static int
protohttp2_on_data_chunk_recv_callback_child(nghttp2_session *session, UNUSED uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;
    
    pxy_conn_child_ctx_t *ctx = (pxy_conn_child_ctx_t *)h2_ctx->ctx;
    log_finest_va("stream_id=%d, len=%zu", stream_id, len);

    // For server side, we're receiving data from H2 server
    // This is where we should send the chunked data to the H1 lp (e.g. response body)
    struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);
    if (len > 0)
    {
        evbuffer_add_printf(outbuf, "%x\r\n", (unsigned int)len);
        evbuffer_add(outbuf, data, len);
        evbuffer_add(outbuf, "\r\n", 2);
    }
    else
    {
        // End of data, send final chunk
        evbuffer_add(outbuf, "0\r\n\r\n", 5);
    }
    nghttp2_session_consume(session, stream_id, len);
    return 0;
}

static int
protohttp2_on_stream_close_callback(UNUSED nghttp2_session *session, int32_t stream_id, UNUSED uint32_t error_code, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_ctx_t *ctx = (pxy_conn_ctx_t *)h2_ctx->ctx;
    log_finest_va("stream_id=%d", stream_id);

    stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, stream_id);
    if (s)
    {
        // Send the final chunk to complete the HTTP/2 stream
        // Send to H2 client (lp is H1 only)
        struct evbuffer *outbuf = bufferevent_get_output(((pxy_conn_ctx_t *)h2_ctx->ctx)->src.bev);
        evbuffer_add(outbuf, "0\r\n\r\n", 5);
        protohttp2_free_stream_ctx(h2_ctx, s);
    }
    return 0;
}

static int
protohttp2_on_stream_close_callback_child(UNUSED nghttp2_session *session, int32_t stream_id, UNUSED uint32_t error_code, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_child_ctx_t *ctx = (pxy_conn_child_ctx_t *)h2_ctx->ctx;
    log_finest_va("stream_id=%d", stream_id);

    stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, stream_id);
    if (s)
    {
        // Send the final chunk to complete the HTTP/2 stream
        // Send to H2 server (lp is H1 only)
        struct evbuffer *outbuf = bufferevent_get_output(((pxy_conn_child_ctx_t *)h2_ctx->ctx)->dst.bev);
        evbuffer_add(outbuf, "0\r\n\r\n", 5);
        protohttp2_free_stream_ctx(h2_ctx, s);
    }
    return 0;
}

/*
 * Interface
 */

void protohttp2_free(pxy_conn_ctx_t *ctx) {
    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp2_ctx_t *h2_ctx = http_ctx->arg;
    if (h2_ctx)
    {
        if (h2_ctx->session) {
            nghttp2_session_del(h2_ctx->session);
        }
        while (h2_ctx->streams)
            protohttp2_free_stream_ctx(h2_ctx, h2_ctx->streams);
        free(h2_ctx);
        http_ctx->arg = NULL;
    }
    protohttps_free(ctx);
}

void protohttp2_free_child(pxy_conn_child_ctx_t *ctx) {
    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp2_ctx_t *h2_ctx = http_ctx->arg;
    if (h2_ctx)
    {
        if (h2_ctx->session) {
            nghttp2_session_del(h2_ctx->session);
        }
        while (h2_ctx->streams)
            protohttp2_free_stream_ctx(h2_ctx, h2_ctx->streams);
        free(h2_ctx);
        http_ctx->arg = NULL;
    }
    protohttp_free_child(ctx);
}

static void NONNULL(1,2)
protohttp2_bev_readcb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
    log_finest("ENTER");

    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp2_ctx_t *h2_ctx = http_ctx->arg;
    struct evbuffer *inbuf = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(inbuf);
    if (!len)
        return;

    unsigned char *data = malloc(len);
    if (!data)
        return;
    evbuffer_remove(inbuf, data, len);

    nghttp2_session *session = h2_ctx->session;
    if (nghttp2_session_mem_recv(session, data, len) < 0)
    {
        log_finest("nghttp2_session_mem_recv failed");
        pxy_conn_term(h2_ctx->ctx, 1);
    }
    else
    {
        // Always call nghttp2_session_send() to process pending frames
        // This is to ensure the HTTP/2 state machine is properly stepped
        nghttp2_session_send(session);
    }
    free(data);
}

static void NONNULL(1)
protohttp2_bev_readcb_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp2_ctx_t *h2_ctx = http_ctx->arg;

    struct evbuffer *inbuf = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(inbuf);
    if (!len) return;

    // Handle HTTP/1.1 data from lp
    while (evbuffer_get_length(inbuf) > 0) {
        log_finest_va("inbuf length: %zu", evbuffer_get_length(inbuf));

        char *line; size_t l;
        switch (h2_ctx->h1_state) {
            case H1_STATE_STATUS_LINE:
                log_finest("Processing status line");

                if (!(line = evbuffer_readln(inbuf, &l, EVBUFFER_EOL_CRLF))) return;
                log_finest_va("H1 Status Line (len=%zu): %s", l, line);
                // Create a new stream context for response
                if (!h2_ctx->h1_active_stream) {
                    // We use the stream id from request here, this is how we match request to response streams
                    // This is a simple solution for this PoC, it's not for multiple concurrent streams
                    int32_t stream_id = protohttp2_get_stream_id_from_fd(h2_ctx, ctx->fd);
                    h2_ctx->h1_active_stream = protohttp2_new_stream_ctx(h2_ctx, stream_id, ctx->fd);
                }
                if (h2_ctx->h1_active_stream) {
                    stream_ctx_t *s = h2_ctx->h1_active_stream;
                    s->headers_count = 0;
                    s->h1_body_finished = 0;
                    char *sp1 = strchr(line, ' ');
                    if (sp1) {
                        *sp1 = '\0';
                        char *part2 = sp1 + 1;
                        while (*part2 == ' ') part2++;
                        char *sp2 = strchr(part2, ' ');
                        if (!sp2) {
                            sp2 = strchr(line, '\0');
                        }
                        if (sp2) {
                            *sp2 = '\0';
                            // This is a response from server (over lp) to client
                            protohttp2_add_header(s, ":status", part2);
                        }
                    }
                }
                free(line); h2_ctx->h1_state = H1_STATE_HEADERS;
                break;
            case H1_STATE_HEADERS:
                if (!(line = evbuffer_readln(inbuf, &l, EVBUFFER_EOL_CRLF))) return;
                log_finest_va("Processing header= %s", line);
                if (l == 0) {
                    if (h2_ctx->h1_active_stream) {
                        stream_ctx_t *s = h2_ctx->h1_active_stream;
                        int has_body = (h2_ctx->h1_chunked || h2_ctx->h1_content_length > 0);

                        nghttp2_data_provider provider;
                        provider.source.ptr = s;
                        provider.read_callback = protohttp2_data_source_read_callback;
                        
                        // The issue is that we don't know which stream ID to use for the response
                        // We need to let nghttp2 handle the stream ID assignment for the response
                        // But we need to make sure the response gets properly routed back to the client
                        // This is tricky because in HTTP/2, responses are sent on new streams, not on the same stream as the request.

                        // ATTENTION: Apparently, the stream_id param in nghttp2_submit_response() is the request stream id to send the response against
                        // This is how nghttp2 matches the response to the correct request stream.
                        // So we pass the same stream ID as the request for the response, and nghttp2 handles the rest
                        int rv = nghttp2_submit_response(h2_ctx->session, s->stream_id, s->headers, s->headers_count, has_body ? &provider : NULL);
                        log_finest_va("nghttp2_submit_response stream_id=%d rv=%d", s->stream_id, rv);

                        if (has_body) {
                            h2_ctx->h1_state = h2_ctx->h1_chunked ? H1_STATE_BODY_CHUNK_HEAD : H1_STATE_BODY_IDENTITY;
                            h2_ctx->h1_chunk_left = (h2_ctx->h1_content_length > 0) ? (size_t)h2_ctx->h1_content_length : 0;
                        } else {
                            s->h1_body_finished = 1; h2_ctx->h1_state = H1_STATE_STATUS_LINE;
                        }
                    }
                    free(line); 
                    // Call send for the session that was just used for processing
                    nghttp2_session_send(h2_ctx->session);
                    continue;
                }
                char *colon = strchr(line, ':');
                if (colon && h2_ctx->h1_active_stream) {
                    *colon = '\0';
                    char *val = colon + 1;
                    while (*val == ' ' || *val == '\t') val++;
                    stream_ctx_t *s = h2_ctx->h1_active_stream;
                    if (!strcasecmp(line, "Content-Length")) {
                        h2_ctx->h1_content_length = atoll(val);
                    } else if (!strcasecmp(line, "Transfer-Encoding") && strstr(val, "chunked")) {
                        h2_ctx->h1_chunked = 1;
                    }
                    if (!strcasecmp(line, "Host")) {
                        for (size_t i = 0; i < s->headers_count; i++) {
                            if (s->headers[i].namelen == 10 && !memcmp(s->headers[i].name, ":authority", 10)) {
                                free(s->headers[i].value);
                                s->headers[i].value = (uint8_t *)strdup(val);
                                s->headers[i].valuelen = strlen(val);
                                break;
                            }
                        }
                    } else if (strcasecmp(line, "Connection") && strcasecmp(line, "Upgrade") && 
                                strcasecmp(line, "Keep-Alive") && strcasecmp(line, "Proxy-Connection") &&
                                strcasecmp(line, "Transfer-Encoding") && strcasecmp(line, "Content-Length")) {
                        protohttp2_add_header(s, line, val);
                    }
                }
                free(line); break;
            case H1_STATE_BODY_IDENTITY:
                {
                    size_t to_read = MIN(evbuffer_get_length(inbuf), h2_ctx->h1_chunk_left);
                    log_finest_va("Processing body (identity)= to_read: %zu, inbuf length: %zu, chunk_left: %zu", to_read, evbuffer_get_length(inbuf), h2_ctx->h1_chunk_left);
                    if (to_read > 0) {
                        unsigned char *data = malloc(to_read);
                        evbuffer_remove(inbuf, data, to_read);
                        evbuffer_add(h2_ctx->h1_active_stream->data_buf, data, to_read);
                        free(data);
                        h2_ctx->h1_chunk_left -= to_read;
                        // Resume data for the correct stream
                        if (h2_ctx->h1_active_stream) {
                            nghttp2_session_resume_data(h2_ctx->session, h2_ctx->h1_active_stream->stream_id);
                        }
                    }
                    if (h2_ctx->h1_chunk_left == 0) {
                        h2_ctx->h1_active_stream->h1_body_finished = 1;
                        if (h2_ctx->h1_active_stream) {
                            nghttp2_session_resume_data(h2_ctx->session, h2_ctx->h1_active_stream->stream_id);
                        }
                        h2_ctx->h1_state = H1_STATE_STATUS_LINE;
                    }
                    // Ensure we always call send to properly step the session state
                    nghttp2_session_send(h2_ctx->session);
                }
                return;
            case H1_STATE_BODY_CHUNK_HEAD:
                log_finest("Processing body (chunk head)");
                if (!(line = evbuffer_readln(inbuf, &l, EVBUFFER_EOL_CRLF))) return;
                h2_ctx->h1_chunk_left = strtoul(line, NULL, 16);
                free(line);
                if (h2_ctx->h1_chunk_left == 0) h2_ctx->h1_state = H1_STATE_BODY_CHUNK_TRAILER;
                else h2_ctx->h1_state = H1_STATE_BODY_CHUNK_DATA;
                continue;
            case H1_STATE_BODY_CHUNK_DATA:
                log_finest("Processing body (chunk data)");
                {
                    size_t to_read = MIN(evbuffer_get_length(inbuf), h2_ctx->h1_chunk_left);
                    if (to_read > 0) {
                        unsigned char *data = malloc(to_read);
                        evbuffer_remove(inbuf, data, to_read);
                        evbuffer_add(h2_ctx->h1_active_stream->data_buf, data, to_read);
                        free(data);
                        h2_ctx->h1_chunk_left -= to_read;
                        if (h2_ctx->h1_active_stream) {
                            int rv = nghttp2_session_resume_data(h2_ctx->session, h2_ctx->h1_active_stream->stream_id);
                            log_finest_va("nghttp2_session_resume_data rv=%d", rv);
                        }
                    }
                    if (h2_ctx->h1_chunk_left == 0) h2_ctx->h1_state = H1_STATE_BODY_CHUNK_TRAILER;
                    // Ensure we always call send to properly step the session state
                    nghttp2_session_send(h2_ctx->session);
                }
                // TODO: Should we just return, see to_read above
                // return;
                continue;
            case H1_STATE_BODY_CHUNK_TRAILER:
                log_finest("Processing body (chunk trailer)");
                if (!(line = evbuffer_readln(inbuf, &l, EVBUFFER_EOL_CRLF))) return;
                if (l == 0) {
                        if (evbuffer_get_length(inbuf) == 0 && h2_ctx->h1_chunk_left == 0 && h2_ctx->h1_active_stream) {
                            h2_ctx->h1_active_stream->h1_body_finished = 1;
                            int rv = nghttp2_session_resume_data(h2_ctx->session, h2_ctx->h1_active_stream->stream_id);
                            log_finest_va("nghttp2_session_resume_data rv=%d", rv);
                            h2_ctx->h1_state = H1_STATE_STATUS_LINE;
                        } else {
                            h2_ctx->h1_state = H1_STATE_BODY_CHUNK_HEAD;
                        }
                }
                free(line); 
                // Call send for the session that was just used for processing
                nghttp2_session_send(h2_ctx->session);
                continue;
        }
    }
    // Always call send at the end to ensure proper session state processing
    nghttp2_session_send(h2_ctx->session);
    log_finest("EXIT");
}

static void NONNULL(1)
protohttp2_bev_readcb_srvdst(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
    log_err_level(LOG_ERR, "readcb called on srvdst");
}

static void NONNULL(1)
protohttp2_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	int seen_resp_header_on_entry = http_ctx->seen_resp_header;

	if (bev == ctx->src.bev) {
		protohttp2_bev_readcb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		protohttp2_bev_readcb_dst(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protohttp2_bev_readcb_srvdst(bev, ctx);
	} else {
		log_err_printf("protohttp2_bev_readcb: UNKWN conn end\n");
		return;
	}

	if (ctx->enomem) {
		return;
	}

	if (!seen_resp_header_on_entry && http_ctx->seen_resp_header) {
		/* response header complete: log connection */
		if (WANT_CONNECT_LOG(ctx->conn)) {
			protohttp_log_connect(ctx);
		}
	}
}

static void NONNULL(1)
protohttp2_bev_readcb_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");

    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp2_ctx_t *h2_ctx = http_ctx->arg;

    struct evbuffer *inbuf = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(inbuf);
    if (!len) return;

    if (!h2_ctx->h2_handshake_done) {
        log_finest("WARN: Received data from lp before H2 handshake is complete");
        return;
    }

    // Handle HTTP/1.1 data from server
    while (evbuffer_get_length(inbuf) > 0) {
        char *line; size_t l;
        switch (h2_ctx->h1_state) {
            case H1_STATE_STATUS_LINE:
                h2_ctx->h1_content_length = -1;
                h2_ctx->h1_chunked = 0;
                h2_ctx->h1_active_stream = NULL;

                if (!(line = evbuffer_readln(inbuf, &l, EVBUFFER_EOL_CRLF))) return;
                log_finest_va("H1 Status Line (len=%zu): %s", l, line);

                // Create a new stream context for response
                if (!h2_ctx->h1_active_stream) {
                    // The stream id is assigned by nghttp2 below when we submit the response, so pass -1 for now
                    h2_ctx->h1_active_stream = protohttp2_new_stream_ctx(h2_ctx, -1, ctx->fd);
                }
                if (h2_ctx->h1_active_stream) {
                    stream_ctx_t *s = h2_ctx->h1_active_stream;
                    s->headers_count = 0;
                    s->h1_body_finished = 0;
                    char *sp1 = strchr(line, ' ');
                    if (sp1) {
                        *sp1 = '\0';
                        char *part2 = sp1 + 1;
                        while (*part2 == ' ') part2++;
                        char *sp2 = strchr(part2, ' ');
                        if (sp2) {
                            *sp2 = '\0';
                            // This is a request from client (over lp) to server
                            protohttp2_add_header(s, ":method", line);
                            protohttp2_add_header(s, ":path", part2);
                            protohttp2_add_header(s, ":scheme", "https");
                            protohttp2_add_header(s, ":authority", "");
                        }
                    }
                }
                free(line); h2_ctx->h1_state = H1_STATE_HEADERS;

                struct evbuffer_ptr ptr = evbuffer_search(inbuf, SSLPROXY_KEY, SSLPROXY_KEY_LEN, NULL);
                if (ptr.pos == 0) {
                    struct evbuffer_ptr eol = evbuffer_search_eol(inbuf, &ptr, NULL, EVBUFFER_EOL_CRLF);
                    if (eol.pos != -1) {
                        size_t len = eol.pos;
                        char *skipped = malloc(len + 1);
                        evbuffer_remove(inbuf, skipped, len);
                        skipped[len] = '\0';
                        log_finest_va("Skip SSLproxy header: %s", skipped);
                        free(skipped);
                        while (evbuffer_get_length(inbuf) > 0) {
                            unsigned char c;
                            evbuffer_copyout(inbuf, &c, 1);
                            if (c == '\r' || c == '\n') evbuffer_drain(inbuf, 1);
                            else break;
                        }
                        // continue;
                    } else return;
                }
                break;
            case H1_STATE_HEADERS:
                if (!(line = evbuffer_readln(inbuf, &l, EVBUFFER_EOL_CRLF))) return;
                log_finest_va("Processing header= %s", line);
                if (l == 0) {
                    if (h2_ctx->h1_active_stream) {
                        stream_ctx_t *s = h2_ctx->h1_active_stream;

                        int has_body = (h2_ctx->h1_chunked || h2_ctx->h1_content_length > 0);

                        nghttp2_data_provider provider;
                        provider.source.ptr = s;
                        provider.read_callback = protohttp2_data_source_read_callback;
                        
                        // For server side (receiving request from client): submit request to server
                        s->stream_id= nghttp2_submit_request(h2_ctx->session, NULL, s->headers, s->headers_count, has_body ? &provider : NULL, s);
                        log_finest_va("nghttp2_submit_request stream_id=%d", s->stream_id);

                        nghttp2_session_send(h2_ctx->session);

                        // Also make sure we're flushing the session properly to complete the stream
                        // The key insight: when we have no body, we must still signal the end of stream
                        // This is critical for nghttpd to process the request and send a response
                        if (!has_body) {
                            // Submit a zero-length DATA frame with END_STREAM flag to properly close the request
                            // This ensures nghttpd properly processes the request even when there's no body
                            nghttp2_data_provider empty_provider;
                            empty_provider.source.ptr = NULL;
                            empty_provider.read_callback = NULL;
                            int data_rv = nghttp2_submit_data(h2_ctx->session, NGHTTP2_FLAG_END_STREAM, s->stream_id, &empty_provider);
                            if (data_rv >= 0) {
                                log_finest_va("Submitted END_STREAM for request stream %d", s->stream_id);
                            } else {
                                log_finest_va("Failed to submit END_STREAM for request stream %d, rv=%d, msg=%s", s->stream_id, data_rv, nghttp2_strerror(data_rv));
                            }
                        }
                        if (has_body) {
                            log_finest_va("Has body, setting state to read body with content_length=%lld chunked=%d", h2_ctx->h1_content_length, h2_ctx->h1_chunked);
                            h2_ctx->h1_state = h2_ctx->h1_chunked ? H1_STATE_BODY_CHUNK_HEAD : H1_STATE_BODY_IDENTITY;
                            h2_ctx->h1_chunk_left = (h2_ctx->h1_content_length > 0) ? (size_t)h2_ctx->h1_content_length : 0;
                        } else {
                            s->h1_body_finished = 1; h2_ctx->h1_state = H1_STATE_STATUS_LINE;
                        }
                    }
                    free(line); 
                    // Call send for the session that was just used for processing
                    nghttp2_session_send(h2_ctx->session);
                    continue;
                }
                char *colon = strchr(line, ':');
                if (colon && h2_ctx->h1_active_stream) {
                    *colon = '\0';
                    char *val = colon + 1;
                    while (*val == ' ' || *val == '\t') val++;
                    stream_ctx_t *s = h2_ctx->h1_active_stream;
                    if (!strcasecmp(line, "Content-Length")) {
                        h2_ctx->h1_content_length = atoll(val);
                    } else if (!strcasecmp(line, "Transfer-Encoding") && strstr(val, "chunked")) {
                        h2_ctx->h1_chunked = 1;
                    }
                    if (!strcasecmp(line, "Host")) {
                        for (size_t i = 0; i < s->headers_count; i++) {
                            if (s->headers[i].namelen == 10 && !memcmp(s->headers[i].name, ":authority", 10)) {
                                free(s->headers[i].value);
                                s->headers[i].value = (uint8_t *)strdup(val);
                                s->headers[i].valuelen = strlen(val);
                                break;
                            }
                        }
                    } else if (strcasecmp(line, "Connection") && strcasecmp(line, "Upgrade") && 
                                strcasecmp(line, "Keep-Alive") && strcasecmp(line, "Proxy-Connection") &&
                                strcasecmp(line, "Transfer-Encoding") && strcasecmp(line, "Content-Length")) {
                        protohttp2_add_header(s, line, val);
                    }
                }
                free(line); break;
            case H1_STATE_BODY_IDENTITY:
                {
                    size_t to_read = MIN(evbuffer_get_length(inbuf), h2_ctx->h1_chunk_left);
                    if (to_read > 0) {
                        unsigned char *data = malloc(to_read);
                        evbuffer_remove(inbuf, data, to_read);
                        evbuffer_add(h2_ctx->h1_active_stream->data_buf, data, to_read);
                        free(data);
                        h2_ctx->h1_chunk_left -= to_read;
                        // Resume data for the correct stream
                        if (h2_ctx->h1_active_stream) {
                            nghttp2_session_resume_data(h2_ctx->session, h2_ctx->h1_active_stream->stream_id);
                        }
                    }
                    if (h2_ctx->h1_chunk_left == 0) {
                        h2_ctx->h1_active_stream->h1_body_finished = 1;
                        if (h2_ctx->h1_active_stream) {
                            nghttp2_session_resume_data(h2_ctx->session, h2_ctx->h1_active_stream->stream_id);
                        }
                        h2_ctx->h1_state = H1_STATE_STATUS_LINE;
                    }
                    // Ensure we always call send to properly step the session state
                    nghttp2_session_send(h2_ctx->session);
                }
                return;
            case H1_STATE_BODY_CHUNK_HEAD:
                if (!(line = evbuffer_readln(inbuf, &l, EVBUFFER_EOL_CRLF))) return;
                h2_ctx->h1_chunk_left = strtoul(line, NULL, 16);
                free(line);
                if (h2_ctx->h1_chunk_left == 0) h2_ctx->h1_state = H1_STATE_BODY_CHUNK_TRAILER;
                else h2_ctx->h1_state = H1_STATE_BODY_CHUNK_DATA;
                continue;
            case H1_STATE_BODY_CHUNK_DATA:
                {
                    size_t to_read = MIN(evbuffer_get_length(inbuf), h2_ctx->h1_chunk_left);
                    if (to_read > 0) {
                        unsigned char *data = malloc(to_read);
                        evbuffer_remove(inbuf, data, to_read);
                        evbuffer_add(h2_ctx->h1_active_stream->data_buf, data, to_read);
                        free(data);
                        h2_ctx->h1_chunk_left -= to_read;
                        if (h2_ctx->h1_active_stream) {
                            nghttp2_session_resume_data(h2_ctx->session, h2_ctx->h1_active_stream->stream_id);
                        }
                    }
                    if (h2_ctx->h1_chunk_left == 0) h2_ctx->h1_state = H1_STATE_BODY_CHUNK_TRAILER;
                    // Ensure we always call send to properly step the session state
                    nghttp2_session_send(h2_ctx->session);
                }
                return;
            case H1_STATE_BODY_CHUNK_TRAILER:
                if (!(line = evbuffer_readln(inbuf, &l, EVBUFFER_EOL_CRLF))) return;
                if (l == 0) {
                        if (evbuffer_get_length(inbuf) == 0 && h2_ctx->h1_chunk_left == 0 && h2_ctx->h1_active_stream) {
                            h2_ctx->h1_active_stream->h1_body_finished = 1;
                            nghttp2_session_resume_data(h2_ctx->session, h2_ctx->h1_active_stream->stream_id);
                            h2_ctx->h1_state = H1_STATE_STATUS_LINE;
                        } else {
                            h2_ctx->h1_state = H1_STATE_BODY_CHUNK_HEAD;
                        }
                }
                free(line); 
                // Call send for the session that was just used for processing
                nghttp2_session_send(h2_ctx->session);
                continue;
        }
    }
    // Always call send at the end to ensure proper session state processing
    nghttp2_session_send(h2_ctx->session);
}

static void NONNULL(1)
protohttp2_bev_readcb_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");

    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    protohttp2_ctx_t *h2_ctx = http_ctx->arg;

    struct evbuffer *inbuf = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(inbuf);
    if (!len) return;

    unsigned char *data = evbuffer_pullup(inbuf, len);

    // This is the trigger that eventually makes on_frame_recv_callback fire
    ssize_t rv = nghttp2_session_mem_recv(h2_ctx->session, data, len);

    if (rv < 0) {
        log_finest_va("nghttp2 error, rv=%zd, msg=%s", rv, nghttp2_strerror((int)rv));
        return;
    }

    evbuffer_drain(inbuf, (size_t)rv);

    // Sometimes receiving a frame (like a SETTINGS frame)
    // requires nghttp2 to send an ACK immediately.
    nghttp2_session_send(h2_ctx->session);
    return;
}

static void NONNULL(1)
protohttp2_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	log_finest("ENTER");

	if (bev == ctx->src.bev) {
		protohttp2_bev_readcb_src_child(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		protohttp2_bev_readcb_dst_child(bev, ctx);
	} else {
		log_err_printf("protohttp2_bev_readcb_child: UNKWN conn end\n");
	}
}

protocol_t protohttp2_setup(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

    // TODO: Send GOAWAY frame to gracefully close the session and wait for it sent, but not here
    // nghttp2_submit_goaway(h2_ctx->session, NGHTTP2_FLAG_NONE, 1, NGHTTP2_NO_ERROR, NULL, 0);
    // nghttp2_session_send(h2_ctx->session);

    ctx->protoctx->proto = PROTO_HTTP2;
    ctx->protoctx->bev_readcb = protohttp2_bev_readcb;
    ctx->protoctx->bev_writecb = protohttp2_bev_writecb;
    ctx->protoctx->proto_free = protohttp2_free;

    protohttp2_ctx_t *h2_ctx = malloc(sizeof(protohttp2_ctx_t));
    if (!h2_ctx) {
        return PROTO_ERROR;
    }
    memset(h2_ctx, 0, sizeof(protohttp2_ctx_t));

    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    h2_ctx->ctx = ctx;
    http_ctx->arg = h2_ctx;
    
    // Initialize session for H2 connections
    nghttp2_session_callbacks *cb; 
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_send_callback(cb, protohttp2_send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, protohttp2_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(cb, protohttp2_on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, protohttp2_on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, protohttp2_on_stream_close_callback);
    nghttp2_session_server_new(&h2_ctx->session, cb, h2_ctx);

	log_finest("Sending initial SETTINGS frame from parent session");
    nghttp2_submit_settings(h2_ctx->session, NGHTTP2_FLAG_NONE, NULL, 0);

    nghttp2_session_callbacks_del(cb);

    return PROTO_HTTP2;
}

protocol_t protohttp2_setup_child(pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");

    // TODO: Send GOAWAY frame to gracefully close the session and wait for it sent, but not here
    // nghttp2_submit_goaway(h2_ctx->session, NGHTTP2_FLAG_NONE, 1, NGHTTP2_NO_ERROR, NULL, 0);
    // nghttp2_session_send(h2_ctx->session);

    ctx->protoctx->proto = PROTO_HTTP2;
    ctx->protoctx->bev_readcb = protohttp2_bev_readcb_child;
    ctx->protoctx->bev_writecb = protohttp2_bev_writecb;
    ctx->protoctx->proto_free = protohttp2_free_child;

    protohttp2_ctx_t *h2_ctx = malloc(sizeof(protohttp2_ctx_t));
    if (!h2_ctx) {
        return PROTO_ERROR;
    }
    memset(h2_ctx, 0, sizeof(protohttp2_ctx_t));

    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    h2_ctx->ctx = ctx;
    http_ctx->arg = h2_ctx;
    
    // Initialize child session for server H2 connections
    nghttp2_session_callbacks *cb; 
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_send_callback(cb, protohttp2_send_callback_child);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, protohttp2_on_frame_recv_callback_child);
    nghttp2_session_callbacks_set_on_header_callback(cb, protohttp2_on_header_callback_child);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, protohttp2_on_data_chunk_recv_callback_child);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, protohttp2_on_stream_close_callback_child);
    nghttp2_session_client_new(&h2_ctx->session, cb, h2_ctx);

	log_finest("Sending initial SETTINGS frame from child session");
    // No need to send max concurrent streams from child - let nghttpd decide based on its own config
    // nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    // nghttp2_submit_settings(h2_ctx->session, NGHTTP2_FLAG_NONE, iv, 1);
    // No need to send initial window update from child - we'll let nghttpd manage flow control and just respond to its WINDOW_UPDATE frames
    // nghttp2_submit_window_update(h2_ctx->session, NGHTTP2_FLAG_NONE, 0, 65535);
    nghttp2_submit_settings(h2_ctx->session, NGHTTP2_FLAG_NONE, NULL, 0);

    nghttp2_session_callbacks_del(cb);
    
    return PROTO_HTTP2;
}
