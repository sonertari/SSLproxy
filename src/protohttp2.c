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

#ifndef WITHOUT_ICAP
#include "icap.h"
#endif /* !WITHOUT_ICAP */

#include <event2/bufferevent.h>
#include <nghttp2/nghttp2.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <ctype.h>

static ssize_t
protohttp2_provider_read_callback(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
    uint32_t *data_flags, nghttp2_data_source *source, void *user_data);

#ifndef WITHOUT_ICAP
static void NONNULL(1) protohttp2_icap_send_data_to_src_cb(icap_ctx_t *icap_ctx);
static void NONNULL(1) protohttp2_icap_send_data_to_dst_cb(icap_ctx_t *icap_ctx);
#endif /* !WITHOUT_ICAP */

static stream_ctx_t *
protohttp2_get_stream_ctx(protohttp2_ctx_t *h2_ctx, int32_t stream_id)
{
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    stream_ctx_t *s = h2_ctx->streams;
    while (s) {
        if (s->stream_id == stream_id)
            return s;
        s = s->next;
    }

    log_finest_va("Cannot find stream context for stream_id=%d", stream_id);
    return NULL;
}

static stream_ctx_t *
protohttp2_new_stream_ctx(protohttp2_ctx_t *h2_ctx, int32_t stream_id)
{
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    log_finest_va("ENTER, stream_id=%d", stream_id);
    stream_ctx_t *s = malloc(sizeof(stream_ctx_t));
    if (!s)
        return NULL;
    memset(s, 0, sizeof(stream_ctx_t));
    s->stream_id = stream_id;
    s->ctx = ctx;
    s->data_buf = evbuffer_new();

    // Set up the data provider hook
    s->provider.source.ptr = s;
    s->provider.read_callback = protohttp2_provider_read_callback;

#ifndef WITHOUT_ICAP
    s->icap_ctx = icap_init(ctx, s, h2_ctx);
	if (!s->icap_ctx) {
        evbuffer_free(s->data_buf);
        free(s);
		return NULL;
    }
    s->icap_ctx->send_data_to_src_cb = protohttp2_icap_send_data_to_src_cb;
    s->icap_ctx->send_data_to_dst_cb = protohttp2_icap_send_data_to_dst_cb;
#endif /* !WITHOUT_ICAP */

    s->next = h2_ctx->streams;
    h2_ctx->streams = s;
    return s;
}

static void
protohttp2_free_stream_headers(stream_ctx_t *s)
{
    for (size_t i = 0; i < s->headers_count; i++) {
        if (s->headers[i].name) {
            free(s->headers[i].name);
            s->headers[i].name = NULL;
        }
        if (s->headers[i].value) {
            free(s->headers[i].value);
            s->headers[i].value = NULL;
        }
    }
    s->headers_count = 0;
    s->headers_capacity = 0;

    free(s->headers);
    s->headers = NULL;
}

// TODO: This function is not used anywhere, but we may need it to terminate connection when all streams are closed.
// int
// protohttp2_stream_count(protohttp2_ctx_t *h2_ctx)
// {
//     int count = 0;
//     stream_ctx_t *s = h2_ctx->streams;
//     while (s) {
//         count++;
//         s = s->next;
//     }
//     return count;
// }

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
        protohttp2_free_stream_headers(s);
    }
    if (s->data_buf) evbuffer_free(s->data_buf);

#ifndef WITHOUT_ICAP
    if (s->icap_ctx) {
        icap_disconnect(s->icap_ctx);
    }
#endif /* !WITHOUT_ICAP */

    free(s);
}

#ifndef WITHOUT_ICAP
static struct evbuffer *
protohttp2_get_h1_headers(stream_ctx_t *s)
{
    pxy_conn_ctx_t *ctx = s->ctx;
    log_finest("ENTER");

    struct evbuffer *buf = evbuffer_new();
    if (!buf)
        return NULL;

    int method_idx = -1, path_idx = -1, status_idx = -1, authority_idx = -1;

    nghttp2_nv *headers = s->headers;
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

    if (status_idx != -1) {
        // log_finest_va("status_idx=%d", status_idx);
        log_finest_va("HTTP/1.1 %.*s", (int)headers[status_idx].valuelen, (char *)headers[status_idx].value);

        // TODO: Add the correct reason phrase, otherwise E2Guardian icap service does not respond, we just use "OK" as a placeholder for now.
        evbuffer_add_printf(buf, "HTTP/1.1 %.*s OK\r\n", (int)headers[status_idx].valuelen, (char *)headers[status_idx].value);
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

static char *
trim_whitespace(char *str, size_t *len)
{
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) {
        *len = 0;
        return str;
    }
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    if (len) *len = end - str + 1;
    return str;
}

static int
protohttp2_add_nv_header(stream_ctx_t *s, const char *name, size_t namelen, const char *value, size_t valuelen)
{
    pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("%.*s: %.*s", (int)namelen, name, (int)valuelen, value);

    if (s->headers_count >= s->headers_capacity) {
        size_t new_capacity = s->headers_capacity == 0 ? 16 : s->headers_capacity * 2;
        nghttp2_nv *tmp = realloc(s->headers, new_capacity * sizeof(nghttp2_nv));
        if (!tmp) {
            log_fine("Failed reallocating headers");
            return -1;
        }
        s->headers = tmp;
        s->headers_capacity = new_capacity;
    }

    nghttp2_nv *nv = &s->headers[s->headers_count];

    nv->name = malloc(namelen);
    if (!nv->name) return -1;
    memcpy(nv->name, name, namelen);
    nv->namelen = namelen;

    // HTTP/2 mandates strict lowercase header names
    for (size_t i = 0; i < nv->namelen; i++) {
        nv->name[i] = tolower(nv->name[i]);
    }

    nv->value = malloc(valuelen);
    if (!nv->value) {
        free(nv->name);
        return -1;
    }
    memcpy(nv->value, value, valuelen);
    nv->valuelen = valuelen;

    nv->flags = NGHTTP2_NV_FLAG_NONE;
    s->headers_count++;
    return 0;
}

int
protohttp2_get_h2_headers(stream_ctx_t *s, struct evbuffer *h1_buf)
{
    pxy_conn_ctx_t *ctx = s->ctx;
    log_finest("ENTER");

    // Clean slate for this stream context's header holder
    if (s->headers) {
        protohttp2_free_stream_headers(s);
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
                    if (protohttp2_add_nv_header(s, ":method", 7, method, m_len) < 0 ||
                        protohttp2_add_nv_header(s, ":path", 5, path, p_len) < 0 ||
                        protohttp2_add_nv_header(s, ":scheme", 7, "https", 5) < 0) {
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
                    if (protohttp2_add_nv_header(s, ":status", 7, status, s_len) < 0) {
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
                if (protohttp2_add_nv_header(s, ":authority", 10, h_value, v_len) < 0) {
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
                if (protohttp2_add_nv_header(s, h_name, n_len, h_value, v_len) < 0) {
                    free(line);
                    return -1;
                }
            }
        }
        free(line);
    }

    return 0;
}

static void NONNULL(1, 2)
protohttp2_bev_writecb(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
    // TODO: Remove this callback and use the callback in https code
	pxy_conn_ctx_t *ctx = arg;
	log_finest("ENTER");
}

static ssize_t
protohttp2_send_callback_src(UNUSED nghttp2_session *session, const uint8_t *data, size_t length, UNUSED int flags, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest("ENTER");

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

    if (bufferevent_write(ctx->dst.bev, data, length) == -1)
        return NGHTTP2_ERR_CALLBACK_FAILURE;

    return (ssize_t)length;
}

static int
protohttp2_on_header_callback(UNUSED nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, UNUSED uint8_t flags, void *user_data)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    if (frame->hd.type != NGHTTP2_HEADERS) {
        log_finest("Not a HEADERS frame, ignoring");
        return 0;
    }

    stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id);
    if (!s) {
        s = protohttp2_new_stream_ctx(h2_ctx, frame->hd.stream_id);
    }

    if (s) {
        if (s->headers_count == s->headers_capacity) {
            s->headers_capacity = s->headers_capacity ? s->headers_capacity * 2 : 16;
            s->headers = realloc(s->headers, s->headers_capacity * sizeof(nghttp2_nv));
        }

        log_finest_va("%.*s=%.*s", (int)namelen, name, (int)valuelen, value);

        nghttp2_nv *nv = &s->headers[s->headers_count++];
        nv->name = malloc(namelen);
        memcpy(nv->name, name, namelen);
        nv->namelen = namelen;
        nv->value = malloc(valuelen);
        memcpy(nv->value, value, valuelen);
        nv->valuelen = valuelen;
        nv->flags = NGHTTP2_NV_FLAG_NONE;
    }
    else {
        log_finest_va("Cannot save header for stream_id=%d: %.*s=%.*s", frame->hd.stream_id, (int)namelen, name, (int)valuelen, value);
    }
    return 0;
}

void
protohttp2_trigger_write_loop(protohttp2_ctx_t *h2_ctx, int reqmod)
{
    const uint8_t *binary_payload;

    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest_va("ENTER, reqmod=%d", reqmod);

    // ATTENTION: The other side of the connection (client or server) is the session for sending data
    nghttp2_session *session = reqmod ? h2_ctx->dst_session : h2_ctx->src_session;
    struct bufferevent *bev = reqmod ? ctx->dst.bev : ctx->src.bev;

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
    stream_ctx_t *s = source->ptr;
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
        protohttp2_ctx_t *h2_ctx = s->icap_ctx->h2_ctx;
        pxy_conn_ctx_t *ctx = h2_ctx->ctx;

        log_finest_va("Set NGHTTP2_DATA_FLAG_EOF for stream_id=%d", s->stream_id);
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
#endif /* !WITHOUT_ICAP */

    return to_read;
}

static int
protohttp2_submit_data(protohttp2_ctx_t *h2_ctx, stream_ctx_t *s, int reqmod)
{
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    int rv = 0;
    
    if (s->headers_count > 0) {
        log_finest_va("Submit headers, headers_count=%zu, stream_id=%d, reqmod=%d", s->headers_count, s->stream_id, reqmod);

        if (reqmod) {
            rv = nghttp2_submit_request(h2_ctx->dst_session, NULL, s->headers, s->headers_count, &s->provider, h2_ctx);
            if (rv < 0) {
                log_finest_va("Fatal: nghttp2_submit_request failed: %s", nghttp2_strerror(rv));
                return -1;
            }
            s->stream_id = rv;
        }
        else {
            rv = nghttp2_submit_response(h2_ctx->src_session, s->stream_id, s->headers, s->headers_count, &s->provider);
            if (rv < 0) {
                log_finest_va("Fatal: nghttp2_submit_response failed: %s", nghttp2_strerror(rv));
                return -1;
            }
        }
        protohttp2_free_stream_headers(s);
    }

    if (evbuffer_get_length(s->data_buf) > 0) {
        log_finest_va("Submit data, data_len=%zu, stream_id=%d, reqmod=%d", evbuffer_get_length(s->data_buf), s->stream_id, reqmod);

        rv = nghttp2_session_resume_data(reqmod ? h2_ctx->dst_session : h2_ctx->src_session, s->stream_id);

        if (rv == NGHTTP2_ERR_INVALID_ARGUMENT) {
            // Clean operational bypass: The engine is already active and polling.
            log_finest_va("Stream %d already active, continuing to explicit write execution.", s->stream_id);
        }
        else if (rv < 0) {
            log_finest_va("Fatal: nghttp2_session_resume_data failed: %s", nghttp2_strerror(rv));
            return -1;
        }
    }

    // Clean Data Wakeup Flush. 
    log_finest_va("Executing scheduled session frame serialization loop for stream %d", s->stream_id);
    protohttp2_trigger_write_loop(h2_ctx, reqmod);

    return 0;
}

#ifndef WITHOUT_ICAP
static void NONNULL(1)
protohttp2_icap_send_data_to_src_cb(icap_ctx_t *icap_ctx)
{
    stream_ctx_t *s = icap_ctx->stream_ctx;
    protohttp2_ctx_t *h2_ctx = icap_ctx->h2_ctx;
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    log_finest_va("ENTER, stream_id=%d, veto_hdr=%zu, veto_body=%zu, data_buf=%zu", s->stream_id,
        evbuffer_get_length(icap_ctx->veto_hdr), evbuffer_get_length(icap_ctx->veto_body), evbuffer_get_length(s->data_buf));

    protohttp2_get_h2_headers(s, icap_ctx->veto_hdr);

    evbuffer_add_buffer(s->data_buf, icap_ctx->veto_body);

    // Send block page to src (client), not dst (server)
    if (protohttp2_submit_data(h2_ctx, s, 0 /*respmod*/) < 0) {
        log_finest_va("Failed to submit data for stream_id=%d", s->stream_id);
        return;
    }
    icap_ctx->made_progress = 1;
}

static void NONNULL(1)
protohttp2_icap_send_data_to_dst_cb(icap_ctx_t *icap_ctx)
{
    stream_ctx_t *s = icap_ctx->stream_ctx;
    protohttp2_ctx_t *h2_ctx = icap_ctx->h2_ctx;
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;

    struct evbuffer *out_hdr = icap_get_last_service_out_hdr(icap_ctx);
    protohttp2_get_h2_headers(s, out_hdr);

    struct evbuffer *out_body = icap_get_last_service_out_body(icap_ctx);
    evbuffer_add_buffer(s->data_buf, out_body);

    log_finest_va("ENTER, stream_id=%d, data_buf=%zu", s->stream_id, evbuffer_get_length(s->data_buf));

    if (protohttp2_submit_data(h2_ctx, s, icap_ctx->reqmod) < 0) {
        log_finest_va("Failed to submit data for stream_id=%d", s->stream_id);
        return;
    }
    icap_ctx->made_progress = 1;
}
#endif /* !WITHOUT_ICAP */

static int
protohttp2_on_frame_recv(UNUSED nghttp2_session *session, const nghttp2_frame *frame, void *user_data, int reqmod)
{
    protohttp2_ctx_t *h2_ctx = (protohttp2_ctx_t *)user_data;

    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest_va("ENTER, frame_type=0x%02x, reqmod=%d", frame->hd.type, reqmod);

    if (frame->hd.type == NGHTTP2_GOAWAY) {
        log_finest("NGHTTP2_GOAWAY received");
        // TODO: Do we need to trigger a write loop here? Does not seem to have any effect.
        // The nghttp2 library should handle this automatically, but we can force a flush to ensure any pending frames are sent.
        // nghttp2_session_send(session);
    }

    if (frame->hd.type == NGHTTP2_WINDOW_UPDATE) {
        log_finest("NGHTTP2_WINDOW_UPDATE received");
        // TODO: Do we need to trigger a write loop here?
        // nghttp2_session_send(session);
    }

    // Check if we received the SETTINGS ACK from the server
    // if (frame->hd.type == NGHTTP2_SETTINGS && (frame->hd.flags & NGHTTP2_FLAG_ACK))
    if (frame->hd.type == NGHTTP2_SETTINGS) {
        if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
            log_finest("NGHTTP2_SETTINGS ACK received from client/server");
        } else {
            log_finest("NGHTTP2_SETTINGS parameter adjustments received");
        }

        // If we were manually holding data, trigger a write now
        // TODO: Do we need to trigger a write loop here?
        // nghttp2_session_send(session);
    }

    // if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE)
    if (frame->hd.type == NGHTTP2_HEADERS) {
        log_finest("NGHTTP2_HEADERS received");

        stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, frame->hd.stream_id);
        if (s) {
#ifndef WITHOUT_ICAP
            if (icap_enabled(s->icap_ctx)) {
                s->icap_ctx->reqmod = reqmod;

                struct evbuffer *outbuf_ptr = icap_get_first_service_in_hdr(s->icap_ctx);
                struct evbuffer *header_buf = protohttp2_get_h1_headers(s);

                protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

                if (reqmod) {
                    if (protohttp_filter_request_header(header_buf, outbuf_ptr, http_ctx, ctx->type, ctx) == -1) {
                        evbuffer_free(header_buf);
                        return -1;
                    }
                }
                else {
                    protohttp_filter_response_header(header_buf, outbuf_ptr, http_ctx, ctx);
                }

                evbuffer_free(header_buf);

                icap_process_data(s->data_buf, s->icap_ctx);
                return 0;
            }
#endif /* !WITHOUT_ICAP */

            // TODO: Filter h2 request/response headers
            return protohttp2_submit_data(h2_ctx, s, reqmod);
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
    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest_va("stream_id=%d, len=%zu", stream_id, len);

    stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, stream_id);
    if (!s) {
        nghttp2_session_consume(session, stream_id, len);
        return 0;
    }

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

    pxy_conn_ctx_t *ctx = h2_ctx->ctx;
    log_finest_va("stream_id=%d", stream_id);

    stream_ctx_t *s = protohttp2_get_stream_ctx(h2_ctx, stream_id);
    if (s) {
#ifndef WITHOUT_ICAP
        if (icap_enabled(s->icap_ctx) && !icap_is_finished(s->icap_ctx)) {
            log_finest("ICAP not finished yet, do not terminate stream");
            return 0;
		}
#endif /* !WITHOUT_ICAP */
        log_finest("Terminate stream");
        protohttp2_free_stream_ctx(h2_ctx, s);
        return 0;
    }
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

void protohttp2_free(pxy_conn_ctx_t *ctx)
{
    protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    if (!http_ctx) {
        return;
    }

    protohttp2_ctx_t *h2_ctx = http_ctx->arg;
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
            protohttp2_free_stream_ctx(h2_ctx, h2_ctx->streams);
        free(h2_ctx);
        http_ctx->arg = NULL;
    }
    protohttps_free(ctx);
}

static void NONNULL(1)
protohttp2_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
    if (!http_ctx) {
        log_finest("protohttp2_bev_readcb: http_ctx is NULL");
        return;
    }

    int seen_resp_header_on_entry = http_ctx->seen_resp_header;

	if (bev == ctx->src.bev || bev == ctx->dst.bev) {
        int reqmod = bev == ctx->src.bev;
        log_finest_va("ENTER, reqmod=%d", reqmod);

        protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
        protohttp2_ctx_t *h2_ctx = http_ctx->arg;
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
            pxy_conn_term(h2_ctx->ctx, reqmod);
        }
        else {
            // Always call nghttp2_session_send() to process pending frames
            // This is to ensure the HTTP/2 state machine is properly stepped
            nghttp2_session_send(reqmod ? h2_ctx->src_session : h2_ctx->dst_session);

            // TODO: Do we need to trigger the write loop here?
            // protohttp2_trigger_write_loop(h2_ctx, reqmod);
        }
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

	if (!seen_resp_header_on_entry && http_ctx->seen_resp_header) {
		/* response header complete: log connection */
		if (WANT_CONNECT_LOG(ctx->conn)) {
			protohttp_log_connect(ctx);
		}
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

    return PROTO_HTTP2;
}
