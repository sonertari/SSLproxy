/*-
 * SSLproxy
 *
 * Copyright (c) 2017-2026, Soner Tari <sonertari@gmail.com>.
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
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

#ifndef PROTOHTTP_H
#define PROTOHTTP_H

#include "pxyconn.h"

typedef struct protohttp_ctx {
	unsigned int seen_req_header : 1;      /* 0 until request header complete */
	unsigned int seen_resp_header : 1;     /* 0 until response hdr complete */
	unsigned int sent_http_conn_close : 1; /* 0 until Conn: close sent */
	unsigned int ocsp_denied : 1;          /* 1 if OCSP was denied */

#ifndef WITHOUT_ICAP
	struct evbuffer *in_hdr;               /* tmp buffer for http headers */
#endif /* !WITHOUT_ICAP */

	/* log strings from HTTP request */
	char *http_method;
	char *http_uri;
	char *http_host;
	char *http_content_type;

	/* log strings from HTTP response */
	char *http_status_code;
	char *http_status_text;
	char *src_http_content_length;
	char *dst_http_content_length;

	unsigned int not_valid : 1;            /* 1 if cannot find HTTP on first line */
	unsigned int seen_keyword_count;
	long long unsigned int seen_bytes;

	pxy_conn_ctx_t *ctx;
} protohttp_ctx_t;

typedef struct {
    int code;
    const char *reason;
} http_status_reason_t;

#ifndef WITHOUT_ICAP
#define PROTOHTTPX_ICAP_FIELD icap_ctx_t *icap_ctx;
#else
#define PROTOHTTPX_ICAP_FIELD
#endif

#ifndef WITHOUT_MIRROR
#define PROTOHTTPX_MIRROR_FIELD unsigned int log_mirror : 1;
#else
#define PROTOHTTPX_MIRROR_FIELD
#endif

#define PROTOHTTPX_STREAM_CTX \
    /* We use int64_t for stream ids to use common stream id type for both H2 and H3, as H3 uses int64_t stream ids. */ \
    int64_t src_stream_id; /* stream id on the client side */ \
    int64_t dst_stream_id; /* stream id on the server side */ \
    pxy_conn_ctx_t *ctx; \
    size_t headers_count; \
    size_t headers_capacity; \
    struct evbuffer *data_buf; \
    size_t src_sent_body_size; \
    size_t dst_sent_body_size; \
    PROTOHTTPX_ICAP_FIELD \
    protohttp_ctx_t *http_ctx; \
    unsigned int src_end_stream : 1; /* 1 after FIN/END_STREAM */ \
    unsigned int dst_end_stream : 1; \
    unsigned int closed : 1;   /* 1 if stream is closing, set after the first on_stream_close event */ \
    unsigned int term : 1;     /* 1 if stream is ready to be terminated */ \
    int ref_count;             /* Active users on the C call stack */ \
    int deferred_free_pending; /* Flag indicating we want to free this */ \
    struct event *ev_free;     /* Libevent timer event to execute the free */ \
    conn_opts_t *conn_opts; \
	unsigned int log_connect : 1; \
	unsigned int log_content : 1; \
	unsigned int log_pcap : 1; \
    PROTOHTTPX_MIRROR_FIELD \
	/* The precedence of filtering rule applied, precedence can only go up not down */ \
	unsigned int filter_precedence;

typedef struct protohttpx_stream_ctx {
    PROTOHTTPX_STREAM_CTX
} protohttpx_stream_ctx_t;

// Dummy common nv header struct for H2/H3
typedef struct {
    uint8_t *name;
    uint8_t *value;
    size_t namelen;
    size_t valuelen;
    uint8_t flags;
} protohttpx_nv_t;

typedef int (*filter_header_t)(protohttpx_stream_ctx_t *);

void protohttp_log_connect(pxy_conn_ctx_t *, protohttp_ctx_t *, unsigned int) NONNULL(1,2);

void protohttpx_free_nv_headers(protohttpx_stream_ctx_t *) NONNULL(1);
int protohttpx_add_nv_header(protohttpx_stream_ctx_t *, const char *,  size_t, const char *, size_t) WUNRES NONNULL(1,2,4);

#ifndef WITHOUT_ICAP
struct evbuffer *protohttpx_get_h1_headers(protohttpx_stream_ctx_t *) WUNRES NONNULL(1);
int protohttpx_get_hx_headers(protohttpx_stream_ctx_t *, struct evbuffer *, int) WUNRES NONNULL(1,2);
#endif /* !WITHOUT_ICAP */

int protohttpx_filter_request_header(protohttpx_stream_ctx_t *s) WUNRES NONNULL(1);
int protohttpx_filter_response_header(protohttpx_stream_ctx_t *s) WUNRES NONNULL(1);

int protohttp_filter_request_header(struct evbuffer *, struct evbuffer *, protohttp_ctx_t *, enum conn_type, pxy_conn_ctx_t *) WUNRES NONNULL(1,2,3,5);
void protohttp_filter_response_header(struct evbuffer *, struct evbuffer *, protohttp_ctx_t *, pxy_conn_ctx_t *) NONNULL(1,2,3,4);

int protohttp_validate(pxy_conn_ctx_t *) NONNULL(1);

void protohttp_free_ctx(protohttp_ctx_t *) NONNULL(1);
void protohttps_free(pxy_conn_ctx_t *) NONNULL(1);
void protohttp_free_child(pxy_conn_child_ctx_t *) NONNULL(1);

protocol_t protohttp_setup(pxy_conn_ctx_t *) NONNULL(1);
protocol_t protohttps_setup(pxy_conn_ctx_t *) NONNULL(1);

protocol_t protohttp_setup_child(pxy_conn_child_ctx_t *) NONNULL(1);
protocol_t protohttps_setup_child(pxy_conn_child_ctx_t *) NONNULL(1);

#endif /* !PROTOHTTP_H */

/* vim: set noet ft=c: */
