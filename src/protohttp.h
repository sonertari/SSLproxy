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
	char *http_content_length;

	unsigned int not_valid : 1;            /* 1 if cannot find HTTP on first line */
	unsigned int seen_keyword_count;
	long long unsigned int seen_bytes;

	// For h2 specific fields, if upgraded
	void *arg;
} protohttp_ctx_t;

void protohttp_log_connect(pxy_conn_ctx_t *, protohttp_ctx_t *) NONNULL(1,2);

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
