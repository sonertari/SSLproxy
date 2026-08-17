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

	pxy_conn_ctx_t *ctx;

	// For h2 specific fields, if upgraded
	void *arg;
} protohttp_ctx_t;

typedef struct {
    int code;
    const char *reason;
} http_status_reason_t;

// Common HTTP status codes and their standard reason phrases, sorted by code
static const http_status_reason_t http_status_reasons[] = {
    { 100, "Continue" },
    { 101, "Switching Protocols" },
    { 102, "Processing" },
    { 103, "Early Hints" },
    { 200, "OK" },
    { 201, "Created" },
    { 202, "Accepted" },
    { 203, "Non-Authoritative Information" },
    { 204, "No Content" },
    { 205, "Reset Content" },
    { 206, "Partial Content" },
    { 207, "Multi-Status" },
    { 208, "Already Reported" },
    { 226, "IM Used" },
    { 300, "Multiple Choices" },
    { 301, "Moved Permanently" },
    { 302, "Found" },
    { 303, "See Other" },
    { 304, "Not Modified" },
    { 305, "Use Proxy" },
    { 307, "Temporary Redirect" },
    { 308, "Permanent Redirect" },
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 402, "Payment Required" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 405, "Method Not Allowed" },
    { 406, "Not Acceptable" },
    { 407, "Proxy Authentication Required" },
    { 408, "Request Timeout" },
    { 409, "Conflict" },
    { 410, "Gone" },
    { 411, "Length Required" },
    { 412, "Precondition Failed" },
    { 413, "Payload Too Large" },
    { 414, "URI Too Long" },
    { 415, "Unsupported Media Type" },
    { 416, "Range Not Satisfied" },
    { 417, "Expectation Failed" },
    { 421, "Misdirected Request" },
    { 422, "Unprocessable Entity" },
    { 423, "Locked" },
    { 424, "Failed Dependency" },
    { 425, "Too Early" },
    { 426, "Upgrade Required" },
    { 428, "Precondition Required" },
    { 429, "Too Many Requests" },
    { 431, "Request Header Fields Too Large" },
    { 451, "Unavailable For Legal Reasons" },
    { 500, "Internal Server Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 504, "Gateway Timeout" },
    { 505, "HTTP Version Not Supported" },
    { 506, "Variant Also Negotiates" },
    { 507, "Insufficient Storage" },
    { 508, "Loop Detected" },
    { 510, "Not Extended" },
    { 511, "Network Authentication Required" }
};

void protohttp_log_connect(pxy_conn_ctx_t *, protohttp_ctx_t *) NONNULL(1,2);

int protohttpx_apply_filter(void *, protocol_t);

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

const char *http_get_reason_phrase(int status_code);

#endif /* !PROTOHTTP_H */

/* vim: set noet ft=c: */
