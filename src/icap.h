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

#ifndef ICAP_H
#define ICAP_H

#ifndef WITHOUT_ICAP

#include "pxyconn.h"
#include "protohttp2.h"
#include "attrib.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>

/* Helper to select the src or dst state based on reqmod flag */
#define ICAP_STATE(svc, reqmod) ((reqmod) ? &(svc)->src : &(svc)->dst)

/*
 * ICAP Service Configuration
 */
typedef enum icap_fail_mode {
	ICAP_FAIL_CLOSE = 0,
	ICAP_FAIL_OPEN
} icap_fail_mode_t;

typedef struct icap_service {
	char *server;                        /* ICAP server hostname/IP */
	int port;                            /* ICAP server port */
	char *reqmod;                        /* REQMOD path component of the ICAP URI (e.g. /reqmod) */
	char *respmod;                       /* RESPMOD path component of the ICAP URI (e.g. /respmod) */
	icap_fail_mode_t icap_fail_open : 1; /* 0: stop, 1: next service in chain on service error */
	icap_fail_mode_t conn_fail_open : 1; /* 0: block, 1: pass through conn on service error */
	unsigned int timeout;                /* Timeout in seconds */
	size_t preview_size;                 /* Preview slice size in bytes; 0 = preview disabled */
	size_t max_body_size;                /* Max body size; 0 = disabled */
	unsigned int allow_204 : 1;          /* 0: Don't allow 204 responses from ICAP, treat as error; 1: Allow 204 responses */
	unsigned int allow_206 : 1;          /* 0: Don't allow 206 responses from ICAP, treat as error; 1: Allow 206 responses */
	char *echo_header;                   /* Header in reqmod to echo to respmod */

	struct icap_service *next;           /* Linked list for configuration */
} icap_service_t;

typedef struct icap_service_ctx icap_service_ctx_t;
typedef void (*proto_data_submit_cb)(icap_ctx_t *) NONNULL(1);
typedef void (*proto_failopen_to_dest_cb)(icap_service_ctx_t *) NONNULL(1);

/*
 * ICAP context - per-connection state for ICAP processing
 */
struct icap_ctx {
	pxy_conn_ctx_t *conn_ctx;
	stream_ctx_t *stream_ctx;         /* For HTTP/2, the stream context */
	protohttp2_ctx_t *h2_ctx;         /* For HTTP/2, the HTTP/2 context */

	unsigned int is_veto : 1;         /* 1 if ICAP server vetoed the transaction */
	unsigned int sent_veto_page : 1;  /* 1 if veto page sent to client */
	struct evbuffer *veto_hdr;        /* The block page headers to inject to the client */
	struct evbuffer *veto_body;       /* The block page body to inject to the client */

	unsigned int reqmod : 1;          /* 1: reqmod or respmod */

#define ICAP_MAX_SERVICES 16          /* Max services per connection */
    icap_service_ctx_t *services[ICAP_MAX_SERVICES];
    int service_count;		          /* Number of services in the services list */

	char *icap_extended_headers;

	size_t src_http_content_length;
	unsigned int  src_http_content_length_set : 1; /* Whether http_content_length is set based on HTTP header info */
	size_t dst_http_content_length;
	unsigned int  dst_http_content_length_set : 1;

	unsigned int made_progress : 1;
	unsigned int term : 1;            /* 1 if ICAP context is ready to be terminated */

	struct event *chain_ev;
	int chain_ev_service_idx;

	proto_data_submit_cb send_data_to_src_cb;
	proto_data_submit_cb send_data_to_dst_cb;
	proto_failopen_to_dest_cb failopen_to_dest_cb;
};

typedef struct icap_service_state {
	unsigned int received_icap_headers : 1;

	size_t header_offset;
	size_t body_offset;

	unsigned int has_body : 1;
	unsigned int null_body : 1;       /* Whether body is null based on header info */

	struct evbuffer *in_hdr;
	struct evbuffer *sent_hdr;
	size_t sent_hdr_size;

	struct evbuffer *out_hdr;

	unsigned int received_http_headers : 1;
	size_t received_hdr_size;

	struct evbuffer *in_body;
	struct evbuffer *sent_body;

	struct evbuffer *out_body;

	size_t remaining_chunk_size;
	size_t sent_body_size;
	unsigned int content_complete : 1;

	unsigned int wait_preview_continue : 1;
	unsigned int detected_204 : 1;    /* Whether 204 detected in ICAP response */
	unsigned int detected_206 : 1;    /* Whether 206 detected in ICAP response */
	size_t use_original_body;         /* Offset of unmodified body indicated by use-original-body extension with 206 */
	size_t body_chunk_len_206;        /* Body chunk length in use-original-body extension with 206 */

	unsigned int wait_terminator : 1;
} icap_service_state_t;

struct icap_service_ctx {
	struct icap_service *svc;         /* ICAP service config */
	icap_ctx_t *icap_ctx;             /* ICAP context for this service */

	int idx;
	struct bufferevent *bev;          /* bufferevent for this service */
	unsigned int failopen : 1;

	char *echo_header;                /* Header in reqmod to echo to respmod */

	icap_service_state_t src;
	icap_service_state_t dst;
};

void icap_ctx_free(icap_ctx_t *, int);
icap_ctx_t *icap_init(pxy_conn_ctx_t *, stream_ctx_t *, protohttp2_ctx_t *) NONNULL(1);
char *icap_chain_str(conn_opts_t *);

/*
 * ICAP chain orchestration
 */
int icap_enabled(icap_ctx_t *);
int icap_is_finished(icap_ctx_t *);
struct evbuffer *icap_get_first_service_in_hdr(icap_ctx_t *) NONNULL(1);
struct evbuffer *icap_get_last_service_out_body(icap_ctx_t *) NONNULL(1);
struct evbuffer *icap_get_last_service_out_hdr(icap_ctx_t *) NONNULL(1);

void icap_service_free(icap_service_t *);
icap_service_t *icap_service_copy(icap_service_t *);
int load_icap_line(conn_opts_t *, const char *, unsigned int) NONNULL(1,2);
int load_icap_struct(conn_opts_t *, unsigned int *, FILE *);

int icap_set_extended_headers(icap_ctx_t *, int) NONNULL(1);
void icap_disconnect(icap_ctx_t *, int) NONNULL(1);

void icap_process_data(struct evbuffer *, icap_ctx_t *) NONNULL(1,2);

#endif /* !WITHOUT_ICAP */

#endif /* !ICAP_H */

/* vim: set noet ft=c: */
