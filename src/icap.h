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
#include "attrib.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>

/*
 * ICAP Service Configuration
 */
typedef enum icap_service_type {
	ICAP_SERVICE_SERIAL_MODIFYING = 0,
	ICAP_SERVICE_PARALLEL_INSPECT
} icap_service_type_t;

typedef enum icap_fail_mode {
	ICAP_FAIL_CLOSE = 0,
	ICAP_FAIL_OPEN
} icap_fail_mode_t;

typedef struct icap_service {
	char *server;                        /* ICAP server hostname/IP */
	int port;                            /* ICAP server port */
	char *uri;                           /* Full ICAP URI (e.g. icap://127.0.0.1/echo) */
	icap_service_type_t type : 1;        /* Modifying vs Inspect */
	icap_fail_mode_t icap_fail_open : 1; /* 0: stop, 1: next service in chain on service error */
	icap_fail_mode_t conn_fail_open : 1; /* 0: block, 1: pass through conn on service error */

	struct icap_service *next;           /* Linked list for configuration */
} icap_service_t;

/*
 * ICAP connection states
 */
typedef enum icap_state {
	ICAP_STATE_IDLE = 0,           /* Not connected to ICAP server */
	ICAP_STATE_CONNECTING,         /* Connecting to ICAP server */
	ICAP_STATE_OPTIONS_REQ,        /* Sending OPTIONS request */
	ICAP_STATE_OPTIONS_RESP,       /* Waiting for OPTIONS response */
	ICAP_STATE_RESPMOD_REQ,        /* Sending RESPMOD request */
	ICAP_STATE_RESPMOD_RESP,       /* Waiting for RESPMOD response */
	ICAP_STATE_REQ_HDR,            /* Sending REQMOD request header */
	ICAP_STATE_REQ_BODY,           /* Sending request body to ICAP */
	ICAP_STATE_RESP_HDR,           /* Waiting for ICAP response header */
	ICAP_STATE_RESP_BODY,          /* Receiving adapted response body */
	ICAP_STATE_DONE,               /* ICAP processing complete */
	ICAP_STATE_ERROR,              /* Error occurred */
	ICAP_STATE_PREVIEW_WAIT        /* Preview sent, waiting for 100-Continue or 204 */
} icap_state_t;

typedef enum {
    ICAP_READ_STATE_WAIT_HEADERS,
    ICAP_READ_STATE_WAIT_BODY,
    ICAP_READ_STATE_PROCESSING,
    ICAP_READ_STATE_PREVIEW_RESPONSE, /* Waiting for 100/204 after preview chunk */
} icap_response_state_t;

typedef struct icap_service_ctx icap_service_ctx_t;

/*
 * ICAP context - per-connection state for ICAP processing
 */
struct icap_ctx {
	/* Current state */
	icap_state_t state;

	/* ICAP server configuration */
	char *server;                     /* ICAP server hostname */
	int port;                         /* ICAP server port */

	// TODO: Make these service specific options, instead of global per connection options
	unsigned int timeout;             /* Timeout in seconds */
	size_t max_body_size;             /* Max body size; 0 = disabled */
	size_t preview_size;              /* Bytes in the preview window; 0 = disabled */

	/* Buffers for ICAP protocol */
	struct evbuffer *icap_buf;        /* ICAP protocol buffer */

	struct bufferevent *conn_bev;
	pxy_conn_ctx_t *conn_ctx;
	unsigned int reqmod : 1;          /* 1: reqmod or respmod */

	/* ICAP processing state */
	unsigned int pending : 1;         /* 1: waiting for ICAP response */
	unsigned int done : 1;            /* 1: ICAP request done */

	unsigned int sent_hdr : 1;        /* 1: ICAP header sent */
	struct evbuffer *hdr;             /* hdr buffer */

	struct evbuffer *body;            /* body buffer */

	/* Chain State Tracking */
	icap_service_t *current_service;  /* Pointer to the current active service in the chain */
	icap_service_ctx_t *serial_ctx;   /* Context for the active serial service, if any */
	int parallel_service_count;       /* Number of parallel services currently active */
#define ICAP_MAX_PARALLEL 8           /* Concurrent connections to parallel services */
	icap_service_ctx_t *parallel_ctx[ICAP_MAX_PARALLEL];

	/* Veto */
	unsigned int is_veto : 1;         /* 1 if ICAP server vetoed the transaction */
	struct evbuffer *veto_page;       /* The block page body to inject to the client */
};

struct icap_service_ctx {
	icap_ctx_t *icap_ctx;             /* ICAP context for this service */
	struct icap_service *svc;         /* ICAP service config */
	struct bufferevent *bev;          /* bufferevent for this service */
	icap_response_state_t read_state; /* Read state */
	icap_service_type_t type : 1;     /* Modifying vs Inspect */
	int idx;                          /* Index in parallel array if parallel service */
};

/*
 * ICAP context management
 */
icap_ctx_t *icap_ctx_new(void) MALLOC;
void icap_ctx_free(icap_ctx_t *);
icap_ctx_t *icap_init(void);

/*
 * ICAP chain orchestration
 */
int icap_enabled(pxy_conn_ctx_t *) NONNULL(1);

void icap_service_free(icap_service_t *);
icap_service_t *icap_service_copy(icap_service_t *);
int icap_chain_parse_spec(conn_opts_t *, const char *) NONNULL(1,2);
int icap_set_extended_headers(pxy_conn_ctx_t *, int) NONNULL(1);

void icap_process_chain(icap_ctx_t *);
void icap_process_data(struct evbuffer *, struct evbuffer *, pxy_conn_ctx_t *, icap_ctx_t *, int) NONNULL(1,2,3,4);

#endif /* !WITHOUT_ICAP */

#endif /* !ICAP_H */

/* vim: set noet ft=c: */
