/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2021, Soner Tari <sonertari@gmail.com>.
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

#ifndef PXYCONN_H
#define PXYCONN_H

#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <netinet/in.h>
#endif

#include "proxy.h"
#include "opts.h"
#include "attrib.h"
#include "pxythrmgr.h"
#include "log.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#define WANT_CONNECT_LOG(ctx)	((ctx)->opts->connectlog||!(ctx)->opts->detach||(ctx)->opts->statslog)
#define WANT_CONTENT_LOG(ctx)	((ctx)->opts->contentlog)

typedef void (*callback_func_t)(struct bufferevent *, void *);
typedef void (*eventcb_func_t)(struct bufferevent *, short, void *);

typedef void (*bev_free_func_t)(struct bufferevent *, pxy_conn_ctx_t *);

/*
 * Proxy connection context state, describes a proxy connection
 * with source and destination socket bufferevents, SSL context and
 * other session state.  One of these exists per handled proxy
 * connection.
 */

/* single socket bufferevent descriptor */
typedef struct pxy_conn_desc {
	struct bufferevent *bev;
	unsigned int closed : 1;
	bev_free_func_t free;
} pxy_conn_desc_t;

typedef enum protocol {
	PROTO_ERROR = -1,
	PROTO_TCP = 0,
} protocol_t;

typedef struct proto_ctx proto_ctx_t;

struct proto_ctx {
	protocol_t proto;
	callback_func_t bev_readcb;
	callback_func_t bev_writecb;
	eventcb_func_t bev_eventcb;
};

/* connection state consisting of two connection descriptors,
 * connection-wide state and the specs and options */
struct pxy_conn_ctx {
	protocol_t proto;

	/* per-connection state */
	struct pxy_conn_desc src;
	struct pxy_conn_desc dst;

	/* store fd and fd event while connected is 0 */
	evutil_socket_t fd;

	// For protocol specific fields, never NULL
	proto_ctx_t *protoctx;

	/* log strings from socket */
	char *srchost_str;
	char *srcport_str;
	char *dsthost_str;
	char *dstport_str;

	/* content log context */
	log_content_ctx_t logctx;

	/* status flags */
	unsigned int src_connected : 1;             /* 0 until src connected */
	unsigned int dst_connected : 1;             /* 0 until dst connected */
	unsigned int enomem : 1;                       /* 1 if out of memory */
	unsigned int term : 1;                     /* 0 until term requested */
	unsigned int term_requestor : 1;          /* 1 client, 0 server side */
	unsigned int seen_sslproxy_line : 1;      /* 1 if seen sslproxy line */

	struct event *ev;

	/* original source and destination address */
	struct sockaddr_storage srcaddr;
	socklen_t srcaddrlen;
	struct sockaddr_storage dstaddr;
	socklen_t dstaddrlen;

	// Thread that the conn is attached to
	pxy_thr_ctx_t *thr;

#ifdef DEBUG_PROXY
	// Unique id of the conn, used in debugging only
	long long unsigned int id;
#endif /* DEBUG_PROXY */

	pxy_thrmgr_ctx_t *thrmgr;
	opts_t *opts;

	evutil_socket_t dst_fd;

	// Conn create time
	time_t ctime;

	// Conn last access time, used to determine expired conns
	// Updated on entry to callback functions
	time_t atime;
	
	// Per-thread conn list, used to determine idle and expired conns, and to close them
	pxy_conn_ctx_t *next;
	pxy_conn_ctx_t *prev;
};

void pxy_log_connect(pxy_conn_ctx_t *) NONNULL(1);

int pxy_log_content_inbuf(pxy_conn_ctx_t *, struct evbuffer *, int) NONNULL(1);
void pxy_log_dbg_evbuf_info(pxy_conn_ctx_t *, pxy_conn_desc_t *, pxy_conn_desc_t *) NONNULL(1,2,3);

void pxy_try_set_watermark(struct bufferevent *, pxy_conn_ctx_t *, struct bufferevent *) NONNULL(1,2,3);
void pxy_try_unset_watermark(struct bufferevent *, pxy_conn_ctx_t *, pxy_conn_desc_t *) NONNULL(1,2,3);

int pxy_try_close_conn_end(pxy_conn_desc_t *, pxy_conn_ctx_t *) NONNULL(1,2);

void pxy_try_disconnect(pxy_conn_ctx_t *, pxy_conn_desc_t *, pxy_conn_desc_t *, int) NONNULL(1,2,3);

int pxy_try_consume_last_input(struct bufferevent *, pxy_conn_ctx_t *) NONNULL(1,2);
void pxy_discard_inbuf(struct bufferevent *) NONNULL(1);

void pxy_conn_ctx_free(pxy_conn_ctx_t *, int) NONNULL(1);
void pxy_conn_free(pxy_conn_ctx_t *, int) NONNULL(1);
void pxy_conn_term(pxy_conn_ctx_t *, int) NONNULL(1);

int pxy_bev_readcb_preexec_logging_and_stats(struct bufferevent *, pxy_conn_ctx_t *) NONNULL(1,2);
int pxy_bev_eventcb_postexec_logging_and_stats(struct bufferevent *, short , pxy_conn_ctx_t *) NONNULL(1,3);

void pxy_bev_readcb(struct bufferevent *, void *);
void pxy_bev_writecb(struct bufferevent *, void *);
void pxy_bev_eventcb(struct bufferevent *, short, void *);

#endif /* !PXYCONN_H */

/* vim: set noet ft=c: */
