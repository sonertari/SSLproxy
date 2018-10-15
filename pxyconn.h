/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
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

#include "proxy.h"
#include "opts.h"
#include "attrib.h"
#include "pxythrmgr.h"
#include "log.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/util.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

/*
 * Print helper for logging code.
 */
#define STRORDASH(x)	(((x)&&*(x))?(x):"-")
#define STRORNONE(x)	(((x)&&*(x))?(x):"")

#define WANT_CONNECT_LOG(ctx)	((ctx)->opts->connectlog||!(ctx)->opts->detach)
// XXX: Remove passthrough condition
#define WANT_CONTENT_LOG(ctx)	((ctx)->opts->contentlog&&((ctx)->proto!=PROTO_PASSTHROUGH))

#define SSLPROXY_KEY		"SSLproxy:"
#define SSLPROXY_KEY_LEN	strlen(SSLPROXY_KEY)

typedef struct pxy_conn_child_ctx pxy_conn_child_ctx_t;

typedef void (*fd_readcb_func_t)(evutil_socket_t,  short, void *);
typedef void (*connect_func_t)(pxy_conn_ctx_t *);

typedef void (*callback_func_t)(struct bufferevent *, void *);
typedef void (*eventcb_func_t)(struct bufferevent *, short, void *);

typedef void (*bufferevent_free_and_close_fd_func_t)(struct bufferevent *, pxy_conn_ctx_t *);

typedef void (*proto_free_func_t)(pxy_conn_ctx_t *);

typedef void (*child_connect_func_t)(pxy_conn_child_ctx_t *);
typedef void (*child_proto_free_func_t)(pxy_conn_child_ctx_t *);

/* single socket bufferevent descriptor */
typedef struct pxy_conn_desc {
	struct bufferevent *bev;
	SSL *ssl;
	unsigned int closed : 1;
} pxy_conn_desc_t;

enum conn_type {
	CONN_TYPE_PARENT = 0,
	CONN_TYPE_CHILD,
};

enum protocol {
	PROTO_ERROR = -1,
	PROTO_PASSTHROUGH = 0,
	PROTO_HTTP,
	PROTO_HTTPS,
	PROTO_POP3,
	PROTO_POP3S,
	PROTO_SMTP,
	PROTO_SMTPS,
	PROTO_AUTOSSL,
	PROTO_TCP,
	PROTO_SSL,
};

typedef struct ssl_ctx ssl_ctx_t;

typedef struct proto_ctx proto_ctx_t;
typedef struct proto_child_ctx proto_child_ctx_t;

struct ssl_ctx {
	/* log strings related to SSL */
	char *ssl_names;
	char *origcrtfpr;
	char *usedcrtfpr;

	/* ssl */
	unsigned int sni_peek_retries : 6;       /* max 64 SNI parse retries */
	unsigned int immutable_cert : 1;  /* 1 if the cert cannot be changed */
	unsigned int generated_cert : 1;     /* 1 if we generated a new cert */

	/* server name indicated by client in SNI TLS extension */
	char *sni;

	X509 *origcrt;

	char *srv_dst_ssl_version;
	char *srv_dst_ssl_cipher;
};

struct proto_ctx {
	enum protocol proto;

	connect_func_t connectcb;
	fd_readcb_func_t fd_readcb;

	callback_func_t bev_readcb;
	callback_func_t bev_writecb;
	eventcb_func_t bev_eventcb;

	bufferevent_free_and_close_fd_func_t bufferevent_free_and_close_fd;

	proto_free_func_t proto_free;

	// For protocol specific fields, if any
	void *arg;
};

struct proto_child_ctx {
	enum protocol proto;

	child_connect_func_t connectcb;

	callback_func_t bev_readcb;
	callback_func_t bev_writecb;
	eventcb_func_t bev_eventcb;

	bufferevent_free_and_close_fd_func_t bufferevent_free_and_close_fd;

	child_proto_free_func_t proto_free;

	// For protocol specific fields, if any
	void *arg;
};

/* parent connection state consisting of three connection descriptors,
 * connection-wide state and the specs and options */
struct pxy_conn_ctx {
	// Common properties
	// @attention The order of these common vars should match with their order in children
	enum conn_type type;

	pxy_conn_ctx_t *conn;                 /* parent's conn ctx is itself */
	enum protocol proto;

	/* per-connection state */
	struct pxy_conn_desc src;
	struct pxy_conn_desc dst;

	/* store fd and fd event while connected is 0 */
	evutil_socket_t fd;
	// End of common properties

	proto_ctx_t *protoctx;

	ssl_ctx_t *sslctx;

	/* log strings from socket */
	char *srchost_str;
	char *srcport_str;
	char *dsthost_str;
	char *dstport_str;

	/* content log context */
	log_content_ctx_t *logctx;

	/* status flags */
	unsigned int connected : 1;       /* 0 until both ends are connected */
	unsigned int enomem : 1;                       /* 1 if out of memory */
	unsigned int srv_dst_connected : 1;   /* 0 until server is connected */
	unsigned int dst_connected : 1;          /* 0 until dst is connected */

	struct pxy_conn_desc srv_dst;

	struct event *ev;

	/* original destination address, family and certificate */
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int af;

	// Thread that the conn is attached to
	pxy_thr_ctx_t *thr;

	// Unique id of the conn
	long long unsigned int id;

	pxy_thrmgr_ctx_t *thrmgr;
	proxyspec_t *spec;
	opts_t *opts;

	struct event_base *evbase;
	struct evdns_base *dnsbase;

	evutil_socket_t dst_fd;
	evutil_socket_t srv_dst_fd;

	// Priv sep socket to obtain a socket for children
	evutil_socket_t clisock;

	// Fd of the listener event for the children
	evutil_socket_t child_fd;
	struct evconnlistener *child_evcl;

	// SSL proxy specific info: The IP:port address the children are listening on, orig client addr, and orig target addr
	char *header_str;
	size_t header_len;
	int sent_header;

	// Child list of the conn
	pxy_conn_child_ctx_t *children;

	// Number of children, active or closed
	unsigned int child_count;

	evutil_socket_t child_src_fd;
	evutil_socket_t child_dst_fd;

	// Conn create time
	time_t ctime;

	// Conn last access time, to determine expired conns
	// Updated on entry to callback functions, parent or child
	time_t atime;
	
	// Per-thread conn list
	pxy_conn_ctx_t *next;

	// Expired conns are link-listed using this pointer
	pxy_conn_ctx_t *next_expired;

#ifdef HAVE_LOCAL_PROCINFO
	/* local process information */
	pxy_conn_lproc_desc_t lproc;
#endif /* HAVE_LOCAL_PROCINFO */
};

/* child connection state consisting of two connection descriptors,
 * connection-wide state */
struct pxy_conn_child_ctx {
	// Common properties
	// @attention The order of these common vars should match with their order in parent
	enum conn_type type;

	pxy_conn_ctx_t *conn;                              /* parent context */
	enum protocol proto;

	/* per-connection state */
	struct pxy_conn_desc src;
	struct pxy_conn_desc dst;

	/* store fd and fd event while connected is 0 */
	evutil_socket_t fd;
	// End of common properties

	proto_child_ctx_t *protoctx;

	/* status flags */
	unsigned int connected : 1;       /* 0 until both ends are connected */

	// For max fd stats
	evutil_socket_t src_fd;
	evutil_socket_t dst_fd;

	// Child index
	unsigned int idx;

	// Children of the conn are link-listed using this pointer
	pxy_conn_child_ctx_t *next;
};

void pxy_discard_inbuf(struct bufferevent *);
int pxy_set_dstaddr(pxy_conn_ctx_t *);
unsigned char *pxy_malloc_packet(size_t, pxy_conn_ctx_t *);
void pxy_insert_sslproxy_header(pxy_conn_ctx_t *, unsigned char *, size_t *);
void pxy_remove_sslproxy_header(unsigned char *, size_t *, pxy_conn_child_ctx_t *);

SSL *pxy_dstssl_create(pxy_conn_ctx_t *);

int pxy_prepare_logging(pxy_conn_ctx_t *);

void pxy_log_connect_src(pxy_conn_ctx_t *);
void pxy_log_connect_srv_dst(pxy_conn_ctx_t *);

int pxy_log_content_inbuf(pxy_conn_ctx_t *, struct evbuffer *, int);
int pxy_log_content_buf(pxy_conn_ctx_t *, unsigned char *, size_t, int);

int pxy_setup_src(pxy_conn_ctx_t *);
int pxy_setup_src_ssl(pxy_conn_ctx_t *);
int pxy_setup_new_src(pxy_conn_ctx_t *);

int pxy_setup_dst(pxy_conn_ctx_t *);
int pxy_setup_srv_dst(pxy_conn_ctx_t *);
int pxy_setup_srv_dst_ssl(pxy_conn_ctx_t *);

struct bufferevent *pxy_bufferevent_setup_child(pxy_conn_child_ctx_t *, evutil_socket_t, SSL *) NONNULL(1);

void bufferevent_free_and_close_fd_ssl(struct bufferevent *, pxy_conn_ctx_t *);

void pxy_close_dst(pxy_conn_ctx_t *);
void pxy_close_srv_dst(pxy_conn_ctx_t *);

void pxy_set_watermark(struct bufferevent *, pxy_conn_ctx_t *, struct bufferevent *);

void pxy_bev_eventcb_connected_src(struct bufferevent *, pxy_conn_ctx_t *);
void pxy_bev_eventcb_eof_src(struct bufferevent *, pxy_conn_ctx_t *);
void pxy_bev_eventcb_error_src(struct bufferevent *, pxy_conn_ctx_t *);

void pxy_bev_eventcb_connected_dst(struct bufferevent *, pxy_conn_ctx_t *);
void pxy_bev_eventcb_eof_dst(struct bufferevent *, pxy_conn_ctx_t *);
void pxy_bev_eventcb_error_dst(struct bufferevent *, pxy_conn_ctx_t *);

void pxy_bev_eventcb_connected_srv_dst(struct bufferevent *, pxy_conn_ctx_t *);
void pxy_bev_eventcb_eof_srv_dst(struct bufferevent *, pxy_conn_ctx_t *);
void pxy_bev_eventcb_error_srv_dst(struct bufferevent *, pxy_conn_ctx_t *);

void pxy_conn_connect_tcp(pxy_conn_ctx_t *);
void pxy_fd_readcb_tcp(evutil_socket_t, short, void *);
void pxy_fd_readcb_ssl(evutil_socket_t, short, void *);

int pxy_setup_child_listener(pxy_conn_ctx_t *);

void pxy_connect_tcp_child(pxy_conn_child_ctx_t *);
void pxy_connect_ssl_child(pxy_conn_child_ctx_t *);

void pxy_bev_readcb_tcp(struct bufferevent *, void *);
void pxy_bev_writecb_tcp(struct bufferevent *, void *);
void pxy_bev_eventcb_tcp(struct bufferevent *, short, void *);

void pxy_bev_readcb_tcp_child(struct bufferevent *, void *);
void pxy_bev_writecb_tcp_child(struct bufferevent *, void *);
void pxy_bev_eventcb_tcp_child(struct bufferevent *, short, void *);

void bufferevent_free_and_close_fd_tcp(struct bufferevent *, pxy_conn_ctx_t *);

void pxy_bev_eventcb_child_src(struct bufferevent *, short events, void *);

void pxy_bev_eventcb_child_eof_dst(struct bufferevent *, pxy_conn_child_ctx_t *);
void pxy_bev_eventcb_child_error_dst(struct bufferevent *, pxy_conn_child_ctx_t *);

void pxy_bev_readcb(struct bufferevent *, void *);
void pxy_bev_writecb(struct bufferevent *, void *);
void pxy_bev_eventcb(struct bufferevent *, short, void *);

void pxy_bev_readcb_child(struct bufferevent *, void *);
void pxy_bev_writecb_child(struct bufferevent *, void *);
void pxy_bev_eventcb_child(struct bufferevent *, short, void *);

void pxy_conn_setup(evutil_socket_t, struct sockaddr *, int,
                    pxy_thrmgr_ctx_t *, proxyspec_t *, opts_t *,
					evutil_socket_t)
                    NONNULL(2,4,5,6);
void pxy_conn_free(pxy_conn_ctx_t *ctx, int) NONNULL(1);
void protossl_free(pxy_conn_ctx_t *ctx) NONNULL(1);

void pxy_conn_connect_passthrough(pxy_conn_ctx_t *);
void pxy_bev_readcb_passthrough(struct bufferevent *, void *);
void pxy_bev_writecb_passthrough(struct bufferevent *, void *);
void pxy_bev_eventcb_passthrough(struct bufferevent *, short, void *);

#endif /* !PXYCONN_H */

/* vim: set noet ft=c: */
