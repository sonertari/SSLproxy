/*
 * SSLsplit - transparent SSL/TLS interception
 * Copyright (c) 2009-2016, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

/*
 * Print helper for logging code.
 */
#define STRORDASH(x)	(((x)&&*(x))?(x):"-")
#define STRORNONE(x)	(((x)&&*(x))?(x):"")

typedef struct pxy_conn_child_ctx pxy_conn_child_ctx_t;

/* single socket bufferevent descriptor */
typedef struct pxy_conn_desc {
	struct bufferevent *bev;
	SSL *ssl;
	unsigned int closed : 1;
} pxy_conn_desc_t;

/* parent connection state consisting of three connection descriptors,
 * connection-wide state and the specs and options */
struct pxy_conn_ctx {
	// Common properties
	// @attention The order of these common vars should match with their order in children
	/* per-connection state */
	struct pxy_conn_desc src;
	struct pxy_conn_desc dst;

	/* status flags */
	unsigned int connected : 1;       /* 0 until both ends are connected */
	unsigned int enomem : 1;                       /* 1 if out of memory */
	/* http */
	unsigned int seen_req_header : 1; /* 0 until request header complete */
	unsigned int seen_resp_header : 1;  /* 0 until response hdr complete */
	unsigned int sent_http_conn_close : 1;   /* 0 until Conn: close sent */
	unsigned int ocsp_denied : 1;                /* 1 if OCSP was denied */

	/* log strings from socket */
	char *srchost_str;
	char *srcport_str;
	char *dsthost_str;
	char *dstport_str;

	/* log strings from HTTP request */
	char *http_method;
	char *http_uri;
	char *http_host;
	char *http_content_type;

	/* log strings from HTTP response */
	char *http_status_code;
	char *http_status_text;
	char *http_content_length;

	/* log strings related to SSL */
	char *ssl_names;
	char *origcrtfpr;
	char *usedcrtfpr;

	/* store fd and fd event while connected is 0 */
	evutil_socket_t fd;
	// End of common properties

	/* content log context */
	log_content_ctx_t *logctx;

	unsigned int srv_dst_connected : 1;   /* 0 until server is connected */
	unsigned int dst_connected : 1;          /* 0 until dst is connected */

	/* ssl */
	unsigned int sni_peek_retries : 6;       /* max 64 SNI parse retries */
	unsigned int immutable_cert : 1;  /* 1 if the cert cannot be changed */
	unsigned int generated_cert : 1;     /* 1 if we generated a new cert */
	unsigned int passthrough : 1;      /* 1 if SSL passthrough is active */
	/* autossl */
	unsigned int clienthello_search : 1;       /* 1 if waiting for hello */
	unsigned int clienthello_found : 1;      /* 1 if conn upgrade to SSL */

	struct pxy_conn_desc srv_dst;
	char *srv_dst_ssl_version;
	char *srv_dst_ssl_cipher;

	struct event *ev;

	/* original destination address, family and certificate */
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int af;
	X509 *origcrt;

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
	int sent_header;

	// Child list of the conn
	pxy_conn_child_ctx_t *children;

	// Number of children, active or closed
	unsigned int child_count;

	evutil_socket_t child_src_fd;
	evutil_socket_t child_dst_fd;

	/* server name indicated by client in SNI TLS extension */
	char *sni;

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
	/* per-connection state */
	struct pxy_conn_desc src;
	struct pxy_conn_desc dst;

	/* status flags */
	unsigned int connected : 1;       /* 0 until both ends are connected */
	unsigned int enomem : 1;                       /* 1 if out of memory */
	/* http */
	unsigned int seen_req_header : 1; /* 0 until request header complete */
	unsigned int seen_resp_header : 1;  /* 0 until response hdr complete */
	unsigned int sent_http_conn_close : 1;   /* 0 until Conn: close sent */
	unsigned int ocsp_denied : 1;                /* 1 if OCSP was denied */

	/* log strings from socket */
	char *srchost_str;
	char *srcport_str;
	char *dsthost_str;
	char *dstport_str;

	/* log strings from HTTP request */
	char *http_method;
	char *http_uri;
	char *http_host;
	char *http_content_type;

	/* log strings from HTTP response */
	char *http_status_code;
	char *http_status_text;
	char *http_content_length;

	/* log strings related to SSL */
	char *ssl_names;
	char *origcrtfpr;
	char *usedcrtfpr;

	/* store fd and fd event while connected is 0 */
	evutil_socket_t fd;
	// End of common properties

	evutil_socket_t src_fd;
	evutil_socket_t dst_fd;

	pxy_conn_ctx_t *parent;

	// Child index
	unsigned int idx;

	// Children of the conn are link-listed using this pointer
	pxy_conn_child_ctx_t *next;
};

void pxy_conn_setup(evutil_socket_t, struct sockaddr *, int,
                    pxy_thrmgr_ctx_t *, proxyspec_t *, opts_t *,
					evutil_socket_t)
                    NONNULL(2,4,5,6);
void pxy_conn_free(pxy_conn_ctx_t *ctx, int) NONNULL(1);

#endif /* !PXYCONN_H */

/* vim: set noet ft=c: */
