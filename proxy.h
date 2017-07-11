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

#ifndef PROXY_H
#define PROXY_H

#include "opts.h"
#include "attrib.h"
#include "pxythrmgr.h"
#include <pthread.h>
#include <uuid.h>

typedef struct proxy_ctx proxy_ctx_t;
typedef struct pxy_conn_ctx pxy_conn_ctx_t;
typedef struct pxy_conn_child_ctx pxy_conn_child_ctx_t;
typedef struct pxy_conn_child_info pxy_conn_child_info_t;

/*
 * Listener context.
 */
typedef struct proxy_listener_ctx {
	pxy_thrmgr_ctx_t *thrmgr;
	proxyspec_t *spec;
	opts_t *opts;
	evutil_socket_t clisock;
	struct evconnlistener *evcl;
	struct proxy_listener_ctx *next;
} proxy_listener_ctx_t;

typedef struct proxy_conn_meta_ctx {
	pxy_thr_ctx_t *thr;
	uuid_t *uuid;

	pxy_thrmgr_ctx_t *thrmgr;
	proxyspec_t *spec;
	opts_t *opts;

#ifdef HAVE_LOCAL_PROCINFO
	/* local process information */
	pxy_conn_lproc_desc_t lproc;
#endif /* HAVE_LOCAL_PROCINFO */

	struct event_base *evbase;
	struct evdns_base *dnsbase;
	unsigned int passthrough : 1;      /* 1 if SSL passthrough is active */
	
	evutil_socket_t clisock;

	/* store fd and fd event while connected is 0 */
	evutil_socket_t fd;

	pxy_conn_ctx_t *parent_ctx;

	evutil_socket_t src_fd;
	evutil_socket_t e2src_fd;
	evutil_socket_t dst_fd;

	unsigned int src_eof : 1;
	unsigned int e2src_eof : 1;
	unsigned int dst_eof : 1;

	// Fd of the listener event for the children
	evutil_socket_t child_fd;
	struct evconnlistener *child_evcl;
	// SSL proxy return address: The IP:port address the children are listening to
	char *child_addr;

	// Child list of the conn
	pxy_conn_child_ctx_t *child_list;
	// Used to print child info, never deleted until the conn is freed
	pxy_conn_child_info_t *child_info_list;

	evutil_socket_t e2dst_fd;
	evutil_socket_t dst2_fd;

	unsigned int e2dst_eof : 1;
	unsigned int dst2_eof : 1;

	// Number of children, active or closed
	unsigned int child_count;

	/* server name indicated by client in SNI TLS extension */
	char *sni;
	/* original destination address, family and certificate */
	struct sockaddr_storage addr;
	socklen_t addrlen;

	// Index of the thread the conn is attached to
	int thridx;

	// Last access time, to determine expired conns
	// Updated on entry to callback functions
	time_t access_time;

	// Per-thread conn list
	proxy_conn_meta_ctx_t *next;
	// Expired conns are link-listed using this pointer
	proxy_conn_meta_ctx_t *next_expired;
} proxy_conn_meta_ctx_t;

proxy_ctx_t * proxy_new(opts_t *, int) NONNULL(1) MALLOC;
void proxy_run(proxy_ctx_t *) NONNULL(1);
void proxy_loopbreak(proxy_ctx_t *) NONNULL(1);
void proxy_free(proxy_ctx_t *) NONNULL(1);
void
proxy_listener_errorcb(struct evconnlistener *listener, UNUSED void *ctx);

#endif /* !PROXY_H */

/* vim: set noet ft=c: */
