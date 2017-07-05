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
typedef struct pxy_conn_child_info pxy_conn_child_info_t;

/*
 * Listener context.
 */
typedef struct proxy_listener_ctx {
	pxy_thrmgr_ctx_t *thrmgr;
	proxyspec_t *spec;
	opts_t *opts;
	struct evconnlistener *evcl;
	struct proxy_listener_ctx *next;
	int clisock;
} proxy_listener_ctx_t;

typedef struct proxy_conn_meta_ctx {
	pxy_thr_ctx_t *thr;
	uuid_t *uuid;

	proxy_listener_ctx_t *lctx;

	evutil_socket_t fd;
	pxy_conn_ctx_t *parent_ctx;

	evutil_socket_t src_fd;
	evutil_socket_t e2src_fd;
	evutil_socket_t dst_fd;

	unsigned int src_eof : 1;
	unsigned int e2src_eof : 1;
	unsigned int dst_eof : 1;
		
	evutil_socket_t fd2;
	struct evconnlistener *evcl2;
	char *pxy_dst;

	pxy_conn_ctx_t *child_ctx;
	pxy_conn_child_info_t *child_info;

	evutil_socket_t e2dst_fd;
	evutil_socket_t dst2_fd;

	unsigned int e2dst_eof : 1;
	unsigned int dst2_eof : 1;

	unsigned int initialized : 1;
	unsigned int child_count;

	/* server name indicated by client in SNI TLS extension */
	char *sni;
	/* original destination address, family and certificate */
	struct sockaddr_storage addr;
	socklen_t addrlen;

	int thridx;

	time_t access_time;
	proxy_conn_meta_ctx_t *next;
	proxy_conn_meta_ctx_t *delete;
} proxy_conn_meta_ctx_t;

proxy_ctx_t * proxy_new(opts_t *, int) NONNULL(1) MALLOC;
void proxy_run(proxy_ctx_t *) NONNULL(1);
void proxy_loopbreak(proxy_ctx_t *) NONNULL(1);
void proxy_free(proxy_ctx_t *) NONNULL(1);
void
proxy_listener_errorcb(struct evconnlistener *listener, UNUSED void *ctx);
void
proxy_listener_acceptcb_e2(struct evconnlistener *listener,
                        evutil_socket_t fd,
                        struct sockaddr *peeraddr, int peeraddrlen,
                        void *arg);

#endif /* !PROXY_H */

/* vim: set noet ft=c: */
