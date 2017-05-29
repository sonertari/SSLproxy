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

typedef struct proxy_ctx proxy_ctx_t;
typedef struct proxy_listener_ctx proxy_listener_ctx_t;
typedef struct pxy_conn_ctx pxy_conn_ctx_t;
typedef struct proxy_conn_meta_ctx proxy_conn_meta_ctx_t;

typedef struct proxy_conn_meta_ctx {
	proxy_listener_ctx_t *lctx;
	pxy_conn_ctx_t *parent_ctx;
	pxy_conn_ctx_t *child_ctx;

	pthread_mutex_t mutex;

	struct evconnlistener *evcl2;
	evutil_socket_t fd2;

	unsigned int released;

	proxy_conn_meta_ctx_t *next;
} proxy_conn_meta_ctx_t;

//typedef struct proxy_listener_ctx proxy_listener_ctx_t;

/*
 * Listener context.
 */
typedef struct proxy_listener_ctx {
	pxy_thrmgr_ctx_t *thrmgr;
	proxyspec_t *spec;
	opts_t *opts;
	struct evconnlistener *evcl;
	struct evconnlistener *evcl_e2;

	struct proxy_listener_ctx *next;
	pxy_conn_ctx_t *ctx;

	evutil_socket_t fd2;

	int clisock;

	pthread_mutex_t mutex;
	proxy_conn_meta_ctx_t *mctx;
} proxy_listener_ctx_t;

proxy_ctx_t * proxy_new(opts_t *, int) NONNULL(1) MALLOC;
void proxy_run(proxy_ctx_t *) NONNULL(1);
void proxy_loopbreak(proxy_ctx_t *) NONNULL(1);
void proxy_free(proxy_ctx_t *) NONNULL(1);

#endif /* !PROXY_H */

/* vim: set noet ft=c: */
