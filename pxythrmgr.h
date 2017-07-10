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

#ifndef PXYTHRMGR_H
#define PXYTHRMGR_H

#include "opts.h"
#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <pthread.h>

typedef struct proxy_conn_meta_ctx proxy_conn_meta_ctx_t;

typedef struct pxy_thr_ctx {
	pthread_t thr;
	int thridx;
	size_t load;
	struct event_base *evbase;
	struct evdns_base *dnsbase;
	int running;
	int timeout_count;
	proxy_conn_meta_ctx_t *mctx_list;
} pxy_thr_ctx_t;

typedef struct pxy_thrmgr_ctx {
	int num_thr;
	opts_t *opts;
	pxy_thr_ctx_t **thr;
	pthread_mutex_t mutex;
} pxy_thrmgr_ctx_t;

pxy_thrmgr_ctx_t * pxy_thrmgr_new(opts_t *) MALLOC;
int pxy_thrmgr_run(pxy_thrmgr_ctx_t *) NONNULL(1) WUNRES;
void pxy_thrmgr_free(pxy_thrmgr_ctx_t *) NONNULL(1);

int pxy_thrmgr_attach(pxy_thrmgr_ctx_t *, struct event_base **,
                      struct evdns_base **, proxy_conn_meta_ctx_t *) WUNRES;
void pxy_thrmgr_attach_child(pxy_thrmgr_ctx_t *ctx, int thridx);
void pxy_thrmgr_detach(pxy_thrmgr_ctx_t *, int, proxy_conn_meta_ctx_t *);
void pxy_thrmgr_detach_child(pxy_thrmgr_ctx_t *, int, proxy_conn_meta_ctx_t *);

void pxy_thrmgr_print_thr_info(pxy_thr_ctx_t *ctx);
void pxy_thrmgr_get_thr_expired_conns(pxy_thr_ctx_t *ctx, proxy_conn_meta_ctx_t **expired_conns);

#endif /* !PXYTHRMGR_H */

/* vim: set noet ft=c: */
