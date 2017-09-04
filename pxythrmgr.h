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

extern int descriptor_table_size;
#define FD_RESERVE 10

typedef struct pxy_conn_ctx pxy_conn_ctx_t;
typedef struct pxy_thrmgr_ctx pxy_thrmgr_ctx_t;

typedef struct pxy_thr_ctx {
	pthread_t thr;
	int thridx;
	pxy_thrmgr_ctx_t *thrmgr;
	size_t load;
	struct event_base *evbase;
	struct evdns_base *dnsbase;
	int running;
	unsigned int timeout_count;
	evutil_socket_t max_fd;
	size_t max_load;
	size_t timedout_conns;
	size_t errors;
	size_t set_watermarks;
	size_t unset_watermarks;
	long long unsigned int intif_in_bytes;
	long long unsigned int intif_out_bytes;
	long long unsigned int extif_in_bytes;
	long long unsigned int extif_out_bytes;
	unsigned short stats_idx;
	pxy_conn_ctx_t *conns;
} pxy_thr_ctx_t;

struct pxy_thrmgr_ctx {
	int num_thr;
	opts_t *opts;
	pxy_thr_ctx_t **thr;
	pthread_mutex_t mutex;
};

pxy_thrmgr_ctx_t * pxy_thrmgr_new(opts_t *) MALLOC;
int pxy_thrmgr_run(pxy_thrmgr_ctx_t *) NONNULL(1) WUNRES;
void pxy_thrmgr_free(pxy_thrmgr_ctx_t *) NONNULL(1);

void pxy_thrmgr_attach(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_attach_child(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_detach(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_detach_child(pxy_conn_ctx_t *) NONNULL(1);

#endif /* !PXYTHRMGR_H */

/* vim: set noet ft=c: */
