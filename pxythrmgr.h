/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2019, Soner Tari <sonertari@gmail.com>.
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

	// Per-thread locking is necessary during connection setup and termination
	// to prevent multithreading issues between thrmgr thread and conn handling threads
	pthread_mutex_t mutex;

	// Statistics
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
	// Each stats has an id, incremented on each stats print
	unsigned short stats_id;
	// Used to print statistics, compared against stats_period
	unsigned int timeout_count;

	// List of active connections on the thread
	pxy_conn_ctx_t *conns;

	// Per-thread sqlite stmt is necessary to prevent multithreading issues between threads
	struct sqlite3_stmt *get_user;

	// SSL conns wait for the first readcb to complete connection setup
	// We keep track of conns at that stage using this list, to close them if they time out
	pxy_conn_ctx_t *pending_ssl_conns;
	long long unsigned int pending_ssl_conn_count;
} pxy_thr_ctx_t;

struct pxy_thrmgr_ctx {
	int num_thr;
	global_t *global;
	pxy_thr_ctx_t **thr;
	// Provides unique conn id, always goes up, never down
	// There is no risk of collision if/when it rolls back to 0
	long long unsigned int conn_count;
};

pxy_thrmgr_ctx_t * pxy_thrmgr_new(global_t *) MALLOC;
int pxy_thrmgr_run(pxy_thrmgr_ctx_t *) NONNULL(1) WUNRES;
void pxy_thrmgr_free(pxy_thrmgr_ctx_t *) NONNULL(1);

void pxy_thrmgr_add_pending_ssl_conn(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_remove_pending_ssl_conn(pxy_conn_ctx_t *) NONNULL(1);

void pxy_thrmgr_add_conn(pxy_conn_ctx_t *) NONNULL(1);

void pxy_thrmgr_attach(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_attach_child(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_detach_unlocked(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_detach(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_detach_child_unlocked(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thrmgr_detach_child(pxy_conn_ctx_t *) NONNULL(1);

#endif /* !PXYTHRMGR_H */

/* vim: set noet ft=c: */
