/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2017-2024, Soner Tari <sonertari@gmail.com>.
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

#ifndef PXYTHR_H
#define PXYTHR_H

#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <pthread.h>

typedef struct pxy_conn_ctx pxy_conn_ctx_t;
typedef struct pxy_thrmgr_ctx pxy_thrmgr_ctx_t;

typedef struct pxy_thr_ctx {
	pthread_t thr;
	int id;
	pxy_thrmgr_ctx_t *thrmgr;
	size_t load;
	struct event_base *evbase;
	int running;

	// Statistics
	evutil_socket_t max_fd;
	size_t max_load;
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
} pxy_thr_ctx_t;

void pxy_thr_attach(pxy_conn_ctx_t *) NONNULL(1);
void pxy_thr_detach(pxy_conn_ctx_t *) NONNULL(1);
void *pxy_thr(void *);

#endif /* !PXYTHR_H */

/* vim: set noet ft=c: */
