/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2025, Soner Tari <sonertari@gmail.com>.
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
#include "pxythr.h"

extern int descriptor_table_size;
#define FD_RESERVE 10

struct pxy_thrmgr_ctx {
	int num_thr;
	global_t *global;
	pxy_thr_ctx_t **thr;
#ifdef DEBUG_PROXY
	// Provides unique conn id, always goes up, never down, used in debugging only
	// There is no risk of collision if/when it rolls back to 0
	long long unsigned int conn_count;
#endif /* DEBUG_PROXY */
};

pxy_thrmgr_ctx_t * pxy_thrmgr_new(global_t *) MALLOC;
int pxy_thrmgr_run(pxy_thrmgr_ctx_t *) NONNULL(1) WUNRES;
void pxy_thrmgr_free(pxy_thrmgr_ctx_t *) NONNULL(1);

void pxy_thrmgr_assign_thr(pxy_conn_ctx_t *) NONNULL(1);

#endif /* !PXYTHRMGR_H */

/* vim: set noet ft=c: */
