/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2017-2020, Soner Tari <sonertari@gmail.com>.
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

#include "pxythr.h"

#include "log.h"
#include "pxyconn.h"

#include <assert.h>
#include <sys/param.h>

/*
 * Attach a connection to its thread.
 * This function cannot fail.
 */
void
pxy_thr_attach(pxy_conn_ctx_t *ctx)
{
	assert(ctx != NULL);
	// A thr should have already been assigned
	assert(ctx->thr != NULL);

	log_finest("Adding conn");

	// Always keep thr load and conns list in sync
	ctx->thr->load++;

	ctx->next = ctx->thr->conns;
	ctx->thr->conns = ctx;
	if (ctx->next)
		ctx->next->prev = ctx;
}

/*
 * Detach a connection from a thread by index.
 * This function cannot fail.
 */
void
pxy_thr_detach(pxy_conn_ctx_t *ctx)
{
	assert(ctx != NULL);
	// If this function is called, the thr conns list cannot be empty
	assert(ctx->thr->conns != NULL);

	log_finest("Removing conn");

	ctx->thr->load--;

	if (ctx->prev) {
		ctx->prev->next = ctx->next;
	} else {
		ctx->thr->conns = ctx->next;
	}
	if (ctx->next)
		ctx->next->prev = ctx->prev;
}

static void
pxy_thr_print_thr_info(pxy_thr_ctx_t *tctx)
{
	log_finest_main_va("thr=%d, load=%lu", tctx->id, tctx->load);

	evutil_socket_t max_fd = 0;
	time_t max_atime = 0;
	time_t max_ctime = 0;

	char *smsg = NULL;

	if (tctx->conns) {
		time_t now = time(NULL);

		pxy_conn_ctx_t *ctx = tctx->conns;
		while (ctx) {
			time_t atime = now - ctx->atime;
			time_t ctime = now - ctx->ctime;

			log_finest_main_va("CONN: thr=%d, id=%llu, fd=%d, dst=%d, p=%d-%d, at=%lld ct=%lld, src_addr=%s:%s, dst_addr=%s:%s",
				tctx->id, ctx->id, ctx->fd, ctx->dst_fd, ctx->src.closed, ctx->dst.closed, (long long)atime, (long long)ctime,
				STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str));

			max_fd = MAX(max_fd, MAX(ctx->fd, ctx->dst_fd));
			max_atime = MAX(max_atime, atime);
			max_ctime = MAX(max_ctime, ctime);

			ctx = ctx->next;
		}
	}

	log_finest_main_va("STATS: thr=%d, mld=%zu, mfd=%d, mat=%lld, mct=%lld, iib=%llu, iob=%llu, eib=%llu, eob=%llu, swm=%zu, uwm=%zu, err=%zu, si=%u",
			tctx->id, tctx->max_load, tctx->max_fd, (long long)max_atime, (long long)max_ctime, tctx->intif_in_bytes, tctx->intif_out_bytes, tctx->extif_in_bytes, tctx->extif_out_bytes,
			tctx->set_watermarks, tctx->unset_watermarks, tctx->errors, tctx->stats_id);

	if (asprintf(&smsg, "STATS: thr=%d, mld=%zu, mfd=%d, mat=%lld, mct=%lld, iib=%llu, iob=%llu, eib=%llu, eob=%llu, swm=%zu, uwm=%zu, err=%zu, si=%u\n",
			tctx->id, tctx->max_load, tctx->max_fd, (long long)max_atime, (long long)max_ctime, tctx->intif_in_bytes, tctx->intif_out_bytes, tctx->extif_in_bytes, tctx->extif_out_bytes,
			tctx->set_watermarks, tctx->unset_watermarks, tctx->errors, tctx->stats_id) < 0) {
		return;
	}

	if (log_stats(smsg) == -1) {
		log_err_level_printf(LOG_WARNING, "Stats logging failed\n");
	}
	free(smsg);

	tctx->stats_id++;

	tctx->errors = 0;
	tctx->set_watermarks = 0;
	tctx->unset_watermarks = 0;

	tctx->intif_in_bytes = 0;
	tctx->intif_out_bytes = 0;
	tctx->extif_in_bytes = 0;
	tctx->extif_out_bytes = 0;

	// Reset these stats with the current values (do not reset to 0 directly, there may be active conns)
	tctx->max_fd = max_fd;
	tctx->max_load = tctx->load;
}

/*
 * Recurring timer event to prevent the event loops from exiting when
 * they run out of events.
 */
static void
pxy_thr_timer_cb(UNUSED evutil_socket_t fd, UNUSED short what, UNUSED void *arg)
{
	pxy_thr_ctx_t *tctx = arg;

	log_finest_main_va("thr=%d, load=%lu, to=%u", tctx->id, tctx->load, tctx->timeout_count);

	// @attention Print thread info only if stats logging is enabled, if disabled debug logs are not printed either
	if (tctx->thrmgr->opts->statslog) {
		tctx->timeout_count++;
		if (tctx->timeout_count >= tctx->thrmgr->opts->stats_period) {
			tctx->timeout_count = 0;
			pxy_thr_print_thr_info(tctx);
		}
	}
}

/*
 * Thread entry point; runs the event loop of the event base.
 * Does not exit until the libevent loop is broken explicitly.
 */
void *
pxy_thr(void *arg)
{
	pxy_thr_ctx_t *tctx = arg;
	struct timeval timer_delay = {10, 0};
	struct event *ev;

	ev = event_new(tctx->evbase, -1, EV_PERSIST, pxy_thr_timer_cb, tctx);
	if (!ev)
		return NULL;
	evtimer_add(ev, &timer_delay);
	tctx->running = 1;
	event_base_dispatch(tctx->evbase);
	event_free(ev);

	return NULL;
}

/* vim: set noet ft=c: */
