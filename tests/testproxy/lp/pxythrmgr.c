/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
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

#include "pxythrmgr.h"

#include "sys.h"
#include "log.h"
#include "pxyconn.h"

#include <string.h>
#include <event2/bufferevent.h>
#include <pthread.h>
#include <assert.h>
#include <sys/param.h>

/*
 * Proxy thread manager: manages the connection handling worker threads
 * and the per-thread resources (i.e. event bases).  The load is shared
 * across num_cpu * 2 connection handling threads, using the number of
 * currently assigned connections as the sole metric.
 *
 * The attach and detach functions are thread-safe.
 */

static void
pxy_thrmgr_print_thr_info(pxy_thr_ctx_t *tctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_print_thr_info: thr=%d, load=%lu\n", tctx->thridx, tctx->load);
#endif /* DEBUG_PROXY */

	unsigned int idx = 1;
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
			
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_print_thr_info: CONN: thr=%d, id=%u, fd=%d, dst=%d, p=%d-%d, at=%lld ct=%lld, src_addr=%s:%s, dst_addr=%s:%s\n",
				tctx->thridx, idx, ctx->fd, ctx->dst_fd, ctx->src.closed, ctx->dst.closed, (long long)atime, (long long)ctime,
				STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str));
#endif /* DEBUG_PROXY */

			max_fd = MAX(max_fd, MAX(ctx->fd, ctx->dst_fd));
			max_atime = MAX(max_atime, atime);
			max_ctime = MAX(max_ctime, ctime);

			idx++;
			ctx = ctx->next;
		}
	}

	if (asprintf(&smsg, "STATS: thr=%d, mld=%zu, mfd=%d, mat=%lld, mct=%lld, iib=%llu, iob=%llu, eib=%llu, eob=%llu, swm=%zu, uwm=%zu, err=%zu, si=%u\n",
			tctx->thridx, tctx->max_load, tctx->max_fd, (long long)max_atime, (long long)max_ctime, tctx->intif_in_bytes, tctx->intif_out_bytes, tctx->extif_in_bytes, tctx->extif_out_bytes,
			tctx->set_watermarks, tctx->unset_watermarks, tctx->errors, tctx->stats_id) < 0) {
		return;
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_print_thr_info: %s", smsg);
#endif /* DEBUG_PROXY */

	if (log_stats(smsg) == -1) {
		log_err_level_printf(LOG_WARNING, "Stats logging failed\n");
	}
	free(smsg);
	smsg = NULL;

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
pxy_thrmgr_timer_cb(UNUSED evutil_socket_t fd, UNUSED short what, UNUSED void *arg)
{
	pxy_thr_ctx_t *ctx = arg;

	pthread_mutex_lock(&ctx->mutex);
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_timer_cb: thr=%d, load=%lu, to=%u\n", ctx->thridx, ctx->load, ctx->timeout_count);
#endif /* DEBUG_PROXY */
	
	// @attention Print thread info only if stats logging is enabled, if disabled debug logs are not printed either
	if (ctx->thrmgr->opts->statslog) {
		ctx->timeout_count++;
		if (ctx->timeout_count >= ctx->thrmgr->opts->stats_period) {
			ctx->timeout_count = 0;
			pxy_thrmgr_print_thr_info(ctx);
		}
	}
	pthread_mutex_unlock(&ctx->mutex);
}

/*
 * Thread entry point; runs the event loop of the event base.
 * Does not exit until the libevent loop is broken explicitly.
 */
static void *
pxy_thrmgr_thr(void *arg)
{
	pxy_thr_ctx_t *ctx = arg;
	struct timeval timer_delay = {10, 0};
	struct event *ev;

	ev = event_new(ctx->evbase, -1, EV_PERSIST, pxy_thrmgr_timer_cb, ctx);
	if (!ev)
		return NULL;
	evtimer_add(ev, &timer_delay);
	ctx->running = 1;
	event_base_dispatch(ctx->evbase);
	event_free(ev);

	return NULL;
}

/*
 * Create new thread manager but do not start any threads yet.
 * This gets called before forking to background.
 */
pxy_thrmgr_ctx_t *
pxy_thrmgr_new(opts_t *opts)
{
	pxy_thrmgr_ctx_t *ctx;

	if (!(ctx = malloc(sizeof(pxy_thrmgr_ctx_t))))
		return NULL;
	memset(ctx, 0, sizeof(pxy_thrmgr_ctx_t));

	ctx->opts = opts;
	ctx->num_thr = 2 * sys_get_cpu_cores();
	return ctx;
}

/*
 * Start the thread manager and associated threads.
 * This must be called after forking.
 *
 * Returns -1 on failure, 0 on success.
 */
int
pxy_thrmgr_run(pxy_thrmgr_ctx_t *ctx)
{
	int idx = -1;

	if (!(ctx->thr = malloc(ctx->num_thr * sizeof(pxy_thr_ctx_t*)))) {
		log_dbg_printf("Failed to allocate memory\n");
		goto leave;
	}
	memset(ctx->thr, 0, ctx->num_thr * sizeof(pxy_thr_ctx_t*));

	for (idx = 0; idx < ctx->num_thr; idx++) {
		if (!(ctx->thr[idx] = malloc(sizeof(pxy_thr_ctx_t)))) {
			log_dbg_printf("Failed to allocate memory\n");
			goto leave;
		}
		memset(ctx->thr[idx], 0, sizeof(pxy_thr_ctx_t));
		ctx->thr[idx]->evbase = event_base_new();
		if (!ctx->thr[idx]->evbase) {
			log_dbg_printf("Failed to create evbase %d\n", idx);
			goto leave;
		}
		ctx->thr[idx]->load = 0;
		ctx->thr[idx]->running = 0;
		ctx->thr[idx]->conns = NULL;
		ctx->thr[idx]->thridx = idx;
		ctx->thr[idx]->timeout_count = 0;
		ctx->thr[idx]->thrmgr = ctx;

		if (pthread_mutex_init(&ctx->thr[idx]->mutex, NULL)) {
			log_dbg_printf("Failed to initialize thr mutex\n");
			goto leave;
		}
	}

	log_dbg_printf("Initialized %d connection handling threads\n",
	               ctx->num_thr);

	for (idx = 0; idx < ctx->num_thr; idx++) {
		if (pthread_create(&ctx->thr[idx]->thr, NULL,
		                   pxy_thrmgr_thr, ctx->thr[idx]))
			goto leave_thr;
		while (!ctx->thr[idx]->running) {
			sched_yield();
		}
	}

	log_dbg_printf("Started %d connection handling threads\n",
	               ctx->num_thr);

	return 0;

leave_thr:
	idx--;
	while (idx >= 0) {
		pthread_cancel(ctx->thr[idx]->thr);
		pthread_join(ctx->thr[idx]->thr, NULL);
		idx--;
	}
	idx = ctx->num_thr - 1;

leave:
	while (idx >= 0) {
		if (ctx->thr[idx]) {
			if (ctx->thr[idx]->evbase) {
				event_base_free(ctx->thr[idx]->evbase);
			}
			pthread_mutex_destroy(&ctx->thr[idx]->mutex);
			free(ctx->thr[idx]);
		}
		idx--;
	}
	if (ctx->thr) {
		free(ctx->thr);
		ctx->thr = NULL;
	}
	return -1;
}

/*
 * Destroy the event manager and stop all threads.
 */
void
pxy_thrmgr_free(pxy_thrmgr_ctx_t *ctx)
{
	if (ctx->thr) {
		for (int idx = 0; idx < ctx->num_thr; idx++) {
			event_base_loopbreak(ctx->thr[idx]->evbase);
			sched_yield();
		}
		for (int idx = 0; idx < ctx->num_thr; idx++) {
			pthread_join(ctx->thr[idx]->thr, NULL);
		}
		for (int idx = 0; idx < ctx->num_thr; idx++) {
			if (ctx->thr[idx]->evbase) {
				event_base_free(ctx->thr[idx]->evbase);
			}
			pthread_mutex_destroy(&ctx->thr[idx]->mutex);
			free(ctx->thr[idx]);
		}
		free(ctx->thr);
	}
	free(ctx);
}

void 
pxy_thrmgr_add_conn(pxy_conn_ctx_t *ctx)
{
	pthread_mutex_lock(&ctx->thr->mutex);
	if (!ctx->in_thr_conns) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_add_conn: Adding conn, id=%llu, fd=%d\n", ctx->id, ctx->fd);
#endif /* DEBUG_PROXY */

		ctx->in_thr_conns = 1;
		// Always keep thr load and conns list in sync
		ctx->thr->load++;
		ctx->next = ctx->thr->conns;
		ctx->thr->conns = ctx;
	} else {
		// Do not add conns twice
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_add_conn: Will not add conn twice, id=%llu, fd=%d\n", ctx->id, ctx->fd);
#endif /* DEBUG_PROXY */
	}
	pthread_mutex_unlock(&ctx->thr->mutex);
}

static void NONNULL(1)
pxy_thrmgr_remove_conn_unlocked(pxy_conn_ctx_t *ctx)
{
	assert(ctx != NULL);

	if (ctx->in_thr_conns) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_remove_conn_unlocked: Removing conn, id=%llu, fd=%d\n", ctx->id, ctx->fd);
#endif /* DEBUG_PROXY */

		// Thr conns list cannot be empty, if the in_thr_conns flag of a conn is set
		assert(ctx->thr->conns != NULL);

		// Shouldn't need to reset the in_thr_conns flag, because the conn ctx will be freed next, but just in case
		ctx->in_thr_conns = 0;
		// We increment thr load in pxy_thrmgr_add_conn() only
		ctx->thr->load--;

		// @attention We may get multiple conns with the same fd combinations, so fds cannot uniquely define a conn; hence the need for unique ids.
		if (ctx->id == ctx->thr->conns->id) {
			ctx->thr->conns = ctx->thr->conns->next;
			return;
		} else {
			pxy_conn_ctx_t *current = ctx->thr->conns->next;
			pxy_conn_ctx_t *previous = ctx->thr->conns;
			while (current != NULL && previous != NULL) {
				if (ctx->id == current->id) {
					previous->next = current->next;
					return;
				}
				previous = current;
				current = current->next;
			}
			// This should never happen
			log_err_level_printf(LOG_CRIT, "Cannot find conn in thr conns\n");
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_thrmgr_remove_conn_unlocked: Cannot find conn in thr conns, id=%llu, fd=%d\n", ctx->id, ctx->fd);
#endif /* DEBUG_PROXY */
			assert(0);
		}
	} else {
		// This can happen if we are closing the conn after a fatal error before setting its event callback
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_remove_conn_unlocked: Conn not in thr conns, id=%llu, fd=%d\n", ctx->id, ctx->fd);
#endif /* DEBUG_PROXY */
	}
}

/*
 * Attach a new connection to a thread.  Chooses the thread with the fewest
 * currently active connections, returns the appropriate event bases.
 * No need to be so accurate about balancing thread loads, so uses 
 * thread-level mutexes, instead of a thrmgr level mutex.
 * Returns the index of the chosen thread (for passing to _detach later).
 * This function cannot fail.
 */
void
pxy_thrmgr_attach(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_attach: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	int thridx = 0;
	size_t minload;

	pxy_thrmgr_ctx_t *tmctx = ctx->thrmgr;
	pthread_mutex_lock(&tmctx->thr[0]->mutex);
	minload = tmctx->thr[0]->load;
	pthread_mutex_unlock(&tmctx->thr[0]->mutex);

#ifdef DEBUG_THREAD
	log_dbg_printf("===> Proxy connection handler thread status:\n"
	               "thr[0]: %zu\n", minload);
#endif /* DEBUG_THREAD */
	for (int idx = 1; idx < tmctx->num_thr; idx++) {
		pthread_mutex_lock(&tmctx->thr[idx]->mutex);
#ifdef DEBUG_THREAD
		log_dbg_printf("thr[%d]: %zu\n", idx, tmctx->thr[idx]->load);
#endif /* DEBUG_THREAD */
		if (minload > tmctx->thr[idx]->load) {
			minload = tmctx->thr[idx]->load;
			thridx = idx;
		}
		pthread_mutex_unlock(&tmctx->thr[idx]->mutex);
	}

	// Defer adding the conn to the conn list of its thread until after a successful conn setup while returning from pxy_conn_connect()
	// otherwise pxy_thrmgr_timer_cb() may try to access the conn ctx while it is being freed on failure (signal 6 crash)
	ctx->thr = tmctx->thr[thridx];
	ctx->evbase = ctx->thr->evbase;

#ifdef DEBUG_THREAD
	log_dbg_printf("thridx: %d\n", thridx);
#endif /* DEBUG_THREAD */
}

/*
 * Detach a connection from a thread by index.
 * This function cannot fail.
 */
void
pxy_thrmgr_detach_unlocked(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_thrmgr_detach_unlocked: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_thrmgr_remove_conn_unlocked(ctx);
}

void
pxy_thrmgr_detach(pxy_conn_ctx_t *ctx)
{
	pthread_mutex_lock(&ctx->thr->mutex);
	pxy_thrmgr_detach_unlocked(ctx);
	pthread_mutex_unlock(&ctx->thr->mutex);
}

/* vim: set noet ft=c: */
