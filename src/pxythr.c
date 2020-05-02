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

size_t
pxy_thr_get_load(pxy_thr_ctx_t *tctx)
{
	size_t load;
	//pthread_mutex_lock(&tctx->mutex);
	load = tctx->load;
	//pthread_mutex_unlock(&tctx->mutex);
	return load;
}

void
pxy_thr_inc_load(pxy_thr_ctx_t *tctx)
{
	//pthread_mutex_lock(&tctx->mutex);
	tctx->load++;
	//pthread_mutex_unlock(&tctx->mutex);
}

void
pxy_thr_dec_load(pxy_thr_ctx_t *tctx)
{
	//pthread_mutex_lock(&tctx->mutex);
	tctx->load--;
	//pthread_mutex_unlock(&tctx->mutex);
}

void
pxy_thr_add_pending_ssl_conn(pxy_conn_ctx_t *ctx)
{
	if (!ctx->sslctx->pending) {
		log_finest("Adding conn");
		ctx->sslctx->pending = 1;
		ctx->thr->pending_ssl_conn_count++;

		ctx->sslctx->next_pending = ctx->thr->pending_ssl_conns;
		ctx->thr->pending_ssl_conns = ctx;
		if (ctx->sslctx->next_pending)
			ctx->sslctx->next_pending->sslctx->prev_pending = ctx;
	}
}

void
pxy_thr_remove_pending_ssl_conn(pxy_conn_ctx_t *ctx)
{
	if (ctx->sslctx && ctx->sslctx->pending) {
		log_finest("Removing conn");

		// Thr pending_ssl_conns list cannot be empty, if the sslctx->pending flag of a conn is set
		assert(ctx->thr->pending_ssl_conns != NULL);

		ctx->sslctx->pending = 0;
		ctx->thr->pending_ssl_conn_count--;

		if (ctx->sslctx->prev_pending) {
			ctx->sslctx->prev_pending->sslctx->next_pending = ctx->sslctx->next_pending;
		} else {
			ctx->thr->pending_ssl_conns = ctx->sslctx->next_pending;
		}
		if (ctx->sslctx->next_pending)
			ctx->sslctx->next_pending->sslctx->prev_pending = ctx->sslctx->prev_pending;

#ifdef DEBUG_PROXY
		// @attention We may get multiple conns with the same fd combinations, so fds cannot uniquely define a conn; hence the need for unique ids.
		if (ctx->thr->pending_ssl_conns) {
			if (ctx->id == ctx->thr->pending_ssl_conns->id) {
				log_fine("Found conn in thr pending_ssl_conns, first");
				assert(0);
			} else {
				pxy_conn_ctx_t *current = ctx->thr->pending_ssl_conns->sslctx->next_pending;
				pxy_conn_ctx_t *previous = ctx->thr->pending_ssl_conns;
				while (current != NULL && previous != NULL) {
					if (ctx->id == current->id) {
						log_fine("Found conn in thr pending_ssl_conns");
						assert(0);
						return;
					}
					previous = current;
					current = current->sslctx->next_pending;
				}
				log_fine("Cannot find conn in thr pending_ssl_conns");
			}
		} else {
			log_fine("Cannot find conn in thr pending_ssl_conns, empty");
		}
#endif /* DEBUG_PROXY */
	}
}

/*
 * Detach a connection from a thread by index.
 * This function cannot fail.
 */
void
pxy_thr_detach(pxy_conn_ctx_t *ctx)
{
	assert(ctx != NULL);
	assert(ctx->children == NULL);

	log_finest("ENTER");

	pxy_thr_remove_pending_ssl_conn(ctx);

	if (!ctx->in_thr_conns) {
		log_fine("Not in thr conns");
		return;
	}

	// Thr conns list cannot be empty
	assert(ctx->thr->conns != NULL);

	log_finest("Removing conn");

	// We increment thr load in pxy_conn_init() only (for parent conns)
	pxy_thr_dec_load(ctx->thr);

	if (ctx->prev) {
		ctx->prev->next = ctx->next;
	} else {
		ctx->thr->conns = ctx->next;
	}
	if (ctx->next)
		ctx->next->prev = ctx->prev;

	// No need to reset the ctx->in_thr_conns flag, as we free the ctx right after calling this function

#ifdef DEBUG_PROXY
	// @attention We may get multiple conns with the same fd combinations, so fds cannot uniquely identify a conn; hence the need for unique ids.
	if (ctx->thr->conns) {
		if (ctx->id == ctx->thr->conns->id) {
			log_fine("Found conn in thr conns, first");
			assert(0);
		} else {
			pxy_conn_ctx_t *current = ctx->thr->conns->next;
			pxy_conn_ctx_t *previous = ctx->thr->conns;
			while (current != NULL && previous != NULL) {
				if (ctx->id == current->id) {
					log_fine("Found conn in thr conns");
					assert(0);
				}
				previous = current;
				current = current->next;
			}
			log_finest("Cannot find conn in thr conns");
		}
	} else {
		log_finest("Cannot find conn in thr conns, empty");
	}
#endif /* DEBUG_PROXY */
}

static void
pxy_thr_get_expired_conns(pxy_thr_ctx_t *tctx, pxy_conn_ctx_t **expired_conns)
{
	*expired_conns = NULL;

	if (tctx->conns) {
		time_t now = time(NULL);

		pxy_conn_ctx_t *ctx = tctx->conns;
		while (ctx) {
			time_t elapsed_time = now - ctx->atime;
			if (elapsed_time > (time_t)tctx->thrmgr->global->conn_idle_timeout) {
				ctx->next_expired = *expired_conns;
				*expired_conns = ctx;
			}
			ctx = ctx->next;
		}

		ctx = tctx->pending_ssl_conns;
		while (ctx) {
			time_t elapsed_time = now - ctx->atime;
			if (elapsed_time > (time_t)tctx->thrmgr->global->conn_idle_timeout) {
				ctx->next_expired = *expired_conns;
				*expired_conns = ctx;
			}
			ctx = ctx->sslctx->next_pending;
		}

		if (tctx->thrmgr->global->statslog) {
			ctx = *expired_conns;
			while (ctx) {
				log_finest_main_va("thr=%d, fd=%d, child_fd=%d, time=%lld, src_addr=%s:%s, dst_addr=%s:%s, user=%s, valid=%d, pc=%d",
					ctx->thr->thridx, ctx->fd, ctx->child_fd, (long long)(now - ctx->atime),
					STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
					STRORDASH(ctx->user), ctx->protoctx->is_valid, ctx->sslctx ? ctx->sslctx->pending : 0);

				char *msg;
				if (asprintf(&msg, "EXPIRED: thr=%d, time=%lld, src_addr=%s:%s, dst_addr=%s:%s, user=%s, valid=%d\n", 
						ctx->thr->thridx, (long long)(now - ctx->atime),
						STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
						STRORDASH(ctx->user), ctx->protoctx->is_valid) < 0) {
					break;
				}

				if (log_conn(msg) == -1) {
					log_err_level_printf(LOG_WARNING, "Expired conn logging failed\n");
				}
				free(msg);

				ctx = ctx->next_expired;
			}
		}
	}
}

static evutil_socket_t
pxy_thr_print_children(pxy_conn_child_ctx_t *ctx,
#ifdef DEBUG_PROXY
	unsigned int parent_idx,
#endif /* DEBUG_PROXY */
	evutil_socket_t max_fd)
{
	while (ctx) {
		// @attention No need to log child stats
		log_finest_main_va("CHILD CONN: thr=%d, id=%d, pid=%u, src=%d, dst=%d, c=%d-%d",
			ctx->conn->thr->thridx, ctx->conn->child_count, parent_idx, ctx->fd, ctx->dst_fd, ctx->src.closed, ctx->dst.closed);

		max_fd = MAX(max_fd, MAX(ctx->fd, ctx->dst_fd));
		ctx = ctx->next;
	}
	return max_fd;
}

static void
pxy_thr_print_info(pxy_thr_ctx_t *tctx)
{
	log_finest_main_va("thr=%d, load=%zu", tctx->thridx, pxy_thr_get_load(tctx));

	unsigned int idx = 1;
	evutil_socket_t max_fd = 0;
	time_t max_atime = 0;
	time_t max_ctime = 0;

	char *smsg = NULL;

	if (tctx->conns || tctx->pending_ssl_conns) {
		time_t now = time(NULL);

		int conns_list = 1;
		pxy_conn_ctx_t *ctx = tctx->conns;
		if (!ctx) {
			ctx = tctx->pending_ssl_conns;
			conns_list = 0;
		}

		while (ctx) {
			time_t atime = now - ctx->atime;
			time_t ctime = now - ctx->ctime;

			log_finest_main_va("PARENT CONN: thr=%d, id=%u, fd=%d, child_fd=%d, dst=%d, srvdst=%d, child_src=%d, child_dst=%d, p=%d-%d-%d c=%d-%d, ce=%d cc=%d, at=%lld ct=%lld, src_addr=%s:%s, dst_addr=%s:%s, user=%s, valid=%d, pc=%d",
				tctx->thridx, idx, ctx->fd, ctx->child_fd, ctx->dst_fd, ctx->srvdst_fd, ctx->child_src_fd, ctx->child_dst_fd,
				ctx->src.closed, ctx->dst.closed, ctx->srvdst.closed, ctx->children ? ctx->children->src.closed : 0, ctx->children ? ctx->children->dst.closed : 0,
				ctx->children ? 1:0, ctx->child_count, (long long)atime, (long long)ctime,
				STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
				STRORDASH(ctx->user), ctx->protoctx->is_valid, ctx->sslctx ? ctx->sslctx->pending : 0);

			// @attention Report idle connections only, i.e. the conns which have been idle since the last time we checked for expired conns
			if (atime >= (time_t)tctx->thrmgr->global->expired_conn_check_period) {
				if (asprintf(&smsg, "IDLE: thr=%d, id=%u, ce=%d cc=%d, at=%lld ct=%lld, src_addr=%s:%s, dst_addr=%s:%s, user=%s, valid=%d, pc=%d\n",
						tctx->thridx, idx, ctx->children ? 1:0, ctx->child_count, (long long)atime, (long long)ctime,
						STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
						STRORDASH(ctx->user), ctx->protoctx->is_valid, ctx->sslctx ? ctx->sslctx->pending : 0) < 0) {
					return;
				}
				if (log_conn(smsg) == -1) {
					log_err_level_printf(LOG_WARNING, "Idle conn logging failed\n");
				}
				free(smsg);
				smsg = NULL;
			}

			// child_src_fd and child_dst_fd fields are mostly for debugging purposes, used in debug printing parent conns.
			// However, while an ssl child is closing, the children list may be empty, but child's ssl fd may be still open,
			// hence we include those fields in this max comparisons too
			max_fd = MAX(max_fd, MAX(ctx->fd, MAX(ctx->dst_fd, MAX(ctx->srvdst_fd, MAX(ctx->child_fd, MAX(ctx->child_src_fd, ctx->child_dst_fd))))));
			max_atime = MAX(max_atime, atime);
			max_ctime = MAX(max_ctime, ctime);

			if (ctx->children) {
				max_fd = pxy_thr_print_children(ctx->children,
#ifdef DEBUG_PROXY
					idx,
#endif /* DEBUG_PROXY */
					max_fd);
			}

			idx++;

			if (conns_list) {
				ctx = ctx->next;
				if (!ctx) {
					// Switch to pending ssl conns list
					ctx = tctx->pending_ssl_conns;
					conns_list = 0;
				}
			} else {
				ctx = ctx->sslctx->next_pending;
			}
		}
	}

	log_finest_main_va("thr=%d, mld=%zu, mfd=%d, mat=%lld, mct=%lld, iib=%llu, iob=%llu, eib=%llu, eob=%llu, swm=%zu, uwm=%zu, to=%zu, err=%zu, pc=%llu, si=%u",
			tctx->thridx, tctx->max_load, tctx->max_fd, (long long)max_atime, (long long)max_ctime, tctx->intif_in_bytes, tctx->intif_out_bytes, tctx->extif_in_bytes, tctx->extif_out_bytes,
			tctx->set_watermarks, tctx->unset_watermarks, tctx->timedout_conns, tctx->errors, tctx->pending_ssl_conn_count, tctx->stats_id);

	if (asprintf(&smsg, "STATS: thr=%d, mld=%zu, mfd=%d, mat=%lld, mct=%lld, iib=%llu, iob=%llu, eib=%llu, eob=%llu, swm=%zu, uwm=%zu, to=%zu, err=%zu, pc=%llu, si=%u\n",
			tctx->thridx, tctx->max_load, tctx->max_fd, (long long)max_atime, (long long)max_ctime, tctx->intif_in_bytes, tctx->intif_out_bytes, tctx->extif_in_bytes, tctx->extif_out_bytes,
			tctx->set_watermarks, tctx->unset_watermarks, tctx->timedout_conns, tctx->errors, tctx->pending_ssl_conn_count, tctx->stats_id) < 0) {
		return;
	}
	if (log_stats(smsg) == -1) {
		log_err_level_printf(LOG_WARNING, "Stats logging failed\n");
	}
	free(smsg);

	tctx->stats_id++;

	tctx->timedout_conns = 0;
	tctx->errors = 0;
	tctx->set_watermarks = 0;
	tctx->unset_watermarks = 0;

	tctx->intif_in_bytes = 0;
	tctx->intif_out_bytes = 0;
	tctx->extif_in_bytes = 0;
	tctx->extif_out_bytes = 0;

	// Reset these stats with the current values (do not reset to 0 directly, there may be active conns)
	tctx->max_fd = max_fd;
	tctx->max_load = pxy_thr_get_load(tctx);
}

/*
 * Recurring timer event to prevent the event loops from exiting when
 * they run out of events.
 */
static void
pxy_thr_timer_cb(UNUSED evutil_socket_t fd, UNUSED short what, UNUSED void *arg)
{
	pxy_thr_ctx_t *ctx = arg;

	log_finest_main_va("thr=%d, load=%zu, to=%u", ctx->thridx, pxy_thr_get_load(ctx), ctx->timeout_count);

	pxy_conn_ctx_t *expired = NULL;
	pxy_thr_get_expired_conns(ctx, &expired);

#ifdef DEBUG_PROXY
	if (expired) {
		time_t now = time(NULL);
#endif /* DEBUG_PROXY */
		while (expired) {
			pxy_conn_ctx_t *next = expired->next_expired;

			log_fine_main_va("Delete timed out conn thr=%d, fd=%d, child_fd=%d, at=%lld ct=%lld",
				expired->thr->thridx, expired->fd, expired->child_fd, (long long)(now - expired->atime), (long long)(now - expired->ctime));

			// @attention Do not call the term function here, free the conn directly
			pxy_conn_free(expired, 1);
			ctx->timedout_conns++;

			expired = next;
		}
#ifdef DEBUG_PROXY
	}
#endif /* DEBUG_PROXY */

	// @attention Print thread info only if stats logging is enabled, if disabled debug logs are not printed either
	if (ctx->thrmgr->global->statslog) {
		ctx->timeout_count++;
		if (ctx->timeout_count >= ctx->thrmgr->global->stats_period) {
			ctx->timeout_count = 0;
			pxy_thr_print_info(ctx);
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
	pxy_thr_ctx_t *ctx = arg;
	struct timeval timer_delay = {ctx->thrmgr->global->expired_conn_check_period, 0};
	struct event *ev;

	ev = event_new(ctx->evbase, -1, EV_PERSIST, pxy_thr_timer_cb, ctx);
	if (!ev)
		return NULL;
	evtimer_add(ev, &timer_delay);
	ctx->running = 1;
	event_base_dispatch(ctx->evbase);
	event_free(ev);

	return NULL;
}

/* vim: set noet ft=c: */
