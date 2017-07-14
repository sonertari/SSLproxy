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

#include "pxythrmgr.h"

#include "sys.h"
#include "log.h"
#include "pxyconn.h"

#include <string.h>
#include <event2/bufferevent.h>
#include <pthread.h>
#include <assert.h>

/*
 * Proxy thread manager: manages the connection handling worker threads
 * and the per-thread resources (i.e. event bases).  The load is shared
 * across num_cpu * 2 connection handling threads, using the number of
 * currently assigned connections as the sole metric.
 *
 * The attach and detach functions are thread-safe.
 */

#define THR_TIMER_TIMEOUT 10
#define THR_TIMER_PRINT_INFO_TIMEOUT 1*THR_TIMER_TIMEOUT
#define CONN_EXPIRE_TIME 120

static void
pxy_thrmgr_get_thr_expired_conns(pxy_thr_ctx_t *ctx, proxy_conn_meta_ctx_t **expired_conns)
{
	*expired_conns = NULL;

	time_t now = time(NULL);

	proxy_conn_meta_ctx_t *mctx = ctx->mctx_list;
	while (mctx) {
		unsigned long elapsed_time = now - mctx->access_time;
		if (elapsed_time > CONN_EXPIRE_TIME) {
			mctx->next_expired = *expired_conns;
			*expired_conns = mctx;
		}

		mctx = mctx->next;
	}
	
	mctx = *expired_conns;
	if (mctx) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_get_thr_expired_conns: ----------------------------- Expired conns: thr=%d\n", ctx->thridx);
		while (mctx) {
			proxy_conn_meta_ctx_t *next = mctx->next_expired;
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_get_expired_conns: thr=%d, fd=%d, child_fd=%d, time=%lld\n",
					mctx->thr->thridx, mctx->fd, mctx->child_fd, (long int) now - mctx->access_time);
			mctx = next;
		}
	}
}

static void
pxy_thrmgr_print_child(pxy_conn_child_ctx_t *child_ctx, int count)
{
	assert(child_ctx != NULL);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> .......... pxy_thrmgr_print_child: thr=%d, cont=%d, src=%d, dst=%d, c=%d-%d, ci=%d\n",
			child_ctx->mctx->thr->thridx, count, child_ctx->src_fd, child_ctx->dst_fd, child_ctx->src.closed, child_ctx->dst.closed, child_ctx->idx);
	if (child_ctx->next) {
		pxy_thrmgr_print_child(child_ctx->next, count);
	}
}

static void
pxy_thrmgr_print_thr_info(pxy_thr_ctx_t *ctx)
{
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info: thr=%d, load=%lu\n", ctx->thridx, ctx->load);

	if (ctx->mctx_list) {
		time_t now = time(NULL);

		proxy_conn_meta_ctx_t *mctx = ctx->mctx_list;
		int count = 0;
		while (mctx) {
			char *host, *port;
			if (mctx->addrlen == 0 || (sys_sockaddr_str((struct sockaddr *)&mctx->addr, mctx->addrlen, &host, &port) != 0)) {
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info: Cannot get host:port: thr=%d, cont=%d, fd=%d, child_fd=%d\n", ctx->thridx, count, mctx->fd, mctx->child_fd);
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info: thr=%d, cont=%d, fd=%d, child_fd=%d, src=%d, dst=%d, srv_dst=%d, child_src=%d, child_dst=%d, p=%d-%d-%d c=%d-%d, pe=%d ce=%d tcc=%d, time=%lld\n",
						ctx->thridx, count, mctx->fd, mctx->child_fd, mctx->src_fd, mctx->dst_fd, mctx->srv_dst_fd, mctx->child_src_fd, mctx->child_dst_fd,
						mctx->src_closed, mctx->dst_closed, mctx->srv_dst_closed, mctx->child_src_closed, mctx->child_dst_closed, mctx->parent ? 1:0, mctx->children ? 1:0, mctx->child_count,(long int) now - mctx->access_time);
			} else {
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info: thr=%d, cont=%d, fd=%d, child_fd=%d, src=%d, dst=%d, srv_dst=%d, child_src=%d, child_dst=%d, p=%d-%d-%d c=%d-%d, pe=%d ce=%d tcc=%d, time=%lld, addr=%s:%s\n",
						ctx->thridx, count, mctx->fd, mctx->child_fd, mctx->src_fd, mctx->dst_fd, mctx->srv_dst_fd, mctx->child_src_fd, mctx->child_dst_fd,
						mctx->src_closed, mctx->dst_closed, mctx->srv_dst_closed, mctx->child_src_closed, mctx->child_dst_closed, mctx->parent ? 1:0, mctx->children ? 1:0, mctx->child_count, (long int) now - mctx->access_time, host ? host : "?", port ? port : "?");
				free(host);
				free(port);
			}

			if (mctx->children) {
				pxy_thrmgr_print_child(mctx->children, count);
			}

			count++;
			mctx = mctx->next;
		}
	}
		
	log_dbg_level_printf(LOG_DBG_MODE_FINE, ">>> pxy_thrmgr_print_thr_info: EXIT\n");
}

/*
 * Recurring timer event to prevent the event loops from exiting when
 * they run out of events.
 */
static void
pxy_thrmgr_timer_cb(UNUSED evutil_socket_t fd, UNUSED short what,
                    UNUSED void *arg)
{
	pxy_thr_ctx_t *ctx = arg;

	if (ctx->timer_cb_running) {
		return;
	}
	ctx->timer_cb_running = 1;

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! pxy_thrmgr_timer_cb <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< THREAD TIMER thr=%d, load=%lu, to=%u\n", ctx->thridx, ctx->load, ctx->timeout_count);
	proxy_conn_meta_ctx_t *expired = NULL;
	pxy_thrmgr_get_thr_expired_conns(ctx, &expired);

	if (expired) {
		time_t now = time(NULL);
		while (expired) {
			proxy_conn_meta_ctx_t *next = expired->next_expired;

			log_dbg_level_printf(LOG_DBG_MODE_FINE, ">>>>> !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! pxy_thrmgr_timer_cb: DELETE thr=%d, fd=%d, child_fd=%d, time=%lld <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< TIMED OUT\n",
					expired->thr->thridx, expired->fd, expired->child_fd, (long int) now - expired->access_time);
			pxy_conn_free(expired->parent);

			expired = next;
		}
	}
	
	ctx->timeout_count++;
	if (ctx->timeout_count * THR_TIMER_TIMEOUT > THR_TIMER_PRINT_INFO_TIMEOUT) {
		ctx->timeout_count = 0;
		pxy_thrmgr_print_thr_info(ctx);
	}

	ctx->timer_cb_running = 0;
}

/*
 * Thread entry point; runs the event loop of the event base.
 * Does not exit until the libevent loop is broken explicitly.
 */
static void *
pxy_thrmgr_thr(void *arg)
{
	pxy_thr_ctx_t *ctx = arg;
	struct timeval timer_delay = {THR_TIMER_TIMEOUT, 0};
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
	int idx = -1, dns = 0;

	dns = opts_has_dns_spec(ctx->opts);

	pthread_mutex_init(&ctx->mutex, NULL);

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
		if (dns) {
			/* only create dns base if we actually need it later */
			ctx->thr[idx]->dnsbase = evdns_base_new(
			                         ctx->thr[idx]->evbase, 1);
			if (!ctx->thr[idx]->dnsbase) {
				log_dbg_printf("Failed to create dnsbase %d\n",
				               idx);
				goto leave;
			}
		}
		ctx->thr[idx]->load = 0;
		ctx->thr[idx]->running = 0;
		ctx->thr[idx]->mctx_list = NULL;
		ctx->thr[idx]->thridx = idx;
		ctx->thr[idx]->timeout_count = 0;
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
			if (ctx->thr[idx]->dnsbase) {
				evdns_base_free(ctx->thr[idx]->dnsbase, 0);
			}
			if (ctx->thr[idx]->evbase) {
				event_base_free(ctx->thr[idx]->evbase);
			}
			free(ctx->thr[idx]);
		}
		idx--;
	}
	pthread_mutex_destroy(&ctx->mutex);
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
	pthread_mutex_destroy(&ctx->mutex);
	if (ctx->thr) {
		for (int idx = 0; idx < ctx->num_thr; idx++) {
			event_base_loopbreak(ctx->thr[idx]->evbase);
			sched_yield();
		}
		for (int idx = 0; idx < ctx->num_thr; idx++) {
			pthread_join(ctx->thr[idx]->thr, NULL);
		}
		for (int idx = 0; idx < ctx->num_thr; idx++) {
			if (ctx->thr[idx]->dnsbase) {
				evdns_base_free(ctx->thr[idx]->dnsbase, 0);
			}
			if (ctx->thr[idx]->evbase) {
				event_base_free(ctx->thr[idx]->evbase);
			}
			free(ctx->thr[idx]);
		}
		free(ctx->thr);
	}
	free(ctx);
}

static void 
pxy_thrmgr_remove_mctx(proxy_conn_meta_ctx_t *node, proxy_conn_meta_ctx_t **head)
{
	assert(node != NULL);
	assert(*head != NULL);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_remove_mctx: DELETING, fd=%d, child_fd=%d\n", node->fd, node->child_fd);
	
	// @attention We may get multiple conns with the same fd combinations, so they cannot uniquely define a conn; hence the need for uuids.
    if (uuid_compare(node->uuid, (*head)->uuid, NULL) == 0) {
        *head = (*head)->next;
        return;
    }

    proxy_conn_meta_ctx_t *current = (*head)->next;
    proxy_conn_meta_ctx_t *previous = *head;
    while (current != NULL && previous != NULL) {
        if (uuid_compare(node->uuid, current->uuid, NULL) == 0) {
            previous->next = current->next;
            return;
        }
        previous = current;
        current = current->next;
    }
}

/*
 * Attach a new connection to a thread.  Chooses the thread with the fewest
 * currently active connections, returns the appropriate event bases.
 * Returns the index of the chosen thread (for passing to _detach later).
 * This function cannot fail.
 */
void
pxy_thrmgr_attach(proxy_conn_meta_ctx_t *mctx)
{
	int thridx;
	size_t minload;

	pxy_thrmgr_ctx_t *ctx = mctx->thrmgr;
	pthread_mutex_lock(&ctx->mutex);

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_attach: ENTER\n");

	thridx = 0;
	minload = ctx->thr[thridx]->load;
#ifdef DEBUG_THREAD
	log_dbg_printf("===> Proxy connection handler thread status:\n"
	               "thr[%d]: %zu\n", thridx, minload);
#endif /* DEBUG_THREAD */
	for (int idx = 1; idx < ctx->num_thr; idx++) {
#ifdef DEBUG_THREAD
		log_dbg_printf("thr[%d]: %zu\n", idx, ctx->thr[idx]->load);
#endif /* DEBUG_THREAD */
		if (minload > ctx->thr[idx]->load) {
			minload = ctx->thr[idx]->load;
			thridx = idx;
		}
	}
	mctx->thr = ctx->thr[thridx];

	mctx->evbase = mctx->thr->evbase;
	mctx->dnsbase = mctx->thr->dnsbase;
	mctx->thr->load++;

	mctx->next = mctx->thr->mctx_list;
	mctx->thr->mctx_list = mctx;

	// @attention We are running on the thrmgr thread, do not call conn thread functions here.
	//pxy_thrmgr_print_thr_info(mctx->thr);

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_attach: EXIT\n");
	pthread_mutex_unlock(&ctx->mutex);

#ifdef DEBUG_THREAD
	log_dbg_printf("thridx: %d\n", thridx);
#endif /* DEBUG_THREAD */
}

void
pxy_thrmgr_attach_child(proxy_conn_meta_ctx_t *mctx)
{
	pthread_mutex_lock(&mctx->thrmgr->mutex);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_attach_child\n");
	mctx->thr->load++;
	pthread_mutex_unlock(&mctx->thrmgr->mutex);
}

/*
 * Detach a connection from a thread by index.
 * This function cannot fail.
 */
void
pxy_thrmgr_detach(proxy_conn_meta_ctx_t *mctx)
{
	pthread_mutex_lock(&mctx->thrmgr->mutex);

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_detach: BEFORE pxy_thrmgr_remove_mctx\n");
	pxy_thrmgr_print_thr_info(mctx->thr);

	mctx->thr->load--;

	if (!mctx->children) {
		pxy_thrmgr_remove_mctx(mctx, &mctx->thr->mctx_list);
	} else {
		log_dbg_level_printf(LOG_DBG_MODE_FINER, ">>>>> pxy_thrmgr_detach: parent has an active child, will not remove from the list, fd=%d, child_fd=%d <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",
				mctx->fd, mctx->child_fd);
	}

	log_dbg_level_printf(LOG_DBG_MODE_FINER, ">>>>> pxy_thrmgr_detach: AFTER pxy_thrmgr_remove_mctx\n");
	pxy_thrmgr_print_thr_info(mctx->thr);

	pthread_mutex_unlock(&mctx->thrmgr->mutex);
}

void
pxy_thrmgr_detach_child(proxy_conn_meta_ctx_t *mctx)
{
	pthread_mutex_lock(&mctx->thrmgr->mutex);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_detach_child\n");
	mctx->thr->load--;
	pthread_mutex_unlock(&mctx->thrmgr->mutex);
}

/* vim: set noet ft=c: */
