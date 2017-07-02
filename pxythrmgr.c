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

/*
 * Dummy recurring timer event to prevent the event loops from exiting when
 * they run out of events.
 */
static void
pxy_thrmgr_timer_cb(UNUSED evutil_socket_t fd, UNUSED short what,
                    UNUSED void *arg)
{
	/* do nothing */
}

/*
 * Thread entry point; runs the event loop of the event base.
 * Does not exit until the libevent loop is broken explicitly.
 */
static void *
pxy_thrmgr_thr(void *arg)
{
	pxy_thr_ctx_t *ctx = arg;
	struct timeval timer_delay = {60, 0};
	struct event *ev;

	ev = event_new(ctx->evbase, -1, EV_PERSIST, pxy_thrmgr_timer_cb, NULL);
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
//	ctx->num_thr = 1;
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

//	pthread_mutexattr_t *attr;
//	pthread_mutexattr_init(attr);
//	pthread_mutexattr_settype(attr, PTHREAD_MUTEX_RECURSIVE);
////	pthread_mutexattr_settype(attr, PTHREAD_MUTEX_ERRORCHECK);

	pthread_mutex_init(&ctx->mutex, NULL);
//	pthread_mutex_init(&ctx->mutex, attr);

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
		ctx->thr[idx]->mctx = NULL;
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

void 
pxy_thrmgr_remove_node(proxy_conn_meta_ctx_t *node, proxy_conn_meta_ctx_t **head)
{
	assert(node != NULL);
	assert(*head != NULL);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_remove_node: DELETING, fd=%d, fd2=%d\n", node->fd, node->fd2);
	
	// @todo Why do we get multiple conns with the same fd? So fd or (fd, fd2) pair cannot uniquely define a connection, but just fd was supposed to be enough.
	// Does libevent free the fd if it fails, and then reuse the same fd immediately?
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
    return;
}

/*
 * Attach a new connection to a thread.  Chooses the thread with the fewest
 * currently active connections, returns the appropriate event bases.
 * Returns the index of the chosen thread (for passing to _detach later).
 * This function cannot fail.
 */
int
pxy_thrmgr_attach(pxy_thrmgr_ctx_t *ctx, struct event_base **evbase,
                  struct evdns_base **dnsbase, proxy_conn_meta_ctx_t *mctx)
{
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> ENTER pxy_thrmgr_attach()\n");

	int thridx;
	size_t minload;

	thridx = 0;
	pthread_mutex_lock(&ctx->mutex);
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
	*evbase = ctx->thr[thridx]->evbase;
	*dnsbase = ctx->thr[thridx]->dnsbase;
	ctx->thr[thridx]->load++;

	mctx->thridx = thridx;

	mctx->next = ctx->thr[thridx]->mctx;
	ctx->thr[thridx]->mctx = mctx;

	pxy_thrmgr_print_thr_info(ctx);

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> EXIT pxy_thrmgr_attach()\n");
	pthread_mutex_unlock(&ctx->mutex);

#ifdef DEBUG_THREAD
	log_dbg_printf("thridx: %d\n", thridx);
#endif /* DEBUG_THREAD */

	return thridx;
}

/*
 * Detach a connection from a thread by index.
 * This function cannot fail.
 */
void
pxy_thrmgr_detach(pxy_thrmgr_ctx_t *ctx, int thridx, proxy_conn_meta_ctx_t *mctx)
{
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_detach()\n");
	pthread_mutex_lock(&ctx->mutex);

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_detach(): BEFORE pxy_thrmgr_remove_node\n");
	pxy_thrmgr_print_thr_info(ctx);

	if (!mctx->child_ctx) {
		pxy_thrmgr_remove_node(mctx, &ctx->thr[thridx]->mctx);
		ctx->thr[thridx]->load--;
	} else {
		log_dbg_level_printf(LOG_DBG_MODE_FINE, ">>>>> pxy_thrmgr_detach(): parent ctx has an active child, will not remove from the list, fd=%d, fd2=%d <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",
				mctx->fd, mctx->fd2);
	}

	log_dbg_level_printf(LOG_DBG_MODE_FINER, ">>>>> pxy_thrmgr_detach(): AFTER pxy_thrmgr_remove_node\n");
	pxy_thrmgr_print_thr_info(ctx);

	pthread_mutex_unlock(&ctx->mutex);
}

void
pxy_thrmgr_detach_e2(pxy_thrmgr_ctx_t *ctx, int thridx, proxy_conn_meta_ctx_t *mctx)
{
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_detach_e2()\n");
	pthread_mutex_lock(&ctx->mutex);

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_detach_e2(): BEFORE pxy_thrmgr_remove_node\n");
	pxy_thrmgr_print_thr_info(ctx);

	if (!mctx->parent_ctx) {
		pxy_thrmgr_remove_node(mctx, &ctx->thr[thridx]->mctx);
		ctx->thr[thridx]->load--;
	} else {
		log_dbg_level_printf(LOG_DBG_MODE_FINE, ">>>>> pxy_thrmgr_detach_e2(): child ctx has an active parent, will not remove from the list, fd=%d, fd2=%d <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n",
				mctx->fd, mctx->fd2);
	}

	log_dbg_level_printf(LOG_DBG_MODE_FINER, ">>>>> pxy_thrmgr_detach_e2(): AFTER pxy_thrmgr_remove_node\n");
	pxy_thrmgr_print_thr_info(ctx);

	pthread_mutex_unlock(&ctx->mutex);
}

void
pxy_thrmgr_print_child_info(pxy_conn_child_info_t *info)
{
	assert(info != NULL);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> .......... pxy_thrmgr_print_child_info(): e2dst=%d, dst2=%d, c=%d-%d, cc=%d, f=%d\n",
			info->e2dst_fd, info->dst2_fd, info->e2dst_eof, info->dst2_eof, info->child_count, info->freed);
	if (info->next) {
		pxy_thrmgr_print_child_info(info->next);
	}
}

void
pxy_thrmgr_print_thr_info(pxy_thrmgr_ctx_t *ctx)
{
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>>---------------------- pxy_thrmgr_print_thr_info(): ENTER\n");

	time_t now = time(NULL);

	for (int i = 0; i < ctx->num_thr; i++) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): thr=%d, load=%lu\n", i, ctx->thr[i]->load);
		
		proxy_conn_meta_ctx_t *mctx = ctx->thr[i]->mctx;
		int count = 0;
		while (mctx) {
			char *host, *port;
			if (sys_sockaddr_str((struct sockaddr *)&mctx->addr, mctx->addrlen, &host, &port) != 0) {
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): sys_sockaddr_str FAILED\n");
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): thr=%d, cont=%d, fd=%d, fd2=%d, src=%d, e2src=%d, dst=%d, e2dst=%d, dst2=%d, p=%d-%d-%d c=%d-%d, init=%d, pe=%d ce=%d tcc=%d, time=%lld\n",
						i, count, mctx->fd, mctx->fd2, mctx->src_fd, mctx->e2src_fd, mctx->dst_fd, mctx->e2dst_fd, mctx->dst2_fd,
						mctx->src_eof, mctx->e2src_eof, mctx->dst_eof, mctx->e2dst_eof, mctx->dst2_eof, mctx->initialized, mctx->parent_ctx ? 1:0, mctx->child_ctx ? 1:0, mctx->child_count,(long int) now - mctx->access_time);
			} else {
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): thr=%d, cont=%d, fd=%d, fd2=%d, src=%d, e2src=%d, dst=%d, e2dst=%d, dst2=%d, p=%d-%d-%d c=%d-%d, init=%d, pe=%d ce=%d tcc=%d, time=%lld, addr=%s:%s\n",
						i, count, mctx->fd, mctx->fd2, mctx->src_fd, mctx->e2src_fd, mctx->dst_fd, mctx->e2dst_fd, mctx->dst2_fd,
						mctx->src_eof, mctx->e2src_eof, mctx->dst_eof, mctx->e2dst_eof, mctx->dst2_eof, mctx->initialized, mctx->parent_ctx ? 1:0, mctx->child_ctx ? 1:0, mctx->child_count, (long int) now - mctx->access_time, host ? host : "?", port ? port : "?");
				free(host);
				free(port);
			}

			if (mctx->child_info) {
				pxy_thrmgr_print_child_info(mctx->child_info);
			}

			count++;
			mctx = mctx->next;
		}
	}
		
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): EXIT\n");
}

void
pxy_thrmgr_get_expired_conns(pxy_thrmgr_ctx_t *ctx, proxy_conn_meta_ctx_t **delete_list)
{
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>>---------------------- pxy_thrmgr_get_expired_conns(): ENTER\n");

	*delete_list = NULL;

	time_t now = time(NULL);

	for (int i = 0; i < ctx->num_thr; i++) {
		proxy_conn_meta_ctx_t *current = ctx->thr[i]->mctx;
		while (current) {
			unsigned long elapsed_time = now - current->access_time;
			if (elapsed_time > 60) {
				current->delete = *delete_list;
				*delete_list = current;
			}
			
			current = current->next;
		}
	}
	
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_get_expired_conns(): ----------------------------- delete list:\n");
	proxy_conn_meta_ctx_t *delete = *delete_list;
	while (delete) {
		proxy_conn_meta_ctx_t *next = delete->delete;
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_get_expired_conns(): thr=%d, fd=%d, fd2=%d, time=%lld\n",
				delete->thridx, delete->fd, delete->fd2, (long int) now - delete->access_time);
		delete = next;
	}
			
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>>---------------------- pxy_thrmgr_get_expired_conns(): EXIT\n");
}

/* vim: set noet ft=c: */
