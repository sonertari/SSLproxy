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

int
pxy_thrmgr_init(pxy_thrmgr_ctx_t *ctx)
{
	int idx = -1, dns = 0;

	dns = opts_has_dns_spec(ctx->opts);

//	pthread_mutex_init(&ctx->mutex, NULL);

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

	return 0;

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
	
//	pxy_thrmgr_init(ctx);
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

//	dns = opts_has_dns_spec(ctx->opts);

//	pthread_mutexattr_t *attr;
//	pthread_mutexattr_init(attr);
//	pthread_mutexattr_settype(attr, PTHREAD_MUTEX_RECURSIVE);
////	pthread_mutexattr_settype(attr, PTHREAD_MUTEX_ERRORCHECK);

	pthread_mutex_init(&ctx->mutex, NULL);
//	pthread_mutex_init(&ctx->mutex, attr);
	pthread_mutex_init(&ctx->mutex2, NULL);

//	if (!(ctx->thr = malloc(ctx->num_thr * sizeof(pxy_thr_ctx_t*)))) {
//		log_dbg_printf("Failed to allocate memory\n");
//		goto leave;
//	}
//	memset(ctx->thr, 0, ctx->num_thr * sizeof(pxy_thr_ctx_t*));
//
//	for (idx = 0; idx < ctx->num_thr; idx++) {
//		if (!(ctx->thr[idx] = malloc(sizeof(pxy_thr_ctx_t)))) {
//			log_dbg_printf("Failed to allocate memory\n");
//			goto leave;
//		}
//		memset(ctx->thr[idx], 0, sizeof(pxy_thr_ctx_t));
//		ctx->thr[idx]->evbase = event_base_new();
//		if (!ctx->thr[idx]->evbase) {
//			log_dbg_printf("Failed to create evbase %d\n", idx);
//			goto leave;
//		}
//		if (dns) {
//			/* only create dns base if we actually need it later */
//			ctx->thr[idx]->dnsbase = evdns_base_new(
//			                         ctx->thr[idx]->evbase, 1);
//			if (!ctx->thr[idx]->dnsbase) {
//				log_dbg_printf("Failed to create dnsbase %d\n",
//				               idx);
//				goto leave;
//			}
//		}
//		ctx->thr[idx]->load = 0;
//		ctx->thr[idx]->running = 0;
//	}
//
//	log_dbg_printf("Initialized %d connection handling threads\n",
//	               ctx->num_thr);

	pxy_thrmgr_init(ctx);

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

//int 
//pxy_thrmgr_is_same_mctx(proxy_conn_meta_ctx_t *mctx1, proxy_conn_meta_ctx_t *mctx2, int stop)
//{
//	if (!mctx1 && !mctx2) {
//		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_is_same_mctx: SAME both NULL\n");
//		return 1;
////	} else if (mctx1 && mctx2) {
////		if ((uuid_compare(mctx1->uuid, mctx2->uuid, NULL) == 0) && (mctx1->fd == mctx2->fd) && (mctx1->fd2 == mctx2->fd2) &&
////				(mctx1->src_fd == mctx2->src_fd) && (mctx1->e2src_fd == mctx2->e2src_fd) &&
////				(mctx1->e2dst_fd == mctx2->e2dst_fd) && (mctx1->dst_fd == mctx2->dst_fd) &&
////				(mctx1->dst2_fd == mctx2->dst2_fd) && (mctx1->child_count == mctx2->child_count) &&
//////				(mctx1->access_time == mctx2->access_time) && (mctx1->initialized == mctx2->initialized) &&
////				// Stop recursion
////				(stop || (pxy_thrmgr_is_same_mctx(mctx1->next, mctx2->next, 1))) ) {
////			log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_is_same_mctx: SAME match ALL, fd=%d, fd2=%d\n", mctx1->fd, mctx1->fd2);
////			return 1;
////		}
////	}
//	} else if ((mctx1 && mctx2) && (uuid_compare(mctx1->uuid, mctx2->uuid, NULL) == 0)) {
//		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_is_same_mctx: UUIDs match, fd=%d, fd2=%d\n", mctx1->fd, mctx1->fd2);
//		return 1;
//	}
//	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_is_same_mctx: NOT same, fd=%d, fd2=%d\n", mctx1->fd, mctx1->fd2);
//	return 0;
//}

void 
pxy_thrmgr_remove_node(proxy_conn_meta_ctx_t *node, proxy_conn_meta_ctx_t **head)
{
	assert(node != NULL);
	assert(*head != NULL);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_remove_node: DELETING, fd=%d, fd2=%d\n", node->fd, node->fd2);
	
	// XXX: Does (fd, fd2) pair uniquely define a connection? Just fd was supposed to be enough.
	// @todo fd may be the same for multiple connections, and if fd2 is NULL, do we get a clash?
//    if ((node->fd == (*head)->fd) && (node->fd2 == (*head)->fd2)) {
//    if (pxy_thrmgr_is_same_mctx(node, *head, 0)) {
    if (uuid_compare(node->uuid, (*head)->uuid, NULL) == 0) {
        *head = (*head)->next;
        return;
    }

    proxy_conn_meta_ctx_t *current = (*head)->next;
    proxy_conn_meta_ctx_t *previous = *head;
    while (current != NULL && previous != NULL) {
//        if ((node->fd == current->fd) && (node->fd2 == current->fd2)) {
//        if (pxy_thrmgr_is_same_mctx(node, current, 0)) {
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
	
	int err = pthread_mutex_lock(&ctx->mutex);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> load pxy_thrmgr_attach() err=%d\n", err);

	thridx = 0;

	if (!ctx->thr) {
		thridx= -1;
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_attach() goto exit_attach\n");
		goto exit_attach;
	}
	
	minload = ctx->thr[thridx]->load;
#ifdef DEBUG_THREAD
	log_dbg_printf("===> Proxy connection handler thread status:\n"
	               "thr[%d]: %zu\n", thridx, minload);
#endif /* DEBUG_THREAD */

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> for pxy_thrmgr_attach()\n");

	for (int idx = 1; idx < ctx->num_thr; idx++) {
#ifdef DEBUG_THREAD
		log_dbg_printf("thr[%d]: %zu\n", idx, ctx->thr[idx]->load);
#endif /* DEBUG_THREAD */
		if (minload > ctx->thr[idx]->load) {
			minload = ctx->thr[idx]->load;
			thridx = idx;
		}
	}
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> evbase pxy_thrmgr_attach()\n");
	*evbase = ctx->thr[thridx]->evbase;
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> dnsbase pxy_thrmgr_attach()\n");
	*dnsbase = ctx->thr[thridx]->dnsbase;
	ctx->thr[thridx]->load++;

	mctx->thridx = thridx;

	mctx->next = ctx->thr[thridx]->mctx;
	ctx->thr[thridx]->mctx = mctx;

#ifdef DEBUG_THREAD
	log_dbg_printf("thridx: %d\n", thridx);
#endif /* DEBUG_THREAD */

	pxy_thrmgr_print_thr_info(ctx);

exit_attach:
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> EXIT pxy_thrmgr_attach()\n");
	pthread_mutex_unlock(&ctx->mutex);
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

	pxy_thrmgr_remove_node(mctx, &ctx->thr[thridx]->mctx);
	ctx->thr[thridx]->load--;

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>> pxy_thrmgr_detach(): AFTER pxy_thrmgr_remove_node\n");
	pxy_thrmgr_print_thr_info(ctx);

	pthread_mutex_unlock(&ctx->mutex);
}

void
pxy_thrmgr_print_thr_info(pxy_thrmgr_ctx_t *ctx)
{
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>>---------------------- pxy_thrmgr_print_thr_info(): ENTER\n");

	proxy_conn_meta_ctx_t *delete_list = NULL;

	time_t now = time(NULL);

	for (int i = 0; i < ctx->num_thr; i++) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): thr=%d, load=%d\n", i, ctx->thr[i]->load);
		
		proxy_conn_meta_ctx_t *current = ctx->thr[i]->mctx;
		int count = 0;
		while (current) {
//			int src_fd = -1;
//			int e2src_fd = -1;
//			int dst_fd = -1;
//			int e2dst_fd = -1;
//			int dst2_fd = -1;
//			
//			if (current->parent_ctx) {
//				if (current->parent_ctx->src.bev) {
//					src_fd = event_get_fd(current->parent_ctx->src.bev);
//				}
//				if (current->parent_ctx->e2src.bev) {
//					e2src_fd = event_get_fd(current->parent_ctx->e2src.bev);
//				}
//				if (current->parent_ctx->dst.bev) {
//					dst_fd = event_get_fd(current->parent_ctx->dst.bev);
//				}
//			}
//
//			if (current->child_ctx) {
//				if (current->child_ctx->e2dst.bev) {
//					e2dst_fd = event_get_fd(current->child_ctx->e2dst.bev);
//				}
//				if (current->child_ctx->dst.bev) {
//					dst2_fd = event_get_fd(current->child_ctx->dst.bev);
//				}
//			}

			int src_fd = current->src_fd;
			int e2src_fd = current->e2src_fd;
			int dst_fd = current->dst_fd;
			int e2dst_fd = current->e2dst_fd;
			int dst2_fd = current->dst2_fd;

			unsigned long elapsed_time = now - current->access_time;
			if (elapsed_time > 30) {
				current->delete = delete_list;
				delete_list = current;
			}
			
			char *host, *port;
			if (sys_sockaddr_str((struct sockaddr *)&current->addr, current->addrlen, &host, &port) != 0) {
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): sys_sockaddr_str FAILED\n");
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): thr=%d, cont=%d, fd=%d, fd2=%d, src=%d, e2src=%d, dst=%d, e2dst=%d, dst2=%d, p=%d-%d-%d c=%d-%d, init=%d, cc=%d, time=%d\n",
						i, count, current->fd, current->fd2, src_fd, e2src_fd, dst_fd, e2dst_fd, dst2_fd, current->src_eof, current->e2src_eof, current->dst_eof, current->e2dst_eof, current->dst2_eof, current->initialized, current->child_count, now - current->access_time);
			} else {
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): thr=%d, cont=%d, fd=%d, fd2=%d, src=%d, e2src=%d, dst=%d, e2dst=%d, dst2=%d, p=%d-%d-%d c=%d-%d, init=%d, cc=%d, time=%d, addr=%s:%s\n",
						i, count, current->fd, current->fd2, src_fd, e2src_fd, dst_fd, e2dst_fd, dst2_fd, current->src_eof, current->e2src_eof, current->dst_eof, current->e2dst_eof, current->dst2_eof, current->initialized, current->child_count, now - current->access_time, host ? host : "?", port ? port : "?");
				free(host);
				free(port);
			}
			count++;
			current = current->next;
		}
	}
	
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): ----------------------------- delete list:\n");
//	proxy_conn_meta_ctx_t *delete = delete_list;
	proxy_conn_meta_ctx_t *new_delete_list = NULL;
	pxy_thrmgr_get_elapsed_conns(ctx, &new_delete_list);
	proxy_conn_meta_ctx_t *delete = new_delete_list;
	while (delete) {
		proxy_conn_meta_ctx_t *next = delete->delete;
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): thr=%d, fd=%d, fd2=%d, time=%d\n",
				delete->thridx, delete->fd, delete->fd2, now - delete->access_time);
		delete = next;
	}
		
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_print_thr_info(): EXIT\n");
}

void
pxy_thrmgr_get_elapsed_conns(pxy_thrmgr_ctx_t *ctx, proxy_conn_meta_ctx_t **delete_list)
{
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>>---------------------- pxy_thrmgr_get_elapsed_conns(): ENTER\n");

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
	
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_get_elapsed_conns(): ----------------------------- delete list:\n");
	proxy_conn_meta_ctx_t *delete = *delete_list;
	while (delete) {
		proxy_conn_meta_ctx_t *next = delete->delete;
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>> pxy_thrmgr_get_elapsed_conns(): thr=%d, fd=%d, fd2=%d, time=%d\n",
				delete->thridx, delete->fd, delete->fd2, now - delete->access_time);
		delete = next;
	}
			
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, ">>>>>---------------------- pxy_thrmgr_get_elapsed_conns(): EXIT\n");
}

/* vim: set noet ft=c: */
