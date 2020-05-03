/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
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

#include "proxy.h"

#include "privsep.h"
#include "pxythrmgr.h"
#include "pxyconn.h"
#include "prototcp.h"
#include "protossl.h"
#include "protohttp.h"
#include "protopop3.h"
#include "protosmtp.h"
#include "protoautossl.h"
#include "cachemgr.h"
#include "opts.h"
#include "log.h"
#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/thread.h>

/*
 * Proxy engine, built around libevent 2.x.
 */

static int signals[] = { SIGTERM, SIGQUIT, SIGHUP, SIGINT, SIGPIPE, SIGUSR1 };

struct proxy_ctx {
	pxy_thrmgr_ctx_t *thrmgr;
	struct event_base *evbase;
	struct event *sev[sizeof(signals)/sizeof(int)];
	struct event *gcev;
	struct proxy_listener_ctx *lctx;
	global_t *global;
	int loopbreak_reason;
};

static proxy_listener_ctx_t * MALLOC
proxy_listener_ctx_new(pxy_thrmgr_ctx_t *thrmgr, proxyspec_t *spec,
                       global_t *global)
{
	proxy_listener_ctx_t *ctx = malloc(sizeof(proxy_listener_ctx_t));
	if (!ctx)
		return NULL;
	memset(ctx, 0, sizeof(proxy_listener_ctx_t));
	ctx->thrmgr = thrmgr;
	ctx->spec = spec;
	ctx->global = global;
	return ctx;
}

static void NONNULL(1)
proxy_listener_ctx_free(proxy_listener_ctx_t *ctx)
{
	if (ctx->evcl) {
		evconnlistener_free(ctx->evcl);
	}
	if (ctx->next) {
		proxy_listener_ctx_free(ctx->next);
	}
	free(ctx);
}

static protocol_t NONNULL(1)
proxy_setup_proto(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->protoctx) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx, 0, sizeof(proto_ctx_t));

	// Default to tcp
	prototcp_setup(ctx);

	protocol_t proto;
	if (ctx->spec->upgrade) {
		proto = protoautossl_setup(ctx);
	} else if (ctx->spec->http) {
		if (ctx->spec->ssl) {
			proto = protohttps_setup(ctx);
		} else {
			proto = protohttp_setup(ctx);
		}
	} else if (ctx->spec->pop3) {
		if (ctx->spec->ssl) {
			proto = protopop3s_setup(ctx);
		} else {
			proto = protopop3_setup(ctx);
		}
	} else if (ctx->spec->smtp) {
		if (ctx->spec->ssl) {
			proto = protosmtps_setup(ctx);
		} else {
			proto = protosmtp_setup(ctx);
		}
	} else if (ctx->spec->ssl) {
		proto = protossl_setup(ctx);
	} else {
		proto = PROTO_TCP;
	}

	if (proto == PROTO_ERROR) {
		free(ctx->protoctx);
	}
	return proto;
}

static pxy_conn_ctx_t * MALLOC NONNULL(2,3,4)
proxy_conn_ctx_new(evutil_socket_t fd,
                 pxy_thrmgr_ctx_t *thrmgr,
                 proxyspec_t *spec, global_t *global,
			     evutil_socket_t clisock)
{
	log_finest_main_va("ENTER, fd=%d", fd);

	pxy_conn_ctx_t *ctx = malloc(sizeof(pxy_conn_ctx_t));
	if (!ctx) {
		return NULL;
	}
	memset(ctx, 0, sizeof(pxy_conn_ctx_t));

	ctx->id = thrmgr->conn_count++;

	log_finest_main_va("id=%llu, fd=%d", ctx->id, fd);

	ctx->type = CONN_TYPE_PARENT;
	ctx->fd = fd;
	ctx->conn = ctx;
	ctx->thrmgr = thrmgr;
	ctx->spec = spec;

	ctx->proto = proxy_setup_proto(ctx);
	if (ctx->proto == PROTO_ERROR) {
		free(ctx);
		return NULL;
	}

	ctx->global = global;
	ctx->clisock = clisock;

	ctx->ctime = time(NULL);
	ctx->atime = ctx->ctime;

	ctx->next = NULL;

#ifdef HAVE_LOCAL_PROCINFO
	ctx->lproc.pid = -1;
#endif /* HAVE_LOCAL_PROCINFO */
	return ctx;
}

/*
 * Does minimal clean-up, called on error by proxy_listener_acceptcb() only.
 * We call this function instead of pxy_conn_ctx_free(), because
 * proxy_listener_acceptcb() runs on thrmgr, whereas pxy_conn_ctx_free()
 * runs on conn handling thr. This is necessary to prevent multithreading issues.
 */
static void NONNULL(1)
proxy_conn_ctx_free(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	if (ctx->ev) {
		event_free(ctx->ev);
	}
	// If the proto doesn't have special args, proto_free() callback is NULL
	if (ctx->protoctx->proto_free) {
		ctx->protoctx->proto_free(ctx);
	}
	free(ctx->protoctx);
	free(ctx);
}

/*
 * Callback for accept events on the socket listener bufferevent.
 * Called when a new incoming connection has been accepted.
 * Initiates the connection to the server.  The incoming connection
 * from the client is not being activated until we have a successful
 * connection to the server, because we need the server's certificate
 * in order to set up the SSL session to the client.
 * For consistency, plain TCP works the same way, even if we could
 * start reading from the client while waiting on the connection to
 * the server to connect.
 */
static void
proxy_listener_acceptcb(UNUSED struct evconnlistener *listener,
                        evutil_socket_t fd,
                        struct sockaddr *peeraddr, int peeraddrlen,
                        void *arg)
{
	proxy_listener_ctx_t *lctx = arg;

	log_finest_main_va("ENTER, fd=%d", fd);

	/* create per connection state */
	pxy_conn_ctx_t *ctx = proxy_conn_ctx_new(fd, lctx->thrmgr, lctx->spec, lctx->global, lctx->clisock);
	if (!ctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating ctx memory\n");
		evutil_closesocket(fd);
		return;
	}

	// Choose the conn handling thr
	pxy_thrmgr_attach(ctx);

	/* prepare logging part 1 and user auth */
	ctx->srcaddrlen = peeraddrlen;
	memcpy(&ctx->srcaddr, peeraddr, ctx->srcaddrlen);

	// Switch from thrmgr to connection handling thread, i.e. change the event base, asap
	// This prevents possible multithreading issues between thrmgr and conn handling threads
	ctx->ev = event_new(ctx->evbase, -1, 0, ctx->protoctx->init_conn, ctx);
	if (!ctx->ev) {
		log_err_level(LOG_CRIT, "Error creating initial event, aborting connection");
		goto out;
	}
	// The only purpose of this event is to change the event base, so it is a one-shot event
	if (event_add(ctx->ev, NULL) == -1)
		goto out;
	event_active(ctx->ev, 0, 0);
	return;
out:
	evutil_closesocket(fd);
	proxy_conn_ctx_free(ctx);
}

/*
 * Callback for error events on the socket listener bufferevent.
 */
void
proxy_listener_errorcb(struct evconnlistener *listener, UNUSED void *arg)
{
	struct event_base *evbase = evconnlistener_get_base(listener);
	int err = EVUTIL_SOCKET_ERROR();
	log_err_level_printf(LOG_CRIT, "Error %d on listener: %s\n", err,
	               evutil_socket_error_to_string(err));
	/* Do not break the event loop if out of fds:
	 * Too many open files (24) */
	if (err == 24) {
		return;
	}
	event_base_loopbreak(evbase);
}

/*
 * Dump a description of an evbase to debugging code.
 */
static void
proxy_debug_base(const struct event_base *ev_base)
{
	log_dbg_printf("Using libevent backend '%s'\n",
	               event_base_get_method(ev_base));

	enum event_method_feature f;
	f = event_base_get_features(ev_base);
	log_dbg_printf("Event base supports: edge %s, O(1) %s, anyfd %s\n",
	               ((f & EV_FEATURE_ET) ? "yes" : "no"),
	               ((f & EV_FEATURE_O1) ? "yes" : "no"),
	               ((f & EV_FEATURE_FDS) ? "yes" : "no"));
}

/*
 * Set up the listener for a single proxyspec and add it to evbase.
 * Returns the proxy_listener_ctx_t pointer if successful, NULL otherwise.
 */
static proxy_listener_ctx_t *
proxy_listener_setup(struct event_base *evbase, pxy_thrmgr_ctx_t *thrmgr,
                     proxyspec_t *spec, global_t *global, evutil_socket_t clisock)
{
	log_finest_main("ENTER");

	int fd;
	if ((fd = privsep_client_opensock(clisock, spec)) == -1) {
		log_err_level_printf(LOG_CRIT, "Error opening socket: %s (%i)\n",
		               strerror(errno), errno);
		return NULL;
	}

	proxy_listener_ctx_t *lctx = proxy_listener_ctx_new(thrmgr, spec, global);
	if (!lctx) {
		log_err_level_printf(LOG_CRIT, "Error creating listener context\n");
		evutil_closesocket(fd);
		return NULL;
	}

	lctx->clisock = clisock;
	
	// @todo Should we enable threadsafe event structs?
	// @attention Do not pass NULL as user-supplied pointer
	lctx->evcl = evconnlistener_new(evbase, proxy_listener_acceptcb,
	                               lctx, LEV_OPT_CLOSE_ON_FREE, 1024, fd);
	if (!lctx->evcl) {
		log_err_level_printf(LOG_CRIT, "Error creating evconnlistener: %s\n",
		               strerror(errno));
		proxy_listener_ctx_free(lctx);
		evutil_closesocket(fd);
		return NULL;
	}
	evconnlistener_set_error_cb(lctx->evcl, proxy_listener_errorcb);
	return lctx;
}

/*
 * Signal handler for SIGTERM, SIGQUIT, SIGINT, SIGHUP, SIGPIPE and SIGUSR1.
 */
static void
proxy_signal_cb(evutil_socket_t fd, UNUSED short what, void *arg)
{
	proxy_ctx_t *ctx = arg;

	if (OPTS_DEBUG(ctx->global)) {
		log_dbg_printf("Received signal %i\n", fd);
	}

	switch(fd) {
	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
		proxy_loopbreak(ctx, fd);
		break;
	case SIGHUP:
	case SIGUSR1:
		if (log_reopen() == -1) {
			log_err_level_printf(LOG_WARNING, "Failed to reopen logs\n");
		} else {
			log_dbg_printf("Reopened log files\n");
		}
		break;
	case SIGPIPE:
		log_err_level_printf(LOG_WARNING, "Received SIGPIPE; ignoring.\n");
		break;
	default:
		log_err_level_printf(LOG_WARNING, "Received unexpected signal %i\n", fd);
		break;
	}
}

/*
 * Garbage collection handler.
 */
static void
proxy_gc_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	proxy_ctx_t *ctx = arg;

	if (OPTS_DEBUG(ctx->global))
		log_dbg_printf("Garbage collecting caches started.\n");

	cachemgr_gc();

	if (OPTS_DEBUG(ctx->global))
		log_dbg_printf("Garbage collecting caches done.\n");
}

/*
 * Set up the core event loop.
 * Socket clisock is the privsep client socket used for binding to ports.
 * Returns ctx on success, or NULL on error.
 */
proxy_ctx_t *
proxy_new(global_t *global, int clisock)
{
	proxy_listener_ctx_t *head;
	proxy_ctx_t *ctx;
	struct evdns_base *dnsbase;
	int rc;

	/* adds locking, only required if accessed from separate threads */
	evthread_use_pthreads();

#ifndef PURIFY
	if (OPTS_DEBUG(global)) {
		event_enable_debug_mode();
	}
#endif /* PURIFY */

	ctx = malloc(sizeof(proxy_ctx_t));
	if (!ctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		goto leave0;
	}
	memset(ctx, 0, sizeof(proxy_ctx_t));

	ctx->global = global;
	ctx->evbase = event_base_new();
	if (!ctx->evbase) {
		log_err_level_printf(LOG_CRIT, "Error getting event base\n");
		goto leave1;
	}

	if (global_has_dns_spec(global)) {
		/* create a dnsbase here purely for being able to test parsing
		 * resolv.conf while we can still alert the user about it. */
		dnsbase = evdns_base_new(ctx->evbase, 0);
		if (!dnsbase) {
			log_err_level_printf(LOG_CRIT, "Error creating dns event base\n");
			goto leave1b;
		}
		rc = evdns_base_resolv_conf_parse(dnsbase, DNS_OPTIONS_ALL,
		                                  "/etc/resolv.conf");
		evdns_base_free(dnsbase, 0);
		if (rc != 0) {
			log_err_level_printf(LOG_CRIT, "evdns cannot parse resolv.conf: "
			               "%s (%d)\n",
			               rc == 1 ? "failed to open file" :
			               rc == 2 ? "failed to stat file" :
			               rc == 3 ? "file too large" :
			               rc == 4 ? "out of memory" :
			               rc == 5 ? "short read from file" :
			               rc == 6 ? "no nameservers in file" :
			               "unknown error", rc);
			goto leave1b;
		}
	}

	if (OPTS_DEBUG(global)) {
		proxy_debug_base(ctx->evbase);
	}

	ctx->thrmgr = pxy_thrmgr_new(global);
	if (!ctx->thrmgr) {
		log_err_level_printf(LOG_CRIT, "Error creating thread manager\n");
		goto leave1b;
	}

	head = ctx->lctx = NULL;
	for (proxyspec_t *spec = global->spec; spec; spec = spec->next) {
		head = proxy_listener_setup(ctx->evbase, ctx->thrmgr,
		                            spec, global, clisock);
		if (!head)
			goto leave2;
		head->next = ctx->lctx;
		ctx->lctx = head;

		char *specstr = proxyspec_str(spec);
		if (!specstr) {
			fprintf(stderr, "out of memory\n");
			exit(EXIT_FAILURE);
		}
		log_dbg_printf("proxy_listener_setup: %s\n", specstr);
		free(specstr);
	}

	for (size_t i = 0; i < (sizeof(signals) / sizeof(int)); i++) {
		ctx->sev[i] = evsignal_new(ctx->evbase, signals[i],
		                           proxy_signal_cb, ctx);
		if (!ctx->sev[i])
			goto leave3;
		evsignal_add(ctx->sev[i], NULL);
	}

	struct timeval gc_delay = {60, 0};
	ctx->gcev = event_new(ctx->evbase, -1, EV_PERSIST, proxy_gc_cb, ctx);
	if (!ctx->gcev)
		goto leave4;
	evtimer_add(ctx->gcev, &gc_delay);

	// @attention Do not close privsep sock, we open new sockets for child conns
	//privsep_client_close(clisock);
	return ctx;

leave4:
	if (ctx->gcev) {
		event_free(ctx->gcev);
	}

leave3:
	for (size_t i = 0; i < (sizeof(ctx->sev) / sizeof(ctx->sev[0])); i++) {
		if (ctx->sev[i]) {
			event_free(ctx->sev[i]);
		}
	}
leave2:
	if (ctx->lctx) {
		proxy_listener_ctx_free(ctx->lctx);
	}
	pxy_thrmgr_free(ctx->thrmgr);
leave1b:
	event_base_free(ctx->evbase);
leave1:
	free(ctx);
leave0:
	return NULL;
}

/*
 * Run the event loop.
 * Returns 0 on non-signal termination, signal number when the event loop was
 * canceled by a signal, or -1 on failure.
 */
int
proxy_run(proxy_ctx_t *ctx)
{
	if (ctx->global->detach) {
		event_reinit(ctx->evbase);
	}
#ifndef PURIFY
	if (OPTS_DEBUG(ctx->global)) {
		event_base_dump_events(ctx->evbase, stderr);
	}
#endif /* PURIFY */
	if (pxy_thrmgr_run(ctx->thrmgr) == -1) {
		log_err_level_printf(LOG_CRIT, "Failed to start thread manager\n");
		return -1;
	}
	if (OPTS_DEBUG(ctx->global)) {
		log_dbg_printf("Starting main event loop.\n");
	}
	event_base_dispatch(ctx->evbase);
	if (OPTS_DEBUG(ctx->global)) {
		log_dbg_printf("Main event loop stopped (reason=%i).\n",
		               ctx->loopbreak_reason);
	}
	return ctx->loopbreak_reason;
}

/*
 * Break the loop of the proxy, causing the proxy_run to return, returning
 * the reason given in reason (signal number, 0 for success, -1 for error).
 */
void
proxy_loopbreak(proxy_ctx_t *ctx, int reason)
{
	ctx->loopbreak_reason = reason;
	event_base_loopbreak(ctx->evbase);
}

/*
 * Free the proxy data structures.
 */
void
proxy_free(proxy_ctx_t *ctx)
{
	if (ctx->gcev) {
		event_free(ctx->gcev);
	}
	if (ctx->lctx) {
		proxy_listener_ctx_free(ctx->lctx);
	}
	for (size_t i = 0; i < (sizeof(ctx->sev) / sizeof(ctx->sev[0])); i++) {
		if (ctx->sev[i]) {
			event_free(ctx->sev[i]);
		}
	}
	if (ctx->thrmgr) {
		pxy_thrmgr_free(ctx->thrmgr);
	}
	if (ctx->evbase) {
		event_base_free(ctx->evbase);
	}
	free(ctx);
}

/* vim: set noet ft=c: */
