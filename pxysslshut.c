/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
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

#include "pxysslshut.h"

#include "log.h"
#include "attrib.h"

#include <stdlib.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>


/*
 * Cleanly shut down an SSL socket.  Libevent currently has no support for
 * cleanly shutting down an SSL socket so we work around that by using a
 * low-level event.  This works for recent versions of OpenSSL.  OpenSSL
 * with the older SSL_shutdown() semantics, not exposing WANT_READ/WRITE
 * may or may not work.
 */

/*
 * SSL shutdown context.
 */

typedef struct pxy_ssl_shutdown_ctx {
	opts_t *opts;
	struct event_base *evbase;
	struct event *ev;
	SSL *ssl;
	unsigned int retries;
} pxy_ssl_shutdown_ctx_t;

static pxy_ssl_shutdown_ctx_t *
pxy_ssl_shutdown_ctx_new(opts_t *opts, struct event_base *evbase, SSL *ssl)
{
	pxy_ssl_shutdown_ctx_t *ctx;

	ctx = malloc(sizeof(pxy_ssl_shutdown_ctx_t));
	if (!ctx)
		return NULL;
	ctx->opts = opts;
	ctx->evbase = evbase;
	ctx->ssl = ssl;
	ctx->ev = NULL;
	ctx->retries = 0;
	return ctx;
}

static void
pxy_ssl_shutdown_ctx_free(pxy_ssl_shutdown_ctx_t *ctx)
{
	free(ctx);
}

#ifdef DEBUG_PROXY
char *sslerr_names[] = {
	"SSL_ERROR_WANT_READ",
	"SSL_ERROR_WANT_WRITE",
	"SSL_ERROR_ZERO_RETURN",
	"SSL_ERROR_SYSCALL",
	"SSL_ERROR_SSL",
	"UNKWN"
	};

static char *
pxy_ssl_shutdown_get_sslerr_name(int sslerr)
{
	if (sslerr == SSL_ERROR_WANT_READ) {
		return sslerr_names[0];
	} else if (sslerr == SSL_ERROR_WANT_WRITE) {
		return sslerr_names[1];
	} else if (sslerr == SSL_ERROR_ZERO_RETURN) {
		return sslerr_names[2];
	} else if (sslerr == SSL_ERROR_SYSCALL) {
		return sslerr_names[3];
	} else if (sslerr == SSL_ERROR_SSL) {
		return sslerr_names[4];
	} else {
		return sslerr_names[5];
	}
}
#endif /* DEBUG_PROXY */

/*
 * The shutdown socket event handler.  This is either
 * scheduled as a timeout-only event, or as a fd read or
 * fd write event, depending on whether SSL_shutdown()
 * indicates it needs read or write on the socket.
 */
static void
pxy_ssl_shutdown_cb(evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_ssl_shutdown_ctx_t *ctx = arg;

	// @attention Increasing the delay to 500 or more fixes some ssl shutdown failures, they report SSL_ERROR_WANT_READ before eventually succeeding
	// @todo Can/should we set an adaptive delay per conn here? Does it matter?
	struct timeval retry_delay = {0, 100};
	short want = 0;
	int rv, sslerr;

	if (ctx->ev) {
		event_free(ctx->ev);
		ctx->ev = NULL;
	}

	/*
	 * Use the new (post-2008) semantics for SSL_shutdown() on a
	 * non-blocking socket.  SSL_shutdown() returns -1 and WANT_READ
	 * if the other end's close notify was not received yet, and
	 * WANT_WRITE it could not write our own close notify.
	 *
	 * This is a good collection of recent and relevant documents:
	 * http://bugs.python.org/issue8108
	 */
	rv = SSL_shutdown(ctx->ssl);
	if (rv == 1)
		goto complete;
	if (rv != -1)
		goto retry;
	
	sslerr = SSL_get_error(ctx->ssl, rv);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_ssl_shutdown_cb: %s, retries=%d, fd=%d\n", pxy_ssl_shutdown_get_sslerr_name(sslerr), ctx->retries, fd);
#endif /* DEBUG_PROXY */

	switch (sslerr) {
		case SSL_ERROR_WANT_READ:
			want = EV_READ;
			goto retry;
		case SSL_ERROR_WANT_WRITE:
			want = EV_WRITE;
			goto retry;
		case SSL_ERROR_ZERO_RETURN:
			goto retry;
		case SSL_ERROR_SYSCALL:
		case SSL_ERROR_SSL:
			goto complete;
		default:
			log_err_level_printf(LOG_CRIT, "Unhandled SSL_shutdown() error %i. Closing fd\n", sslerr);
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_ssl_shutdown_cb: Unhandled SSL_shutdown() error %i. Closing fd, fd=%d\n", sslerr, fd);
#endif /* DEBUG_PROXY */

			goto complete;
	}
	goto complete;

retry:
	if (ctx->retries++ >= 50) {
		log_err_level_printf(LOG_WARNING, "Failed to shutdown SSL connection cleanly: Max retries reached. Closing fd\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_ssl_shutdown_cb: Failed to shutdown SSL connection cleanly: Max retries reached. Closing fd, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

		goto complete;
	}

	ctx->ev = event_new(ctx->evbase, fd, want, pxy_ssl_shutdown_cb, ctx);
	if (!ctx->ev)
		goto memout;
	if (event_add(ctx->ev, &retry_delay) == -1) {
		event_free(ctx->ev);
		goto memout;
	}
	return;

memout:
	log_err_printf("Failed to shutdown SSL connection cleanly: Cannot create event. Closing fd\n");
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_ssl_shutdown_cb: Failed to shutdown SSL connection cleanly: Cannot create event. Closing fd, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

complete:
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_print_free(ssl_ssl_state_to_str(ctx->ssl, "SSL_free() in state "));
	}
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_ssl_shutdown_cb: fd=%d, %s", fd, ssl_ssl_state_to_str(ctx->ssl, "SSL_free() in state "));
#endif /* DEBUG_PROXY */

	SSL_free(ctx->ssl);
	evutil_closesocket(fd);
	pxy_ssl_shutdown_ctx_free(ctx);
}

/*
 * Cleanly shutdown an SSL session on file descriptor fd using low-level
 * file descriptor readiness events on event base evbase.
 * Guarantees that SSL and the corresponding SSL_CTX are freed and the
 * socket is closed, eventually, or in the case of fatal errors, immediately.
 */
void
pxy_ssl_shutdown(opts_t *opts, struct event_base *evbase, SSL *ssl,
                 evutil_socket_t fd)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_ssl_shutdown: ENTER, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	pxy_ssl_shutdown_ctx_t *sslshutctx;

	sslshutctx = pxy_ssl_shutdown_ctx_new(opts, evbase, ssl);
	if (!sslshutctx) {
		if (OPTS_DEBUG(opts)) {
			log_dbg_print_free(ssl_ssl_state_to_str(ssl, "SSL_free() in state "));
		}
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_ssl_shutdown: fd=%d, %s", fd, ssl_ssl_state_to_str(ssl, "SSL_free() in state "));
#endif /* DEBUG_PROXY */

		SSL_free(ssl);
		evutil_closesocket(fd);
		return;
	}
	pxy_ssl_shutdown_cb(fd, 0, sslshutctx);
}

/* vim: set noet ft=c: */
