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

#include "pxyconn.h"

#include "privsep.h"
#include "pxysslshut.h"
#include "cachemgr.h"
#include "ssl.h"
#include "opts.h"
#include "sys.h"
#include "util.h"
#include "base64.h"
#include "url.h"
#include "log.h"
#include "attrib.h"
#include "proc.h"

#include <netinet/in.h>
#include <arpa/inet.h>
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
#include <event2/dns.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <assert.h>
#include <sys/param.h>


/*
 * Maximum size of data to buffer per connection direction before
 * temporarily stopping to read data from the other end.
 */
#define OUTBUF_LIMIT	(128*1024)

/*
 * Print helper for logging code.
 */
#define STRORDASH(x)	(((x)&&*(x))?(x):"-")

/*
 * Context used for all server sessions.
 */
#ifdef USE_SSL_SESSION_ID_CONTEXT
static unsigned long ssl_session_context = 0x31415926;
#endif /* USE_SSL_SESSION_ID_CONTEXT */


/*
 * Proxy connection context state, describes a proxy connection
 * with source and destination socket bufferevents, SSL context and
 * other session state.  One of these exists per handled proxy
 * connection.
 */

#ifdef HAVE_LOCAL_PROCINFO
/* local process data - filled in iff pid != -1 */
typedef struct pxy_conn_lproc_desc {
	struct sockaddr_storage srcaddr;
	socklen_t srcaddrlen;

	pid_t pid;
	uid_t uid;
	gid_t gid;

	/* derived log strings */
	char *exec_path;
	char *user;
	char *group;
} pxy_conn_lproc_desc_t;
#endif /* HAVE_LOCAL_PROCINFO */

#define WANT_CONNECT_LOG(ctx)	((ctx)->opts->connectlog||!(ctx)->opts->detach)
#define WANT_CONTENT_LOG(ctx)	((ctx)->opts->contentlog&&!(ctx)->passthrough)

#define SSLPROXY_KEY		"SSLproxy:"
#define SSLPROXY_KEY_LEN	strlen(SSLPROXY_KEY)

static pxy_conn_ctx_t * MALLOC NONNULL(2,3,4)
pxy_conn_ctx_new(evutil_socket_t fd,
                 pxy_thrmgr_ctx_t *thrmgr,
                 proxyspec_t *spec, opts_t *opts,
			     evutil_socket_t clisock)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_new: ENTER fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	pxy_conn_ctx_t *ctx = malloc(sizeof(pxy_conn_ctx_t));
	if (!ctx) {
		log_err_printf("ERROR: Error allocating memory\n");
		evutil_closesocket(fd);
		return NULL;
	}
	memset(ctx, 0, sizeof(pxy_conn_ctx_t));

	ctx->uuid = malloc(sizeof(uuid_t));
	if (!ctx->uuid) {
		log_err_printf("ERROR: Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx);
		return NULL;
	}

	uuid_create(ctx->uuid, NULL);

#if defined (DEBUG_PROXY) && defined (OPENBSD)
	char *uuid_str;
	uuid_to_string(ctx->uuid, &uuid_str, NULL);
	if (uuid_str) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_new: uuid=%s, fd=%d\n", uuid_str, fd);
		free(uuid_str);
	}
#endif /* OPENBSD && DEBUG_PROXY */
	
	ctx->fd = fd;
	ctx->thrmgr = thrmgr;
	ctx->spec = spec;
	ctx->opts = opts;
	ctx->clisock = clisock;

	ctx->clienthello_search = ctx->spec->upgrade;

	ctx->ctime = time(NULL);
	ctx->atime = ctx->ctime;
	
	ctx->next = NULL;

	pxy_thrmgr_attach(ctx);
	
#ifdef HAVE_LOCAL_PROCINFO
	ctx->lproc.pid = -1;
#endif /* HAVE_LOCAL_PROCINFO */
#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%p             pxy_conn_ctx_new\n", (void*)ctx);
	}
#endif /* DEBUG_PROXY */
	return ctx;
}

static pxy_conn_child_ctx_t * MALLOC NONNULL(2)
pxy_conn_ctx_new_child(evutil_socket_t fd, pxy_conn_ctx_t *parent)
{
	assert(parent != NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_new_child: ENTER fd=%d\n", fd);
#endif /* DEBUG_PROXY */
	pxy_conn_child_ctx_t *ctx = malloc(sizeof(pxy_conn_child_ctx_t));
	if (!ctx) {
		return NULL;
	}
	memset(ctx, 0, sizeof(pxy_conn_child_ctx_t));
	ctx->fd = fd;
	ctx->parent = parent;
	// @attention Child ctxs use the parent's event bases, otherwise we would get multithreading issues
	pxy_thrmgr_attach_child(parent);
#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(parent->opts)) {
		log_dbg_printf("%p             pxy_conn_ctx_new_child\n", (void*)ctx);
	}
#endif /* DEBUG_PROXY */
	return ctx;
}

static void NONNULL(1)
pxy_conn_ctx_free_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_free_child: ENTER fd=%d, pfd=%d\n", ctx->fd, ctx->parent->fd);
	if (OPTS_DEBUG(ctx->parent->opts)) {
		log_dbg_printf("%p             pxy_conn_ctx_free_child\n",
		                (void*)ctx);
	}
#endif /* DEBUG_PROXY */
	pxy_thrmgr_detach_child(ctx->parent);
	
	if (ctx->srchost_str) {
		free(ctx->srchost_str);
	}
	if (ctx->srcport_str) {
		free(ctx->srcport_str);
	}
	if (ctx->dsthost_str) {
		free(ctx->dsthost_str);
	}
	if (ctx->dstport_str) {
		free(ctx->dstport_str);
	}
	if (ctx->ssl_names) {
		free(ctx->ssl_names);
	}
	if (ctx->origcrtfpr) {
		free(ctx->origcrtfpr);
	}
	if (ctx->usedcrtfpr) {
		free(ctx->usedcrtfpr);
	}
	free(ctx);
}

/*
 * Free bufferenvent and close underlying socket properly.
 * For OpenSSL bufferevents, this will shutdown the SSL connection.
 */
static void
bufferevent_free_and_close_fd(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "bufferevent_free_and_close_fd: ENTER i:%zu o:%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(bev)), fd);
#endif /* DEBUG_PROXY */

	SSL *ssl = NULL;

	if ((ctx->spec->ssl || ctx->clienthello_found) && !ctx->passthrough) {
		ssl = bufferevent_openssl_get_ssl(bev); /* does not inc refc */
	}

#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("            %p bufferevent_free_and_close_fd fd=%d\n",
		               (void*)bev, fd);
	}
#endif /* DEBUG_PROXY */

	// @todo Check if we need to NULL all cbs?
	// @see https://stackoverflow.com/questions/31688709/knowing-all-callbacks-have-run-with-libevent-and-bufferevent-free
	//bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	bufferevent_free(bev); /* does not free SSL unless the option
	                          BEV_OPT_CLOSE_ON_FREE was set */
	if (ssl) {
		pxy_ssl_shutdown(ctx->opts, ctx->evbase, ssl, fd);
	} else {
		if (evutil_closesocket(fd) == -1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "bufferevent_free_and_close_fd: evutil_closesocket FAILED, fd=%d\n", fd);
#endif /* DEBUG_PROXY */
		}
	}
}

/*
 * Free bufferenvent and close underlying socket properly.
 * This is for non-OpenSSL bufferevents.
 */
static void
bufferevent_free_and_close_fd_nonssl(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("            %p bufferevent_free_and_close_fd_nonssl fd=%d\n",
		               (void*)bev, fd);
	}
#endif /* DEBUG_PROXY */

	bufferevent_free(bev);

	if (evutil_closesocket(fd) == -1) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "bufferevent_free_and_close_fd_nonssl: evutil_closesocket FAILED, fd=%d\n", fd);
#endif /* DEBUG_PROXY */
	}
}

static void NONNULL(1,2)
pxy_conn_remove_child(pxy_conn_child_ctx_t *child, pxy_conn_child_ctx_t **head)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_remove_child: ENTER fd=%d\n", child->fd);
#endif /* DEBUG_PROXY */

    if (child->fd == (*head)->fd) {
        *head = (*head)->next;
        return;
    }

    pxy_conn_child_ctx_t *current = (*head)->next;
    pxy_conn_child_ctx_t *previous = *head;
    while (current != NULL && previous != NULL) {
        if (child->fd == current->fd) {
            previous->next = current->next;
            return;
        }
        previous = current;
        current = current->next;
    }
    return;
}

static void NONNULL(1)
pxy_conn_free_child(pxy_conn_child_ctx_t *ctx)
{
	assert(ctx->parent != NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_free_child: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_conn_ctx_t *parent = ctx->parent;

	pxy_conn_desc_t *dst = &ctx->dst;
	if (dst->bev) {
		bufferevent_free_and_close_fd(dst->bev, ctx->parent);
		dst->bev = NULL;
	}

	pxy_conn_desc_t *src = &ctx->src;
	if (src->bev) {
		bufferevent_free_and_close_fd_nonssl(src->bev, ctx->parent);
		src->bev = NULL;
	}

	pxy_conn_remove_child(ctx, &parent->children);
	pxy_conn_ctx_free_child(ctx);
}

static void NONNULL(1)
pxy_conn_ctx_free(pxy_conn_ctx_t *ctx, int by_requestor)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_free: ENTER fd=%d\n", ctx->fd);
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%p             pxy_conn_ctx_free\n",
		                (void*)ctx);
	}
#endif /* DEBUG_PROXY */
	if (WANT_CONTENT_LOG(ctx) && ctx->logctx) {
		if (log_content_close(&ctx->logctx, by_requestor) == -1) {
			log_err_printf("WARNING: Content log close failed\n");
		}
	}
	pxy_thrmgr_detach(ctx);
	if (ctx->srchost_str) {
		free(ctx->srchost_str);
	}
	if (ctx->srcport_str) {
		free(ctx->srcport_str);
	}
	if (ctx->dsthost_str) {
		free(ctx->dsthost_str);
	}
	if (ctx->dstport_str) {
		free(ctx->dstport_str);
	}
	if (ctx->http_method) {
		free(ctx->http_method);
	}
	if (ctx->http_uri) {
		free(ctx->http_uri);
	}
	if (ctx->http_host) {
		free(ctx->http_host);
	}
	if (ctx->http_content_type) {
		free(ctx->http_content_type);
	}
	if (ctx->http_status_code) {
		free(ctx->http_status_code);
	}
	if (ctx->http_status_text) {
		free(ctx->http_status_text);
	}
	if (ctx->http_content_length) {
		free(ctx->http_content_length);
	}
	if (ctx->ssl_names) {
		free(ctx->ssl_names);
	}
	if (ctx->origcrtfpr) {
		free(ctx->origcrtfpr);
	}
	if (ctx->usedcrtfpr) {
		free(ctx->usedcrtfpr);
	}
#ifdef HAVE_LOCAL_PROCINFO
	if (ctx->lproc.exec_path) {
		free(ctx->lproc.exec_path);
	}
	if (ctx->lproc.user) {
		free(ctx->lproc.user);
	}
	if (ctx->lproc.group) {
		free(ctx->lproc.group);
	}
#endif /* HAVE_LOCAL_PROCINFO */
	if (ctx->origcrt) {
		X509_free(ctx->origcrt);
	}
	if (ctx->ev) {
		event_free(ctx->ev);
	}
	if (ctx->uuid) {
		free(ctx->uuid);
	}
	if (ctx->sni) {
		free(ctx->sni);
	}
	if (ctx->header_str) {
		free(ctx->header_str);
	}
	if (ctx->srv_dst_ssl_version) {
		free(ctx->srv_dst_ssl_version);
	}
	if (ctx->srv_dst_ssl_cipher) {
		free(ctx->srv_dst_ssl_cipher);
	}
	free(ctx);
}

void NONNULL(1)
pxy_conn_free(pxy_conn_ctx_t *ctx, int by_requestor)
{
	evutil_socket_t fd = ctx->fd;

#ifdef DEBUG_PROXY
	evutil_socket_t child_fd = ctx->child_fd;
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_conn_free: ENTER fd=%d, child_fd=%d\n", fd, child_fd);
#endif /* DEBUG_PROXY */

	pxy_conn_desc_t *src = &ctx->src;
	if (!src->closed) {
		if (src->bev) {
			bufferevent_free_and_close_fd(src->bev, ctx);
			src->bev = NULL;
		} else {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_conn_free: evutil_closesocket on NULL src->bev, fd=%d\n", fd);
#endif /* DEBUG_PROXY */
			// @todo src fd may be open, although src.bev is NULL, where do we close the src fd?
			evutil_closesocket(fd);
		}
	}

	pxy_conn_desc_t *srv_dst = &ctx->srv_dst;
	if (srv_dst->bev) {
		bufferevent_free_and_close_fd(srv_dst->bev, ctx);
		srv_dst->bev = NULL;
	}

	pxy_conn_desc_t *dst = &ctx->dst;
	if (dst->bev) {
		bufferevent_free_and_close_fd_nonssl(dst->bev, ctx);
		dst->bev = NULL;
	}

	// @attention Free the child ctxs asap, we need their fds
	while (ctx->children) {
		pxy_conn_free_child(ctx->children);
	}

	// @attention Parent may be closing before there was any child at all nor was child_evcl ever created
	if (ctx->child_evcl) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_conn_free: Freeing child_evcl, pfd=%d, child_fd=%d, cfd=%d\n",
				ctx->fd, ctx->child_fd, ctx->children ? ctx->children->fd : -1);
#endif /* DEBUG_PROXY */
		// @attention child_evcl was created with LEV_OPT_CLOSE_ON_FREE, so do not close ctx->child_fd
		evconnlistener_free(ctx->child_evcl);
		ctx->child_evcl = NULL;
	}

	pxy_conn_ctx_free(ctx, by_requestor);
}

/* forward declaration of libevent callbacks */
static void pxy_bev_readcb(struct bufferevent *, void *);
static void pxy_bev_writecb(struct bufferevent *, void *);
static void pxy_bev_eventcb(struct bufferevent *, short, void *);
static void pxy_fd_readcb(evutil_socket_t, short, void *);
static void pxy_bev_readcb_child(struct bufferevent *, void *);
static void pxy_bev_writecb_child(struct bufferevent *, void *);
static void pxy_bev_eventcb_child(struct bufferevent *, short, void *);

/* forward declaration of OpenSSL callbacks */
#ifndef OPENSSL_NO_TLSEXT
static int pxy_ossl_servername_cb(SSL *ssl, int *al, void *arg);
#endif /* !OPENSSL_NO_TLSEXT */
static int pxy_ossl_sessnew_cb(SSL *, SSL_SESSION *);
static void pxy_ossl_sessremove_cb(SSL_CTX *, SSL_SESSION *);
static SSL_SESSION * pxy_ossl_sessget_cb(SSL *, unsigned char *, int, int *);

/*
 * Dump information on a certificate to the debug log.
 */
static void
pxy_debug_crt(X509 *crt)
{
	char *sj = ssl_x509_subject(crt);
	if (sj) {
		log_dbg_printf("Subject DN: %s\n", sj);
		free(sj);
	}

	char *names = ssl_x509_names_to_str(crt);
	if (names) {
		log_dbg_printf("Common Names: %s\n", names);
		free(names);
	}

	char *fpr;
	if (!(fpr = ssl_x509_fingerprint(crt, 1))) {
		log_err_printf("WARNING: Error generating X509 fingerprint\n");
	} else {
		log_dbg_printf("Fingerprint: %s\n", fpr);
		free(fpr);
	}

#ifdef DEBUG_CERTIFICATE
	/* dump certificate */
	log_dbg_print_free(ssl_x509_to_str(crt));
	log_dbg_print_free(ssl_x509_to_pem(crt));
#endif /* DEBUG_CERTIFICATE */
}

static void
pxy_log_connect_nonhttp(pxy_conn_ctx_t *ctx)
{
	char *msg;
#ifdef HAVE_LOCAL_PROCINFO
	char *lpi = NULL;
#endif /* HAVE_LOCAL_PROCINFO */
	int rv;

#ifdef HAVE_LOCAL_PROCINFO
	if (ctx->opts->lprocinfo) {
		rv = asprintf(&lpi, "lproc:%i:%s:%s:%s",
		              ctx->lproc.pid,
		              STRORDASH(ctx->lproc.user),
		              STRORDASH(ctx->lproc.group),
		              STRORDASH(ctx->lproc.exec_path));
		if ((rv < 0) || !lpi) {
			ctx->enomem = 1;
			goto out;
		}
	} else {
		lpi = "";
	}
#endif /* HAVE_LOCAL_PROCINFO */

	if (!ctx->src.ssl) {
		rv = asprintf(&msg, "%s %s %s %s %s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "\n",
		              ctx->passthrough ? "passthrough" : "tcp",
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str)
#ifdef HAVE_LOCAL_PROCINFO
		              , lpi
#endif /* HAVE_LOCAL_PROCINFO */
		             );
	} else {
		rv = asprintf(&msg, "%s %s %s %s %s "
		              "sni:%s names:%s "
		              "sproto:%s:%s dproto:%s:%s "
		              "origcrt:%s usedcrt:%s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "\n",
		              ctx->clienthello_found ? "upgrade" : "ssl",
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str),
		              STRORDASH(ctx->sni),
		              STRORDASH(ctx->ssl_names),
		              SSL_get_version(ctx->src.ssl),
		              SSL_get_cipher(ctx->src.ssl),
		              !ctx->srv_dst.closed ? SSL_get_version(ctx->srv_dst.ssl):ctx->srv_dst_ssl_version,
		              !ctx->srv_dst.closed ? SSL_get_cipher(ctx->srv_dst.ssl):ctx->srv_dst_ssl_cipher,
		              STRORDASH(ctx->origcrtfpr),
		              STRORDASH(ctx->usedcrtfpr)
#ifdef HAVE_LOCAL_PROCINFO
		              , lpi
#endif /* HAVE_LOCAL_PROCINFO */
		              );
	}
	if ((rv < 0) || !msg) {
		ctx->enomem = 1;
		goto out;
	}
	if (!ctx->opts->detach) {
		log_err_printf("INFO: %s", msg);
	}
	if (ctx->opts->connectlog) {
		if (log_connect_print_free(msg) == -1) {
			free(msg);
			log_err_printf("WARNING: Connection logging failed\n");
		}
	} else {
		free(msg);
	}
out:
#ifdef HAVE_LOCAL_PROCINFO
	if (lpi && ctx->opts->lprocinfo) {
		free(lpi);
	}
#endif /* HAVE_LOCAL_PROCINFO */
	return;
}

static void
pxy_log_connect_http(pxy_conn_ctx_t *ctx)
{
	char *msg;
#ifdef HAVE_LOCAL_PROCINFO
	char *lpi = NULL;
#endif /* HAVE_LOCAL_PROCINFO */
	int rv;

#ifdef DEBUG_PROXY
	if (ctx->passthrough) {
		log_err_printf("WARNING: pxy_log_connect_http called while in "
		               "passthrough mode\n");
		return;
	}
#endif

#ifdef HAVE_LOCAL_PROCINFO
	if (ctx->opts->lprocinfo) {
		rv = asprintf(&lpi, "lproc:%i:%s:%s:%s",
		              ctx->lproc.pid,
		              STRORDASH(ctx->lproc.user),
		              STRORDASH(ctx->lproc.group),
		              STRORDASH(ctx->lproc.exec_path));
		if ((rv < 0) || !lpi) {
			ctx->enomem = 1;
			goto out;
		}
	}
#endif /* HAVE_LOCAL_PROCINFO */

	if (!ctx->spec->ssl) {
		rv = asprintf(&msg, "http %s %s %s %s %s %s %s %s %s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "%s\n",
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str),
		              STRORDASH(ctx->http_host),
		              STRORDASH(ctx->http_method),
		              STRORDASH(ctx->http_uri),
		              STRORDASH(ctx->http_status_code),
		              STRORDASH(ctx->http_content_length),
#ifdef HAVE_LOCAL_PROCINFO
		              lpi,
#endif /* HAVE_LOCAL_PROCINFO */
		              ctx->ocsp_denied ? " ocsp:denied" : "");
	} else {
		rv = asprintf(&msg, "https %s %s %s %s %s %s %s %s %s "
		              "sni:%s names:%s "
		              "sproto:%s:%s dproto:%s:%s "
		              "origcrt:%s usedcrt:%s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "%s\n",
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str),
		              STRORDASH(ctx->http_host),
		              STRORDASH(ctx->http_method),
		              STRORDASH(ctx->http_uri),
		              STRORDASH(ctx->http_status_code),
		              STRORDASH(ctx->http_content_length),
		              STRORDASH(ctx->sni),
		              STRORDASH(ctx->ssl_names),
		              SSL_get_version(ctx->src.ssl),
		              SSL_get_cipher(ctx->src.ssl),
		              !ctx->srv_dst.closed ? SSL_get_version(ctx->srv_dst.ssl):ctx->srv_dst_ssl_version,
		              !ctx->srv_dst.closed ? SSL_get_cipher(ctx->srv_dst.ssl):ctx->srv_dst_ssl_cipher,
		              STRORDASH(ctx->origcrtfpr),
		              STRORDASH(ctx->usedcrtfpr),
#ifdef HAVE_LOCAL_PROCINFO
		              lpi,
#endif /* HAVE_LOCAL_PROCINFO */
		              ctx->ocsp_denied ? " ocsp:denied" : "");
	}
	if ((rv < 0 ) || !msg) {
		ctx->enomem = 1;
		goto out;
	}
	if (!ctx->opts->detach) {
		log_err_printf("INFO: %s", msg);
	}
	if (ctx->opts->connectlog) {
		if (log_connect_print_free(msg) == -1) {
			free(msg);
			log_err_printf("WARNING: Connection logging failed\n");
		}
	} else {
		free(msg);
	}
out:
#ifdef HAVE_LOCAL_PROCINFO
	if (lpi) {
		free(lpi);
	}
#endif /* HAVE_LOCAL_PROCINFO */
	return;
}

/*
 * Called by OpenSSL when a new src SSL session is created.
 * OpenSSL increments the refcount before calling the callback and will
 * decrement it again if we return 0.  Returning 1 will make OpenSSL skip
 * the refcount decrementing.  In other words, return 0 if we did not
 * keep a pointer to the object (which we never do here).
 */
#ifdef HAVE_SSLV2
#define MAYBE_UNUSED 
#else /* !HAVE_SSLV2 */
#define MAYBE_UNUSED UNUSED
#endif /* !HAVE_SSLV2 */
static int
pxy_ossl_sessnew_cb(MAYBE_UNUSED SSL *ssl, SSL_SESSION *sess)
#undef MAYBE_UNUSED
{
#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL new session callback:\n");
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	} else {
		log_dbg_printf("(null)\n");
	}
#endif /* DEBUG_SESSION_CACHE */
#ifdef HAVE_SSLV2
	/* Session resumption seems to fail for SSLv2 with protocol
	 * parsing errors, so we disable caching for SSLv2. */
	if (SSL_version(ssl) == SSL2_VERSION) {
		log_err_printf("WARNING: Session resumption denied to SSLv2"
		               "client.\n");
		return 0;
	}
#endif /* HAVE_SSLV2 */
	if (sess) {
		cachemgr_ssess_set(sess);
	}
	return 0;
}

/*
 * Called by OpenSSL when a src SSL session should be removed.
 * OpenSSL calls SSL_SESSION_free() after calling the callback;
 * we do not need to free the reference here.
 */
static void
pxy_ossl_sessremove_cb(UNUSED SSL_CTX *sslctx, SSL_SESSION *sess)
{
#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL remove session callback:\n");
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	} else {
		log_dbg_printf("(null)\n");
	}
#endif /* DEBUG_SESSION_CACHE */
	if (sess) {
		cachemgr_ssess_del(sess);
	}
}

/*
 * Called by OpenSSL when a src SSL session is requested by the client.
 */
static SSL_SESSION *
pxy_ossl_sessget_cb(UNUSED SSL *ssl, unsigned char *id, int idlen, int *copy)
{
	SSL_SESSION *sess;

#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL get session callback:\n");
#endif /* DEBUG_SESSION_CACHE */

	*copy = 0; /* SSL should not increment reference count of session */
	sess = cachemgr_ssess_get(id, idlen);

#ifdef DEBUG_SESSION_CACHE
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	}
#endif /* DEBUG_SESSION_CACHE */

	log_dbg_printf("SSL session cache: %s\n", sess ? "HIT" : "MISS");
	return sess;
}

/*
 * Set SSL_CTX options that are the same for incoming and outgoing SSL_CTX.
 */
static void
pxy_sslctx_setoptions(SSL_CTX *sslctx, pxy_conn_ctx_t *ctx)
{
	SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
	SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */

	/*
	 * Do not use HAVE_SSLV2 because we need to set SSL_OP_NO_SSLv2 if it
	 * is available and WITH_SSLV2 was not used.
	 */
#ifdef SSL_OP_NO_SSLv2
#ifdef WITH_SSLV2
	if (ctx->opts->no_ssl2) {
#endif /* WITH_SSLV2 */
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
#ifdef WITH_SSLV2
	}
#endif /* WITH_SSLV2 */
#endif /* !SSL_OP_NO_SSLv2 */
#ifdef HAVE_SSLV3
	if (ctx->opts->no_ssl3) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv3);
	}
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	if (ctx->opts->no_tls10) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1);
	}
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	if (ctx->opts->no_tls11) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1_1);
	}
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	if (ctx->opts->no_tls12) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1_2);
	}
#endif /* HAVE_TLSV12 */

#ifdef SSL_OP_NO_COMPRESSION
	if (!ctx->opts->sslcomp) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_COMPRESSION);
	}
#endif /* SSL_OP_NO_COMPRESSION */

	SSL_CTX_set_cipher_list(sslctx, ctx->opts->ciphers);
}

/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and key.
 */
static SSL_CTX *
pxy_srcsslctx_create(pxy_conn_ctx_t *ctx, X509 *crt, STACK_OF(X509) *chain,
                     EVP_PKEY *key)
{
	SSL_CTX *sslctx = SSL_CTX_new(ctx->opts->sslmethod());
	if (!sslctx)
		return NULL;

	pxy_sslctx_setoptions(sslctx, ctx);

	SSL_CTX_sess_set_new_cb(sslctx, pxy_ossl_sessnew_cb);
	SSL_CTX_sess_set_remove_cb(sslctx, pxy_ossl_sessremove_cb);
	SSL_CTX_sess_set_get_cb(sslctx, pxy_ossl_sessget_cb);
	SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_SERVER |
	                                       SSL_SESS_CACHE_NO_INTERNAL);
#ifdef USE_SSL_SESSION_ID_CONTEXT
	SSL_CTX_set_session_id_context(sslctx, (void *)(&ssl_session_context),
	                                       sizeof(ssl_session_context));
#endif /* USE_SSL_SESSION_ID_CONTEXT */
#ifndef OPENSSL_NO_TLSEXT
	SSL_CTX_set_tlsext_servername_callback(sslctx, pxy_ossl_servername_cb);
	SSL_CTX_set_tlsext_servername_arg(sslctx, ctx);
#endif /* !OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_DH
	if (ctx->opts->dh) {
		SSL_CTX_set_tmp_dh(sslctx, ctx->opts->dh);
	} else {
		SSL_CTX_set_tmp_dh_callback(sslctx, ssl_tmp_dh_callback);
	}
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	if (ctx->opts->ecdhcurve) {
		EC_KEY *ecdh = ssl_ec_by_name(ctx->opts->ecdhcurve);
		SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
		EC_KEY_free(ecdh);
	} else {
		EC_KEY *ecdh = ssl_ec_by_name(NULL);
		SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
		EC_KEY_free(ecdh);
	}
#endif /* !OPENSSL_NO_ECDH */
	SSL_CTX_use_certificate(sslctx, crt);
	SSL_CTX_use_PrivateKey(sslctx, key);
	for (int i = 0; i < sk_X509_num(chain); i++) {
		X509 *c = sk_X509_value(chain, i);
		ssl_x509_refcount_inc(c); /* next call consumes a reference */
		SSL_CTX_add_extra_chain_cert(sslctx, c);
	}

#ifdef DEBUG_SESSION_CACHE
	if (OPTS_DEBUG(ctx->opts)) {
		int mode = SSL_CTX_get_session_cache_mode(sslctx);
		log_dbg_printf("SSL session cache mode: %08x\n", mode);
		if (mode == SSL_SESS_CACHE_OFF)
			log_dbg_printf("SSL_SESS_CACHE_OFF\n");
		if (mode & SSL_SESS_CACHE_CLIENT)
			log_dbg_printf("SSL_SESS_CACHE_CLIENT\n");
		if (mode & SSL_SESS_CACHE_SERVER)
			log_dbg_printf("SSL_SESS_CACHE_SERVER\n");
		if (mode & SSL_SESS_CACHE_NO_AUTO_CLEAR)
			log_dbg_printf("SSL_SESS_CACHE_NO_AUTO_CLEAR\n");
		if (mode & SSL_SESS_CACHE_NO_INTERNAL_LOOKUP)
			log_dbg_printf("SSL_SESS_CACHE_NO_INTERNAL_LOOKUP\n");
		if (mode & SSL_SESS_CACHE_NO_INTERNAL_STORE)
			log_dbg_printf("SSL_SESS_CACHE_NO_INTERNAL_STORE\n");
	}
#endif /* DEBUG_SESSION_CACHE */

	return sslctx;
}

static int
pxy_srccert_write_to_gendir(pxy_conn_ctx_t *ctx, X509 *crt, int is_orig)
{
	char *fn;
	int rv;

	if (!ctx->origcrtfpr)
		return -1;
	if (is_orig) {
		rv = asprintf(&fn, "%s/%s.crt", ctx->opts->certgendir,
		              ctx->origcrtfpr);
	} else {
		if (!ctx->usedcrtfpr)
			return -1;
		rv = asprintf(&fn, "%s/%s-%s.crt", ctx->opts->certgendir,
		              ctx->origcrtfpr, ctx->usedcrtfpr);
	}
	if (rv == -1) {
		ctx->enomem = 1;
		return -1;
	}
	rv = log_cert_submit(fn, crt);
	free(fn);
	return rv;
}

static void
pxy_srccert_write(pxy_conn_ctx_t *ctx)
{
	if (ctx->opts->certgen_writeall || ctx->generated_cert) {
		if (pxy_srccert_write_to_gendir(ctx,
		                SSL_get_certificate(ctx->src.ssl), 0) == -1) {
			log_err_printf("ERROR: Failed to write used certificate\n");
		}
	}
	if (ctx->opts->certgen_writeall) {
		if (pxy_srccert_write_to_gendir(ctx, ctx->origcrt, 1) == -1) {
			log_err_printf("ERROR: Failed to write orig certificate\n");
		}
	}
}

static cert_t *
pxy_srccert_create(pxy_conn_ctx_t *ctx)
{
	cert_t *cert = NULL;

	if (ctx->opts->tgcrtdir) {
		if (ctx->sni) {
			cert = cachemgr_tgcrt_get(ctx->sni);
			if (!cert) {
				char *wildcarded;
				wildcarded = ssl_wildcardify(ctx->sni);
				if (!wildcarded) {
					ctx->enomem = 1;
					return NULL;
				}
				cert = cachemgr_tgcrt_get(wildcarded);
				free(wildcarded);
			}
			if (cert && OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Target cert by SNI\n");
			}
		} else if (ctx->origcrt) {
			char **names = ssl_x509_names(ctx->origcrt);
			for (char **p = names; *p; p++) {
				if (!cert) {
					cert = cachemgr_tgcrt_get(*p);
				}
				if (!cert) {
					char *wildcarded;
					wildcarded = ssl_wildcardify(*p);
					if (!wildcarded) {
						ctx->enomem = 1;
					} else {
						cert = cachemgr_tgcrt_get(
						       wildcarded);
						free(wildcarded);
					}
				}
				free(*p);
			}
			free(names);
			if (ctx->enomem) {
				return NULL;
			}
			if (cert && OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Target cert by origcrt\n");
			}
		}

		if (cert) {
			ctx->immutable_cert = 1;
		}
	}

	if (!cert && ctx->origcrt && ctx->opts->key) {
		cert = cert_new();

		cert->crt = cachemgr_fkcrt_get(ctx->origcrt);
		if (cert->crt) {
			if (OPTS_DEBUG(ctx->opts))
				log_dbg_printf("Certificate cache: HIT\n");
		} else {
			if (OPTS_DEBUG(ctx->opts))
				log_dbg_printf("Certificate cache: MISS\n");
			cert->crt = ssl_x509_forge(ctx->opts->cacrt,
			                           ctx->opts->cakey,
			                           ctx->origcrt, NULL,
			                           ctx->opts->key);
			cachemgr_fkcrt_set(ctx->origcrt, cert->crt);
		}
		cert_set_key(cert, ctx->opts->key);
		cert_set_chain(cert, ctx->opts->chain);
		ctx->generated_cert = 1;
	}

	if ((WANT_CONNECT_LOG(ctx) || ctx->opts->certgendir) && ctx->origcrt) {
		ctx->origcrtfpr = ssl_x509_fingerprint(ctx->origcrt, 0);
		if (!ctx->origcrtfpr)
			ctx->enomem = 1;
	}
	if ((WANT_CONNECT_LOG(ctx) || ctx->opts->certgen_writeall) &&
	    cert && cert->crt) {
		ctx->usedcrtfpr = ssl_x509_fingerprint(cert->crt, 0);
		if (!ctx->usedcrtfpr)
			ctx->enomem = 1;
	}

	return cert;
}

/*
 * Create new SSL context for the incoming connection, based on the original
 * destination SSL certificate.
 * Returns NULL if no suitable certificate could be found.
 */
static SSL *
pxy_srcssl_create(pxy_conn_ctx_t *ctx, SSL *origssl)
{
	cert_t *cert;

	cachemgr_dsess_set((struct sockaddr*)&ctx->addr,
	                   ctx->addrlen, ctx->sni,
	                   SSL_get0_session(origssl));

	ctx->origcrt = SSL_get_peer_certificate(origssl);

	if (OPTS_DEBUG(ctx->opts)) {
		if (ctx->origcrt) {
			log_dbg_printf("===> Original server certificate:\n");
			pxy_debug_crt(ctx->origcrt);
		} else {
			log_dbg_printf("===> Original server has no cert!\n");
		}
	}

	cert = pxy_srccert_create(ctx);
	if (!cert)
		return NULL;

	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("===> Forged server certificate:\n");
		pxy_debug_crt(cert->crt);
	}

	if (WANT_CONNECT_LOG(ctx)) {
		ctx->ssl_names = ssl_x509_names_to_str(ctx->origcrt ?
		                                       ctx->origcrt :
		                                       cert->crt);
		if (!ctx->ssl_names)
			ctx->enomem = 1;
	}

	SSL_CTX *sslctx = pxy_srcsslctx_create(ctx, cert->crt, cert->chain,
	                                       cert->key);
	cert_free(cert);
	if (!sslctx) {
		ctx->enomem = 1;
		return NULL;
	}
	SSL *ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
	if (!ssl) {
		ctx->enomem = 1;
		return NULL;
	}
#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
	return ssl;
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * OpenSSL servername callback, called when OpenSSL receives a servername
 * TLS extension in the clientHello.  Must switch to a new SSL_CTX with
 * a different certificate if we want to replace the server cert here.
 * We generate a new certificate if the current one does not match the
 * supplied servername.  This should only happen if the original destination
 * server supplies a certificate which does not match the server name we
 * indicate to it.
 */
static int
pxy_ossl_servername_cb(SSL *ssl, UNUSED int *al, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	const char *sn;
	X509 *sslcrt;

	if (!(sn = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)))
		return SSL_TLSEXT_ERR_NOACK;

	if (!ctx->sni) {
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Warning: SNI parser yielded no "
			               "hostname, copying OpenSSL one: "
			               "[NULL] != [%s]\n", sn);
		}
		ctx->sni = strdup(sn);
		if (!ctx->sni) {
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
	}
	if (OPTS_DEBUG(ctx->opts)) {
		if (!!strcmp(sn, ctx->sni)) {
			/*
			 * This may happen if the client resumes a session, but
			 * uses a different SNI hostname when resuming than it
			 * used when the session was created.  OpenSSL
			 * correctly ignores the SNI in the ClientHello in this
			 * case, but since we have already sent the SNI onwards
			 * to the original destination, there is no way back.
			 * We log an error and hope this never happens.
			 */
			log_dbg_printf("Warning: SNI parser yielded different "
			               "hostname than OpenSSL callback for "
			               "the same ClientHello message: "
			               "[%s] != [%s]\n", ctx->sni, sn);
		}
	}

	/* generate a new certificate with sn as additional altSubjectName
	 * and replace it both in the current SSL ctx and in the cert cache */
	if (!ctx->immutable_cert &&
	    !ssl_x509_names_match((sslcrt = SSL_get_certificate(ssl)), sn)) {
		X509 *newcrt;
		SSL_CTX *newsslctx;

		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Certificate cache: UPDATE "
			               "(SNI mismatch)\n");
		}
		newcrt = ssl_x509_forge(ctx->opts->cacrt, ctx->opts->cakey,
		                        sslcrt, sn, ctx->opts->key);
		if (!newcrt) {
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
		cachemgr_fkcrt_set(ctx->origcrt, newcrt);
		ctx->generated_cert = 1;
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("===> Updated forged server "
			               "certificate:\n");
			pxy_debug_crt(newcrt);
		}
		if (WANT_CONNECT_LOG(ctx)) {
			if (ctx->ssl_names) {
				free(ctx->ssl_names);
			}
			ctx->ssl_names = ssl_x509_names_to_str(newcrt);
			if (!ctx->ssl_names) {
				ctx->enomem = 1;
			}
		}
		if (WANT_CONNECT_LOG(ctx) || ctx->opts->certgendir) {
			if (ctx->usedcrtfpr) {
				free(ctx->usedcrtfpr);
			}
			ctx->usedcrtfpr = ssl_x509_fingerprint(newcrt, 0);
			if (!ctx->usedcrtfpr) {
				ctx->enomem = 1;
			}
		}

		newsslctx = pxy_srcsslctx_create(ctx, newcrt, ctx->opts->chain,
		                                 ctx->opts->key);
		if (!newsslctx) {
			X509_free(newcrt);
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
		SSL_set_SSL_CTX(ssl, newsslctx); /* decr's old incr new refc */
		SSL_CTX_free(newsslctx);
		X509_free(newcrt);
	} else if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Certificate cache: KEEP (SNI match or "
		               "target mode)\n");
	}

	return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_TLSEXT */

/*
 * Create new SSL context for outgoing connections to the original destination.
 * If hostname sni is provided, use it for Server Name Indication.
 */
static SSL *
pxy_dstssl_create(pxy_conn_ctx_t *ctx)
{
	SSL_CTX *sslctx;
	SSL *ssl;
	SSL_SESSION *sess;

	sslctx = SSL_CTX_new(ctx->opts->sslmethod());
	if (!sslctx) {
		ctx->enomem = 1;
		return NULL;
	}

	pxy_sslctx_setoptions(sslctx, ctx);

	SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);

	ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
	if (!ssl) {
		ctx->enomem = 1;
		return NULL;
	}
#ifndef OPENSSL_NO_TLSEXT
	if (ctx->sni) {
		SSL_set_tlsext_host_name(ssl, ctx->sni);
	}
#endif /* !OPENSSL_NO_TLSEXT */

#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */

	/* session resuming based on remote endpoint address and port */
	sess = cachemgr_dsess_get((struct sockaddr *)&ctx->addr,
	                          ctx->addrlen, ctx->sni); /* new sess inst */
	if (sess) {
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Attempt reuse dst SSL session\n");
		}
		SSL_set_session(ssl, sess); /* increments sess refcount */
		SSL_SESSION_free(sess);
	}

	return ssl;
}

/*
 * Set up a bufferevent structure for either a dst or src connection,
 * optionally with or without SSL.  Sets all callbacks, enables read
 * and write events, but does not call bufferevent_socket_connect().
 *
 * For dst connections, pass -1 as fd.  Pass a pointer to an initialized
 * SSL struct as ssl if the connection should use SSL.
 *
 * Returns pointer to initialized bufferevent structure, as returned
 * by bufferevent_socket_new() or bufferevent_openssl_socket_new().
 */
static struct bufferevent * NONNULL(1)
pxy_bufferevent_setup(pxy_conn_ctx_t *ctx, evutil_socket_t fd, SSL *ssl)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bufferevent_setup: ENTER fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	struct bufferevent *bev;

	if (ssl) {
		bev = bufferevent_openssl_socket_new(ctx->evbase, fd, ssl,
				((fd == -1) ? BUFFEREVENT_SSL_CONNECTING : BUFFEREVENT_SSL_ACCEPTING), BEV_OPT_DEFER_CALLBACKS);
	} else {
		// @todo Do we really need to defer callbacks? BEV_OPT_DEFER_CALLBACKS seems responsible for the issue with srv_dst: We get writecb sometimes, no eventcb for CONNECTED event
		bev = bufferevent_socket_new(ctx->evbase, fd, BEV_OPT_DEFER_CALLBACKS);
	}
	if (!bev) {
		log_err_printf("ERROR: Error creating bufferevent socket\n");
		return NULL;
	}
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	if (ssl) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bufferevent_setup: bufferevent_openssl_set_allow_dirty_shutdown\n");
#endif /* DEBUG_PROXY */
		/* Prevent unclean (dirty) shutdowns to cause error
		 * events on the SSL socket bufferevent. */
		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
	}
#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	// @attention Do not set callbacks here, srv_dst does not set r cb
	//bufferevent_setcb(bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	// @todo Should we enable events here?
	//bufferevent_enable(bev, EV_READ|EV_WRITE);

#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("            %p pxy_bufferevent_setup\n",
		               (void*)bev);
	}
#endif /* DEBUG_PROXY */
	return bev;
}

static struct bufferevent * NONNULL(1)
pxy_bufferevent_setup_child(pxy_conn_child_ctx_t *ctx, evutil_socket_t fd, SSL *ssl)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bufferevent_setup_child: ENTER fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	struct bufferevent *bev;

	if (ssl) {
		bev = bufferevent_openssl_socket_new(ctx->parent->evbase, fd, ssl,
				((fd == -1) ? BUFFEREVENT_SSL_CONNECTING : BUFFEREVENT_SSL_ACCEPTING), BEV_OPT_DEFER_CALLBACKS);
	} else {
		bev = bufferevent_socket_new(ctx->parent->evbase, fd, BEV_OPT_DEFER_CALLBACKS);
	}
	if (!bev) {
		log_err_printf("ERROR: Error creating bufferevent socket\n");
		return NULL;
	}

#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	if (ssl) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bufferevent_setup_child: bufferevent_openssl_set_allow_dirty_shutdown\n");
#endif /* DEBUG_PROXY */
		/* Prevent unclean (dirty) shutdowns to cause error
		 * events on the SSL socket bufferevent. */
		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
	}
#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	bufferevent_setcb(bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);

	// @attention We cannot enable events here, because src events will be deferred until after dst is connected
	//bufferevent_enable(bev, EV_READ|EV_WRITE);

#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->parent->opts)) {
		log_dbg_printf("            %p pxy_bufferevent_setup_child\n",
		               (void*)bev);
	}
#endif /* DEBUG_PROXY */
	return bev;
}

/*
 * Filter a single line of HTTP request headers.
 * Also fills in some context fields for logging.
 *
 * Returns NULL if the current line should be deleted from the request.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns `line' if the line should be kept.
 */
static char *
pxy_http_reqhdr_filter_line(const char *line, pxy_conn_ctx_t *ctx, int child)
{
	/* parse information for connect log */
	if (!ctx->http_method) {
		/* first line */
		char *space1, *space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1) {
			/* not HTTP */
			ctx->seen_req_header = 1;
		} else {
			ctx->http_method = malloc(space1 - line + 1);
			if (ctx->http_method) {
				memcpy(ctx->http_method, line, space1 - line);
				ctx->http_method[space1 - line] = '\0';
			} else {
				ctx->enomem = 1;
				return NULL;
			}
			space1++;
			if (!space2) {
				/* HTTP/0.9 */
				ctx->seen_req_header = 1;
				space2 = space1 + strlen(space1);
			}
			ctx->http_uri = malloc(space2 - space1 + 1);
			if (ctx->http_uri) {
				memcpy(ctx->http_uri, space1, space2 - space1);
				ctx->http_uri[space2 - space1] = '\0';
			} else {
				ctx->enomem = 1;
				return NULL;
			}
		}
	} else {
		/* not first line */
		char *newhdr;

		if (!ctx->http_host && !strncasecmp(line, "Host:", 5)) {
			ctx->http_host = strdup(util_skipws(line + 5));
			if (!ctx->http_host) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (!strncasecmp(line, "Content-Type:", 13)) {
			ctx->http_content_type = strdup(util_skipws(line + 13));
			if (!ctx->http_content_type) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (!strncasecmp(line, "Connection:", 11)) {
			ctx->sent_http_conn_close = 1;
			if (!(newhdr = strdup("Connection: close"))) {
				ctx->enomem = 1;
				return NULL;
			}
			return newhdr;
		} else if (!strncasecmp(line, "Accept-Encoding:", 16) ||
		           !strncasecmp(line, "Keep-Alive:", 11)) {
			return NULL;
		} else if (child && (!strncasecmp(line, SSLPROXY_KEY, SSLPROXY_KEY_LEN) ||
				   // @attention flickr keeps redirecting to https with 301 unless we remove the Via line of squid
				   // Apparently flickr assumes the existence of Via header field or squid keyword a sign of plain http, even if we are using https
		           !strncasecmp(line, "Via:", 4) ||
				   // Also do not send the loopback address to the Internet
		           !strncasecmp(line, "X-Forwarded-For:", 16))) {
			return NULL;
		} else if (line[0] == '\0') {
			ctx->seen_req_header = 1;
			if (!ctx->sent_http_conn_close) {
				newhdr = strdup("Connection: close\r\n");
				if (!newhdr) {
					ctx->enomem = 1;
					return NULL;
				}
				return newhdr;
			}
		}
	}

	return (char*)line;
}

/*
 * Filter a single line of HTTP response headers.
 *
 * Returns NULL if the current line should be deleted from the response.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns `line' if the line should be kept.
 */
static char *
pxy_http_resphdr_filter_line(const char *line, pxy_conn_ctx_t *ctx)
{
	/* parse information for connect log */
	if (!ctx->http_status_code) {
		/* first line */
		char *space1, *space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1 || !!strncmp(line, "HTTP", 4)) {
			/* not HTTP or HTTP/0.9 */
			ctx->seen_resp_header = 1;
		} else {
			size_t len_code, len_text;

			if (space2) {
				len_code = space2 - space1 - 1;
				len_text = strlen(space2 + 1);
			} else {
				len_code = strlen(space1 + 1);
				len_text = 0;
			}
			ctx->http_status_code = malloc(len_code + 1);
			ctx->http_status_text = malloc(len_text + 1);
			if (!ctx->http_status_code || !ctx->http_status_text) {
				ctx->enomem = 1;
				return NULL;
			}
			memcpy(ctx->http_status_code, space1 + 1, len_code);
			ctx->http_status_code[len_code] = '\0';
			if (space2) {
				memcpy(ctx->http_status_text,
				       space2 + 1, len_text);
			}
			ctx->http_status_text[len_text] = '\0';
		}
	} else {
		/* not first line */
		if (!ctx->http_content_length &&
		    !strncasecmp(line, "Content-Length:", 15)) {
			ctx->http_content_length =
				strdup(util_skipws(line + 15));
			if (!ctx->http_content_length) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (
		    /* HPKP: Public Key Pinning Extension for HTTP
		     * (draft-ietf-websec-key-pinning)
		     * remove to prevent public key pinning */
		    !strncasecmp(line, "Public-Key-Pins:", 16) ||
		    !strncasecmp(line, "Public-Key-Pins-Report-Only:", 28) ||
		    /* HSTS: HTTP Strict Transport Security (RFC 6797)
		     * remove to allow users to accept bad certs */
		    !strncasecmp(line, "Strict-Transport-Security:", 26) ||
		    /* Alternate Protocol
		     * remove to prevent switching to QUIC, SPDY et al */
		    !strncasecmp(line, "Alternate-Protocol:", 19)) {
			return NULL;
		} else if (line[0] == '\0') {
			ctx->seen_resp_header = 1;
		}
	}

	return (char*)line;
}

/*
 * Return 1 if uri is an OCSP GET URI, 0 if not.
 */
static int
pxy_ocsp_is_valid_uri(const char *uri, pxy_conn_ctx_t *ctx)
{
	char *buf_url;
	size_t sz_url;
	char *buf_b64;
	size_t sz_b64;
	unsigned char *buf_asn1;
	size_t sz_asn1;
	int ret;

	buf_url = strrchr(uri, '/');
	if (!buf_url)
		return 0;
	buf_url++;

	/*
	 * Do some quick checks to avoid unnecessary buffer allocations and
	 * decoding URL, Base64 and ASN.1:
	 * -   OCSP requests begin with a SEQUENCE (0x30), so the first Base64
	 *     byte is 'M' or, unlikely but legal, the URL encoding thereof.
	 * -   There should be no query string in OCSP GET requests.
	 * -   Encoded OCSP request ASN.1 blobs are longer than 32 bytes.
	 */
	if (buf_url[0] != 'M' && buf_url[0] != '%')
		return 0;
	if (strchr(uri, '?'))
		return 0;
	sz_url = strlen(buf_url);
	if (sz_url < 32)
		return 0;
	buf_b64 = url_dec(buf_url, sz_url, &sz_b64);
	if (!buf_b64) {
		ctx->enomem = 1;
		return 0;
	}
	buf_asn1 = base64_dec(buf_b64, sz_b64, &sz_asn1);
	if (!buf_asn1) {
		ctx->enomem = 1;
		free(buf_b64);
		return 0;
	}
	ret = ssl_is_ocspreq(buf_asn1, sz_asn1);
	free(buf_asn1);
	free(buf_b64);
	return ret;
}

/*
 * Called after a request header was completely read.
 * If the request is an OCSP request, deny the request by sending an
 * OCSP response of type tryLater and close the connection to the server.
 *
 * Reference:
 * RFC 2560: X.509 Internet PKI Online Certificate Status Protocol (OCSP)
 */
static void
pxy_ocsp_deny(pxy_conn_ctx_t *ctx, int child)
{
	struct evbuffer *inbuf, *outbuf;
	static const char ocspresp[] =
		"HTTP/1.0 200 OK\r\n"
		"Content-Type: application/ocsp-response\r\n"
		"Content-Length: 5\r\n"
		"Connection: close\r\n"
		"\r\n"
		"\x30\x03"      /* OCSPResponse: SEQUENCE */
		"\x0a\x01"      /* OCSPResponseStatus: ENUMERATED */
		"\x03";         /* tryLater (3) */

	if (!ctx->http_method)
		return;
	if (!strncasecmp(ctx->http_method, "GET", 3) &&
		// @attention Arg 2 is used only for enomem, so the type cast should be ok
	    pxy_ocsp_is_valid_uri(ctx->http_uri, (pxy_conn_ctx_t *)ctx))
		goto deny;
	if (!strncasecmp(ctx->http_method, "POST", 4) &&
	    ctx->http_content_type &&
	    !strncasecmp(ctx->http_content_type,
	                 "application/ocsp-request", 24))
		goto deny;
	return;

deny:
	inbuf = bufferevent_get_input(ctx->src.bev);
	outbuf = bufferevent_get_output(ctx->src.bev);

	if (evbuffer_get_length(inbuf) > 0) {
		if (WANT_CONTENT_LOG(child ? ((pxy_conn_child_ctx_t *)ctx)->parent:ctx)) {
			logbuf_t *lb;
			lb = logbuf_new_alloc(evbuffer_get_length(inbuf),
			                      NULL, NULL);
			if (lb &&
			    (evbuffer_copyout(inbuf, lb->buf, lb->sz) != -1)) {
				if (log_content_submit(ctx->logctx, lb,
				                       1/*req*/) == -1) {
					logbuf_free(lb);
					log_err_printf("WARNING: Content log "
					               "submission failed\n");
				}
			}
		}
		evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
	}
	bufferevent_free_and_close_fd(ctx->dst.bev, child ? ((pxy_conn_child_ctx_t *)ctx)->parent:ctx);
	ctx->dst.bev = NULL;
	ctx->dst.closed = 1;
	evbuffer_add_printf(outbuf, ocspresp);
	ctx->ocsp_denied = 1;
	if (WANT_CONTENT_LOG(child ? ((pxy_conn_child_ctx_t *)ctx)->parent:ctx)) {
		logbuf_t *lb;
		lb = logbuf_new_copy(ocspresp, sizeof(ocspresp) - 1,
		                     NULL, NULL);
		if (lb) {
			if (log_content_submit(ctx->logctx, lb,
			                       0/*resp*/) == -1) {
				logbuf_free(lb);
				log_err_printf("WARNING: Content log "
				               "submission failed\n");
			}
		}
	}
}

/*
 * Peek into pending data to see if it is an SSL/TLS ClientHello, and if so,
 * upgrade the connection from plain TCP to SSL/TLS.
 *
 * Return 1 if ClientHello was found and connection was upgraded to SSL/TLS,
 * 0 otherwise.
 *
 * WARNING: This is experimental code and will need to be improved.
 *
 * TODO - enable search and skip bytes before ClientHello in case it does not
 *        start at offset 0 (i.e. chello > vec_out[0].iov_base)
 * TODO - peek into more than just the current segment
 * TODO - add retry mechanism for short truncated ClientHello, possibly generic
 */
int
pxy_conn_autossl_peek_and_upgrade(pxy_conn_ctx_t *ctx)
{
	struct evbuffer *inbuf;
	struct evbuffer_iovec vec_out[1];
	const unsigned char *chello;
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Checking for a client hello\n");
	}
	/* peek the buffer */
	inbuf = bufferevent_get_input(ctx->src.bev);
	if (evbuffer_peek(inbuf, 1024, 0, vec_out, 1)) {
		if (ssl_tls_clienthello_parse(vec_out[0].iov_base,
		                              vec_out[0].iov_len,
		                              0, &chello, &ctx->sni) == 0) {
			if (OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Peek found ClientHello\n");
			}
			ctx->srv_dst.ssl = pxy_dstssl_create(ctx);
			if (!ctx->srv_dst.ssl) {
				log_err_printf("ERROR: Error creating SSL for "
				               "upgrade\n");
				return 0;
			}
			ctx->srv_dst.bev = bufferevent_openssl_filter_new(
			               ctx->evbase, ctx->srv_dst.bev, ctx->srv_dst.ssl,
			               BUFFEREVENT_SSL_CONNECTING,
			               BEV_OPT_DEFER_CALLBACKS);
			bufferevent_setcb(ctx->srv_dst.bev, pxy_bev_readcb,
			                  pxy_bev_writecb, pxy_bev_eventcb,
			                  ctx);

#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_autossl_peek_and_upgrade: bufferevent_enable fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			bufferevent_enable(ctx->srv_dst.bev, EV_READ|EV_WRITE);
			if (!ctx->srv_dst.bev) {
				return 0;
			}
			if (OPTS_DEBUG(ctx->opts)) {
				log_err_printf("INFO: Replaced dst bufferevent, new "
				               "one is %p\n", (void *)ctx->srv_dst.bev);
			}
			ctx->clienthello_search = 0;
			ctx->clienthello_found = 1;
			return 1;
		} else {
			if (OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Peek found no ClientHello\n");
			}
			return 0;
		}
	}
	return 0;
}

#ifdef DEBUG_PROXY
char *bev_names[] = {
	"src",
	"dst",
	"srv_dst",
	"NULL",
	"UNKWN"
	};

static char *
pxy_get_event_name(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (bev == ctx->src.bev) {
		return bev_names[0];
	} else if (bev == ctx->dst.bev) {
		return bev_names[1];
	} else if (bev == ctx->srv_dst.bev) {
		return bev_names[2];
	} else if (bev == NULL) {
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_get_event_name: event_name=NULL\n");
		return bev_names[3];
	} else {
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_get_event_name: event_name=UNKWN\n");
		return bev_names[4];
	}
}

static char *
pxy_get_event_name_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	if (bev == ctx->src.bev) {
		return bev_names[0];
	} else if (bev == ctx->dst.bev) {
		return bev_names[1];
	} else if (bev == NULL) {
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_get_event_name_child: event_name=NULL\n");
		return bev_names[3];
	} else {
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_get_event_name_child: event_name=UNKWN\n");
		return bev_names[4];
	}
}
#endif /* DEBUG_PROXY */

static void
pxy_http_reqhdr_filter(struct evbuffer *inbuf, struct evbuffer *outbuf, struct bufferevent *bev, pxy_conn_ctx_t *ctx, pxy_conn_ctx_t *parent, int child)
{
	logbuf_t *lb = NULL, *tail = NULL;
	int inserted_header = 0;
	char *line;
	while ((line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF))) {
		char *replace;
		if (WANT_CONTENT_LOG(parent)) {
			logbuf_t *tmp;
			tmp = logbuf_new_printf(NULL, NULL,
									"%s\r\n", line);
			if (tail) {
				if (tmp) {
					tail->next = tmp;
					tail = tail->next;
				}
			} else {
				lb = tail = tmp;
			}
		}
		replace = pxy_http_reqhdr_filter_line(line, ctx, child);
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_http_reqhdr_filter: src line, fd=%d: %s\n", ctx->fd, line);
#endif /* DEBUG_PROXY */
		if (replace == line) {
			evbuffer_add_printf(outbuf, "%s\r\n", line);
		} else if (replace) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_http_reqhdr_filter: src REPLACED line, fd=%d: %s\n", ctx->fd, replace);
#endif /* DEBUG_PROXY */
			evbuffer_add_printf(outbuf, "%s\r\n", replace);
			free(replace);
		} else {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_http_reqhdr_filter: src REMOVED line, fd=%d: %s\n", ctx->fd, line);
#endif /* DEBUG_PROXY */
		}
		free(line);

		if (!child && !inserted_header) {
			inserted_header = 1;
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_http_reqhdr_filter: src INSERT header_str line, fd=%d: %s\n", ctx->fd, ctx->header_str);
#endif /* DEBUG_PROXY */
			evbuffer_add_printf(outbuf, "%s\r\n", ctx->header_str);
		}

		if (ctx->seen_req_header) {
			/* request header complete */
			if (parent->opts->deny_ocsp) {
				pxy_ocsp_deny(ctx, 0);
			}
			break;
		}
	}
	if (lb && WANT_CONTENT_LOG(parent)) {
		if (log_content_submit(parent->logctx, lb,
							   1/*req*/) == -1) {
			logbuf_free(lb);
			log_err_printf("WARNING: Content log "
						   "submission failed\n");
		}
	}
	if (!ctx->seen_req_header) {
		goto leave;
	}

	// @todo Fix this
	/* out of memory condition? */
	if (ctx->enomem) {
		pxy_conn_free(parent, (bev == ctx->src.bev));
		goto leave;
	}

	/* no data left after parsing headers? */
	if (evbuffer_get_length(inbuf) == 0)
		goto leave;

	if (WANT_CONTENT_LOG(parent)) {
		logbuf_t *lb;
		lb = logbuf_new_alloc(evbuffer_get_length(inbuf), NULL, NULL);
		if (lb && (evbuffer_copyout(inbuf, lb->buf, lb->sz) != -1)) {
			if (log_content_submit(parent->logctx, lb,
								   (bev == ctx->src.bev)) == -1) {
				logbuf_free(lb);
				log_err_printf("WARNING: Content log "
							   "submission failed\n");
			}
		}
	}
	evbuffer_add_buffer(outbuf, inbuf);
leave:
	return;
}

static void
pxy_http_resphdr_filter(struct evbuffer *inbuf, struct evbuffer *outbuf, struct bufferevent *bev, pxy_conn_ctx_t *ctx, pxy_conn_ctx_t *parent, int child)
{
	logbuf_t *lb = NULL, *tail = NULL;
	char *line;
	while ((line = evbuffer_readln(inbuf, NULL,
								   EVBUFFER_EOL_CRLF))) {
		char *replace;
		if (WANT_CONTENT_LOG(parent)) {
			logbuf_t *tmp;
			tmp = logbuf_new_printf(NULL, NULL,
									"%s\r\n", line);
			if (tail) {
				if (tmp) {
					tail->next = tmp;
					tail = tail->next;
				}
			} else {
				lb = tail = tmp;
			}
		}
		replace = pxy_http_resphdr_filter_line(line, ctx);
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_http_resphdr_filter: dst line, fd=%d: %s\n", ctx->fd, line);
#endif /* DEBUG_PROXY */
		if (replace == line) {
			evbuffer_add_printf(outbuf, "%s\r\n", line);
		} else if (replace) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_http_resphdr_filter: dst REPLACED line, fd=%d: %s\n", ctx->fd, replace);
#endif /* DEBUG_PROXY */
			evbuffer_add_printf(outbuf, "%s\r\n", replace);
			free(replace);
		} else {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_http_resphdr_filter: dst REMOVED line, fd=%d: %s\n", ctx->fd, line);
#endif /* DEBUG_PROXY */
		}
		free(line);
		if (ctx->seen_resp_header) {
			/* response header complete: log connection */
			if (!child && WANT_CONNECT_LOG(parent)) {
				pxy_log_connect_http(parent);
			}
			break;
		}
	}
	if (lb && WANT_CONTENT_LOG(parent)) {
		if (log_content_submit(parent->logctx, lb,
							   0/*resp*/) == -1) {
			logbuf_free(lb);
			log_err_printf("WARNING: Content log "
						   "submission failed\n");
		}
	}
	if (!ctx->seen_resp_header) {
		goto leave;
	}

	// @todo Fix this
	/* out of memory condition? */
	if (ctx->enomem) {
		pxy_conn_free(parent, (bev == ctx->src.bev));
		goto leave;
	}

	/* no data left after parsing headers? */
	if (evbuffer_get_length(inbuf) == 0)
		goto leave;

	if (WANT_CONTENT_LOG(parent)) {
		logbuf_t *lb;
		lb = logbuf_new_alloc(evbuffer_get_length(inbuf), NULL, NULL);
		if (lb && (evbuffer_copyout(inbuf, lb->buf, lb->sz) != -1)) {
			if (log_content_submit(parent->logctx, lb,
								   (bev == ctx->src.bev)) == -1) {
				logbuf_free(lb);
				log_err_printf("WARNING: Content log "
							   "submission failed\n");
			}
		}
	}
	evbuffer_add_buffer(outbuf, inbuf);
leave:
	return;
}

static void
pxy_process_response(struct evbuffer *inbuf, struct evbuffer *outbuf, struct bufferevent *bev, pxy_conn_ctx_t *ctx, pxy_conn_ctx_t *parent)
{
	size_t packet_size = evbuffer_get_length(inbuf);
	char *packet = malloc(packet_size);
	if (!packet) {
		ctx->enomem = 1;
		return;
	}

	if (evbuffer_remove(inbuf, packet, packet_size) < 0) {
		log_err_printf("ERROR: evbuffer_remove cannot drain the buffer\n");
	}

	if (evbuffer_add(outbuf, packet, packet_size) < 0) {
		log_err_printf("ERROR: evbuffer_add failed\n");
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_response: dst packet (size=%lu)\n", packet_size);
#endif /* DEBUG_PROXY */

	if (WANT_CONTENT_LOG(parent)) {
		logbuf_t *lb;
		lb = logbuf_new_alloc(packet_size, NULL, NULL);
		if (lb) {
			memcpy(lb->buf, packet, lb->sz);
			if (log_content_submit(parent->logctx, lb, (bev == ctx->src.bev)) == -1) {
				logbuf_free(lb);
				log_err_printf("WARNING: Content log "
							   "submission failed\n");
			}
		}
	}
	free(packet);
}

/*
 * Callback for read events on the up- and downstream connection bufferevents.
 * Called when there is data ready in the input evbuffer.
 */
static void
pxy_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	ctx->atime = time(NULL);
	size_t bytes = evbuffer_get_length(bufferevent_get_input(bev));

#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%p %p %s readcb\n", arg, (void*)bev,
		               (bev == ctx->src.bev) ? "src" : "dst");
	}

	char *event_name = pxy_get_event_name(bev, ctx);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb: ENTER %s, fd=%d, child_fd=%d, size=%lu\n",
			event_name, ctx->fd, ctx->child_fd, bytes);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		log_err_printf("ERROR: readcb called when other end not connected - "
		               "aborting.\n");
		log_exceptcb();
		return;
	}

	// @attention srv_dst r cb is not set/enabled, so we only have src and dst at this point
	pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(other->bev);

	if (other->closed) {
		log_dbg_printf("Warning: Drained %zu bytes (conn closed)\n",
		               evbuffer_get_length(inbuf));
		evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
		return;
	}

	if (bev == ctx->src.bev) {
		ctx->thr->intif_in_bytes += bytes;

		if (ctx->clienthello_search) {
			if (pxy_conn_autossl_peek_and_upgrade(ctx)) {
				return;
			}
		}
	
		/* request header munging */
		if (ctx->spec->http) {
			if (!ctx->seen_req_header) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb: HTTP Request Header size=%lu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
				pxy_http_reqhdr_filter(inbuf, outbuf, bev, ctx, ctx, 0);
			} else {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb: HTTP Request Body size=%lu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
				goto leave;
			}
		} else {
			size_t header_len = strlen(ctx->header_str);
			size_t packet_size = evbuffer_get_length(inbuf);
			// +2 is for \r\n
			char *packet = malloc(packet_size + header_len + 2);
			if (!packet) {
				// @todo Should we just set enomem?
				ctx->enomem = 1;
				pxy_conn_free(ctx, 1);
				return;
			}

			if (evbuffer_remove(inbuf, packet, packet_size) < 0) {
				log_err_printf("ERROR: evbuffer_remove cannot drain the buffer\n");
			}

#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb: src ORIG packet (size=%lu), fd=%d:\n%.*s\n",
					packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

			// We insert our special header line to the first packet we get, e.g. right after the first \r\n
			// @todo Should we look for GET/POST or Host header lines to detect the first packet?
			// But there is no guarantie that they will exist, due to fragmentation.
			// @attention We cannot append the ssl proxy address at the end of the packet or in between the header and the content,
			// because (1) the packet may be just the first fragment split somewhere not appropriate for appending a header,
			// and (2) there may not be any content.
			// And we are dealing pop3 and smtp also, not just http.

			// @attention Cannot use string manipulation functions; we are dealing with binary arrays here, not NULL-terminated strings
			if (!ctx->sent_header) {
				if (ctx->spec->mail) {
					memmove(packet + header_len + 2, packet, packet_size);
					memcpy(packet, ctx->header_str, header_len);
					memcpy(packet + header_len, "\r\n", 2);
					packet_size+= header_len + 2;
					ctx->sent_header = 1;
				} else {
					char *pos = memmem(packet, packet_size, "\r\n", 2);
					if (pos) {
						memmove(pos + 2 + header_len, pos, packet_size - (pos - packet));
						memcpy(pos + 2, ctx->header_str, header_len);
						memcpy(pos + 2 + header_len, "\r\n", 2);
						packet_size+= header_len + 2;
						ctx->sent_header = 1;
					} else {
#ifdef DEBUG_PROXY
						log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_readcb: No CRLF in packet\n");
#endif /* DEBUG_PROXY */
					}
				}
			}

			if (evbuffer_add(outbuf, packet, packet_size) < 0) {
				log_err_printf("ERROR: evbuffer_add failed\n");
			}

#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb: src packet (size=%lu), fd=%d:\n%.*s\n",
					packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

			if (WANT_CONTENT_LOG(ctx)) {
				logbuf_t *lb;
				lb = logbuf_new_alloc(packet_size, NULL, NULL);
				if (lb) {
					memcpy(lb->buf, packet, lb->sz);
					if (log_content_submit(ctx->logctx, lb, (bev == ctx->src.bev)) == -1) {
						logbuf_free(lb);
						log_err_printf("WARNING: Content log "
									   "submission failed\n");
					}
				}
			}
			free(packet);
		}
	}
	else if (bev == ctx->dst.bev) {
		ctx->thr->intif_out_bytes += bytes;

		if (ctx->spec->http) {
			if (!ctx->seen_resp_header) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb: HTTP Response Header size=%lu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
				pxy_http_resphdr_filter(inbuf, outbuf, bev, ctx, ctx, 0);
			} else {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb: HTTP Response Body size=%lu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
				goto leave;
			}
		} else {
			pxy_process_response(inbuf, outbuf, bev, ctx, ctx);
		}
	}
	goto watermark;

leave:
	if (WANT_CONTENT_LOG(ctx)) {
		logbuf_t *lb;
		lb = logbuf_new_alloc(evbuffer_get_length(inbuf), NULL, NULL);
		if (lb && (evbuffer_copyout(inbuf, lb->buf, lb->sz) != -1)) {
			if (log_content_submit(ctx->logctx, lb,
								   (bev == ctx->src.bev)) == -1) {
				logbuf_free(lb);
				log_err_printf("WARNING: Content log "
							   "submission failed\n");
			}
		}
	}
	evbuffer_add_buffer(outbuf, inbuf);

watermark:
	if (evbuffer_get_length(outbuf) >= OUTBUF_LIMIT) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_readcb: setwatermark, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		/* temporarily disable data source;
		 * set an appropriate watermark. */
		bufferevent_setwatermark(other->bev, EV_WRITE, OUTBUF_LIMIT/2, OUTBUF_LIMIT);
		bufferevent_disable(bev, EV_READ);
		ctx->thr->set_watermarks++;
	}
}

static void
pxy_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	assert(ctx->parent != NULL);
	pxy_conn_ctx_t *parent = ctx->parent;
	
	ctx->parent->atime = time(NULL);

	size_t bytes = evbuffer_get_length(bufferevent_get_input(bev));

#ifdef DEBUG_PROXY
	evutil_socket_t pfd = parent->fd;
	char *event_name = pxy_get_event_name_child(bev, ctx);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child: ENTER %s fd=%d, pfd=%d, size=%lu\n",
			event_name, ctx->fd, pfd, bytes);
#endif /* DEBUG_PROXY */
		
	if (!ctx->connected) {
		log_err_printf("ERROR: readcb called when other end not connected - "
		               "aborting.\n");
		log_exceptcb();
		return;
	}

	pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(other->bev);

	if (other->closed) {
		log_dbg_printf("Warning: Drained %zu bytes (conn closed)\n",
		               evbuffer_get_length(inbuf));
		evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
		return;
	}

	if (bev == ctx->src.bev) {
		parent->thr->extif_out_bytes += bytes;

		/* request header munging */
		if (parent->spec->http) {
			if (!ctx->seen_req_header) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child: HTTP Request Header size=%lu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
				pxy_http_reqhdr_filter(inbuf, outbuf, bev, (pxy_conn_ctx_t *)ctx, parent, 1);
			} else {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child: HTTP Request Body size=%lu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
				goto leave;
			}
		} else {
			size_t packet_size = evbuffer_get_length(inbuf);
			char *packet = malloc(packet_size);
			if (!packet) {
				ctx->enomem = 1;
				pxy_conn_free(parent, 1);
				return;
			}

			if (evbuffer_remove(inbuf, packet, packet_size) < 0) {
				log_err_printf("ERROR: evbuffer_remove cannot drain the buffer\n");
			}

			size_t header_len = strlen(parent->header_str);
			char *pos = memmem(packet, packet_size, parent->header_str, header_len);
			if (pos) {
				memmove(pos, pos + header_len + 2, packet_size - (pos - packet) - (header_len + 2));
				packet_size-= header_len + 2;
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_readcb_child: REMOVED SSLproxy header\n");
#endif /* DEBUG_PROXY */
			}

			if (evbuffer_add(outbuf, packet, packet_size) < 0) {
				log_err_printf("ERROR: evbuffer_add failed\n");
			}

#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child: src packet (size=%lu), fd=%d, parent fd=%d:\n%.*s\n",
					packet_size, ctx->fd, pfd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

			if (WANT_CONTENT_LOG(parent)) {
				logbuf_t *lb;
				lb = logbuf_new_alloc(packet_size, NULL, NULL);
				if (lb) {
					memcpy(lb->buf, packet, lb->sz);
					if (log_content_submit(parent->logctx, lb, (bev == ctx->src.bev)) == -1) {
						logbuf_free(lb);
						log_err_printf("WARNING: Content log "
									   "submission failed\n");
					}
				}
			}
			free(packet);
		}
	}
	else if (bev == ctx->dst.bev) {
		parent->thr->extif_in_bytes += bytes;

		if (parent->spec->http) {
			if (!ctx->seen_resp_header) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child: HTTP Response Header size=%lu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
				pxy_http_resphdr_filter(inbuf, outbuf, bev, (pxy_conn_ctx_t *)ctx, parent, 1);
			} else {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child: HTTP Response Body size=%lu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
				goto leave;
			}
		} else {
			pxy_process_response(inbuf, outbuf, bev, (pxy_conn_ctx_t *)ctx, parent);
		}
	}
	goto watermark;

leave:
	if (WANT_CONTENT_LOG(parent)) {
		logbuf_t *lb;
		lb = logbuf_new_alloc(evbuffer_get_length(inbuf), NULL, NULL);
		if (lb && (evbuffer_copyout(inbuf, lb->buf, lb->sz) != -1)) {
			if (log_content_submit(parent->logctx, lb,
								   (bev == ctx->src.bev)) == -1) {
				logbuf_free(lb);
				log_err_printf("WARNING: Content log "
							   "submission failed\n");
			}
		}
	}
	evbuffer_add_buffer(outbuf, inbuf);

watermark:
	if (evbuffer_get_length(outbuf) >= OUTBUF_LIMIT) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_readcb_child: setwatermark, pfd=%d\n", ctx->parent->fd);
#endif /* DEBUG_PROXY */
		/* temporarily disable data source;
		 * set an appropriate watermark. */
		bufferevent_setwatermark(other->bev, EV_WRITE, OUTBUF_LIMIT/2, OUTBUF_LIMIT);
		bufferevent_disable(bev, EV_READ);
		ctx->parent->thr->set_watermarks++;
	}
}

static void
pxy_conn_connect_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_connect_child: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_conn_ctx_t *parent = ctx->parent;

	if (!parent->addrlen) {
		log_err_printf("ERROR: Child no target address; aborting connection\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_free(parent, 1);
		return;
	}

	ctx->src.ssl = NULL;
	ctx->src.bev = pxy_bufferevent_setup_child(ctx, ctx->fd, ctx->src.ssl);
	if (!ctx->src.bev) {
		log_err_printf("ERROR: Error creating child src\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_free(parent, 1);
		return;
	}

	ctx->src_fd = bufferevent_getfd(ctx->src.bev);
	parent->child_src_fd = ctx->src_fd;
	parent->thr->max_fd = MAX(parent->thr->max_fd, ctx->src_fd);
	
	// @attention Do not enable src events here yet, they will be enabled after dst connects
	// @todo Do we need a read watermark for the header line of SSL proxy address?
	//bufferevent_setwatermark(ctx->src.bev, EV_READ, 200, OUTBUF_LIMIT);

	/* create server-side socket and eventbuffer */
	// Children rely on the findings of parent
	if ((parent->spec->ssl || parent->clienthello_found) && !parent->passthrough) {
		ctx->dst.ssl = pxy_dstssl_create(parent);
		if (!ctx->dst.ssl) {
			log_err_printf("ERROR: Error creating SSL\n");
			// pxy_conn_free()>pxy_conn_free_child() will close the fd, since we have a non-NULL src.bev now
			pxy_conn_free(parent, 1);
			return;
		}
	}
	if (parent->clienthello_found) {
		if (OPTS_DEBUG(parent->opts)) {
			log_dbg_printf("Completing autossl upgrade\n");
		}
		ctx->dst.bev = bufferevent_openssl_filter_new(
					   parent->evbase, ctx->dst.bev, ctx->dst.ssl,
					   BUFFEREVENT_SSL_ACCEPTING,
					   BEV_OPT_DEFER_CALLBACKS);
		if (ctx->dst.bev) {
			bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);
		}
	} else {
		ctx->dst.bev = pxy_bufferevent_setup_child(ctx, -1, ctx->dst.ssl);
	}
	if (!ctx->dst.bev) {
		log_err_printf("ERROR: Error creating bufferevent\n");
		if (ctx->dst.ssl) {
			SSL_free(ctx->dst.ssl);
			ctx->dst.ssl = NULL;
		}
		pxy_conn_free(parent, 1);
		return;
	}

	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);

	/* initiate connection */
	// @attention No need to check retval here, the eventcb should handle the errors
	bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&parent->addr, parent->addrlen);
	
	ctx->dst_fd = bufferevent_getfd(ctx->dst.bev);
	parent->child_dst_fd = ctx->dst_fd;
	parent->thr->max_fd = MAX(parent->thr->max_fd, ctx->dst_fd);

	if (OPTS_DEBUG(parent->opts)) {
		char *host, *port;
		if (sys_sockaddr_str((struct sockaddr *)&parent->addr, parent->addrlen, &host, &port) != 0) {
			log_dbg_printf("pxy_conn_connect_child: Connecting to [?]:?\n");
		} else {
			log_dbg_printf("pxy_conn_connect_child: Connecting to [%s]:%s\n", host, port);
			free(host);
			free(port);
		}
	}
}

static void
pxy_conn_setup_child(evutil_socket_t fd, pxy_conn_ctx_t *parent)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_setup_child: ENTER fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	pxy_conn_child_ctx_t *ctx = pxy_conn_ctx_new_child(fd, parent);
	if (!ctx) {
		log_err_printf("ERROR: Error allocating memory\n");
		evutil_closesocket(fd);
		pxy_conn_free(parent, 1);
		return;
	}

	// Prepend ctx to meta ctx child list
	// If the last child is deleted, the child_list may become null again
	ctx->next = parent->children;
	parent->children = ctx;

	parent->child_count++;
	ctx->idx = parent->child_count;

	pxy_conn_connect_child(ctx);
}

/*
 * Callback for accept events on the socket listener bufferevent.
 */
static void
proxy_listener_acceptcb_child(UNUSED struct evconnlistener *listener,
                        evutil_socket_t fd,
                        UNUSED struct sockaddr *peeraddr, UNUSED int peeraddrlen,
                        void *arg)
{
	pxy_conn_ctx_t *parent = arg;
	assert(parent != NULL);

	parent->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "proxy_listener_acceptcb_child: ENTER fd=%d, pfd=%d, child_fd=%d\n", fd, parent->fd, parent->child_fd);

	char *host, *port;
	if (sys_sockaddr_str(peeraddr, peeraddrlen, &host, &port) == 0) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "proxy_listener_acceptcb_child: Peer addr=[%s]:%s, child fd=%d, pfd=%d\n", host, port, fd, parent->fd);
		free(host);
		free(port);
	}
#endif /* DEBUG_PROXY */
	pxy_conn_setup_child(fd, parent);
}

static int
pxy_connected_enable(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = ctx->fd;

#ifdef DEBUG_PROXY
	char *event_name = pxy_get_event_name(bev, ctx);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_connected_enable: ENTER %s fd=%d\n", event_name, fd);
#endif /* DEBUG_PROXY */

	if (bev == ctx->srv_dst.bev && !ctx->srv_dst_connected) {
		ctx->srv_dst_connected = 1;
		ctx->srv_dst_fd = bufferevent_getfd(ctx->srv_dst.bev);
		ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->srv_dst_fd);

		// @attention Create and enable dst.bev before, but connect here, because we check if dst.bev is NULL elsewhere
		if (bufferevent_socket_connect(ctx->dst.bev,
								   (struct sockaddr *)&ctx->spec->parent_dst_addr,
								   ctx->spec->parent_dst_addrlen) == -1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_connected_enable: FAILED bufferevent_socket_connect for dst, fd=%d\n", fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free(ctx, 1);
			return 0;
		}
		ctx->dst_fd = bufferevent_getfd(ctx->dst.bev);
		ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->dst_fd);
	}

	if (bev == ctx->dst.bev && !ctx->dst_connected) {
		ctx->dst_connected = 1;
	}

	if (ctx->srv_dst_connected && ctx->dst_connected && !ctx->connected) {
		ctx->connected = 1;

		pxy_conn_desc_t *srv_dst_ctx = &ctx->srv_dst;
		if ((ctx->spec->ssl || ctx->clienthello_found) && !ctx->passthrough) {
			ctx->src.ssl = pxy_srcssl_create(ctx, srv_dst_ctx->ssl);
			if (!ctx->src.ssl) {
				bufferevent_free_and_close_fd(ctx->srv_dst.bev, ctx);
				ctx->srv_dst.bev = NULL;
				ctx->srv_dst.ssl = NULL;
				if (ctx->opts->passthrough && !ctx->enomem) {
					ctx->passthrough = 1;
					ctx->connected = 0;
					log_dbg_printf("No cert found; "
					               "falling back "
					               "to passthrough\n");
					pxy_fd_readcb(fd, 0, ctx);
					return 0;
				}
				pxy_conn_free(ctx, 1);
				return 0;
			}
		}
		if (ctx->clienthello_found) {
			if (OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Completing autossl upgrade\n");
			}
			ctx->src.bev = bufferevent_openssl_filter_new(
			               ctx->evbase, ctx->src.bev, ctx->src.ssl,
			               BUFFEREVENT_SSL_ACCEPTING,
			               BEV_OPT_DEFER_CALLBACKS);
		} else {
			ctx->src.bev = pxy_bufferevent_setup(ctx, fd, ctx->src.ssl);
		}
		if (!ctx->src.bev) {
			log_err_printf("ERROR: Error creating bufferevent\n");
			if (ctx->src.ssl) {
				SSL_free(ctx->src.ssl);
				ctx->src.ssl = NULL;
			}
			pxy_conn_free(ctx, 1);
			return 0;
		}
		bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

		if (sys_sockaddr_str((struct sockaddr *)
							 &ctx->addr, ctx->addrlen,
							 &ctx->dsthost_str,
							 &ctx->dstport_str) != 0) {
			ctx->enomem = 1;
			pxy_conn_free(ctx, 1);
			return 0;
		}

		/* prepare logging, part 2 */
		if (WANT_CONNECT_LOG(ctx) || WANT_CONTENT_LOG(ctx)) {
#ifdef HAVE_LOCAL_PROCINFO
			if (ctx->opts->lprocinfo) {
				/* fetch process info */
				if (proc_pid_for_addr(&ctx->lproc.pid,
				        (struct sockaddr*)&ctx->lproc.srcaddr,
				        ctx->lproc.srcaddrlen) == 0 &&
				    ctx->lproc.pid != -1 &&
				    proc_get_info(ctx->lproc.pid,
				                  &ctx->lproc.exec_path,
				                  &ctx->lproc.uid,
				                  &ctx->lproc.gid) == 0) {
					/* fetch user/group names */
					ctx->lproc.user = sys_user_str(
					                ctx->lproc.uid);
					ctx->lproc.group = sys_group_str(
					                ctx->lproc.gid);
					if (!ctx->lproc.user ||
					    !ctx->lproc.group) {
						ctx->enomem = 1;
						pxy_conn_free(ctx, 1);
						return 0;
					}
				}
			}
#endif /* HAVE_LOCAL_PROCINFO */
		}
		if (WANT_CONTENT_LOG(ctx)) {
			if (log_content_open(&ctx->logctx, ctx->opts,
			                     ctx->srchost_str, ctx->srcport_str,
			                     ctx->dsthost_str, ctx->dstport_str,
#ifdef HAVE_LOCAL_PROCINFO
			                     ctx->lproc.exec_path,
			                     ctx->lproc.user,
			                     ctx->lproc.group
#else /* HAVE_LOCAL_PROCINFO */
			                     NULL, NULL, NULL
#endif /* HAVE_LOCAL_PROCINFO */
			                    ) == -1) {
				if (errno == ENOMEM)
					ctx->enomem = 1;
				pxy_conn_free(ctx, 1);
				return 0;
			}
		}

		// @attention Free the srv_dst of the parent ctx asap, we don't need it, but we need its fd
		// So save its ssl info for logging
		if (ctx->srv_dst.ssl) {
			ctx->srv_dst_ssl_version = strdup(SSL_get_version(ctx->srv_dst.ssl));
			ctx->srv_dst_ssl_cipher = strdup(SSL_get_cipher(ctx->srv_dst.ssl));
		}

		pxy_conn_desc_t *srv_dst = &ctx->srv_dst;
		if (srv_dst->bev) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_connected_enable: evutil_closesocket srv_dst->bev, fd=%d\n", bufferevent_getfd(srv_dst->bev));
#endif /* DEBUG_PROXY */
			// @attention Since both eventcb and writecb for srv_dst are enabled, either eventcb or writecb may get a NULL srv_dst bev, causing a crash with signal 10.
			// So, from this point on, we should check if srv_dst in NULL or not.
			bufferevent_free_and_close_fd(srv_dst->bev, ctx);
			srv_dst->bev = NULL;
			srv_dst->closed = 1;
		}

		// @attention Defer child setup and evcl creation until parent init is complete, otherwise (1) causes multithreading issues (proxy_listener_acceptcb is
		// running on a different thread from the conn, and we only have thrmgr mutex), and (2) we need to clean up less upon errors.
		// Child evcls use the evbase of the parent thread, otherwise we would get multithreading issues.
		evutil_socket_t cfd;
		if ((cfd = privsep_client_opensock_child(ctx->clisock, ctx->spec)) == -1) {
			log_err_printf("ERROR: Error opening socket: %s (%i)\n", strerror(errno), errno);
			pxy_conn_free(ctx, 1);
			return 0;
		}
		ctx->child_fd = cfd;
		ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->child_fd);

		// @attention Do not pass NULL as user-supplied pointer
		struct evconnlistener *child_evcl = evconnlistener_new(ctx->thr->evbase, proxy_listener_acceptcb_child, ctx, LEV_OPT_CLOSE_ON_FREE, 1024, ctx->child_fd);
		if (!child_evcl) {
			log_err_printf("ERROR: Error creating child evconnlistener: %s, fd=%d, child_fd=%d\n", strerror(errno), fd, ctx->child_fd);
			// @attention Cannot call proxy_listener_ctx_free() on child_evcl, child_evcl does not have any ctx with next listener
			// @attention Close child fd separately, because child evcl does not exist yet, hence fd would not be closed by calling pxy_conn_free()
			evutil_closesocket(ctx->child_fd);
			pxy_conn_free(ctx, 1);
			return 0;
		}
		ctx->child_evcl = child_evcl;

		evconnlistener_set_error_cb(child_evcl, proxy_listener_errorcb);
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_connected_enable: Finished setting up child, parent fd=%d, NEW cfd=%d\n", fd, ctx->child_fd);	
#endif /* DEBUG_PROXY */

		struct sockaddr_in child_listener_addr;
		socklen_t child_listener_len = sizeof(child_listener_addr);

		if (getsockname(ctx->child_fd, (struct sockaddr *)&child_listener_addr, &child_listener_len) < 0) {
			perror("getsockname");
			log_err_printf("ERROR: pxy_connected_enable getsockname error=%s\n", strerror(errno));
			// @todo If getsockname() fails, should we really terminate the connection?
			// @attention Do not close the child fd here, because child evcl exists now, hence pxy_conn_free() will close it while freeing child_evcl
			pxy_conn_free(ctx, 1);
			return 0;
		}

		// @attention Children are always listening on an IPv4 loopback address
		char addr[INET_ADDRSTRLEN];
		if (!inet_ntop(AF_INET, &child_listener_addr.sin_addr, addr, INET_ADDRSTRLEN)) {
			pxy_conn_free(ctx, 1);
			return 0;
		}

		// SSLproxy: [127.0.0.1]:34649,[192.168.3.24]:47286,[74.125.206.108]:465,s
		// @todo Port may be less than 5 chars
		// SSLproxy:        +   + [ + addr         + ] + : + p + , + [ + srchost_str              + ] + : + srcport_str              + , + [ + dsthost_str              + ] + : + dstport_str              + , + s + NULL
		// SSLPROXY_KEY_LEN + 1 + 1 + strlen(addr) + 1 + 1 + 5 + 1 + 1 + strlen(ctx->srchost_str) + 1 + 1 + strlen(ctx->srcport_str) + 1 + 1 + strlen(ctx->dsthost_str) + 1 + 1 + strlen(ctx->dstport_str) + 1 + 1 + 1
		int header_len = SSLPROXY_KEY_LEN + strlen(addr) + strlen(ctx->srchost_str) + strlen(ctx->srcport_str) + strlen(ctx->dsthost_str) + strlen(ctx->dstport_str) + 20;
		// @todo Always check malloc retvals. Should we close the conn if malloc fails?
		ctx->header_str = malloc(header_len);
		if (!ctx->header_str) {
			pxy_conn_free(ctx, 1);
			return 0;
		}
		snprintf(ctx->header_str, header_len, "%s [%s]:%u,[%s]:%s,[%s]:%s,%s",
				SSLPROXY_KEY, addr, ntohs(child_listener_addr.sin_port), ctx->srchost_str, ctx->srcport_str, ctx->dsthost_str, ctx->dstport_str, ctx->spec->ssl ? "s":"p");

#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_connected_enable: Enable src, SSLproxy header= %s, fd=%d, child_fd=%d\n", ctx->header_str, fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
		// Now open the gates
		bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	}
	
	// @attention srv_dst.bev may be NULL, if its writecb fires first
	if ((bev==ctx->src.bev) || (ctx->srv_dst.bev && (bev==ctx->srv_dst.bev))) {
		pxy_conn_desc_t *this;
		if (ctx->srv_dst.bev) {
			this = (bev==ctx->src.bev) ? &ctx->src : &ctx->srv_dst;
		} else if (bev==ctx->src.bev) {
			this = &ctx->src;
		} else {
			return 1;
		}

		/* log connection if we don't analyze any headers */
		if ((!this->ssl || (bev == ctx->src.bev)) &&
		    (!ctx->spec->http || ctx->passthrough) &&
		    WANT_CONNECT_LOG(ctx)) {
			pxy_log_connect_nonhttp(ctx);
		}

		/* write SSL certificates to gendir */
		if (this->ssl && (bev == ctx->src.bev) &&
		    ctx->opts->certgendir) {
			pxy_srccert_write(ctx);
		}

		if (OPTS_DEBUG(ctx->opts)) {
			if (this->ssl) {
				/* for SSL, we get two connect events */
				log_dbg_printf("pxy_connected_enable: SSL connected %s [%s]:%s"
				               " %s %s\n",
				               bev == ctx->srv_dst.bev ?
				               "to" : "from",
				               bev == ctx->srv_dst.bev ?
				               ctx->dsthost_str :
				               ctx->srchost_str,
				               bev == ctx->srv_dst.bev ?
				               ctx->dstport_str :
				               ctx->srcport_str,
				               SSL_get_version(this->ssl),
				               SSL_get_cipher(this->ssl));
			} else {
				/* for TCP, we get only a dst connect event,
				 * since src was already connected from the
				 * beginning; mirror SSL debug output anyway
				 * in order not to confuse anyone who might be
				 * looking closely at the output */
				log_dbg_printf("pxy_connected_enable: TCP connected to [%s]:%s\n",
				               ctx->dsthost_str,
				               ctx->dstport_str);
				log_dbg_printf("pxy_connected_enable: TCP connected from [%s]:%s\n",
				               ctx->srchost_str,
				               ctx->srcport_str);
			}
		}
	}
	return 1;
}

/*
 * Callback for write events on the up- and downstream connection bufferevents.
 * Called when either all data from the output evbuffer has been written,
 * or if the outbuf is only half full again after having been full.
 */
static void
pxy_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	// @attention srv_dst.bev may be NULL
#ifdef DEBUG_PROXY
	char *event_name = pxy_get_event_name(bev, ctx);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb: ENTER %s fd=%d, child_fd=%d\n", event_name, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */

	ctx->atime = time(NULL);

	if ((bev==ctx->src.bev) || (bev==ctx->dst.bev)) {
		if (bev == ctx->dst.bev && !ctx->dst_connected) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_writecb: writecb before connected %s, fd=%d, child_fd=%d\n", event_name, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
			pxy_bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
			// @todo Should return instead?
		}
		
		pxy_conn_desc_t *this = (bev==ctx->src.bev) ? &ctx->src : &ctx->dst;
		pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;
		void (*this_free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *) = (bev==ctx->dst.bev) ? &bufferevent_free_and_close_fd_nonssl : &bufferevent_free_and_close_fd;

		if (other->closed) {
			struct evbuffer *outbuf = bufferevent_get_output(bev);
			if (evbuffer_get_length(outbuf) == 0) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb: other->closed, terminate conn\n");
#endif /* DEBUG_PROXY */
				/* finished writing and other end is closed;
				 * close this end too and clean up memory */
				this->closed = 1;
				this_free_and_close_fd_func(bev, ctx);
				this->bev = NULL;
				pxy_conn_free(ctx, (bev == ctx->dst.bev));
			}
			return;
		}

		if (other->bev && !(bufferevent_get_enabled(other->bev) & EV_READ)) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_writecb: unset watermark, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			/* data source temporarily disabled;
			 * re-enable and reset watermark to 0. */
			bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
			bufferevent_enable(other->bev, EV_READ);
			ctx->thr->unset_watermarks++;
		}
	} else if (bev == ctx->srv_dst.bev && !ctx->srv_dst_connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_writecb: writecb before connected %s fd=%d, child_fd=%d\n", event_name, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
		// @todo Should enable the lines below to workaround eventcb issue? Would it help?
		// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls. This is a workaround for this error condition, nothing else seems to work.
		// @attention Do not try to free the conn here, since the listener cb may not be finished yet, causes multithreading issues
		// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
		pxy_bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
	}
}

static void
pxy_bev_writecb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	assert(ctx->parent != NULL);

	pxy_conn_ctx_t *parent = ctx->parent;

#ifdef DEBUG_PROXY
	char *event_name = pxy_get_event_name_child(bev, ctx);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_child: ENTER %s fd=%d, child_fd=%d, cfd=%d\n", event_name, parent->fd, parent->child_fd, ctx->fd);
#endif /* DEBUG_PROXY */

	parent->atime = time(NULL);

	if (bev == ctx->dst.bev && !ctx->connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_writecb_child: writecb before connected %s fd=%d, pfd=%d\n", event_name, ctx->fd, ctx->parent->fd);
#endif /* DEBUG_PROXY */
		pxy_bev_eventcb_child(bev, BEV_EVENT_CONNECTED, ctx);
	}
		
	pxy_conn_desc_t *this = (bev==ctx->src.bev) ? &ctx->src : &ctx->dst;
	pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;
	void (*this_free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *) = (bev==ctx->src.bev) ? &bufferevent_free_and_close_fd_nonssl : &bufferevent_free_and_close_fd;

	if (other->closed) {
		struct evbuffer *outbuf = bufferevent_get_output(bev);
		if (evbuffer_get_length(outbuf) == 0) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_child: other->closed, terminate conn\n");
#endif /* DEBUG_PROXY */
			/* finished writing and other end is closed;
			 * close this end too and clean up memory */
			this->closed = 1;
			this_free_and_close_fd_func(bev, ctx->parent);
			this->bev = NULL;
			pxy_conn_free_child(ctx);
		}
		return;
	}

	if (other->bev && !(bufferevent_get_enabled(other->bev) & EV_READ)) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_writecb_child: unset watermark, pfd=%d\n", ctx->parent->fd);
#endif /* DEBUG_PROXY */
		/* data source temporarily disabled;
		 * re-enable and reset watermark to 0. */
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(other->bev, EV_READ);
		ctx->parent->thr->unset_watermarks++;
	}
}

static void
pxy_print_ssl_error(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	unsigned long sslerr;

	/* Can happen for socket errs, ssl errs;
	 * may happen for unclean ssl socket shutdowns. */
	sslerr = bufferevent_get_openssl_error(bev);
	if (!errno && !sslerr) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
		/* We have disabled notification for unclean shutdowns
		 * so this should not happen; log a warning. */
		log_err_printf("WARNING: Spurious error from "
					   "bufferevent (errno=0,sslerr=0)\n");
#else /* LIBEVENT_VERSION_NUMBER < 0x02010000 */
		/* Older versions of libevent will report these. */
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Unclean SSL shutdown, fd=%d\n", ctx->fd);
		}
#endif /* LIBEVENT_VERSION_NUMBER < 0x02010000 */
	} else if (ERR_GET_REASON(sslerr) ==
			   SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE) {
		/* these can happen due to client cert auth,
		 * only log error if debugging is activated */
		log_dbg_printf("Error from bufferevent: "
					   "%i:%s %lu:%i:%s:%i:%s:%i:%s\n",
					   errno,
					   errno ? strerror(errno) : "-",
					   sslerr,
					   ERR_GET_REASON(sslerr),
					   sslerr ?
					   ERR_reason_error_string(sslerr) : "-",
					   ERR_GET_LIB(sslerr),
					   sslerr ?
					   ERR_lib_error_string(sslerr) : "-",
					   ERR_GET_FUNC(sslerr),
					   sslerr ?
					   ERR_func_error_string(sslerr) : "-");
		while ((sslerr = bufferevent_get_openssl_error(bev))) {
			log_dbg_printf("Additional SSL error: "
						   "%lu:%i:%s:%i:%s:%i:%s\n",
						   sslerr,
						   ERR_GET_REASON(sslerr),
						   ERR_reason_error_string(sslerr),
						   ERR_GET_LIB(sslerr),
						   ERR_lib_error_string(sslerr),
						   ERR_GET_FUNC(sslerr),
						   ERR_func_error_string(sslerr));
		}
	} else {
		/* real errors */
		log_err_printf("ERROR: Error from bufferevent: "
					   "%i:%s %lu:%i:%s:%i:%s:%i:%s\n",
					   errno,
					   errno ? strerror(errno) : "-",
					   sslerr,
					   ERR_GET_REASON(sslerr),
					   sslerr ?
					   ERR_reason_error_string(sslerr) : "-",
					   ERR_GET_LIB(sslerr),
					   sslerr ?
					   ERR_lib_error_string(sslerr) : "-",
					   ERR_GET_FUNC(sslerr),
					   sslerr ?
					   ERR_func_error_string(sslerr) : "-");
		while ((sslerr = bufferevent_get_openssl_error(bev))) {
			log_err_printf("ERROR: Additional SSL error: "
						   "%lu:%i:%s:%i:%s:%i:%s\n",
						   sslerr,
						   ERR_GET_REASON(sslerr),
						   ERR_reason_error_string(sslerr),
						   ERR_GET_LIB(sslerr),
						   ERR_lib_error_string(sslerr),
						   ERR_GET_FUNC(sslerr),
						   ERR_func_error_string(sslerr));
		}
	}
}

/*
 * Callback for meta events on the up- and downstream connection bufferevents.
 * Called when EOF has been reached, a connection has been made, and on errors.
 */
static void
pxy_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	int is_requestor = (bev == ctx->src.bev);

	ctx->atime = time(NULL);

	// @attention srv_dst.bev may be NULL
#ifdef DEBUG_PROXY
	char *event_name = pxy_get_event_name(bev, ctx);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb: ENTER %s fd=%d, child_fd=%d\n", event_name, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
	
	if (events & BEV_EVENT_CONNECTED) {
		pxy_connected_enable(bev, ctx);
		return;
	}

	// @attention If the bev is srv_dst.bev, these variables are initialized wrong, but they are not used in that case.
	pxy_conn_desc_t *this = (bev==ctx->src.bev) ? &ctx->src : &ctx->dst;
	pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;

	void (*this_free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *) = (this->bev==ctx->src.bev) ? &bufferevent_free_and_close_fd : &bufferevent_free_and_close_fd_nonssl;
	void (*other_free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *) = (other->bev==ctx->dst.bev) ? &bufferevent_free_and_close_fd_nonssl : &bufferevent_free_and_close_fd;

	if (events & BEV_EVENT_ERROR) {
		log_err_printf("ERROR: pxy_bev_eventcb error, fd=%d\n", ctx->fd);
		pxy_print_ssl_error(bev, ctx);
		ctx->thr->errors++;

		if (bev == ctx->srv_dst.bev) {
			if (!ctx->connected) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_eventcb: ERROR !ctx->connected %s, fd=%d\n", event_name, ctx->fd);
#endif /* DEBUG_PROXY */
				/* the callout to the original destination failed,
				 * e.g. because it asked for client cert auth, so
				 * close the accepted socket and clean up */
				pxy_conn_free(ctx, 1);
			}
			return;
		} else {
			if (!ctx->connected) {
				other->closed = 1;
			} else if (!other->closed) {
				/* if the other end is still open and doesn't have data
				 * to send, close it, otherwise its writecb will close
				 * it after writing what's left in the output buffer */
				struct evbuffer *outbuf;
				outbuf = bufferevent_get_output(other->bev);
				if (evbuffer_get_length(outbuf) == 0) {
					other_free_and_close_fd_func(other->bev, ctx);
					other->bev = NULL;
					other->closed = 1;
				}
			}
		}
		goto leave;
	}

	if (events & BEV_EVENT_EOF) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb: EOF %s fd=%d\n", event_name, ctx->fd);
#endif /* DEBUG_PROXY */

		if (bev == ctx->srv_dst.bev) {
			log_err_printf("WARNING: pxy_bev_eventcb: EOF on outbound connection before connection establishment, fd=%d\n", ctx->fd);
			pxy_conn_free(ctx, 1);
			return;
		} else {
#ifdef DEBUG_PROXY
			if (OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("evbuffer size at EOF: "
							   "i:%zu o:%zu i:%zu o:%zu\n",
								evbuffer_get_length(
									bufferevent_get_input(bev)),
								evbuffer_get_length(
									bufferevent_get_output(bev)),
								other->closed ? 0 : evbuffer_get_length(
									bufferevent_get_input(other->bev)),
								other->closed ? 0 : evbuffer_get_length(
									bufferevent_get_output(other->bev))
								);
			}
#endif /* DEBUG_PROXY */

			// @todo How to handle the following case?
			if (!ctx->connected) {
				log_err_printf("WARNING: pxy_bev_eventcb: EOF on outbound connection before connection establishment, fd=%d\n", ctx->fd);
				other->closed = 1;
			} else if (!other->closed) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
				/* if there is data pending in the closed connection,
				 * handle it here, otherwise it will be lost. */
				if (evbuffer_get_length(bufferevent_get_input(bev))) {
#ifdef DEBUG_PROXY
					log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb: evbuffer_get_length(inbuf) > 0, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
					pxy_bev_readcb(bev, ctx);
				}
				/* if the other end is still open and doesn't
				 * have data to send, close it, otherwise its
				 * writecb will close it after writing what's
				 * left in the output buffer. */
				if (evbuffer_get_length(bufferevent_get_output(other->bev)) == 0) {
#ifdef DEBUG_PROXY
					log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb: evbuffer_get_length(outbuf) == 0, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
					other->closed = 1;
					other_free_and_close_fd_func(other->bev, ctx);
					other->bev = NULL;
				}
			}

		}
		goto leave;
	}
	// @attention srv_dst should never reach leave, its bev may be NULL
	return;

leave:
	/* we only get a single disconnect event here for both connections */
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("pxy_bev_eventcb: %s disconnected to [%s]:%s, fd=%d\n",
					   this->ssl ? "SSL" : "TCP",
					   ctx->dsthost_str, ctx->dstport_str, ctx->fd);
		log_dbg_printf("pxy_bev_eventcb: %s disconnected from [%s]:%s, fd=%d\n",
					   this->ssl ? "SSL" : "TCP",
					   ctx->srchost_str, ctx->srcport_str, ctx->fd);
	}

	this->closed = 1;
	this_free_and_close_fd_func(bev, ctx);
	this->bev = NULL;
	if (other->closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_conn_free(ctx, is_requestor);
	}
}

static void
pxy_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	assert(ctx->parent != NULL);

	pxy_conn_ctx_t *parent = ctx->parent;
	parent->atime = time(NULL);

#ifdef DEBUG_PROXY
	char *event_name = pxy_get_event_name_child(bev, ctx);
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child: ENTER %s fd=%d, child_fd=%d\n", event_name, parent->fd, parent->child_fd);
#endif /* DEBUG_PROXY */

	pxy_conn_desc_t *this = (bev==ctx->src.bev) ? &ctx->src : &ctx->dst;
	pxy_conn_desc_t *other = (bev==ctx->src.bev) ? &ctx->dst : &ctx->src;

	void (*this_free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *) = (this->bev==ctx->src.bev) ? &bufferevent_free_and_close_fd_nonssl : &bufferevent_free_and_close_fd;
	void (*other_free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *) = (other->bev==ctx->dst.bev) ? &bufferevent_free_and_close_fd : &bufferevent_free_and_close_fd_nonssl;

	if (events & BEV_EVENT_CONNECTED) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child: Connected %s fd=%d\n", event_name, ctx->fd);
#endif /* DEBUG_PROXY */
		if (bev == ctx->dst.bev) {
			ctx->connected = 1;

			// @attention Create and enable src.bev before, but connect here, because we check if dst.bev is NULL elsewhere
			bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
		}
		parent->thr->max_fd = MAX(parent->thr->max_fd, MAX(bufferevent_getfd(ctx->src.bev), bufferevent_getfd(ctx->dst.bev)));
		return;
	}

	if (events & BEV_EVENT_ERROR) {
		log_err_printf("ERROR: pxy_bev_eventcb_child error, fd=%d\n", ctx->fd);
		pxy_print_ssl_error(bev, parent);
		parent->thr->errors++;

		if (!ctx->connected) {
			/* the callout to the original destination failed,
			 * e.g. because it asked for client cert auth, so
			 * close the accepted socket and clean up */
			other->closed = 1;
		} else if (!other->closed) {
			/* if the other end is still open and doesn't have data
			 * to send, close it, otherwise its writecb will close
			 * it after writing what's left in the output buffer */
			struct evbuffer *outbuf;
			outbuf = bufferevent_get_output(other->bev);
			if (evbuffer_get_length(outbuf) == 0) {
				other_free_and_close_fd_func(other->bev, ctx->parent);
				other->bev = NULL;
				other->closed = 1;
			}
		}
		goto leave;
	}

	if (events & BEV_EVENT_EOF) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child: EOF %s fd=%d\n", event_name, ctx->fd);

		if (OPTS_DEBUG(parent->opts)) {
			log_dbg_printf("evbuffer size at EOF: "
			               "i:%zu o:%zu i:%zu o:%zu\n",
			                evbuffer_get_length(
			                    bufferevent_get_input(bev)),
			                evbuffer_get_length(
			                    bufferevent_get_output(bev)),
			                other->closed ? 0 : evbuffer_get_length(
			                    bufferevent_get_input(other->bev)),
			                other->closed ? 0 : evbuffer_get_length(
			                    bufferevent_get_output(other->bev))
			                );
		}
#endif /* DEBUG_PROXY */

		// @todo How to handle the following case?
		if (!ctx->connected) {
			log_err_printf("WARNING: pxy_bev_eventcb_child: EOF on outbound connection before connection establishment, fd=%d, pfd=%d\n", ctx->fd, parent->fd);
			other->closed = 1;
		} else if (!other->closed) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child: !other->closed, terminate conn, fd=%d, pfd=%d\n", ctx->fd, parent->fd);
#endif /* DEBUG_PROXY */
			/* if there is data pending in the closed connection,
			 * handle it here, otherwise it will be lost. */
			if (evbuffer_get_length(bufferevent_get_input(bev))) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child: evbuffer_get_length(inbuf) > 0, terminate conn, fd=%d, pfd=%d\n", ctx->fd, parent->fd);
#endif /* DEBUG_PROXY */
				pxy_bev_readcb_child(bev, ctx);
			}
			/* if the other end is still open and doesn't
			 * have data to send, close it, otherwise its
			 * writecb will close it after writing what's
			 * left in the output buffer. */
			if (evbuffer_get_length(bufferevent_get_output(other->bev)) == 0) {
#ifdef DEBUG_PROXY
				log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child: evbuffer_get_length(outbuf) == 0, terminate conn, fd=%d, pfd=%d\n", ctx->fd, parent->fd);
#endif /* DEBUG_PROXY */
				other->closed = 1;
				other_free_and_close_fd_func(other->bev, ctx->parent);
				other->bev = NULL;
			}
		}
		goto leave;
	}

leave:
	/* we only get a single disconnect event here for both connections */
	if (OPTS_DEBUG(parent->opts)) {
		log_dbg_printf("pxy_bev_eventcb_child: %s disconnected to [%s]:%s, fd=%d, pfd=%d\n",
					   this->ssl ? "SSL" : "TCP",
					   parent->dsthost_str, parent->dstport_str, ctx->fd, parent->fd);
		log_dbg_printf("pxy_bev_eventcb_child: %s disconnected from [%s]:%s, fd=%d, pfd=%d\n",
					   this->ssl ? "SSL" : "TCP",
					   parent->srchost_str, parent->srcport_str, ctx->fd, parent->fd);
	}

	this->closed = 1;
	this_free_and_close_fd_func(bev, ctx->parent);
	this->bev = NULL;
	if (other->closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child: other->closed, terminate conn, fd=%d, pfd=%d\n", ctx->fd, parent->fd);
#endif /* DEBUG_PROXY */
		pxy_conn_free_child(ctx);
	}
}

/*
 * Complete the connection.  This gets called after finding out where to
 * connect to.
 */
static void
pxy_conn_connect(pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = ctx->fd;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_connect: ENTER fd=%d\n", fd);
#endif /* DEBUG_PROXY */
	if (!ctx->addrlen) {
		log_err_printf("ERROR: No target address; aborting connection\n");
		evutil_closesocket(fd);
		pxy_conn_ctx_free(ctx, 1);
		return;
	}

	ctx->dst.ssl= NULL;
	ctx->dst.bev = pxy_bufferevent_setup(ctx, -1, ctx->dst.ssl);
	if (!ctx->dst.bev) {
		log_err_printf("ERROR: Error creating parent dst\n");
		evutil_closesocket(fd);
		pxy_conn_ctx_free(ctx, 1);
		return;
	}

	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);

	/* create server-side socket and eventbuffer */
	if (ctx->spec->ssl && !ctx->passthrough) {
		ctx->srv_dst.ssl = pxy_dstssl_create(ctx);
		if (!ctx->srv_dst.ssl) {
			log_err_printf("ERROR: Error creating SSL for srv_dst\n");
			pxy_conn_free(ctx, 1);
			return;
		}
	}

	ctx->srv_dst.bev = pxy_bufferevent_setup(ctx, -1, ctx->srv_dst.ssl);
	if (!ctx->srv_dst.bev) {
		if (ctx->srv_dst.ssl) {
			SSL_free(ctx->srv_dst.ssl);
			ctx->srv_dst.ssl = NULL;
		}
		pxy_conn_free(ctx, 1);
		return;
	}
	
	if (OPTS_DEBUG(ctx->opts)) {
		char *host, *port;
		if (sys_sockaddr_str((struct sockaddr *)&ctx->addr,
		                     ctx->addrlen, &host, &port) != 0) {
			log_dbg_printf("Connecting to [?]:?\n");
		} else {
			log_dbg_printf("Connecting to [%s]:%s\n", host, port);
			free(host);
			free(port);
		}
	}

	// @attention Sometimes dst write cb fires but not event cb, especially if this listener cb is not finished yet, so the conn stalls.
	// @todo Why does event cb not fire sometimes?
	// @attention BEV_OPT_DEFER_CALLBACKS seems responsible for the issue with srv_dst, libevent acts as if we call event connect() ourselves.
	// @see Launching connections on socket-based bufferevents at http://www.wangafu.net/~nickm/libevent-book/Ref6_bufferevent.html
	// Disable and NULL r cb, we do nothing for srv_dst in r cb.
	bufferevent_setcb(ctx->srv_dst.bev, NULL, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->srv_dst.bev, EV_WRITE);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srv_dst.bev, (struct sockaddr *)&ctx->addr, ctx->addrlen) == -1) {
		log_err_printf("ERROR: pxy_conn_connect: bufferevent_socket_connect for srv_dst failed, fd=%d\n", fd);
		// @attention Do not try to close the conn here , otherwise both pxy_conn_connect() and eventcb try to free the conn using pxy_conn_free(),
		// they are running on different threads, causing multithreading issues, e.g. signal 10.
		// @todo Should we use thrmgr->mutex? Can we?
	}

	// @attention Do not do anything else with the ctx after connecting socket, otherwise if pxy_bev_eventcb fires on error, such as due to "No route to host",
	// the conn is closed and freed up, and we get multithreading issues, e.g. signal 11. We are on the thrmgr thread. So, just return.
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * The SNI hostname has been resolved.  Fill the first resolved address into
 * the context and continue connecting.
 */
static void
pxy_sni_resolve_cb(int errcode, struct evutil_addrinfo *ai, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_sni_resolve_cb: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (errcode) {
		log_err_printf("ERROR: Cannot resolve SNI hostname '%s': %s\n",
		               ctx->sni, evutil_gai_strerror(errcode));
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx, 1);
		return;
	}

	memcpy(&ctx->addr, ai->ai_addr, ai->ai_addrlen);
	ctx->addrlen = ai->ai_addrlen;
	evutil_freeaddrinfo(ai);
	pxy_conn_connect(ctx);
}
#endif /* !OPENSSL_NO_TLSEXT */

/*
 * The src fd is readable.  This is used to sneak-preview the SNI on SSL
 * connections.  If ctx->ev is NULL, it was called manually for a non-SSL
 * connection.  If ctx->passthrough is set, it was called a second time
 * after the first ssl callout failed because of client cert auth.
 */
#ifndef OPENSSL_NO_TLSEXT
#define MAYBE_UNUSED 
#else /* OPENSSL_NO_TLSEXT */
#define MAYBE_UNUSED UNUSED
#endif /* OPENSSL_NO_TLSEXT */
static void
pxy_fd_readcb(MAYBE_UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
#undef MAYBE_UNUSED
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_fd_readcb: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->atime = time(NULL);

#ifndef OPENSSL_NO_TLSEXT
	// Child connections will use the sni info obtained by the parent conn
	/* for SSL, peek ClientHello and parse SNI from it */
	if (ctx->spec->ssl && !ctx->passthrough /*&& ctx->ev*/) {
		unsigned char buf[1024];
		ssize_t n;
		const unsigned char *chello;
		int rv;

		n = recv(fd, buf, sizeof(buf), MSG_PEEK);
		if (n == -1) {
			log_err_printf("ERROR: Error peeking on fd, aborting "
			               "connection, fd=%d\n", ctx->fd);
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx, 1);
			return;
		}
		if (n == 0) {
			/* socket got closed while we were waiting */
			log_err_printf("ERROR: Socket got closed while waiting, fd=%d\n", ctx->fd);
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx, 1);
			return;
		}

		rv = ssl_tls_clienthello_parse(buf, n, 0, &chello, &ctx->sni);
		if ((rv == 1) && !chello) {
			log_err_printf("ERROR: Peeking did not yield a (truncated) "
			               "ClientHello message, "
			               "aborting connection, fd=%d\n", ctx->fd);
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx, 1);
			return;
		}
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("SNI peek: [%s] [%s], fd=%d\n",
			               ctx->sni ? ctx->sni : "n/a",
			               ((rv == 1) && chello) ?
			               "incomplete" : "complete", ctx->fd);
		}
		if ((rv == 1) && chello && (ctx->sni_peek_retries++ < 50)) {
			/* ssl_tls_clienthello_parse indicates that we
			 * should retry later when we have more data, and we
			 * haven't reached the maximum retry count yet.
			 * Reschedule this event as timeout-only event in
			 * order to prevent busy looping over the read event.
			 * Because we only peeked at the pending bytes and
			 * never actually read them, fd is still ready for
			 * reading now.  We use 25 * 0.2 s = 5 s timeout. */
			struct timeval retry_delay = {0, 100};

			event_free(ctx->ev);
			ctx->ev = event_new(ctx->evbase, fd, 0,
			                    pxy_fd_readcb, ctx);
			if (!ctx->ev) {
				log_err_printf("ERROR: Error creating retry "
				               "event, aborting "
				               "connection, fd=%d\n", ctx->fd);
				evutil_closesocket(fd);
				pxy_conn_ctx_free(ctx, 1);
				return;
			}
			event_add(ctx->ev, &retry_delay);
			return;
		}
		event_free(ctx->ev);
		ctx->ev = NULL;
	}

	if (ctx->sni && !ctx->addrlen && ctx->spec->sni_port) {
		char sniport[6];
		struct evutil_addrinfo hints;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = ctx->af;
		hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		snprintf(sniport, sizeof(sniport), "%i", ctx->spec->sni_port);
		evdns_getaddrinfo(ctx->dnsbase, ctx->sni, sniport, &hints,
		                  pxy_sni_resolve_cb, ctx);
		return;
	}
#endif /* !OPENSSL_NO_TLSEXT */

	pxy_conn_connect(ctx);
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
void
pxy_conn_setup(evutil_socket_t fd,
               struct sockaddr *peeraddr, int peeraddrlen,
               pxy_thrmgr_ctx_t *thrmgr,
               proxyspec_t *spec, opts_t *opts,
			   evutil_socket_t clisock)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_setup: ENTER fd=%d\n", fd);

	char *host, *port;
	if (sys_sockaddr_str(peeraddr, peeraddrlen, &host, &port) == 0) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_setup: Peer=[%s]:%s, fd=%d\n", host, port, fd);
		free(host);
		free(port);
	}
#endif /* DEBUG_PROXY */

	/* create per connection state and attach to thread */
	pxy_conn_ctx_t *ctx = pxy_conn_ctx_new(fd, thrmgr, spec, opts, clisock);
	if (!ctx) {
		log_err_printf("ERROR: Error allocating memory\n");
		evutil_closesocket(fd);
		return;
	}

	ctx->af = peeraddr->sa_family;
	ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->fd);

	/* determine original destination of connection */
	if (spec->natlookup) {
		/* NAT engine lookup */
		ctx->addrlen = sizeof(struct sockaddr_storage);
		if (spec->natlookup((struct sockaddr *)&ctx->addr, &ctx->addrlen,
		                    fd, peeraddr, peeraddrlen) == -1) {
			log_err_printf("ERROR: Connection not found in NAT "
			               "state table, aborting connection\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx, 1);
			return;
		}
	} else if (spec->connect_addrlen > 0) {
		/* static forwarding */
		ctx->addrlen = spec->connect_addrlen;
		memcpy(&ctx->addr, &spec->connect_addr, ctx->addrlen);
	} else {
		/* SNI mode */
		if (!ctx->spec->ssl) {
			/* if this happens, the proxyspec parser is broken */
			log_err_printf("ERROR: SNI mode used for non-SSL connection; "
			               "aborting connection\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx, 1);
			return;
		}
	}

	if (sys_sockaddr_str(peeraddr, peeraddrlen,
						 &ctx->srchost_str,
						 &ctx->srcport_str) != 0) {
		goto memout;
	}

	/* prepare logging, part 1 */
	if (WANT_CONNECT_LOG(ctx) || WANT_CONTENT_LOG(ctx)) {
#ifdef HAVE_LOCAL_PROCINFO
		if (ctx->opts->lprocinfo) {
			memcpy(&ctx->lproc.srcaddr, peeraddr, peeraddrlen);
			ctx->lproc.srcaddrlen = peeraddrlen;
		}
#endif /* HAVE_LOCAL_PROCINFO */
	}

	/* for SSL, defer dst connection setup to initial_readcb */
	if (ctx->spec->ssl) {
		ctx->ev = event_new(ctx->evbase, fd, EV_READ, pxy_fd_readcb, ctx);
		if (!ctx->ev)
			goto memout;
		event_add(ctx->ev, NULL);
	} else {
		pxy_fd_readcb(fd, 0, ctx);
	}
	return;

memout:
	log_err_printf("ERROR: Aborting connection setup (out of memory)!\n");
	evutil_closesocket(fd);
	pxy_conn_ctx_free(ctx, 1);
}

/* vim: set noet ft=c: */
