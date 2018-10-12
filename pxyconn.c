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

#include "pxyconn.h"

#include "protohttp.h"
#include "protoautossl.h"

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

#ifdef HAVE_NETFILTER
#include <glob.h>
#endif /* HAVE_NETFILTER */

/*
 * Maximum size of data to buffer per connection direction before
 * temporarily stopping to read data from the other end.
 */
#define OUTBUF_LIMIT	(128*1024)

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

int descriptor_table_size = 0;

typedef void (*event_callback_func_t)(struct bufferevent *, pxy_conn_ctx_t *);

// Forward declarations of callback function tables
callback_func_t readcb_funcs[][3];
callback_func_t writecb_funcs[][3];
event_callback_func_t eventcb_funcs[][3][3];
fd_readcb_func_t fd_readcb_funcs[];
connect_func_t conn_connect_funcs[];

typedef void (*child_event_callback_func_t)(struct bufferevent *, pxy_conn_child_ctx_t *);

callback_func_t child_readcb_funcs[][2];
callback_func_t child_writecb_funcs[][2];
child_event_callback_func_t child_eventcb_funcs[][3][2];
child_connect_func_t child_connect_funcs[];

static void bufferevent_free_and_close_fd_tcp(struct bufferevent *, pxy_conn_ctx_t *);

enum protocol
prototcp_setup(pxy_conn_ctx_t *ctx)
{
	ctx->proto_ctx->proto = PROTO_TCP;
	ctx->proto_ctx->connectcb = pxy_conn_connect_tcp;
	ctx->proto_ctx->fd_readcb = pxy_fd_readcb_tcp;
	
	ctx->proto_ctx->bev_readcb = pxy_bev_readcb_tcp;
	ctx->proto_ctx->bev_writecb = pxy_bev_writecb_tcp;
	ctx->proto_ctx->bev_eventcb = pxy_bev_eventcb_tcp;

	ctx->proto_ctx->bufferevent_free_and_close_fd = bufferevent_free_and_close_fd_tcp;
	ctx->proto_ctx->proto_free = NULL;
	return PROTO_TCP;
}

enum protocol
prototcp_setup_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->proto_ctx->proto = PROTO_TCP;
	ctx->proto_ctx->connectcb = pxy_connect_tcp_child;

	ctx->proto_ctx->bev_readcb = pxy_bev_readcb_tcp_child;
	ctx->proto_ctx->bev_writecb = pxy_bev_writecb_tcp_child;
	ctx->proto_ctx->bev_eventcb = pxy_bev_eventcb_tcp_child;

	ctx->proto_ctx->bufferevent_free_and_close_fd = bufferevent_free_and_close_fd_tcp;
	ctx->proto_ctx->proto_free = NULL;
	return PROTO_TCP;
}

static enum protocol
setup_proto(pxy_conn_ctx_t *ctx)
{
	ctx->proto_ctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->proto_ctx) {
		return PROTO_ERROR;
	}

	// Default to tcp
	prototcp_setup(ctx);

	if (ctx->spec->upgrade) {
		return protoautossl_setup(ctx);
	} else if (ctx->spec->http) {
		if (ctx->spec->ssl) {
			return protohttps_setup(ctx);
		} else {
			return protohttp_setup(ctx);
		}
	} else if (ctx->spec->pop3) {
		if (ctx->spec->ssl) {
			return PROTO_POP3S;
		} else {
			return PROTO_POP3;
		}
	} else if (ctx->spec->smtp) {
		if (ctx->spec->ssl) {
			return PROTO_SMTPS;
		} else {
			return PROTO_SMTP;
		}
	} else if (ctx->spec->ssl) {
		return PROTO_SSL;
	} else {
		return PROTO_TCP;
	}
}

static enum protocol
setup_proto_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->proto_ctx = malloc(sizeof(proto_child_ctx_t));
	if (!ctx->proto_ctx) {
		return PROTO_ERROR;
	}

	// Default to tcp
	prototcp_setup_child(ctx);

	if (ctx->conn->spec->upgrade) {
		return protoautossl_setup_child(ctx);
	} else if (ctx->conn->spec->http) {
		if (ctx->conn->spec->ssl) {
			return protohttps_setup_child(ctx);
		} else {
			return protohttp_setup_child(ctx);
		}
	} else if (ctx->conn->spec->pop3) {
		if (ctx->conn->spec->ssl) {
			return PROTO_POP3S;
		} else {
			return PROTO_POP3;
		}
	} else if (ctx->conn->spec->smtp) {
		if (ctx->conn->spec->ssl) {
			return PROTO_SMTPS;
		} else {
			return PROTO_SMTP;
		}
	} else if (ctx->conn->spec->ssl) {
		return PROTO_SSL;
	} else {
		return PROTO_TCP;
	}
}

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
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		return NULL;
	}
	memset(ctx, 0, sizeof(pxy_conn_ctx_t));

	ctx->id = thrmgr->conn_count++;

#if defined (DEBUG_PROXY)
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_new: id=%llu, fd=%d\n", ctx->id, fd);
#endif /* DEBUG_PROXY */
	
	ctx->type = CONN_TYPE_PARENT;
	ctx->fd = fd;
	ctx->conn = ctx;
	ctx->thrmgr = thrmgr;
	ctx->spec = spec;

	ctx->proto_ctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->proto_ctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx);
		return NULL;
	}
	memset(ctx->proto_ctx, 0, sizeof(proto_ctx_t));
	ctx->proto = setup_proto(ctx);
	if (ctx->proto == PROTO_ERROR) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx->proto_ctx);
		free(ctx);
		return NULL;
	}

	ctx->opts = opts;
	ctx->clisock = clisock;

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
pxy_conn_ctx_new_child(evutil_socket_t fd, pxy_conn_ctx_t *conn)
{
	assert(conn != NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_new_child: ENTER fd=%d\n", fd);
#endif /* DEBUG_PROXY */
	pxy_conn_child_ctx_t *ctx = malloc(sizeof(pxy_conn_child_ctx_t));
	if (!ctx) {
		return NULL;
	}
	memset(ctx, 0, sizeof(pxy_conn_child_ctx_t));

	ctx->type = CONN_TYPE_CHILD;
	ctx->fd = fd;
	ctx->conn = conn;

	ctx->proto_ctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->proto_ctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx);
		return NULL;
	}
	memset(ctx->proto_ctx, 0, sizeof(proto_ctx_t));
	ctx->proto = setup_proto_child(ctx);
	if (ctx->proto == PROTO_ERROR) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx->proto_ctx);
		free(ctx);
		return NULL;
	}

	// @attention Child connections use the parent's event bases, otherwise we would get multithreading issues
	pxy_thrmgr_attach_child(conn);
#ifdef DEBUG_PROXY
	if (OPTS_DEBUG(conn->opts)) {
		log_dbg_printf("%p             pxy_conn_ctx_new_child\n", (void*)ctx);
	}
#endif /* DEBUG_PROXY */
	return ctx;
}

static void NONNULL(1)
pxy_conn_ctx_free_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_free_child: ENTER fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
	if (OPTS_DEBUG(ctx->conn->opts)) {
		log_dbg_printf("%p             pxy_conn_ctx_free_child\n",
		                (void*)ctx);
	}
#endif /* DEBUG_PROXY */
	pxy_thrmgr_detach_child(ctx->conn);

	// If the proto doesn't have special args, proto_free() callback is NULL
	if (ctx->proto_ctx->proto_free) {
		ctx->proto_ctx->proto_free(ctx);
	}
	free(ctx->proto_ctx);
	free(ctx);
}

static void
bufferevent_free_and_close_fd_tcp(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "bufferevent_free_and_close_fd_tcp: ENTER i:%zu o:%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(bev)), fd);
#endif /* DEBUG_PROXY */

	bufferevent_free(bev);

	if (evutil_closesocket(fd) == -1) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "bufferevent_free_and_close_fd_tcp: evutil_closesocket FAILED, fd=%d\n", fd);
#endif /* DEBUG_PROXY */
	}
}

void
bufferevent_free_and_close_fd_ssl(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "bufferevent_free_and_close_fd_ssl: ENTER i:%zu o:%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(bev)), fd);
#endif /* DEBUG_PROXY */

	SSL *ssl = bufferevent_openssl_get_ssl(bev); /* does not inc refc */

	// @todo Check if we need to NULL all cbs?
	// @see https://stackoverflow.com/questions/31688709/knowing-all-callbacks-have-run-with-libevent-and-bufferevent-free
	//bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	bufferevent_free(bev); /* does not free SSL unless the option BEV_OPT_CLOSE_ON_FREE was set */
	pxy_ssl_shutdown(ctx->opts, ctx->evbase, ssl, fd);
}

/*
 * Free bufferenvent and close underlying socket properly.
 * For OpenSSL bufferevents, this will shutdown the SSL connection.
 */
static void
bufferevent_free_and_close_fd(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	ctx->proto_ctx->bufferevent_free_and_close_fd(bev, ctx);
}

/*
 * Free bufferenvent and close underlying socket properly.
 * This is for non-OpenSSL bufferevents.
 */
static void
bufferevent_free_and_close_fd_nonssl(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	bufferevent_free_and_close_fd_tcp(bev, ctx);
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
	assert(ctx->conn != NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_free_child: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_conn_desc_t *dst = &ctx->dst;
	if (dst->bev) {
		bufferevent_free_and_close_fd(dst->bev, ctx->conn);
		dst->bev = NULL;
	}

	pxy_conn_desc_t *src = &ctx->src;
	if (src->bev) {
		bufferevent_free_and_close_fd_nonssl(src->bev, ctx->conn);
		src->bev = NULL;
	}

	pxy_conn_remove_child(ctx, &ctx->conn->children);
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
			log_err_level_printf(LOG_WARNING, "Content log close failed\n");
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
	// If the proto doesn't have special args, proto_free() callback is NULL
	if (ctx->proto_ctx->proto_free) {
		ctx->proto_ctx->proto_free(ctx);
	}
	free(ctx->proto_ctx);
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
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_conn_free: Freeing child_evcl, conn fd=%d, child_fd=%d, cfd=%d\n",
				ctx->fd, ctx->child_fd, ctx->children ? ctx->children->fd : -1);
#endif /* DEBUG_PROXY */
		// @attention child_evcl was created with LEV_OPT_CLOSE_ON_FREE, so do not close ctx->child_fd
		evconnlistener_free(ctx->child_evcl);
		ctx->child_evcl = NULL;
	}

	pxy_conn_ctx_free(ctx, by_requestor);
}

/* forward declaration of libevent callbacks */
static void pxy_fd_readcb(evutil_socket_t, short, void *);

/* forward declaration of OpenSSL callbacks */
#ifndef OPENSSL_NO_TLSEXT
static int pxy_ossl_servername_cb(SSL *ssl, int *al, void *arg);
#endif /* !OPENSSL_NO_TLSEXT */
static int pxy_ossl_sessnew_cb(SSL *, SSL_SESSION *);
static void pxy_ossl_sessremove_cb(SSL_CTX *, SSL_SESSION *);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
static SSL_SESSION * pxy_ossl_sessget_cb(SSL *, unsigned char *, int, int *);
#else /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
static SSL_SESSION * pxy_ossl_sessget_cb(SSL *, const unsigned char *, int, int *);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

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
		log_err_level_printf(LOG_WARNING, "Error generating X509 fingerprint\n");
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

	/*
	 * The following ifdef's within asprintf arguments list generates
	 * warnings with -Wembedded-directive on some compilers.
	 * Not fixing the code in order to avoid more code duplication.
	 */

	if (!ctx->src.ssl) {
		rv = asprintf(&msg, "CONN: %s %s %s %s %s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "\n",
		              ctx->passthrough ? "passthrough" : (ctx->spec->pop3 ? "pop3" : (ctx->spec->smtp ? "smtp" : "tcp")),
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str)
#ifdef HAVE_LOCAL_PROCINFO
		              , lpi
#endif /* HAVE_LOCAL_PROCINFO */
		             );
	} else {
		rv = asprintf(&msg, "CONN: %s %s %s %s %s "
		              "sni:%s names:%s "
		              "sproto:%s:%s dproto:%s:%s "
		              "origcrt:%s usedcrt:%s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "\n",
		              ctx->proto == PROTO_AUTOSSL ? "upgrade" : (ctx->spec->pop3 ? "pop3s" : (ctx->spec->smtp ? "smtps" : "ssl")),
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str),
		              STRORDASH(ctx->sni),
		              STRORDASH(ctx->ssl_names),
		              SSL_get_version(ctx->src.ssl),
		              SSL_get_cipher(ctx->src.ssl),
		              !ctx->srv_dst.closed && ctx->srv_dst.ssl ? SSL_get_version(ctx->srv_dst.ssl):ctx->srv_dst_ssl_version,
		              !ctx->srv_dst.closed && ctx->srv_dst.ssl ? SSL_get_cipher(ctx->srv_dst.ssl):ctx->srv_dst_ssl_cipher,
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
		log_err_printf("%s", msg);
	} else if (ctx->opts->statslog) {
		if (log_conn(msg) == -1) {
			log_err_level_printf(LOG_WARNING, "Conn logging failed\n");
		}
	}
	if (ctx->opts->connectlog) {
		if (log_connect_print_free(msg) == -1) {
			free(msg);
			log_err_level_printf(LOG_WARNING, "Connection logging failed\n");
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
		log_err_level_printf(LOG_WARNING, "Session resumption denied to SSLv2"
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
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
pxy_ossl_sessget_cb(UNUSED SSL *ssl, unsigned char *id, int idlen, int *copy)
#else /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
pxy_ossl_sessget_cb(UNUSED SSL *ssl, const unsigned char *id, int idlen, int *copy)
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
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

#ifdef SSL_OP_NO_SSLv2
#ifdef HAVE_SSLV2
	if (ctx->opts->no_ssl2) {
#endif /* HAVE_SSLV2 */
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
#ifdef HAVE_SSLV2
	}
#endif /* HAVE_SSLV2 */
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	if (ctx->opts->sslversion) {
		if (SSL_CTX_set_min_proto_version(sslctx, ctx->opts->sslversion) == 0 ||
			SSL_CTX_set_max_proto_version(sslctx, ctx->opts->sslversion) == 0) {
			SSL_CTX_free(sslctx);
			return NULL;
		}
	}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

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
			log_err_level_printf(LOG_CRIT, "Failed to write used certificate\n");
		}
	}
	if (ctx->opts->certgen_writeall) {
		if (pxy_srccert_write_to_gendir(ctx, ctx->origcrt, 1) == -1) {
			log_err_level_printf(LOG_CRIT, "Failed to write orig certificate\n");
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
			                           ctx->origcrt,
			                           ctx->opts->key,
			                           NULL,
			                           ctx->opts->crlurl);
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
	if (ctx->opts->allow_wrong_host && !ctx->immutable_cert &&
	    !ssl_x509_names_match((sslcrt = SSL_get_certificate(ssl)), sn)) {
		X509 *newcrt;
		SSL_CTX *newsslctx;

		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Certificate cache: UPDATE "
			               "(SNI mismatch)\n");
		}
		newcrt = ssl_x509_forge(ctx->opts->cacrt, ctx->opts->cakey,
		                        sslcrt, ctx->opts->key,
		                        sn, ctx->opts->crlurl);
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
SSL *
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	if (ctx->opts->sslversion) {
		if (SSL_CTX_set_min_proto_version(sslctx, ctx->opts->sslversion) == 0 ||
			SSL_CTX_set_max_proto_version(sslctx, ctx->opts->sslversion) == 0) {
			SSL_CTX_free(sslctx);
			ctx->enomem = 1;
			return NULL;
		}
	}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

	if (ctx->opts->verify_peer) {
		SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_default_verify_paths(sslctx);
	} else {
		SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);
	}

	if (ctx->opts->clientcrt) {
		if (!SSL_CTX_use_certificate(sslctx, ctx->opts->clientcrt))
			log_dbg_printf("loading client certificate failed");
	}
	if (ctx->opts->clientkey) {
		if (!SSL_CTX_use_PrivateKey(sslctx, ctx->opts->clientkey))
			log_dbg_printf("loading client key failed");
	}

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
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
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

struct bufferevent * NONNULL(1)
pxy_bufferevent_setup_child(pxy_conn_child_ctx_t *ctx, evutil_socket_t fd, SSL *ssl)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bufferevent_setup_child: ENTER fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	struct bufferevent *bev;

	if (ssl) {
		bev = bufferevent_openssl_socket_new(ctx->conn->evbase, fd, ssl,
				((fd == -1) ? BUFFEREVENT_SSL_CONNECTING : BUFFEREVENT_SSL_ACCEPTING), BEV_OPT_DEFER_CALLBACKS);
	} else {
		bev = bufferevent_socket_new(ctx->conn->evbase, fd, BEV_OPT_DEFER_CALLBACKS);
	}
	if (!bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
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
	if (OPTS_DEBUG(ctx->conn->opts)) {
		log_dbg_printf("            %p pxy_bufferevent_setup_child\n",
		               (void*)bev);
	}
#endif /* DEBUG_PROXY */
	return bev;
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
#endif /* DEBUG_PROXY */

#ifdef HAVE_NETFILTER
/*
 * Copied from:
 * https://github.com/tmux/tmux/blob/master/compat/getdtablecount.c
 */
int
getdtablecount(void)
{
	char path[PATH_MAX];
	glob_t g;
	int n = 0;

	if (snprintf(path, sizeof path, "/proc/%ld/fd/*", (long)getpid()) < 0) {
		log_err_level_printf(LOG_CRIT, "snprintf overflow\n");
		return 0;
	}
	if (glob(path, 0, NULL, &g) == 0)
		n = g.gl_pathc;
	globfree(&g);
	return n;
}
#endif /* HAVE_NETFILTER */

void
pxy_connect_tcp_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_connect_child_tcp: ENTER, conn fd=%d, child_fd=%d\n", ctx->conn->fd, ctx->conn->child_fd);
#endif /* DEBUG_PROXY */

	/* create server-side socket and eventbuffer */
	ctx->dst.ssl = NULL;
	ctx->dst.bev = pxy_bufferevent_setup_child(ctx, -1, ctx->dst.ssl);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent\n");
		pxy_conn_free(ctx->conn, 1);
		return;
	}
}

void
pxy_connect_ssl_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_connect_child_ssl: ENTER, conn fd=%d, child_fd=%d\n", ctx->conn->fd, ctx->conn->child_fd);
#endif /* DEBUG_PROXY */

	/* create server-side socket and eventbuffer */
	// Children rely on the findings of parent
	ctx->dst.ssl = pxy_dstssl_create(ctx->conn);
	if (!ctx->dst.ssl) {
		log_err_level_printf(LOG_CRIT, "Error creating SSL\n");
		// pxy_conn_free()>pxy_conn_free_child() will close the fd, since we have a non-NULL src.bev now
		pxy_conn_free(ctx->conn, 1);
		return;
	}

	ctx->dst.bev = pxy_bufferevent_setup_child(ctx, -1, ctx->dst.ssl);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent\n");
		SSL_free(ctx->dst.ssl);
		ctx->dst.ssl = NULL;
		pxy_conn_free(ctx->conn, 1);
		return;
	}
}

/*
 * Callback for accept events on the socket listener bufferevent.
 */
static void
proxy_listener_acceptcb_child(UNUSED struct evconnlistener *listener, evutil_socket_t fd,
                        UNUSED struct sockaddr *peeraddr, UNUSED int peeraddrlen, void *arg)
{
	pxy_conn_ctx_t *conn = arg;

	conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "proxy_listener_acceptcb_child: ENTER fd=%d, conn fd=%d, child_fd=%d\n", fd, conn->fd, conn->child_fd);

	char *host, *port;
	if (sys_sockaddr_str(peeraddr, peeraddrlen, &host, &port) == 0) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "proxy_listener_acceptcb_child: Peer addr=[%s]:%s, child fd=%d, conn fd=%d\n", host, port, fd, conn->fd);
		free(host);
		free(port);
	}
#endif /* DEBUG_PROXY */

	int dtable_count = getdtablecount();

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "proxy_listener_acceptcb_child: descriptor_table_size=%d, current fd count=%d, reserve=%d, fd=%d\n", descriptor_table_size, dtable_count, FD_RESERVE, fd);
#endif /* DEBUG_PROXY */

	// Close the conn if we are out of file descriptors, or libevent will crash us, @see pxy_conn_setup() for explanation
	if (dtable_count + FD_RESERVE >= descriptor_table_size) {
		errno = EMFILE;
		log_err_level_printf(LOG_CRIT, "Out of file descriptors\n");
		evutil_closesocket(fd);
		pxy_conn_free(conn, 1);
		return;
	}

	pxy_conn_child_ctx_t *ctx = pxy_conn_ctx_new_child(fd, conn);
	if (!ctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		pxy_conn_free(conn, 1);
		return;
	}

	// Prepend child ctx to conn ctx child list
	// @attention If the last child is deleted, the children list may become null again
	ctx->next = conn->children;
	conn->children = ctx;

	conn->child_count++;
	ctx->idx = conn->child_count;

	if (!ctx->conn->addrlen) {
		log_err_level_printf(LOG_CRIT, "Child no target address; aborting connection\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_free(ctx->conn, 1);
		return;
	}

	ctx->src.ssl = NULL;
	ctx->src.bev = pxy_bufferevent_setup_child(ctx, ctx->fd, ctx->src.ssl);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating child src\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_free(ctx->conn, 1);
		return;
	}

	ctx->src_fd = bufferevent_getfd(ctx->src.bev);
	ctx->conn->child_src_fd = ctx->src_fd;
	ctx->conn->thr->max_fd = MAX(ctx->conn->thr->max_fd, ctx->src_fd);
	
	// @attention Do not enable src events here yet, they will be enabled after dst connects

	/* create server-side socket and eventbuffer */
	// Children rely on the findings of parent
	if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
		ctx->proto_ctx->connectcb(ctx);
	} else {
		child_connect_func_t child_connect_func = child_connect_funcs[ctx->proto];
		if (child_connect_func) {
			child_connect_func(ctx);
		} else {
			log_err_printf("proxy_listener_acceptcb_child: NULL child_conn_connect_func\n");
		}
	}

	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);

	if (OPTS_DEBUG(ctx->conn->opts)) {
		char *host, *port;
		if (sys_sockaddr_str((struct sockaddr *)&ctx->conn->addr, ctx->conn->addrlen, &host, &port) != 0) {
			log_dbg_printf("proxy_listener_acceptcb_child: Connecting to [?]:?\n");
		} else {
			log_dbg_printf("proxy_listener_acceptcb_child: Connecting to [%s]:%s\n", host, port);
			free(host);
			free(port);
		}
	}

	/* initiate connection */
	// @attention No need to check retval here, the eventcb should handle the errors
	bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->conn->addr, ctx->conn->addrlen);
	
	ctx->dst_fd = bufferevent_getfd(ctx->dst.bev);
	ctx->conn->child_dst_fd = ctx->dst_fd;
	ctx->conn->thr->max_fd = MAX(ctx->conn->thr->max_fd, ctx->dst_fd);
}

int
pxy_log_content_buf(pxy_conn_ctx_t *ctx, unsigned char *buf, size_t sz, int req)
{
	if (WANT_CONTENT_LOG(ctx->conn)) {
		if (buf) {
			logbuf_t *lb = logbuf_new_alloc(sz, NULL, NULL);
			if (!lb) {
				ctx->conn->enomem = 1;
				return -1;
			}
			memcpy(lb->buf, buf, lb->sz);
			if (log_content_submit(ctx->conn->logctx, lb, req) == -1) {
				logbuf_free(lb);
				log_err_level_printf(LOG_WARNING, "Content log submission failed\n");
				return -1;
			}
		}
	}
	return 0;
}

int
pxy_log_content_inbuf(pxy_conn_ctx_t *ctx, struct evbuffer *inbuf, int req)
{
	if (WANT_CONTENT_LOG(ctx->conn)) {
		size_t sz = evbuffer_get_length(inbuf);
		unsigned char *buf = malloc(sz);
		if (!buf) {
			ctx->conn->enomem = 1;
			return -1;
		}
		if (evbuffer_copyout(inbuf, buf, sz) == -1) {
			return -1;
		}
		if (pxy_log_content_buf(ctx, buf, sz, req) == -1) {
			return -1;
		}
	}
	return 0;
}

void
pxy_set_watermark(struct bufferevent *bev, pxy_conn_ctx_t *ctx, struct bufferevent *other)
{
	if (evbuffer_get_length(bufferevent_get_output(other)) >= OUTBUF_LIMIT) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_set_watermark: %s, fd=%d\n", pxy_get_event_name(bev, ctx), ctx->fd);
#endif /* DEBUG_PROXY */
		/* temporarily disable data source;
		 * set an appropriate watermark. */
		bufferevent_setwatermark(other, EV_WRITE, OUTBUF_LIMIT/2, OUTBUF_LIMIT);
		bufferevent_disable(bev, EV_READ);
		ctx->thr->set_watermarks++;
	}
}

void
pxy_discard_inbuf(struct bufferevent *bev)
{
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	size_t inbuf_size = evbuffer_get_length(inbuf);

	log_dbg_printf("Warning: Drained %zu bytes (conn closed)\n", inbuf_size);
	evbuffer_drain(inbuf, inbuf_size);
}

static void
pxy_bev_readcb_passthrough_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_passthrough_src: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	// Passthrough packets are transfered between src and srv_dst
	if (ctx->srv_dst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	evbuffer_add_buffer(bufferevent_get_output(ctx->srv_dst.bev), bufferevent_get_input(bev));
	pxy_set_watermark(bev, ctx, ctx->srv_dst.bev);
}

static void
pxy_bev_readcb_passthrough_srv_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_passthrough_srv_dst: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	// Passthrough packets are transfered between src and srv_dst
	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	evbuffer_add_buffer(bufferevent_get_output(ctx->src.bev), bufferevent_get_input(bev));
	pxy_set_watermark(bev, ctx, ctx->src.bev);
}

void
pxy_insert_sslproxy_header(pxy_conn_ctx_t *ctx, unsigned char *packet, size_t *packet_size)
{
	// @attention Cannot use string manipulation functions; we are dealing with binary arrays here, not NULL-terminated strings
	if (!ctx->sent_header) {
		memmove(packet + ctx->header_len + 2, packet, *packet_size);
		memcpy(packet, ctx->header_str, ctx->header_len);
		memcpy(packet + ctx->header_len, "\r\n", 2);
		*packet_size+= ctx->header_len + 2;
		ctx->sent_header = 1;
	}
}

unsigned char *
pxy_malloc_packet(size_t sz, pxy_conn_ctx_t *ctx)
{
	unsigned char *packet = malloc(sz);
	if (!packet) {
		// @todo Should we just set enomem?
		ctx->enomem = 1;
		pxy_conn_free(ctx, 1);
		return NULL;
	}
	return packet;
}

static void
pxy_bev_readcb_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_src: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	if (ctx->dst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);
	size_t inbuf_size = evbuffer_get_length(inbuf);

	ctx->thr->intif_in_bytes += inbuf_size;

	if (pxy_log_content_inbuf(ctx, inbuf, 1) == -1) {
		return;
	}

	size_t packet_size = inbuf_size;
	// +2 is for \r\n
	unsigned char *packet = pxy_malloc_packet(packet_size + ctx->header_len + 2, ctx);
	if (!packet) {
		return;
	}

	if (evbuffer_remove(inbuf, packet, packet_size) == -1) {
		log_err_printf("pxy_bev_readcb_src: evbuffer_remove failed, fd=%d\n", ctx->fd);
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_src: ORIG packet (size=%zu), fd=%d:\n%.*s\n",
			packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

	pxy_insert_sslproxy_header(ctx, packet, &packet_size);

	if (evbuffer_add(outbuf, packet, packet_size) == -1) {
		log_err_printf("pxy_bev_readcb_src: evbuffer_add failed, fd=%d\n", ctx->fd);
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_src: NEW packet (size=%zu), fd=%d:\n%.*s\n",
			packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */
	free(packet);
	pxy_set_watermark(bev, ctx, ctx->dst.bev);
}

static void
pxy_bev_readcb_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_dst: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
	
	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);
	size_t inbuf_size = evbuffer_get_length(inbuf);

	ctx->thr->intif_out_bytes += inbuf_size;

	if (pxy_log_content_inbuf(ctx, inbuf, 0) == -1) {
		return;
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_dst: packet size=%zu, fd=%d\n", inbuf_size, ctx->fd);
#endif /* DEBUG_PROXY */
	evbuffer_add_buffer(outbuf, inbuf);
	pxy_set_watermark(bev, ctx, ctx->src.bev);
}

static void
pxy_bev_readcb_srv_dst(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
	log_err_printf("pxy_bev_readcb_srv_dst: readcb called on srv_dst\n");
}

enum conn_end
get_conn_end(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (bev == ctx->src.bev) {
		return CONN_END_SRC;
	} else if (bev == ctx->dst.bev) {
		return CONN_END_DST;
	} else if (bev == ctx->srv_dst.bev) {
		return CONN_END_SRV_DST;
	} else {
		log_err_printf("get_conn_end: unknown bev\n");
		return CONN_END_UNKWN;
	}
}

static enum conn_end
get_conn_end_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	if (bev == ctx->src.bev) {
		return CONN_END_SRC;
	} else if (bev == ctx->dst.bev) {
		return CONN_END_DST;
	} else {
		log_err_printf("get_conn_end_child: unknown bev\n");
		return CONN_END_UNKWN;
	}
}

/*
 * Callback for read events on the up- and downstream connection bufferevents.
 * Called when there is data ready in the input evbuffer.
 */
void
pxy_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb: readcb called when other end not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
		ctx->proto_ctx->bev_readcb(bev, ctx);
		return;
	}

	enum conn_end ce = get_conn_end(bev, ctx);
	if (ce != CONN_END_UNKWN) {
		callback_func_t readcb = readcb_funcs[ctx->proto][ce];
		if (readcb) {
			readcb(bev, ctx);
		} else {
			log_err_printf("pxy_bev_readcb: NULL readcb on %d\n", ce);
		}
	} else {
		log_err_printf("pxy_bev_readcb: UNKWN conn end\n");
	}
}

void
pxy_remove_sslproxy_header(unsigned char *packet, size_t *packet_size, pxy_conn_child_ctx_t *ctx)
{
	unsigned char *pos = memmem(packet, *packet_size, ctx->conn->header_str, ctx->conn->header_len);
	if (pos) {
		memmove(pos, pos + ctx->conn->header_len + 2, *packet_size - (pos - packet) - (ctx->conn->header_len + 2));
		*packet_size-= ctx->conn->header_len + 2;
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_readcb_child: REMOVED SSLproxy header, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	}
}

static void
pxy_bev_readcb_child_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_src: ENTER, fd=%d, conn fd=%d, size=%zu\n",
			ctx->fd, ctx->conn->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
		
	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child: readcb called when other end not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (ctx->dst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	size_t inbuf_size = evbuffer_get_length(inbuf);

	ctx->conn->thr->extif_out_bytes += inbuf_size;

	size_t packet_size = inbuf_size;
	unsigned char *packet = pxy_malloc_packet(packet_size, ctx->conn);
	if (!packet) {
		return;
	}

	if (evbuffer_remove(inbuf, packet, packet_size) == -1) {
		log_err_printf("pxy_bev_readcb_child: src evbuffer_remove failed, fd=%d\n", ctx->fd);
	}

	pxy_remove_sslproxy_header(packet, &packet_size, ctx);

	if (evbuffer_add(outbuf, packet, packet_size) == -1) {
		log_err_printf("pxy_bev_readcb_child: src evbuffer_add failed, fd=%d\n", ctx->fd);
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child: src packet (size=%zu), fd=%d, conn fd=%d:\n%.*s\n",
			packet_size, ctx->fd, ctx->conn->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

	pxy_log_content_buf((pxy_conn_ctx_t *)ctx, packet, packet_size, 1);
	free(packet);

	pxy_set_watermark(bev, ctx->conn, ctx->dst.bev);
}

static void
pxy_bev_readcb_child_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_dst: ENTER, fd=%d, conn fd=%d, size=%zu\n",
			ctx->fd, ctx->conn->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
		
	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child: readcb called when other end not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);

	size_t inbuf_size = evbuffer_get_length(inbuf);

	ctx->conn->thr->extif_in_bytes += inbuf_size;
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child: dst packet size=%zu, fd=%d\n", inbuf_size, ctx->fd);
#endif /* DEBUG_PROXY */
	pxy_log_content_inbuf((pxy_conn_ctx_t *)ctx, inbuf, 0);
	evbuffer_add_buffer(outbuf, inbuf);

	pxy_set_watermark(bev, ctx->conn, ctx->src.bev);
}

void
pxy_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child: readcb called when other end not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
		ctx->proto_ctx->bev_readcb(bev, ctx);
		return;
	}

	enum conn_end ce = get_conn_end_child(bev, ctx);
	if (ce != CONN_END_UNKWN) {
		callback_func_t readcb = child_readcb_funcs[ctx->proto][ce];
		if (readcb) {
			readcb(bev, ctx);
		} else {
			log_err_printf("pxy_bev_readcb_child: NULL readcb on %d\n", ce);
		}
	} else {
		log_err_printf("pxy_bev_readcb_child: UNKWN conn end\n");
	}
}

static void
pxy_unset_watermark(struct bufferevent *bev, pxy_conn_ctx_t *ctx, pxy_conn_desc_t *other)
{
	if (other->bev && !(bufferevent_get_enabled(other->bev) & EV_READ)) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_unset_watermark: %s, fd=%d\n", pxy_get_event_name(bev, ctx), ctx->fd);
#endif /* DEBUG_PROXY */
		/* data source temporarily disabled;
		 * re-enable and reset watermark to 0. */
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(other->bev, EV_READ);
		ctx->thr->unset_watermarks++;
	}
}

static void
pxy_connect_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (!ctx->dst_connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_connect_dst: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
		// This is a workaround for this error condition, nothing else seems to work.
		// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
		// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
		if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
			ctx->proto_ctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
		} else {
			pxy_bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
		}
	}
}

static void
pxy_connect_srv_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (!ctx->srv_dst_connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_connect_srv_dst: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
		// This is a workaround for this error condition, nothing else seems to work.
		// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
		// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
		if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
			ctx->proto_ctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
		} else {
			pxy_bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
		}
	}
}

static int
pxy_close_conn_end_ifnodata(pxy_conn_desc_t *conn_end, pxy_conn_ctx_t *ctx, void (*free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *))
{
	/* if the other end is still open and doesn't have data
	 * to send, close it, otherwise its writecb will close
	 * it after writing what's left in the output buffer */
	if (evbuffer_get_length(bufferevent_get_output(conn_end->bev)) == 0) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_close_conn_end_ifnodata: evbuffer_get_length(outbuf) == 0, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		free_and_close_fd_func(conn_end->bev, ctx);
		conn_end->bev = NULL;
		conn_end->closed = 1;
		return 1;
	}
	return 0;
}

static void
pxy_bev_writecb_passthrough_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	// @attention srv_dst.bev may be NULL
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_passthrough_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (ctx->srv_dst.closed) {
		if (pxy_close_conn_end_ifnodata(&ctx->src, ctx, &bufferevent_free_and_close_fd_nonssl)) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_passthrough_src: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free(ctx, 1);
		}			
		return;
	}
	pxy_unset_watermark(bev, ctx, &ctx->srv_dst);
}

static void
pxy_bev_writecb_passthrough_srv_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_passthrough_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_connect_srv_dst(bev, ctx);

	if (ctx->src.closed) {
		if (pxy_close_conn_end_ifnodata(&ctx->srv_dst, ctx, &bufferevent_free_and_close_fd_nonssl) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_passthrough_srv_dst: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free(ctx, 0);
		}			
		return;
	}
	pxy_unset_watermark(bev, ctx, &ctx->src);
}

static void
pxy_bev_writecb_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (ctx->dst.closed) {
		if (pxy_close_conn_end_ifnodata(&ctx->src, ctx, &bufferevent_free_and_close_fd) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_src: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free(ctx, 1);
		}			
		return;
	}
	pxy_unset_watermark(bev, ctx, &ctx->dst);
}

static void
pxy_bev_writecb_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_connect_dst(bev, ctx);

	if (ctx->src.closed) {
		if (pxy_close_conn_end_ifnodata(&ctx->dst, ctx, &bufferevent_free_and_close_fd_nonssl) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_dst: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free(ctx, 0);
		}			
		return;
	}
	pxy_unset_watermark(bev, ctx, &ctx->src);
}

static void
pxy_bev_writecb_srv_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	pxy_connect_srv_dst(bev, ctx);
}

/*
 * Callback for write events on the up- and downstream connection bufferevents.
 * Called when either all data from the output evbuffer has been written,
 * or if the outbuf is only half full again after having been full.
 */
void
pxy_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
		ctx->proto_ctx->bev_writecb(bev, ctx);
		return;
	}

	enum conn_end ce = get_conn_end(bev, ctx);
	if (ce != CONN_END_UNKWN) {
		callback_func_t writecb = writecb_funcs[ctx->proto][ce];
		if (writecb) {
			writecb(bev, ctx);
		} else {
			log_err_printf("pxy_bev_writecb: NULL writecb on %d\n", ce);
		}
	} else {
		log_err_printf("pxy_bev_writecb: UNKWN conn end\n");
	}
}

static void
pxy_bev_writecb_child_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_child_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->conn->atime = time(NULL);

	if (ctx->dst.closed) {
		if (pxy_close_conn_end_ifnodata(&ctx->src, ctx->conn, &bufferevent_free_and_close_fd_nonssl) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_child_src: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free_child(ctx);
		}			
		return;
	}
	pxy_unset_watermark(bev, ctx->conn, &ctx->dst);
}

static void
pxy_connect_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	if (!ctx->connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_connect_dst_child: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
		// This is a workaround for this error condition, nothing else seems to work.
		// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
		// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
		if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
			ctx->proto_ctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
		} else {
			pxy_bev_eventcb_child(bev, BEV_EVENT_CONNECTED, ctx);
		}
	}
}

static void
pxy_bev_writecb_child_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_child_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->conn->atime = time(NULL);

	pxy_connect_dst_child(bev, ctx);

	if (ctx->src.closed) {
		if (pxy_close_conn_end_ifnodata(&ctx->dst, ctx->conn, &bufferevent_free_and_close_fd) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_child_dst: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free_child(ctx);
		}			
		return;
	}

	pxy_unset_watermark(bev, ctx->conn, &ctx->src);
}

void
pxy_bev_writecb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
		ctx->proto_ctx->bev_writecb(bev, ctx);
		return;
	}

	enum conn_end ce = get_conn_end_child(bev, ctx);
	if (ce != CONN_END_UNKWN) {
		callback_func_t writecb = child_writecb_funcs[ctx->proto][ce];
		if (writecb) {
			writecb(bev, ctx);
		} else {
			log_err_printf("pxy_bev_writecb_child: NULL writecb on %d\n", ce);
		}
	} else {
		log_err_printf("pxy_bev_writecb_child: UNKWN conn end\n");
	}
}

static int
pxy_prepare_logging_local_procinfo(UNUSED pxy_conn_ctx_t *ctx)
{
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
				return -1;
			}
		}
	}
#endif /* HAVE_LOCAL_PROCINFO */
	return 0;
}

static int
pxy_prepare_passthrough_logging(pxy_conn_ctx_t *ctx)
{
	/* prepare logging, part 2 */
	if (WANT_CONNECT_LOG(ctx)) {
		return pxy_prepare_logging_local_procinfo(ctx);
	}
	return 0;
}

int
pxy_prepare_logging(pxy_conn_ctx_t *ctx)
{
	/* prepare logging, part 2 */
	if (WANT_CONNECT_LOG(ctx) || WANT_CONTENT_LOG(ctx)) {
		return pxy_prepare_logging_local_procinfo(ctx);
	}
	if (WANT_CONTENT_LOG(ctx)) {
		if (log_content_open(&ctx->logctx, ctx->opts,
							 STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str),
							 STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
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
			return -1;
		}
	}
	return 0;
}

static void
pxy_log_passthrough_connect_type(pxy_conn_ctx_t *ctx)
{
	if (OPTS_DEBUG(ctx->opts)) {
		/* for TCP, we get only a dst connect event,
		 * since src was already connected from the
		 * beginning; mirror SSL debug output anyway
		 * in order not to confuse anyone who might be
		 * looking closely at the output */
		log_dbg_printf("pxy_log_passthrough_connect_type: TCP connected to [%s]:%s\n",
					   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str));
		log_dbg_printf("pxy_log_passthrough_connect_type: TCP connected from [%s]:%s\n",
					   STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str));
	}
}

static void
pxy_log_passthrough_connect_src(pxy_conn_ctx_t *ctx)
{
	if (WANT_CONNECT_LOG(ctx) || ctx->opts->statslog) {
		pxy_log_connect_nonhttp(ctx);
	}
	pxy_log_passthrough_connect_type(ctx);
}

static void
pxy_bev_eventcb_passthrough_connected_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_passthrough_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	pxy_log_passthrough_connect_src(ctx);
}

static int
pxy_check_src_bev(pxy_conn_ctx_t *ctx)
{
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating src bufferevent\n");
		if (ctx->src.ssl) {
			SSL_free(ctx->src.ssl);
			ctx->src.ssl = NULL;
		}
		pxy_conn_free(ctx, 1);
		return -1;
	}
	return 0;
}

int
pxy_setup_src(pxy_conn_ctx_t *ctx)
{
	ctx->src.bev = pxy_bufferevent_setup(ctx, ctx->fd, ctx->src.ssl);
	return pxy_check_src_bev(ctx);
}

int
pxy_set_dstaddr(pxy_conn_ctx_t *ctx)
{
	if (sys_sockaddr_str((struct sockaddr *)&ctx->addr, ctx->addrlen, &ctx->dsthost_str, &ctx->dstport_str) != 0) {
		ctx->enomem = 1;
		pxy_conn_free(ctx, 1);
		return -1;
	}
	return 0;
}

static int
pxy_passthrough_enable_src(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_passthrough_enable_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->connected = 1;

	if (pxy_setup_src(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	if (pxy_set_dstaddr(ctx) == -1) {
		return -1;
	}

	if (pxy_prepare_passthrough_logging(ctx) == -1) {
		return -1;
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_passthrough_enable_src: Enabling src, %s, fd=%d, child_fd=%d\n", ctx->header_str, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
	// Now open the gates
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void
pxy_bev_eventcb_passthrough_connected_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_passthrough_connected_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->srv_dst_connected) {
		ctx->srv_dst_connected = 1;
		ctx->srv_dst_fd = bufferevent_getfd(ctx->srv_dst.bev);
		ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->srv_dst_fd);
	}

	if (ctx->srv_dst_connected && !ctx->connected) {
		if (pxy_passthrough_enable_src(ctx) == -1) {
			return;
		}
	}
	pxy_log_passthrough_connect_type(ctx);
}

int
pxy_setup_child_listener(pxy_conn_ctx_t *ctx)
{
	// @attention Defer child setup and evcl creation until after parent init is complete, otherwise (1) causes multithreading issues (proxy_listener_acceptcb is
	// running on a different thread from the conn, and we only have thrmgr mutex), and (2) we need to clean up less upon errors.
	// Child evcls use the evbase of the parent thread, otherwise we would get multithreading issues.
	if ((ctx->child_fd = privsep_client_opensock_child(ctx->clisock, ctx->spec)) == -1) {
		log_err_level_printf(LOG_CRIT, "Error opening child socket: %s (%i)\n", strerror(errno), errno);
		pxy_conn_free(ctx, 1);
		return -1;
	}
	ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->child_fd);

	// @attention Do not pass NULL as user-supplied pointer
	struct evconnlistener *child_evcl = evconnlistener_new(ctx->thr->evbase, proxy_listener_acceptcb_child, ctx, LEV_OPT_CLOSE_ON_FREE, 1024, ctx->child_fd);
	if (!child_evcl) {
		log_err_level_printf(LOG_CRIT, "Error creating child evconnlistener: %s\n", strerror(errno));
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_setup_child_listener: Error creating child evconnlistener: %s, fd=%d, child_fd=%d\n", strerror(errno), ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
		// @attention Cannot call proxy_listener_ctx_free() on child_evcl, child_evcl does not have any ctx with next listener
		// @attention Close child fd separately, because child evcl does not exist yet, hence fd would not be closed by calling pxy_conn_free()
		evutil_closesocket(ctx->child_fd);
		pxy_conn_free(ctx, 1);
		return -1;
	}
	ctx->child_evcl = child_evcl;

	evconnlistener_set_error_cb(child_evcl, proxy_listener_errorcb);
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_setup_child_listener: Finished setting up child, fd=%d, NEW child_fd=%d\n", ctx->fd, ctx->child_fd);	
#endif /* DEBUG_PROXY */

	struct sockaddr_in child_listener_addr;
	socklen_t child_listener_len = sizeof(child_listener_addr);

	if (getsockname(ctx->child_fd, (struct sockaddr *)&child_listener_addr, &child_listener_len) < 0) {
		log_err_level_printf(LOG_CRIT, "Error in getsockname: %s\n", strerror(errno));
		// @todo If getsockname() fails, should we really terminate the connection?
		// @attention Do not close the child fd here, because child evcl exists now, hence pxy_conn_free() will close it while freeing child_evcl
		pxy_conn_free(ctx, 1);
		return -1;
	}

	// @attention Children are always listening on an IPv4 loopback address
	char addr[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &child_listener_addr.sin_addr, addr, INET_ADDRSTRLEN)) {
		pxy_conn_free(ctx, 1);
		return -1;
	}

	// SSLproxy: [127.0.0.1]:34649,[192.168.3.24]:47286,[74.125.206.108]:465,s
	// @todo Port may be less than 5 chars
	// SSLproxy:        +   + [ + addr         + ] + : + p + , + [ + srchost_str              + ] + : + srcport_str              + , + [ + dsthost_str              + ] + : + dstport_str              + , + s + NULL
	// SSLPROXY_KEY_LEN + 1 + 1 + strlen(addr) + 1 + 1 + 5 + 1 + 1 + strlen(ctx->srchost_str) + 1 + 1 + strlen(ctx->srcport_str) + 1 + 1 + strlen(ctx->dsthost_str) + 1 + 1 + strlen(ctx->dstport_str) + 1 + 1 + 1
	ctx->header_len = SSLPROXY_KEY_LEN + strlen(addr) + strlen(ctx->srchost_str) + strlen(ctx->srcport_str) + strlen(ctx->dsthost_str) + strlen(ctx->dstport_str) + 20;
	// @todo Always check malloc retvals. Should we close the conn if malloc fails?
	ctx->header_str = malloc(ctx->header_len);
	if (!ctx->header_str) {
		pxy_conn_free(ctx, 1);
		return -1;
	}
	snprintf(ctx->header_str, ctx->header_len, "%s [%s]:%u,[%s]:%s,[%s]:%s,%s",
			SSLPROXY_KEY, addr, ntohs(child_listener_addr.sin_port), STRORNONE(ctx->srchost_str), STRORNONE(ctx->srcport_str),
			STRORNONE(ctx->dsthost_str), STRORNONE(ctx->dstport_str), ctx->spec->ssl ? "s":"p");
	return 0;
}

void
pxy_close_srv_dst(pxy_conn_ctx_t *ctx)
{
	// @attention Free the srv_dst of the conn asap, we don't need it anymore, but we need its fd
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_close_srv_dst: Closing srv_dst, fd=%d, srv_dst fd=%d\n", ctx->fd, bufferevent_getfd(ctx->srv_dst.bev));
#endif /* DEBUG_PROXY */
	// So save its ssl info for logging
	if (ctx->srv_dst.ssl) {
		ctx->srv_dst_ssl_version = strdup(SSL_get_version(ctx->srv_dst.ssl));
		ctx->srv_dst_ssl_cipher = strdup(SSL_get_cipher(ctx->srv_dst.ssl));
	}

	// @attention When both eventcb and writecb for srv_dst are enabled, either eventcb or writecb may get a NULL srv_dst bev, causing a crash with signal 10.
	// So, from this point on, we should check if srv_dst is NULL or not.
	bufferevent_free_and_close_fd(ctx->srv_dst.bev, ctx);
	ctx->srv_dst.bev = NULL;
	ctx->srv_dst.closed = 1;
}

void
pxy_close_dst(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_close_dst: Closing dst, fd=%d, dst fd=%d\n", ctx->fd, bufferevent_getfd(ctx->dst.bev));
#endif /* DEBUG_PROXY */
	bufferevent_free_and_close_fd(ctx->dst.bev, ctx);
	ctx->dst.bev = NULL;
	ctx->dst.closed = 1;
}

static void
pxy_engage_passthrough_mode(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_engage_passthrough_mode: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	// @attention Do not call bufferevent_free_and_close_fd(), otherwise connection stalls due to ssl shutdown
	// We get srv_dst writecb while ssl shutdown is still in progress, and srv_dst readcb never fires
	//bufferevent_free_and_close_fd(ctx->srv_dst.bev, ctx);
	SSL_free(ctx->srv_dst.ssl);
	bufferevent_free_and_close_fd_nonssl(ctx->srv_dst.bev, ctx);
	ctx->srv_dst.bev = NULL;
	ctx->srv_dst.ssl = NULL;
	ctx->passthrough = 1;
	ctx->proto = PROTO_PASSTHROUGH;
	ctx->connected = 0;
	ctx->srv_dst_connected = 0;

	// Close and free dst if open
	if (!ctx->dst.closed) {
		ctx->dst.closed = 1;
		bufferevent_free_and_close_fd_nonssl(ctx->dst.bev, ctx);
		ctx->dst.bev = NULL;
		ctx->dst_fd = 0;
	}

	pxy_fd_readcb(ctx->fd, 0, ctx);
}

static int
pxy_log_masterkey(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this)
{
	if (this->ssl) {
		/* log master key */
		if (ctx->opts->masterkeylog) {
			char *keystr;
			keystr = ssl_ssl_masterkey_to_str(this->ssl);
			if ((keystr == NULL) ||
				(log_masterkey_print_free(keystr) == -1)) {
				if (errno == ENOMEM)
					ctx->enomem = 1;
				pxy_conn_free(ctx, 1);
				return -1;
			}
		}
	}
	return 0;
}

static void
pxy_log_dbg_connect_type(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this)
{
	if (OPTS_DEBUG(ctx->opts)) {
		if (this->ssl) {
			char *keystr;
			/* for SSL, we get two connect events */
			log_dbg_printf("pxy_log_connect_type: SSL connected to [%s]:%s %s %s\n",
						   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
						   SSL_get_version(this->ssl), SSL_get_cipher(this->ssl));
			keystr = ssl_ssl_masterkey_to_str(this->ssl);
			if (keystr) {
				log_dbg_print_free(keystr);
			}
		} else {
			/* for TCP, we get only a dst connect event,
			 * since src was already connected from the
			 * beginning; mirror SSL debug output anyway
			 * in order not to confuse anyone who might be
			 * looking closely at the output */
			log_dbg_printf("pxy_log_connect_type: TCP connected to [%s]:%s\n",
						   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str));
			log_dbg_printf("pxy_log_connect_type: TCP connected from [%s]:%s\n",
						   STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str));
		}
	}
}

void
pxy_log_connect_src(pxy_conn_ctx_t *ctx)
{
	/* log connection if we don't analyze any headers */
	if (!ctx->spec->http && (WANT_CONNECT_LOG(ctx) || ctx->opts->statslog)) {
		pxy_log_connect_nonhttp(ctx);
	}

	if (ctx->src.ssl && ctx->opts->certgendir) {
		/* write SSL certificates to gendir */
		pxy_srccert_write(ctx);
	}

	if (pxy_log_masterkey(ctx, &ctx->src) == -1) {
		return;
	}

	pxy_log_dbg_connect_type(ctx, &ctx->src);
}

void
pxy_log_connect_srv_dst(pxy_conn_ctx_t *ctx)
{
	// @attention srv_dst.bev may be NULL, if its writecb fires first
	if (ctx->srv_dst.bev) {
		/* log connection if we don't analyze any headers */
		if (!ctx->srv_dst.ssl && !ctx->spec->http && (WANT_CONNECT_LOG(ctx) || ctx->opts->statslog)) {
			pxy_log_connect_nonhttp(ctx);
		}

		if (pxy_log_masterkey(ctx, &ctx->srv_dst) == -1) {
			return;
		}

		pxy_log_dbg_connect_type(ctx, &ctx->srv_dst);
	}
}

int
pxy_setup_src_ssl(pxy_conn_ctx_t *ctx)
{
	// @todo Make srv_dst.ssl the origssl param
	ctx->src.ssl = pxy_srcssl_create(ctx, ctx->srv_dst.ssl);
	if (!ctx->src.ssl) {
		if (ctx->opts->passthrough && !ctx->enomem) {
			log_err_level_printf(LOG_WARNING, "No cert found; falling back to passthrough, fd=%d\n", ctx->fd);
			pxy_engage_passthrough_mode(ctx);
			// return protocol change
			return 1;
		}
		pxy_conn_free(ctx, 1);
		return -1;
	}
	return 0;
}

int
pxy_setup_new_src(pxy_conn_ctx_t *ctx)
{
	ctx->src.bev = bufferevent_openssl_filter_new(ctx->evbase, ctx->src.bev, ctx->src.ssl,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_DEFER_CALLBACKS);
	return pxy_check_src_bev(ctx);
}

static int
pxy_enable_src(pxy_conn_ctx_t *ctx)
{
	ctx->connected = 1;

	if (ctx->spec->ssl) {
		int rv;
		if ((rv = pxy_setup_src_ssl(ctx)) != 0) {
			return rv;
		}
	}
	if (pxy_setup_src(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	if (pxy_set_dstaddr(ctx) == -1) {
		return -1;
	}

	if (pxy_prepare_logging(ctx) == -1) {
		return -1;
	}

	pxy_close_srv_dst(ctx);

	if (pxy_setup_child_listener(ctx) == -1) {
		return -1;
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_enable_src: Enabling src, %s, fd=%d, child_fd=%d\n", ctx->header_str, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
	// Now open the gates
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

void
pxy_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_connect_src(ctx);
}

void
pxy_bev_eventcb_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_connected_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->dst_connected = 1;

	if (ctx->srv_dst_connected && ctx->dst_connected && !ctx->connected) {
		pxy_enable_src(ctx);
	}
}

void
pxy_bev_eventcb_connected_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_connected_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->srv_dst_connected = 1;
	ctx->srv_dst_fd = bufferevent_getfd(ctx->srv_dst.bev);
	ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->srv_dst_fd);

	// @attention Create and enable dst.bev before, but connect here, because we check if dst.bev is NULL elsewhere
	if (bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->spec->conn_dst_addr, ctx->spec->conn_dst_addrlen) == -1) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_eventcb_connected_srv_dst: FAILED bufferevent_socket_connect for dst, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_conn_free(ctx, 1);
		return;
	}
	ctx->dst_fd = bufferevent_getfd(ctx->dst.bev);
	ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->dst_fd);

	if (ctx->srv_dst_connected && ctx->dst_connected && !ctx->connected) {
		if (pxy_enable_src(ctx) == -1) {
			return;
		}
	}

	pxy_log_connect_srv_dst(ctx);
}

static void
pxy_log_err_ssl_error(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	unsigned long sslerr;

	/* Can happen for socket errs, ssl errs;
	 * may happen for unclean ssl socket shutdowns. */
	sslerr = bufferevent_get_openssl_error(bev);
	if (!errno && !sslerr) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
		/* We have disabled notification for unclean shutdowns
		 * so this should not happen; log a warning. */
		log_err_level_printf(LOG_WARNING, "Spurious error from bufferevent (errno=0,sslerr=0)\n");
#else /* LIBEVENT_VERSION_NUMBER < 0x02010000 */
		/* Older versions of libevent will report these. */
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Unclean SSL shutdown, fd=%d\n", ctx->fd);
		}
#endif /* LIBEVENT_VERSION_NUMBER < 0x02010000 */
	} else if (ERR_GET_REASON(sslerr) == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE) {
		/* these can happen due to client cert auth,
		 * only log error if debugging is activated */
		log_dbg_printf("Error from bufferevent: %i:%s %lu:%i:%s:%i:%s:%i:%s\n",
					   errno, errno ? strerror(errno) : "-", sslerr,
					   ERR_GET_REASON(sslerr), sslerr ? ERR_reason_error_string(sslerr) : "-",
					   ERR_GET_LIB(sslerr), sslerr ? ERR_lib_error_string(sslerr) : "-",
					   ERR_GET_FUNC(sslerr), sslerr ? ERR_func_error_string(sslerr) : "-");
		while ((sslerr = bufferevent_get_openssl_error(bev))) {
			log_dbg_printf("Additional SSL error: %lu:%i:%s:%i:%s:%i:%s\n",
						   sslerr,
						   ERR_GET_REASON(sslerr), ERR_reason_error_string(sslerr),
						   ERR_GET_LIB(sslerr), ERR_lib_error_string(sslerr),
						   ERR_GET_FUNC(sslerr), ERR_func_error_string(sslerr));
		}
	} else {
		/* real errors */
		log_err_printf("Error from bufferevent: %i:%s %lu:%i:%s:%i:%s:%i:%s\n",
					   errno, errno ? strerror(errno) : "-",
					   sslerr,
					   ERR_GET_REASON(sslerr), sslerr ? ERR_reason_error_string(sslerr) : "-",
					   ERR_GET_LIB(sslerr), sslerr ? ERR_lib_error_string(sslerr) : "-",
					   ERR_GET_FUNC(sslerr), sslerr ? ERR_func_error_string(sslerr) : "-");
		while ((sslerr = bufferevent_get_openssl_error(bev))) {
			log_err_printf("Additional SSL error: %lu:%i:%s:%i:%s:%i:%s\n",
						   sslerr,
						   ERR_GET_REASON(sslerr), ERR_reason_error_string(sslerr),
						   ERR_GET_LIB(sslerr), ERR_lib_error_string(sslerr),
						   ERR_GET_FUNC(sslerr), ERR_func_error_string(sslerr));
		}
	}
}

static void
pxy_log_dbg_evbuf_info(UNUSED pxy_conn_ctx_t *ctx, UNUSED pxy_conn_desc_t *this, UNUSED pxy_conn_desc_t *other)
{
#ifdef DEBUG_PROXY
	// Use ctx->conn, because this function is used by child conns too
	if (OPTS_DEBUG(ctx->conn->opts)) {
		log_dbg_printf("evbuffer size at EOF: i:%zu o:%zu i:%zu o:%zu\n",
						evbuffer_get_length(bufferevent_get_input(this->bev)),
						evbuffer_get_length(bufferevent_get_output(this->bev)),
						other->closed ? 0 : evbuffer_get_length(bufferevent_get_input(other->bev)),
						other->closed ? 0 : evbuffer_get_length(bufferevent_get_output(other->bev)));
	}
#endif /* DEBUG_PROXY */
}

static void
pxy_consume_last_input(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	/* if there is data pending in the closed connection,
	 * handle it here, otherwise it will be lost. */
	if (evbuffer_get_length(bufferevent_get_input(bev))) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_process_last_input: evbuffer_get_length(inbuf) > 0, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
			ctx->proto_ctx->bev_readcb(bev, ctx);
		} else {
			pxy_bev_readcb(bev, ctx);
		}
	}
}

static void
pxy_log_dbg_disconnect(pxy_conn_ctx_t *ctx)
{
	// On parent connections, ctx->src.ssl is enough to know the type of connection
	/* we only get a single disconnect event here for both connections */
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("pxy_log_disconnect: %s disconnected to [%s]:%s, fd=%d\n",
					   ctx->src.ssl ? "SSL" : "TCP",
					   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str), ctx->fd);
		log_dbg_printf("pxy_log_disconnect: %s disconnected from [%s]:%s, fd=%d\n",
					   ctx->src.ssl ? "SSL" : "TCP",
					   STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), ctx->fd);
	}
}

static void
pxy_disconnect(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this,
		void (*this_free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *), pxy_conn_desc_t *other, int is_requestor)
{
	// @attention srv_dst should never reach here unless in passthrough mode, its bev may be NULL
	this->closed = 1;
	this_free_and_close_fd_func(this->bev, ctx);
	this->bev = NULL;
	if (other->closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_disconnect: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_conn_free(ctx, is_requestor);
	}
}

static void
pxy_bev_eventcb_passthrough_eof_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_passthrough_eof_src: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_dbg_evbuf_info(ctx, &ctx->src, &ctx->srv_dst);

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->srv_dst.closed = 1;
	} else if (!ctx->srv_dst.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_passthrough_eof_src: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_consume_last_input(bev, ctx);
		pxy_close_conn_end_ifnodata(&ctx->srv_dst, ctx, &bufferevent_free_and_close_fd_nonssl);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->src, &bufferevent_free_and_close_fd_nonssl, &ctx->srv_dst, 1);
}

static void
pxy_bev_eventcb_passthrough_eof_srv_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_passthrough_eof_srv_dst: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_dbg_evbuf_info(ctx, &ctx->srv_dst, &ctx->src);

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_passthrough_eof_srv_dst: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_consume_last_input(bev, ctx);
		pxy_close_conn_end_ifnodata(&ctx->src, ctx, &bufferevent_free_and_close_fd_nonssl);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->srv_dst, &bufferevent_free_and_close_fd_nonssl, &ctx->src, 0);
}

void
pxy_bev_eventcb_eof_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_eof_src: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_dbg_evbuf_info(ctx, &ctx->src, &ctx->dst);

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_eof_src: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_consume_last_input(bev, ctx);
		pxy_close_conn_end_ifnodata(&ctx->dst, ctx, &bufferevent_free_and_close_fd_nonssl);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->src, &bufferevent_free_and_close_fd, &ctx->dst, 1);
}

void
pxy_bev_eventcb_eof_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_eof_dst: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_dbg_evbuf_info(ctx, &ctx->dst, &ctx->src);

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_eof_dst: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_consume_last_input(bev, ctx);
		pxy_close_conn_end_ifnodata(&ctx->src, ctx, &bufferevent_free_and_close_fd);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->dst, &bufferevent_free_and_close_fd_nonssl, &ctx->src, 0);
}

void
pxy_bev_eventcb_eof_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_eof_srv_dst: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment on srv_dst\n");
	pxy_conn_free(ctx, 0);
}

static void
pxy_bev_eventcb_passthrough_error_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	// Passthrough packets are transfered between src and srv_dst
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_passthrough_error_src: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_printf("pxy_bev_eventcb_passthrough_error_src: Client-side BEV_EVENT_ERROR\n");
	pxy_log_err_ssl_error(bev, ctx);
	ctx->thr->errors++;

	if (!ctx->connected) {
		ctx->srv_dst.closed = 1;
	} else if (!ctx->srv_dst.closed) {
		pxy_close_conn_end_ifnodata(&ctx->srv_dst, ctx, &bufferevent_free_and_close_fd_nonssl);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->src, &bufferevent_free_and_close_fd_nonssl, &ctx->srv_dst, 1);
}

static void
pxy_bev_eventcb_passthrough_error_srv_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	// Passthrough packets are transfered between src and srv_dst
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_passthrough_error_srv_dst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_printf("pxy_bev_eventcb_passthrough_error_srv_dst: Client-side BEV_EVENT_ERROR\n");
	pxy_log_err_ssl_error(bev, ctx);
	ctx->thr->errors++;

	if (!ctx->connected) {
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		pxy_close_conn_end_ifnodata(&ctx->src, ctx, &bufferevent_free_and_close_fd_nonssl);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->srv_dst, &bufferevent_free_and_close_fd_nonssl, &ctx->src, 0);
}

void
pxy_bev_eventcb_error_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_error_src: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_printf("pxy_bev_eventcb_error_src: Client-side BEV_EVENT_ERROR\n");
	pxy_log_err_ssl_error(bev, ctx);
	ctx->thr->errors++;

	if (!ctx->connected) {
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		pxy_close_conn_end_ifnodata(&ctx->dst, ctx, &bufferevent_free_and_close_fd_nonssl);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->src, &bufferevent_free_and_close_fd, &ctx->dst, 1);
}

void
pxy_bev_eventcb_error_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_error_dst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_printf("pxy_bev_eventcb_error_dst: Client-side BEV_EVENT_ERROR\n");
	pxy_log_err_ssl_error(bev, ctx);
	ctx->thr->errors++;

	if (!ctx->connected) {
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		pxy_close_conn_end_ifnodata(&ctx->src, ctx, &bufferevent_free_and_close_fd);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->dst, &bufferevent_free_and_close_fd_nonssl, &ctx->src, 0);
}

void
pxy_bev_eventcb_error_srv_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_error_srv_dst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_printf("pxy_bev_eventcb_error_srv_dst: Client-side BEV_EVENT_ERROR\n");
	pxy_log_err_ssl_error(bev, ctx);
	ctx->thr->errors++;

	if (!ctx->connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_eventcb_error_srv_dst: ERROR !ctx->connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		/* the callout to the original destination failed,
		 * e.g. because it asked for client cert auth, so
		 * close the accepted socket and clean up */
		if (ctx->srv_dst.ssl && ctx->opts->passthrough && bufferevent_get_openssl_error(bev)) {
			/* ssl callout failed, fall back to plain TCP passthrough of SSL connection */
			log_err_level_printf(LOG_WARNING, "SSL srv_dst connection failed; falling back to passthrough, fd=%d\n", ctx->fd);
			pxy_engage_passthrough_mode(ctx);
			return;
		}
		pxy_conn_free(ctx, 0);
	}
}

static void
pxy_bev_eventcb_src(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_src(bev, ctx);
	}
}

static void
pxy_bev_eventcb_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_dst(bev, ctx);
	}
}

static void
pxy_bev_eventcb_srv_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_connected_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_srv_dst(bev, ctx);
	}
}

enum bev_event {
	EVENT_CONNECTED = 0,
	EVENT_EOF,
	EVENT_ERROR,
	EVENT_UNKWN,
};

static enum bev_event
get_event(short events)
{
	if (events & BEV_EVENT_CONNECTED) {
		return EVENT_CONNECTED;
	} else if (events & BEV_EVENT_EOF) {
		return EVENT_EOF;
	} else if (events & BEV_EVENT_ERROR) {
		return EVENT_ERROR;
	} else {
		return EVENT_UNKWN;
	}
}

/*
 * Callback for meta events on the up- and downstream connection bufferevents.
 * Called when EOF has been reached, a connection has been made, and on errors.
 */
void
pxy_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
		ctx->proto_ctx->bev_eventcb(bev, events, arg);
		return;
	}

	enum bev_event event = get_event(events);
	if (event != EVENT_UNKWN) {
		enum conn_end ce = get_conn_end(bev, ctx);
		if (ce != CONN_END_UNKWN) {
			event_callback_func_t eventcb = eventcb_funcs[ctx->proto][event][ce];
			if (eventcb) {
				eventcb(bev, ctx);
			} else {
				log_err_printf("pxy_bev_eventcb: NULL eventcb on %d\n", ce);
			}
		} else {
			log_err_printf("pxy_bev_eventcb: UNKWN conn end\n");
		}
	} else {
		log_err_printf("pxy_bev_eventcb: UNKWN event\n");
	}
}

static void
pxy_disconnect_child(pxy_conn_child_ctx_t *ctx, pxy_conn_desc_t *this,
		void (*this_free_and_close_fd_func)(struct bufferevent *, pxy_conn_ctx_t *), pxy_conn_desc_t *other)
{
	this->closed = 1;
	this_free_and_close_fd_func(this->bev, ctx->conn);
	this->bev = NULL;
	if (other->closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_disconnect_child: other->closed, terminate conn, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		pxy_conn_free_child(ctx);
	}
}

static void
pxy_log_dbg_disconnect_child(pxy_conn_child_ctx_t *ctx)
{
	// On child connections, ctx->dst.ssl is enough to know the type of connection
	/* we only get a single disconnect event here for both connections */
	if (OPTS_DEBUG(ctx->conn->opts)) {
		log_dbg_printf("pxy_log_dbg_disconnect_child: %s disconnected to [%s]:%s, fd=%d, conn fd=%d\n",
					   ctx->dst.ssl ? "SSL" : "TCP",
					   STRORDASH(ctx->conn->dsthost_str), STRORDASH(ctx->conn->dstport_str), ctx->fd, ctx->conn->fd);
		log_dbg_printf("pxy_log_dbg_disconnect_child: %s disconnected from [%s]:%s, fd=%d, conn fd=%d\n",
					   ctx->dst.ssl ? "SSL" : "TCP",
					   STRORDASH(ctx->conn->srchost_str), STRORDASH(ctx->conn->srcport_str), ctx->fd, ctx->conn->fd);
	}
}

static void
pxy_bev_eventcb_child_connected_src(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child_connected_src: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	ctx->conn->thr->max_fd = MAX(ctx->conn->thr->max_fd, MAX(bufferevent_getfd(ctx->src.bev), bufferevent_getfd(ctx->dst.bev)));
}

static void
pxy_bev_eventcb_child_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child_connected_dst: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	ctx->connected = 1;

	// @attention Create and enable src.bev before, but connect here, because we check if dst.bev is NULL elsewhere
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);

	ctx->conn->thr->max_fd = MAX(ctx->conn->thr->max_fd, MAX(bufferevent_getfd(ctx->src.bev), bufferevent_getfd(ctx->dst.bev)));
}

static void
pxy_consume_last_input_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	/* if there is data pending in the closed connection,
	 * handle it here, otherwise it will be lost. */
	if (evbuffer_get_length(bufferevent_get_input(bev))) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_consume_last_input_child: evbuffer_get_length(inbuf) > 0, terminate conn, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
			ctx->proto_ctx->bev_readcb(bev, ctx);
		} else {
			pxy_bev_readcb_child(bev, ctx);
		}
	}
}

static void
pxy_bev_eventcb_child_eof_src(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child_eof_src: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
	pxy_log_dbg_evbuf_info(ctx->conn, &ctx->src, &ctx->dst);
#endif /* DEBUG_PROXY */

	// @todo How to handle the following case?
	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_child_eof_src: EOF on outbound connection before connection establishment, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child_eof_src: !other->closed, terminate conn, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		pxy_consume_last_input_child(bev, ctx);
		pxy_close_conn_end_ifnodata(&ctx->dst, ctx->conn, &bufferevent_free_and_close_fd);
	}
	pxy_log_dbg_disconnect_child(ctx);
	pxy_disconnect_child(ctx, &ctx->src, &bufferevent_free_and_close_fd_nonssl, &ctx->dst);
}

void
pxy_bev_eventcb_child_eof_dst(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child_eof_dst: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
	pxy_log_dbg_evbuf_info(ctx->conn, &ctx->dst, &ctx->src);
#endif /* DEBUG_PROXY */

	// @todo How to handle the following case?
	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_child_eof_dst: EOF on outbound connection before connection establishment, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child_eof_dst: !other->closed, terminate conn, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		pxy_consume_last_input_child(bev, ctx);
		pxy_close_conn_end_ifnodata(&ctx->src, ctx->conn, &bufferevent_free_and_close_fd_nonssl);
	}
	pxy_log_dbg_disconnect_child(ctx);
	pxy_disconnect_child(ctx, &ctx->dst, &bufferevent_free_and_close_fd, &ctx->src);
}

static void
pxy_bev_eventcb_child_error_src(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_child_error_src: BEV_EVENT_ERROR, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
	log_err_printf("Server-side BEV_EVENT_ERROR\n");
	pxy_log_err_ssl_error(bev, ctx->conn);
	ctx->conn->thr->errors++;

	if (!ctx->connected) {
		/* the callout to the original destination failed,
		 * e.g. because it asked for client cert auth, so
		 * close the accepted socket and clean up */
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		/* if the other end is still open and doesn't have data
		 * to send, close it, otherwise its writecb will close
		 * it after writing what's left in the output buffer */
		pxy_close_conn_end_ifnodata(&ctx->dst, ctx->conn, &bufferevent_free_and_close_fd);
	}
	pxy_log_dbg_disconnect_child(ctx);
	pxy_disconnect_child(ctx, &ctx->src, &bufferevent_free_and_close_fd_nonssl, &ctx->dst);
}

void
pxy_bev_eventcb_child_error_dst(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_bev_eventcb_child_error_dst: BEV_EVENT_ERROR, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
	log_err_printf("Server-side BEV_EVENT_ERROR\n");
	pxy_log_err_ssl_error(bev, ctx->conn);
	ctx->conn->thr->errors++;

	if (!ctx->connected) {
		/* the callout to the original destination failed,
		 * e.g. because it asked for client cert auth, so
		 * close the accepted socket and clean up */
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		/* if the other end is still open and doesn't have data
		 * to send, close it, otherwise its writecb will close
		 * it after writing what's left in the output buffer */
		pxy_close_conn_end_ifnodata(&ctx->src, ctx->conn, &bufferevent_free_and_close_fd_nonssl);
	}
	pxy_log_dbg_disconnect_child(ctx);
	pxy_disconnect_child(ctx, &ctx->dst, &bufferevent_free_and_close_fd, &ctx->src);
}

void
pxy_bev_eventcb_child_src(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_child_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_child_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_child_error_src(bev, ctx);
	}
}

static void
pxy_bev_eventcb_child_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_child_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_child_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_child_error_dst(bev, ctx);
	}
}

void
pxy_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
		ctx->proto_ctx->bev_eventcb(bev, events, arg);
		return;
	}

	enum bev_event event = get_event(events);
	if (event != EVENT_UNKWN) {
		enum conn_end ce = get_conn_end_child(bev, ctx);
		if (ce != CONN_END_UNKWN) {
			child_event_callback_func_t eventcb = child_eventcb_funcs[ctx->proto][event][ce];
			if (eventcb) {
				eventcb(bev, ctx);
			} else {
				log_err_printf("pxy_bev_eventcb_child: NULL eventcb on %d\n", ce);
			}
		} else {
			log_err_printf("pxy_bev_eventcb_child: UNKWN conn end\n");
		}
	} else {
		log_err_printf("pxy_bev_eventcb_child: UNKWN event\n");
	}
}

int
pxy_setup_dst(pxy_conn_ctx_t *ctx)
{
	ctx->dst.ssl= NULL;
	ctx->dst.bev = pxy_bufferevent_setup(ctx, -1, ctx->dst.ssl);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating parent dst\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx, 1);
		return -1;
	}
	return 0;
}

int
pxy_setup_srv_dst(pxy_conn_ctx_t *ctx)
{
	ctx->srv_dst.bev = pxy_bufferevent_setup(ctx, -1, ctx->srv_dst.ssl);
	if (!ctx->srv_dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating srv_dst\n");
		if (ctx->srv_dst.ssl) {
			SSL_free(ctx->srv_dst.ssl);
			ctx->srv_dst.ssl = NULL;
		}
		pxy_conn_free(ctx, 1);
		return -1;
	}
	return 0;
}

int
pxy_setup_srv_dst_ssl(pxy_conn_ctx_t *ctx)
{
	if (ctx->spec->ssl) {
		ctx->srv_dst.ssl = pxy_dstssl_create(ctx);
		if (!ctx->srv_dst.ssl) {
			log_err_level_printf(LOG_CRIT, "Error creating SSL for srv_dst\n");
			pxy_conn_free(ctx, 1);
			return -1;
		}
	}
	return 0;
}

static void
pxy_conn_connect_passthrough(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_connect_passthrough: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (pxy_setup_srv_dst(ctx) == -1) {
		return;
	}

	// @attention Sometimes dst write cb fires but not event cb, especially if this listener cb is not finished yet, so the conn stalls.
	bufferevent_setcb(ctx->srv_dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->srv_dst.bev, EV_READ|EV_WRITE);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srv_dst.bev, (struct sockaddr *)&ctx->addr, ctx->addrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "pxy_conn_connect_passthrough: bufferevent_socket_connect for srv_dst failed\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_conn_connect_passthrough: bufferevent_socket_connect for srv_dst failed, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	}
}

void
pxy_conn_connect_tcp(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_connect_tcp: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (pxy_setup_dst(ctx) == -1) {
		return;
	}

	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);

	/* create server-side socket and eventbuffer */
	if (pxy_setup_srv_dst_ssl(ctx) == -1) {
		return;
	}
	if (pxy_setup_srv_dst(ctx) == -1) {
		return;
	}

	// @attention Sometimes dst write cb fires but not event cb, especially if this listener cb is not finished yet, so the conn stalls.
	// @todo Why does event cb not fire sometimes?
	// @attention BEV_OPT_DEFER_CALLBACKS seems responsible for the issue with srv_dst, libevent acts as if we call event connect() ourselves.
	// @see Launching connections on socket-based bufferevents at http://www.wangafu.net/~nickm/libevent-book/Ref6_bufferevent.html
	// Disable and NULL r cb, we do nothing for srv_dst in r cb
	bufferevent_setcb(ctx->srv_dst.bev, NULL, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->srv_dst.bev, EV_WRITE);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srv_dst.bev, (struct sockaddr *)&ctx->addr, ctx->addrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "pxy_conn_connect_tcp: bufferevent_socket_connect for srv_dst failed\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_conn_connect_tcp: bufferevent_socket_connect for srv_dst failed, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		// @attention Do not try to close the conn here, otherwise both pxy_conn_connect() and eventcb try to free the conn using pxy_conn_free(),
		// they are running on different threads, causing multithreading issues, e.g. signal 10.
		// @todo Should we use thrmgr->mutex? Can we?
	}
}

/*
 * Complete the connection.  This gets called after finding out where to
 * connect to.
 */
static void
pxy_conn_connect(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_connect: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	if (!ctx->addrlen) {
		log_err_level_printf(LOG_CRIT, "No target address; aborting connection\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx, 1);
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

	if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
		ctx->proto_ctx->connectcb(ctx);
		return;
	}
	
	connect_func_t conn_connect_func = conn_connect_funcs[ctx->proto];
	if (conn_connect_func) {
		conn_connect_func(ctx);
	} else {
		log_err_printf("pxy_conn_connect: NULL conn_connect_func\n");
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
		log_err_printf("Cannot resolve SNI hostname '%s': %s\n", ctx->sni, evutil_gai_strerror(errcode));
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
void
pxy_fd_readcb_tcp(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_fd_readcb_tcp: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	pxy_conn_connect(ctx);
}

#ifndef OPENSSL_NO_TLSEXT
#define MAYBE_UNUSED 
#else /* OPENSSL_NO_TLSEXT */
#define MAYBE_UNUSED UNUSED
#endif /* OPENSSL_NO_TLSEXT */
void
pxy_fd_readcb_ssl(MAYBE_UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_fd_readcb_ssl: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

#ifndef OPENSSL_NO_TLSEXT
	// Child connections will use the sni info obtained by the parent conn
	/* for SSL, peek ClientHello and parse SNI from it */

	unsigned char buf[1024];
	ssize_t n;
	const unsigned char *chello;
	int rv;

	n = recv(fd, buf, sizeof(buf), MSG_PEEK);
	if (n == -1) {
		log_err_printf("Error peeking on fd, aborting connection\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "ERROR: Error peeking on fd, aborting connection, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		evutil_closesocket(fd);
		pxy_conn_ctx_free(ctx, 1);
		return;
	}
	if (n == 0) {
		/* socket got closed while we were waiting */
		log_err_printf("Socket got closed while waiting\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "ERROR: Socket got closed while waiting, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		evutil_closesocket(fd);
		pxy_conn_ctx_free(ctx, 1);
		return;
	}

	rv = ssl_tls_clienthello_parse(buf, n, 0, &chello, &ctx->sni);
	if ((rv == 1) && !chello) {
		log_err_printf("Peeking did not yield a (truncated) ClientHello message, aborting connection\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "ERROR: Peeking did not yield a (truncated) ClientHello message, aborting connection, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		evutil_closesocket(fd);
		pxy_conn_ctx_free(ctx, 1);
		return;
	}
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("SNI peek: [%s] [%s], fd=%d\n", ctx->sni ? ctx->sni : "n/a",
					   ((rv == 1) && chello) ? "incomplete" : "complete", ctx->fd);
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
		if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
			ctx->ev = event_new(ctx->evbase, fd, 0, ctx->proto_ctx->fd_readcb, ctx);
		} else {
			ctx->ev = event_new(ctx->evbase, fd, 0, pxy_fd_readcb, ctx);
		}
		if (!ctx->ev) {
			log_err_level_printf(LOG_CRIT, "Error creating retry event, aborting connection\n");
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "Error creating retry event, aborting connection, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx, 1);
			return;
		}
		event_add(ctx->ev, &retry_delay);
		return;
	}
	event_free(ctx->ev);
	ctx->ev = NULL;

	if (ctx->sni && !ctx->addrlen && ctx->spec->sni_port) {
		char sniport[6];
		struct evutil_addrinfo hints;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = ctx->af;
		hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		snprintf(sniport, sizeof(sniport), "%i", ctx->spec->sni_port);
		evdns_getaddrinfo(ctx->dnsbase, ctx->sni, sniport, &hints, pxy_sni_resolve_cb, ctx);
		return;
	}
#endif /* !OPENSSL_NO_TLSEXT */

	pxy_conn_connect(ctx);
}

static void
pxy_fd_readcb(evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_fd_readcb: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->atime = time(NULL);

	fd_readcb_func_t fd_readcb_func = fd_readcb_funcs[ctx->proto];
	if (fd_readcb_func) {
		fd_readcb_func(fd, what, arg);
	} else {
		log_err_printf("pxy_fd_readcb: NULL fd_readcb_func\n");
	}
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
	int dtable_count = getdtablecount();

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_setup: ENTER fd=%d\n", fd);

	char *host, *port;
	if (sys_sockaddr_str(peeraddr, peeraddrlen, &host, &port) == 0) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_setup: Peer=[%s]:%s, fd=%d\n", host, port, fd);
		free(host);
		free(port);
	}

	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_setup: descriptor_table_size=%d, current fd count=%d, reserve=%d\n", descriptor_table_size, dtable_count, FD_RESERVE);
#endif /* DEBUG_PROXY */

	// Close the conn if we are out of file descriptors, or libevent will crash us
	// @attention We cannot guess the number of children in a connection at conn setup time. So, FD_RESERVE is just a ball park figure.
	// But what if a connection passes the check below, but eventually tries to create more children than FD_RESERVE allows for? This will crash us the same.
	// Beware, this applies to all current conns, not just the last connection setup.
	// For example, 20x conns pass the check below before creating any children, at which point we reach at the last FD_RESERVE fds,
	// then they all start creating children, which crashes us again.
	// So, no matter how large an FD_RESERVE we choose, there will always be a risk of running out of fds, if we check the number of fds here only.
	// If we are left with less than FD_RESERVE fds, we should not create more children than FD_RESERVE allows for either.
	// Therefore, we check if we are out of fds in proxy_listener_acceptcb_child() and close the conn there too.
	// @attention These checks are expected to slow us further down, but it is critical to avoid a crash in case we run out of fds.
	if (dtable_count + FD_RESERVE >= descriptor_table_size) {
		errno = EMFILE;
		log_err_level_printf(LOG_CRIT, "Out of file descriptors\n");
		evutil_closesocket(fd);
		return;
	}

	/* create per connection state and attach to thread */
	pxy_conn_ctx_t *ctx = pxy_conn_ctx_new(fd, thrmgr, spec, opts, clisock);
	if (!ctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		return;
	}

	ctx->af = peeraddr->sa_family;
	ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->fd);

	/* determine original destination of connection */
	if (spec->natlookup) {
		/* NAT engine lookup */
		ctx->addrlen = sizeof(struct sockaddr_storage);
		if (spec->natlookup((struct sockaddr *)&ctx->addr, &ctx->addrlen, fd, peeraddr, peeraddrlen) == -1) {
			log_err_printf("Connection not found in NAT state table, aborting connection\n");
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
			log_err_printf("SNI mode used for non-SSL connection; aborting connection\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx, 1);
			return;
		}
	}

	if (sys_sockaddr_str(peeraddr, peeraddrlen, &ctx->srchost_str, &ctx->srcport_str) != 0) {
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
		if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
			ctx->ev = event_new(ctx->evbase, fd, EV_READ, ctx->proto_ctx->fd_readcb, ctx);
		} else {
			ctx->ev = event_new(ctx->evbase, fd, EV_READ, pxy_fd_readcb, ctx);
		}
		if (!ctx->ev)
			goto memout;
		event_add(ctx->ev, NULL);
	} else {
		if (ctx->proto == PROTO_HTTP || ctx->proto == PROTO_HTTPS || ctx->proto == PROTO_AUTOSSL) {
			ctx->proto_ctx->fd_readcb(fd, 0, ctx);
		} else {
			pxy_fd_readcb(fd, 0, ctx);
		}
	}
	return;

memout:
	log_err_level_printf(LOG_CRIT, "Aborting connection setup (out of memory)!\n");
	evutil_closesocket(fd);
	pxy_conn_ctx_free(ctx, 1);
}

void
pxy_bev_readcb_tcp(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_tcp: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (bev == ctx->src.bev) {
		pxy_bev_readcb_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_readcb_dst(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		pxy_bev_readcb_srv_dst(bev, arg);
	} else {
		log_err_printf("pxy_bev_readcb_tcp: UNKWN conn end\n");
	}
}

void
pxy_bev_writecb_tcp(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (bev == ctx->src.bev) {
		pxy_bev_writecb_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_writecb_dst(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		pxy_bev_writecb_srv_dst(bev, arg);
	} else {
		log_err_printf("pxy_bev_writecb: UNKWN conn end\n");
	}
}

void
pxy_bev_eventcb_tcp(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (bev == ctx->src.bev) {
		pxy_bev_eventcb_src(bev, events, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_eventcb_dst(bev, events, arg);
	} else if (bev == ctx->srv_dst.bev) {
		pxy_bev_eventcb_srv_dst(bev, events, arg);
	} else {
		log_err_printf("pxy_bev_eventcb: UNKWN conn end\n");
	}
}

void
pxy_bev_readcb_tcp_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "protohttp_bev_readcb_child: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (bev == ctx->src.bev) {
		pxy_bev_readcb_child_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_readcb_child_dst(bev, arg);
	} else {
		log_err_printf("protohttp_bev_readcb_child: UNKWN conn end\n");
	}
}

void
pxy_bev_writecb_tcp_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (bev == ctx->src.bev) {
		pxy_bev_writecb_child_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_writecb_child_dst(bev, arg);
	} else {
		log_err_printf("protohttp_bev_writecb_child: UNKWN conn end\n");
	}
}

void
pxy_bev_eventcb_tcp_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (bev == ctx->src.bev) {
		pxy_bev_eventcb_child_src(bev, events, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_eventcb_child_dst(bev, events, arg);
	} else {
		log_err_printf("protohttp_bev_eventcb_child: UNKWN conn end\n");
	}
}

callback_func_t readcb_funcs[][3] = {
	/* CONN_END_SRC, CONN_END_DST, CONN_END_SRV_DST */
	{pxy_bev_readcb_passthrough_src, NULL, pxy_bev_readcb_passthrough_srv_dst}, /* PROTO_PASSTHROUGH */
	{NULL, NULL, NULL}, /* PROTO_HTTP */
	{NULL, NULL, NULL}, /* PROTO_HTTPS */
	{pxy_bev_readcb_src, pxy_bev_readcb_dst, pxy_bev_readcb_srv_dst}, /* PROTO_POP3 */
	{pxy_bev_readcb_src, pxy_bev_readcb_dst, pxy_bev_readcb_srv_dst}, /* PROTO_POP3S */
	{pxy_bev_readcb_src, pxy_bev_readcb_dst, pxy_bev_readcb_srv_dst}, /* PROTO_SMTP */
	{pxy_bev_readcb_src, pxy_bev_readcb_dst, pxy_bev_readcb_srv_dst}, /* PROTO_SMTPS */
	{NULL, NULL, NULL}, /* PROTO_AUTOSSL */
	{pxy_bev_readcb_src, pxy_bev_readcb_dst, pxy_bev_readcb_srv_dst}, /* PROTO_TCP */
	{pxy_bev_readcb_src, pxy_bev_readcb_dst, pxy_bev_readcb_srv_dst}, /* PROTO_SSL */
};

callback_func_t child_readcb_funcs[][2] = {
	/* CONN_END_SRC, CONN_END_DST */
	{NULL, NULL}, /* XXX: Remove PROTO_PASSTHROUGH */
	{NULL, NULL}, /* PROTO_HTTP */
	{NULL, NULL}, /* PROTO_HTTPS */
	{pxy_bev_readcb_child_src, pxy_bev_readcb_child_dst}, /* PROTO_POP3 */
	{pxy_bev_readcb_child_src, pxy_bev_readcb_child_dst}, /* PROTO_POP3S */
	{pxy_bev_readcb_child_src, pxy_bev_readcb_child_dst}, /* PROTO_SMTP */
	{pxy_bev_readcb_child_src, pxy_bev_readcb_child_dst}, /* PROTO_SMTPS */
	{NULL, NULL}, /* PROTO_AUTOSSL */
	{pxy_bev_readcb_child_src, pxy_bev_readcb_child_dst}, /* PROTO_TCP */
	{pxy_bev_readcb_child_src, pxy_bev_readcb_child_dst}, /* PROTO_SSL */
};

callback_func_t writecb_funcs[][3] = {
	/* CONN_END_SRC, CONN_END_DST, CONN_END_SRV_DST */
	{pxy_bev_writecb_passthrough_src, NULL, pxy_bev_writecb_passthrough_srv_dst}, /* PROTO_PASSTHROUGH */
	{NULL, NULL, NULL}, /* PROTO_HTTP */
	{NULL, NULL, NULL}, /* PROTO_HTTPS */
	{pxy_bev_writecb_src, pxy_bev_writecb_dst, pxy_bev_writecb_srv_dst}, /* PROTO_POP3 */
	{pxy_bev_writecb_src, pxy_bev_writecb_dst, pxy_bev_writecb_srv_dst}, /* PROTO_POP3S */
	{pxy_bev_writecb_src, pxy_bev_writecb_dst, pxy_bev_writecb_srv_dst}, /* PROTO_SMTP */
	{pxy_bev_writecb_src, pxy_bev_writecb_dst, pxy_bev_writecb_srv_dst}, /* PROTO_SMTPS */
	{NULL, NULL, NULL}, /* PROTO_AUTOSSL */
	{pxy_bev_writecb_src, pxy_bev_writecb_dst, pxy_bev_writecb_srv_dst}, /* PROTO_TCP */
	{pxy_bev_writecb_src, pxy_bev_writecb_dst, pxy_bev_writecb_srv_dst}, /* PROTO_SSL */
};

callback_func_t child_writecb_funcs[][2] = {
	/* CONN_END_SRC, CONN_END_DST */
	{NULL, NULL}, /* PROTO_PASSTHROUGH */
	{NULL, NULL}, /* PROTO_HTTP */
	{NULL, NULL}, /* PROTO_HTTPS */
	{pxy_bev_writecb_child_src, pxy_bev_writecb_child_dst}, /* PROTO_POP3 */
	{pxy_bev_writecb_child_src, pxy_bev_writecb_child_dst}, /* PROTO_POP3S */
	{pxy_bev_writecb_child_src, pxy_bev_writecb_child_dst}, /* PROTO_SMTP */
	{pxy_bev_writecb_child_src, pxy_bev_writecb_child_dst}, /* PROTO_SMTPS */
	{NULL, NULL}, /* PROTO_AUTOSSL */
	{pxy_bev_writecb_child_src, pxy_bev_writecb_child_dst}, /* PROTO_TCP */
	{pxy_bev_writecb_child_src, pxy_bev_writecb_child_dst}, /* PROTO_SSL */
};

event_callback_func_t eventcb_funcs[][3][3] = {
	{ /* PROTO_PASSTHROUGH */
		/* CONN_END_SRC, CONN_END_DST, CONN_END_SRV_DST */
		{pxy_bev_eventcb_passthrough_connected_src, NULL, pxy_bev_eventcb_passthrough_connected_srv_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_passthrough_eof_src, NULL, pxy_bev_eventcb_passthrough_eof_srv_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_passthrough_error_src, NULL, pxy_bev_eventcb_passthrough_error_srv_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_HTTP */
		{NULL, NULL, NULL}, /* EVENT_CONNECTED */
		{NULL, NULL, NULL}, /* EVENT_EOF */
		{NULL, NULL, NULL} /* EVENT_ERROR */
	},
	{ /* PROTO_HTTPS */
		{NULL, NULL, NULL}, /* EVENT_CONNECTED */
		{NULL, NULL, NULL}, /* EVENT_EOF */
		{NULL, NULL, NULL} /* EVENT_ERROR */
	},
	{ /* PROTO_POP3 */
		{pxy_bev_eventcb_connected_src, pxy_bev_eventcb_connected_dst, pxy_bev_eventcb_connected_srv_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_eof_src, pxy_bev_eventcb_eof_dst, pxy_bev_eventcb_eof_srv_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_error_src, pxy_bev_eventcb_error_dst, pxy_bev_eventcb_error_srv_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_POP3S */
		{pxy_bev_eventcb_connected_src, pxy_bev_eventcb_connected_dst, pxy_bev_eventcb_connected_srv_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_eof_src, pxy_bev_eventcb_eof_dst, pxy_bev_eventcb_eof_srv_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_error_src, pxy_bev_eventcb_error_dst, pxy_bev_eventcb_error_srv_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_SMTP */
		{pxy_bev_eventcb_connected_src, pxy_bev_eventcb_connected_dst, pxy_bev_eventcb_connected_srv_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_eof_src, pxy_bev_eventcb_eof_dst, pxy_bev_eventcb_eof_srv_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_error_src, pxy_bev_eventcb_error_dst, pxy_bev_eventcb_error_srv_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_SMTPS */
		{pxy_bev_eventcb_connected_src, pxy_bev_eventcb_connected_dst, pxy_bev_eventcb_connected_srv_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_eof_src, pxy_bev_eventcb_eof_dst, pxy_bev_eventcb_eof_srv_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_error_src, pxy_bev_eventcb_error_dst, pxy_bev_eventcb_error_srv_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_AUTOSSL */
		{NULL, NULL, NULL}, /* EVENT_CONNECTED */
		{NULL, NULL, NULL}, /* EVENT_EOF */
		{NULL, NULL, NULL} /* EVENT_ERROR */
	},
	{ /* PROTO_TCP */
		{pxy_bev_eventcb_connected_src, pxy_bev_eventcb_connected_dst, pxy_bev_eventcb_connected_srv_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_eof_src, pxy_bev_eventcb_eof_dst, pxy_bev_eventcb_eof_srv_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_error_src, pxy_bev_eventcb_error_dst, pxy_bev_eventcb_error_srv_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_SSL */
		{pxy_bev_eventcb_connected_src, pxy_bev_eventcb_connected_dst, pxy_bev_eventcb_connected_srv_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_eof_src, pxy_bev_eventcb_eof_dst, pxy_bev_eventcb_eof_srv_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_error_src, pxy_bev_eventcb_error_dst, pxy_bev_eventcb_error_srv_dst} /* EVENT_ERROR */
	},
};

child_event_callback_func_t child_eventcb_funcs[][3][2] = {
	{ /* PROTO_PASSTHROUGH */
		/* CONN_END_SRC, CONN_END_DST */
		{NULL, NULL}, /* EVENT_CONNECTED */
		{NULL, NULL}, /* EVENT_EOF */
		{NULL, NULL} /* EVENT_ERROR */
	},
	{ /* PROTO_HTTP */
		{NULL, NULL}, /* EVENT_CONNECTED */
		{NULL, NULL}, /* EVENT_EOF */
		{NULL, NULL} /* EVENT_ERROR */
	},
	{ /* PROTO_HTTPS */
		{NULL, NULL}, /* EVENT_CONNECTED */
		{NULL, NULL}, /* EVENT_EOF */
		{NULL, NULL} /* EVENT_ERROR */
	},
	{ /* PROTO_POP3 */
		{pxy_bev_eventcb_child_connected_src, pxy_bev_eventcb_child_connected_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_child_eof_src, pxy_bev_eventcb_child_eof_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_child_error_src, pxy_bev_eventcb_child_error_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_POP3S */
		{pxy_bev_eventcb_child_connected_src, pxy_bev_eventcb_child_connected_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_child_eof_src, pxy_bev_eventcb_child_eof_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_child_error_src, pxy_bev_eventcb_child_error_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_SMTP */
		{pxy_bev_eventcb_child_connected_src, pxy_bev_eventcb_child_connected_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_child_eof_src, pxy_bev_eventcb_child_eof_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_child_error_src, pxy_bev_eventcb_child_error_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_SMTPS */
		{pxy_bev_eventcb_child_connected_src, pxy_bev_eventcb_child_connected_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_child_eof_src, pxy_bev_eventcb_child_eof_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_child_error_src, pxy_bev_eventcb_child_error_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_AUTOSSL */
		{NULL, NULL}, /* EVENT_CONNECTED */
		{NULL, NULL}, /* EVENT_EOF */
		{NULL, NULL} /* EVENT_ERROR */
	},
	{ /* PROTO_TCP */
		{pxy_bev_eventcb_child_connected_src, pxy_bev_eventcb_child_connected_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_child_eof_src, pxy_bev_eventcb_child_eof_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_child_error_src, pxy_bev_eventcb_child_error_dst} /* EVENT_ERROR */
	},
	{ /* PROTO_SSL */
		{pxy_bev_eventcb_child_connected_src, pxy_bev_eventcb_child_connected_dst}, /* EVENT_CONNECTED */
		{pxy_bev_eventcb_child_eof_src, pxy_bev_eventcb_child_eof_dst}, /* EVENT_EOF */
		{pxy_bev_eventcb_child_error_src, pxy_bev_eventcb_child_error_dst} /* EVENT_ERROR */
	},
};

connect_func_t conn_connect_funcs[] = {
	pxy_conn_connect_passthrough, /* PROTO_PASSTHROUGH */
	NULL, /* PROTO_HTTP */
	NULL, /* PROTO_HTTPS */
	pxy_conn_connect_tcp, /* PROTO_POP3 */
	pxy_conn_connect_tcp, /* PROTO_POP3S */
	pxy_conn_connect_tcp, /* PROTO_SMTP */
	pxy_conn_connect_tcp, /* PROTO_SMTPS */
	NULL, /* PROTO_AUTOSSL */
	pxy_conn_connect_tcp, /* PROTO_TCP */
	pxy_conn_connect_tcp, /* PROTO_SSL */
};

child_connect_func_t child_connect_funcs[] = {
	NULL, /* PROTO_PASSTHROUGH */
	NULL, /* PROTO_HTTP */
	NULL, /* PROTO_HTTPS */
	pxy_connect_tcp_child, /* PROTO_POP3 */
	pxy_connect_ssl_child, /* PROTO_POP3S */
	pxy_connect_tcp_child, /* PROTO_SMTP */
	pxy_connect_ssl_child, /* PROTO_SMTPS */
	NULL, /* PROTO_AUTOSSL */
	pxy_connect_tcp_child, /* PROTO_TCP */
	pxy_connect_ssl_child, /* PROTO_SSL */
};

fd_readcb_func_t fd_readcb_funcs[] = {
	pxy_fd_readcb_tcp, /* PROTO_PASSTHROUGH */
	NULL, /* PROTO_HTTP */
	NULL, /* PROTO_HTTPS */
	pxy_fd_readcb_tcp, /* PROTO_POP3 */
	pxy_fd_readcb_ssl, /* PROTO_POP3S */
	pxy_fd_readcb_tcp, /* PROTO_SMTP */
	pxy_fd_readcb_ssl, /* PROTO_SMTPS */
	NULL, /* PROTO_AUTOSSL */
	pxy_fd_readcb_tcp, /* PROTO_TCP */
	pxy_fd_readcb_ssl, /* PROTO_SSL */
};

/* vim: set noet ft=c: */
