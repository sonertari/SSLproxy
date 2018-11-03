/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2018, Soner Tari <sonertari@gmail.com>.
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

#include "prototcp.h"
#include "protossl.h"
#include "protohttp.h"
#include "protoautossl.h"
#include "protopassthrough.h"

#include "privsep.h"
#include "sys.h"
#include "log.h"
#include "attrib.h"
#include "proc.h"

#include <string.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <assert.h>

#include <event2/listener.h>

#ifdef HAVE_NETFILTER
#include <glob.h>
#endif /* HAVE_NETFILTER */

/*
 * Maximum size of data to buffer per connection direction before
 * temporarily stopping to read data from the other end.
 */
#define OUTBUF_LIMIT	(128*1024)

int descriptor_table_size = 0;

// @attention The order of names should match the order in protocol enum
char *protocol_names[] = {
	// ERROR = -1
	"PASSTHROUGH", // = 0
	"HTTP",
	"HTTPS",
	"POP3",
	"POP3S",
	"SMTP",
	"SMTPS",
	"AUTOSSL",
	"TCP",
	"SSL",
};

static protocol_t NONNULL(1)
pxy_setup_proto(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->protoctx) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx, 0, sizeof(proto_ctx_t));

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
			return (protossl_setup(ctx) != PROTO_ERROR) ? PROTO_POP3S : PROTO_ERROR;
		} else {
			return PROTO_POP3;
		}
	} else if (ctx->spec->smtp) {
		if (ctx->spec->ssl) {
			return (protossl_setup(ctx) != PROTO_ERROR) ? PROTO_SMTPS : PROTO_ERROR;
		} else {
			return PROTO_SMTP;
		}
	} else if (ctx->spec->ssl) {
		return protossl_setup(ctx);
	} else {
		return PROTO_TCP;
	}
}

static protocol_t NONNULL(1)
pxy_setup_proto_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->protoctx = malloc(sizeof(proto_child_ctx_t));
	if (!ctx->protoctx) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx, 0, sizeof(proto_child_ctx_t));

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
			return (protossl_setup_child(ctx) != PROTO_ERROR) ? PROTO_POP3S : PROTO_ERROR;
		} else {
			return PROTO_POP3;
		}
	} else if (ctx->conn->spec->smtp) {
		if (ctx->conn->spec->ssl) {
			return (protossl_setup_child(ctx) != PROTO_ERROR) ? PROTO_SMTPS : PROTO_ERROR;
		} else {
			return PROTO_SMTP;
		}
	} else if (ctx->conn->spec->ssl) {
		return protossl_setup_child(ctx);
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
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_new: ENTER, fd=%d\n", fd);
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

	ctx->protoctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->protoctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx);
		return NULL;
	}
	memset(ctx->protoctx, 0, sizeof(proto_ctx_t));

	ctx->proto = pxy_setup_proto(ctx);
	if (ctx->proto == PROTO_ERROR) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx->protoctx);
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
	return ctx;
}

static pxy_conn_child_ctx_t * MALLOC NONNULL(2)
pxy_conn_ctx_new_child(evutil_socket_t fd, pxy_conn_ctx_t *conn)
{
	assert(conn != NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_new_child: ENTER, child fd=%d, fd=%d\n", fd, conn->fd);
#endif /* DEBUG_PROXY */

	pxy_conn_child_ctx_t *ctx = malloc(sizeof(pxy_conn_child_ctx_t));
	if (!ctx) {
		return NULL;
	}
	memset(ctx, 0, sizeof(pxy_conn_child_ctx_t));

	ctx->type = CONN_TYPE_CHILD;
	ctx->fd = fd;
	ctx->conn = conn;

	ctx->protoctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->protoctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx);
		return NULL;
	}
	memset(ctx->protoctx, 0, sizeof(proto_ctx_t));

	ctx->proto = pxy_setup_proto_child(ctx);
	if (ctx->proto == PROTO_ERROR) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		free(ctx->protoctx);
		free(ctx);
		return NULL;
	}

	// @attention Child connections use the parent's event bases, otherwise we would get multithreading issues
	pxy_thrmgr_attach_child(conn);
	return ctx;
}

static void NONNULL(1)
pxy_conn_ctx_free_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_free_child: ENTER, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	pxy_thrmgr_detach_child(ctx->conn);

	// If the proto doesn't have special args, proto_free() callback is NULL
	if (ctx->protoctx->proto_free) {
		ctx->protoctx->proto_free(ctx);
	}
	free(ctx->protoctx);
	free(ctx);
}

static void NONNULL(1,2)
pxy_conn_remove_child(pxy_conn_child_ctx_t *child, pxy_conn_child_ctx_t **head)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_remove_child: ENTER, child fd=%d, fd=%d\n", child->fd, child->conn->fd);
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

static void
pxy_conn_free_child(pxy_conn_child_ctx_t *ctx)
{
	assert(ctx->conn != NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_free_child: ENTER, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	if (ctx->dst.bev) {
		ctx->dst.free(ctx->dst.bev, ctx->conn);
		ctx->dst.bev = NULL;
	}

	if (ctx->src.bev) {
		ctx->src.free(ctx->src.bev, ctx->conn);
		ctx->src.bev = NULL;
	}

	pxy_conn_remove_child(ctx, &ctx->conn->children);
	pxy_conn_ctx_free_child(ctx);
}

void
pxy_conn_term_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_term_child: ENTER, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	ctx->term = 1;
}

void
pxy_conn_free_children(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_free_children: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// @attention Free the child ctxs asap, we need their fds
	while (ctx->children) {
		pxy_conn_free_child(ctx->children);
	}

	// @attention Parent may be closing before there was any child at all nor was child_evcl ever created
	if (ctx->child_evcl) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_conn_free_children: Freeing child_evcl, child fd=%d, children->fd=%d, fd=%d\n",
				ctx->child_fd, ctx->children ? ctx->children->fd : -1, ctx->fd);
#endif /* DEBUG_PROXY */

		// @attention child_evcl was created with LEV_OPT_CLOSE_ON_FREE, so do not close ctx->child_fd
		evconnlistener_free(ctx->child_evcl);
		ctx->child_evcl = NULL;
	}
}

void
pxy_conn_ctx_free(pxy_conn_ctx_t *ctx, int by_requestor)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_ctx_free: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (WANT_CONTENT_LOG(ctx)) {
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
	if (ctx->ev) {
		event_free(ctx->ev);
	}
	if (ctx->sslproxy_header) {
		free(ctx->sslproxy_header);
	}
	// If the proto doesn't have special args, proto_free() callback is NULL
	if (ctx->protoctx->proto_free) {
		ctx->protoctx->proto_free(ctx);
	}
	free(ctx->protoctx);
	free(ctx);
}

void
pxy_conn_free(pxy_conn_ctx_t *ctx, int by_requestor)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_free: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->src.closed) {
		if (ctx->src.bev) {
			ctx->src.free(ctx->src.bev, ctx);
			ctx->src.bev = NULL;
		} else {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_conn_free: evutil_closesocket on NULL src->bev, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			// @todo src fd may be open, although src.bev is NULL, where do we close the src fd?
			evutil_closesocket(ctx->fd);
		}
	}

	if (ctx->srvdst.bev) {
		ctx->srvdst.free(ctx->srvdst.bev, ctx);
		ctx->srvdst.bev = NULL;
	}

	if (ctx->dst.bev) {
		ctx->dst.free(ctx->dst.bev, ctx);
		ctx->dst.bev = NULL;
	}

	pxy_conn_free_children(ctx);
	pxy_conn_ctx_free(ctx, by_requestor);
}

void
pxy_conn_term(pxy_conn_ctx_t *ctx, int by_requestor)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_term: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->term = 1;
	ctx->term_requestor = by_requestor;
}

void
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
		              ctx->proto == PROTO_PASSTHROUGH ? "passthrough" : (ctx->proto == PROTO_POP3 ? "pop3" : (ctx->proto == PROTO_SMTP ? "smtp" : "tcp")),
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
		              ctx->proto == PROTO_AUTOSSL ? "autossl" : (ctx->proto == PROTO_POP3S ? "pop3s" : (ctx->proto == PROTO_SMTPS ? "smtps" : "ssl")),
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str),
		              STRORDASH(ctx->sslctx->sni),
		              STRORDASH(ctx->sslctx->ssl_names),
		              SSL_get_version(ctx->src.ssl),
		              SSL_get_cipher(ctx->src.ssl),
		              !ctx->srvdst.closed && ctx->srvdst.ssl ? SSL_get_version(ctx->srvdst.ssl):ctx->sslctx->srvdst_ssl_version,
		              !ctx->srvdst.closed && ctx->srvdst.ssl ? SSL_get_cipher(ctx->srvdst.ssl):ctx->sslctx->srvdst_ssl_cipher,
		              STRORDASH(ctx->sslctx->origcrtfpr),
		              STRORDASH(ctx->sslctx->usedcrtfpr)
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

int
pxy_log_content_buf(pxy_conn_ctx_t *ctx, unsigned char *buf, size_t sz, int req)
{
	if (WANT_CONTENT_LOG(ctx->conn)) {
		if (buf) {
			logbuf_t *lb = logbuf_new_alloc(sz, NULL);
			if (!lb) {
				ctx->conn->enomem = 1;
				return -1;
			}
			memcpy(lb->buf, buf, lb->sz);
			if (log_content_submit(&ctx->conn->logctx, lb, req) == -1) {
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
			free(buf);
			return -1;
		}
		if (pxy_log_content_buf(ctx, buf, sz, req) == -1) {
			free(buf);
			return -1;
		}
	}
	return 0;
}

int
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
				pxy_conn_term(ctx, 1);
				return -1;
			}
		}
	}
#endif /* HAVE_LOCAL_PROCINFO */
	return 0;
}

int
pxy_prepare_logging(pxy_conn_ctx_t *ctx)
{
	/* prepare logging, part 2 */
	if (WANT_CONNECT_LOG(ctx) || WANT_CONTENT_LOG(ctx)) {
		if (pxy_prepare_logging_local_procinfo(ctx) == -1) {
			return -1;
		}
	}
	if (WANT_CONTENT_LOG(ctx)) {
		if (log_content_open(&ctx->logctx, ctx->opts,
							(struct sockaddr *)&ctx->srcaddr,
							ctx->srcaddrlen,
							(struct sockaddr *)&ctx->dstaddr,
							ctx->dstaddrlen,
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
			pxy_conn_term(ctx, 1);
			return -1;
		}
	}
	return 0;
}

static void NONNULL(1,2)
pxy_log_dbg_connect_type(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this)
{
	if (OPTS_DEBUG(ctx->opts)) {
		if (this->ssl) {
			char *keystr;
			/* for SSL, we get two connect events */
			log_dbg_printf("%s connected to [%s]:%s %s %s\n",
						   protocol_names[ctx->proto],
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
			log_dbg_printf("%s connected to [%s]:%s\n",
						   protocol_names[ctx->proto],
						   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str));
			log_dbg_printf("%s connected from [%s]:%s\n",
						   protocol_names[ctx->proto],
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
		protossl_srccert_write(ctx);
	}

	if (protossl_log_masterkey(ctx, &ctx->src) == -1) {
		return;
	}

	pxy_log_dbg_connect_type(ctx, &ctx->src);
}

void
pxy_log_connect_srvdst(pxy_conn_ctx_t *ctx)
{
	// @attention srvdst.bev may be NULL, if its writecb fires first
	if (ctx->srvdst.bev) {
		/* log connection if we don't analyze any headers */
		if (!ctx->srvdst.ssl && !ctx->spec->http && (WANT_CONNECT_LOG(ctx) || ctx->opts->statslog)) {
			pxy_log_connect_nonhttp(ctx);
		}

		if (protossl_log_masterkey(ctx, &ctx->srvdst) == -1) {
			return;
		}

		pxy_log_dbg_connect_type(ctx, &ctx->srvdst);
	}
}

void
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
pxy_log_dbg_disconnect(pxy_conn_ctx_t *ctx)
{
	/* we only get a single disconnect event here for both connections */
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%s disconnected to [%s]:%s, fd=%d\n",
					   protocol_names[ctx->proto],
					   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str), ctx->fd);
		log_dbg_printf("%s disconnected from [%s]:%s, fd=%d\n",
					   protocol_names[ctx->proto],
					   STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), ctx->fd);
	}
}

static void
pxy_log_dbg_disconnect_child(pxy_conn_child_ctx_t *ctx)
{
	/* we only get a single disconnect event here for both connections */
	if (OPTS_DEBUG(ctx->conn->opts)) {
		log_dbg_printf("Child %s disconnected to [%s]:%s, child fd=%d, fd=%d\n",
					   protocol_names[ctx->proto],
					   STRORDASH(ctx->conn->dsthost_str), STRORDASH(ctx->conn->dstport_str), ctx->fd, ctx->conn->fd);
		log_dbg_printf("Child %s disconnected from [%s]:%s, child fd=%d, fd=%d\n",
					   protocol_names[ctx->proto],
					   STRORDASH(ctx->conn->srchost_str), STRORDASH(ctx->conn->srcport_str), ctx->fd, ctx->conn->fd);
	}
}

#ifdef __APPLE__
#define getdtablecount() 0
#endif /* __APPLE__ */

#ifdef __linux__
/*
 * Copied from:
 * https://github.com/tmux/tmux/blob/master/compat/getdtablecount.c
 * 
 * Copyright (c) 2017 Nicholas Marriott <nicholas.marriott@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
int
getdtablecount()
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
#endif /* __linux__ */

unsigned char *
pxy_malloc_packet(size_t sz, pxy_conn_ctx_t *ctx)
{
	unsigned char *packet = malloc(sz);
	if (!packet) {
		ctx->enomem = 1;
		return NULL;
	}
	return packet;
}

#ifdef DEBUG_PROXY
char *bev_names[] = {
	"src",
	"dst",
	"srvdst",
	"NULL",
	"UNKWN"
};

static char *
pxy_get_event_name(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	// XXX: Used by watermark functions only, remove
	if (bev == ctx->src.bev) {
		return bev_names[0];
	} else if (bev == ctx->dst.bev) {
		return bev_names[1];
	} else if (bev == ctx->srvdst.bev) {
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

void
pxy_try_set_watermark(struct bufferevent *bev, pxy_conn_ctx_t *ctx, struct bufferevent *other)
{
	if (evbuffer_get_length(bufferevent_get_output(other)) >= OUTBUF_LIMIT) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_try_set_watermark: %s, fd=%d\n", pxy_get_event_name(bev, ctx), ctx->fd);
#endif /* DEBUG_PROXY */

		/* temporarily disable data source;
		 * set an appropriate watermark. */
		bufferevent_setwatermark(other, EV_WRITE, OUTBUF_LIMIT/2, OUTBUF_LIMIT);
		bufferevent_disable(bev, EV_READ);
		ctx->thr->set_watermarks++;
	}
}

void
pxy_try_unset_watermark(struct bufferevent *bev, pxy_conn_ctx_t *ctx, pxy_conn_desc_t *other)
{
	if (other->bev && !(bufferevent_get_enabled(other->bev) & EV_READ)) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_try_unset_watermark: %s, fd=%d\n", pxy_get_event_name(bev, ctx), ctx->fd);
#endif /* DEBUG_PROXY */

		/* data source temporarily disabled;
		 * re-enable and reset watermark to 0. */
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(other->bev, EV_READ);
		ctx->thr->unset_watermarks++;
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

void
pxy_insert_sslproxy_header(pxy_conn_ctx_t *ctx, unsigned char *packet, size_t *packet_size)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_insert_sslproxy_header: INSERT, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// @attention Cannot use string manipulation functions; we are dealing with binary arrays here, not NULL-terminated strings
	memmove(packet + ctx->sslproxy_header_len + 2, packet, *packet_size);
	memcpy(packet, ctx->sslproxy_header, ctx->sslproxy_header_len);
	memcpy(packet + ctx->sslproxy_header_len, "\r\n", 2);
	*packet_size+= ctx->sslproxy_header_len + 2;
	ctx->sent_sslproxy_header = 1;
}

void
pxy_try_remove_sslproxy_header(pxy_conn_child_ctx_t *ctx, unsigned char *packet, size_t *packet_size)
{
	// @attention Cannot use string manipulation functions; we are dealing with binary arrays here, not NULL-terminated strings
	unsigned char *pos = memmem(packet, *packet_size, ctx->conn->sslproxy_header, ctx->conn->sslproxy_header_len);
	if (pos) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_try_remove_sslproxy_header: REMOVE, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

		memmove(pos, pos + ctx->conn->sslproxy_header_len + 2, *packet_size - (pos - packet) - (ctx->conn->sslproxy_header_len + 2));
		*packet_size-= ctx->conn->sslproxy_header_len + 2;
		ctx->removed_sslproxy_header = 1;
	}
}

/*
 * Callback for accept events on the socket listener bufferevent.
 */
static void
pxy_listener_acceptcb_child(UNUSED struct evconnlistener *listener, evutil_socket_t fd,
                        UNUSED struct sockaddr *peeraddr, UNUSED int peeraddrlen, void *arg)
{
	pxy_conn_ctx_t *conn = arg;

	conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_listener_acceptcb_child: ENTER, child fd=%d, conn->child_fd=%d, fd=%d\n", fd, conn->child_fd, conn->fd);

	char *host, *port;
	if (sys_sockaddr_str(peeraddr, peeraddrlen, &host, &port) == 0) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_listener_acceptcb_child: peer addr=[%s]:%s, child fd=%d, fd=%d\n", host, port, fd, conn->fd);
		free(host);
		free(port);
	}
#endif /* DEBUG_PROXY */

	if (!conn->dstaddrlen) {
		log_err_level_printf(LOG_CRIT, "Child no target address; aborting connection\n");
		evutil_closesocket(fd);
		pxy_conn_term(conn, 1);
		goto out;
	}

	int dtable_count = getdtablecount();

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_listener_acceptcb_child: descriptor_table_size=%d, current fd count=%d, reserve=%d, fd=%d\n",
			descriptor_table_size, dtable_count, FD_RESERVE, fd);
#endif /* DEBUG_PROXY */

	// Close the conn if we are out of file descriptors, or libevent will crash us, @see pxy_conn_setup() for explanation
	if (dtable_count + FD_RESERVE >= descriptor_table_size) {
		errno = EMFILE;
		log_err_level_printf(LOG_CRIT, "Out of file descriptors\n");
		evutil_closesocket(fd);
		pxy_conn_term(conn, 1);
		goto out;
	}

	pxy_conn_child_ctx_t *ctx = pxy_conn_ctx_new_child(fd, conn);
	if (!ctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		pxy_conn_term(conn, 1);
		goto out;
	}

	// Prepend child ctx to conn ctx child list
	// @attention If the last child is deleted, the children list may become null again
	ctx->next = conn->children;
	conn->children = ctx;

	conn->child_count++;
	ctx->idx = conn->child_count;

	// @attention Do not enable src events here yet, they will be enabled after dst connects
	if (prototcp_setup_src_child(ctx) == -1) {
		goto out;
	}

	// src_fd is different from fd
	ctx->src_fd = bufferevent_getfd(ctx->src.bev);
	ctx->conn->child_src_fd = ctx->src_fd;
	ctx->conn->thr->max_fd = MAX(ctx->conn->thr->max_fd, ctx->src_fd);
	
	/* create server-side socket and eventbuffer */
	// Children rely on the findings of parent
	ctx->protoctx->connectcb(ctx);

	if (ctx->conn->term || ctx->conn->enomem) {
		goto out;
	}

	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);

	if (OPTS_DEBUG(ctx->conn->opts)) {
		char *host, *port;
		if (sys_sockaddr_str((struct sockaddr *)&ctx->conn->dstaddr, ctx->conn->dstaddrlen, &host, &port) == 0) {
			log_dbg_printf("Child connecting to [%s]:%s\n", host, port);
			free(host);
			free(port);
		} else {
			log_dbg_printf("Child connecting to [?]:?\n");
		}
	}

	/* initiate connection */
	// @attention No need to check retval here, the eventcb should handle the errors
	bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->conn->dstaddr, ctx->conn->dstaddrlen);
	
	ctx->dst_fd = bufferevent_getfd(ctx->dst.bev);
	ctx->conn->child_dst_fd = ctx->dst_fd;
	ctx->conn->thr->max_fd = MAX(ctx->conn->thr->max_fd, ctx->dst_fd);

out:
	// @attention Do not use ctx->conn here, ctx may be uninitialized
	// @attention Call pxy_conn_free() directly, not term functions here
	// This is our last chance to close and free the conn
	if (conn->term || conn->enomem) {
		pxy_conn_free(conn, conn->term ? conn->term_requestor : 1);
	}
}

int
pxy_setup_child_listener(pxy_conn_ctx_t *ctx)
{
	// @attention Defer child setup and evcl creation until after parent init is complete, otherwise (1) causes multithreading issues (proxy_listener_acceptcb is
	// running on a different thread from the conn, and we only have thrmgr mutex), and (2) we need to clean up less upon errors.
	// Child evcls use the evbase of the parent thread, otherwise we would get multithreading issues.
	if ((ctx->child_fd = privsep_client_opensock_child(ctx->clisock, ctx->spec)) == -1) {
		log_err_level_printf(LOG_CRIT, "Error opening child socket: %s (%i)\n", strerror(errno), errno);
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->child_fd);

	// @attention Do not pass NULL as user-supplied pointer
	struct evconnlistener *child_evcl = evconnlistener_new(ctx->thr->evbase, pxy_listener_acceptcb_child, ctx, LEV_OPT_CLOSE_ON_FREE, 1024, ctx->child_fd);
	if (!child_evcl) {
		log_err_level_printf(LOG_CRIT, "Error creating child evconnlistener: %s\n", strerror(errno));
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_setup_child_listener: Error creating child evconnlistener: %s, fd=%d, child_fd=%d\n", strerror(errno), ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */

		// @attention Cannot call proxy_listener_ctx_free() on child_evcl, child_evcl does not have any ctx with next listener
		// @attention Close child fd separately, because child evcl does not exist yet, hence fd would not be closed by calling pxy_conn_free()
		evutil_closesocket(ctx->child_fd);
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->child_evcl = child_evcl;

	evconnlistener_set_error_cb(child_evcl, proxy_listener_errorcb);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_setup_child_listener: Finished setting up child, NEW child_fd=%d, fd=%d\n", ctx->child_fd, ctx->fd);	
#endif /* DEBUG_PROXY */

	struct sockaddr_in child_listener_addr;
	socklen_t child_listener_len = sizeof(child_listener_addr);

	if (getsockname(ctx->child_fd, (struct sockaddr *)&child_listener_addr, &child_listener_len) < 0) {
		log_err_level_printf(LOG_CRIT, "Error in getsockname: %s\n", strerror(errno));
		// @todo If getsockname() fails, should we really terminate the connection?
		// @attention Do not close the child fd here, because child evcl exists now, hence pxy_conn_free() will close it while freeing child_evcl
		pxy_conn_term(ctx, 1);
		return -1;
	}

	// @attention Children are always listening on an IPv4 loopback address
	char addr[INET_ADDRSTRLEN];
	if (!inet_ntop(AF_INET, &child_listener_addr.sin_addr, addr, INET_ADDRSTRLEN)) {
		pxy_conn_term(ctx, 1);
		return -1;
	}

	if (pxy_set_dstaddr(ctx) == -1) {
		return -1;
	}

	// SSLproxy: [127.0.0.1]:34649,[192.168.3.24]:47286,[74.125.206.108]:465,s
	// @todo Port may be less than 5 chars
	// SSLproxy:        +   + [ + addr         + ] + : + p + , + [ + srchost_str              + ] + : + srcport_str              + , + [ + dsthost_str              + ] + : + dstport_str              + , + s
	// SSLPROXY_KEY_LEN + 1 + 1 + strlen(addr) + 1 + 1 + 5 + 1 + 1 + strlen(ctx->srchost_str) + 1 + 1 + strlen(ctx->srcport_str) + 1 + 1 + strlen(ctx->dsthost_str) + 1 + 1 + strlen(ctx->dstport_str) + 1 + 1
	ctx->sslproxy_header_len = SSLPROXY_KEY_LEN + strlen(addr) + strlen(ctx->srchost_str) + strlen(ctx->srcport_str) + strlen(ctx->dsthost_str) + strlen(ctx->dstport_str) + 19;

	// @todo Always check malloc retvals. Should we close the conn if malloc fails?
	// +1 for NULL
	ctx->sslproxy_header = malloc(ctx->sslproxy_header_len + 1);
	if (!ctx->sslproxy_header) {
		pxy_conn_term(ctx, 1);
		return -1;
	}

	// printf(3): "snprintf() will write at most size-1 of the characters (the size'th character then gets the terminating NULL)"
	// So, +1 for NULL
	snprintf(ctx->sslproxy_header, ctx->sslproxy_header_len + 1, "%s [%s]:%u,[%s]:%s,[%s]:%s,%s",
			SSLPROXY_KEY, addr, ntohs(child_listener_addr.sin_port), STRORNONE(ctx->srchost_str), STRORNONE(ctx->srcport_str),
			STRORNONE(ctx->dsthost_str), STRORNONE(ctx->dstport_str), ctx->spec->ssl ? "s":"p");
	return 0;
}

int
pxy_try_close_conn_end(pxy_conn_desc_t *conn_end, pxy_conn_ctx_t *ctx)
{
	/* if the other end is still open and doesn't have data
	 * to send, close it, otherwise its writecb will close
	 * it after writing what's left in the output buffer */
	if (evbuffer_get_length(bufferevent_get_output(conn_end->bev)) == 0) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_try_close_conn_end: evbuffer_get_length(outbuf) == 0, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		conn_end->free(conn_end->bev, ctx);
		conn_end->bev = NULL;
		conn_end->closed = 1;
		return 1;
	}
	return 0;
}

int
pxy_connect_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_connect_srvdst: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
	// This is a workaround for this error condition, nothing else seems to work.
	// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
	// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
	ctx->protoctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);

	return pxy_bev_eventcb_postexec_logging_and_stats(bev, BEV_EVENT_CONNECTED, ctx);
}

void
pxy_try_disconnect(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this, pxy_conn_desc_t *other, int is_requestor)
{
	// @attention srvdst should never reach here unless in passthrough mode, its bev may be NULL
	this->closed = 1;
	this->free(this->bev, ctx);
	this->bev = NULL;
	if (other->closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_try_disconnect: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		// Uses only ctx to log disconnect, never any of the bevs
		pxy_log_dbg_disconnect(ctx);
		pxy_conn_term(ctx, is_requestor);
	}
}

void
pxy_try_disconnect_child(pxy_conn_child_ctx_t *ctx, pxy_conn_desc_t *this, pxy_conn_desc_t *other)
{
	this->closed = 1;
	this->free(this->bev, ctx->conn);
	this->bev = NULL;
	if (other->closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_try_disconnect_child: other->closed, terminate conn, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

		// Uses only ctx to log disconnect, never any of the bevs
		pxy_log_dbg_disconnect_child(ctx);
		pxy_conn_term_child(ctx);
	}
}

int
pxy_try_consume_last_input(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	/* if there is data pending in the closed connection,
	 * handle it here, otherwise it will be lost. */
	if (evbuffer_get_length(bufferevent_get_input(bev))) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_try_consume_last_input: evbuffer_get_length(inbuf) > 0, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		if (pxy_bev_readcb_preexec_logging_and_stats(bev, ctx) == -1) {
			return -1;
		}
		ctx->protoctx->bev_readcb(bev, ctx);
	}
	return 0;
}

int
pxy_try_consume_last_input_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	/* if there is data pending in the closed connection,
	 * handle it here, otherwise it will be lost. */
	if (evbuffer_get_length(bufferevent_get_input(bev))) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_try_consume_last_input_child: evbuffer_get_length(inbuf) > 0, terminate conn, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

		if (pxy_bev_readcb_preexec_logging_and_stats_child(bev, ctx) == -1) {
			return -1;
		}
		ctx->protoctx->bev_readcb(bev, ctx);
	}
	return 0;
}

int
pxy_set_dstaddr(pxy_conn_ctx_t *ctx)
{
	if (sys_sockaddr_str((struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen, &ctx->dsthost_str, &ctx->dstport_str) != 0) {
		// sys_sockaddr_str() may fail due to either malloc() or getnameinfo()
		ctx->enomem = 1;
		pxy_conn_term(ctx, 1);
		return -1;
	}
	return 0;
}

int
pxy_bev_readcb_preexec_logging_and_stats(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (bev == ctx->src.bev || bev == ctx->dst.bev) {
		struct evbuffer *inbuf = bufferevent_get_input(bev);
		size_t inbuf_size = evbuffer_get_length(inbuf);

		if (bev == ctx->src.bev) {
			ctx->thr->intif_in_bytes += inbuf_size;
		} else {
			ctx->thr->intif_out_bytes += inbuf_size;
		}

		if (ctx->proto != PROTO_PASSTHROUGH) {
			// HTTP content logging at this point may record certain header lines twice, if we have not seen all headers yet
			return pxy_log_content_inbuf(ctx, inbuf, (bev == ctx->src.bev));
		}
	}
	return 0;
}

/*
 * Callback for read events on the up- and downstream connection bufferevents.
 * Called when there is data ready in the input evbuffer.
 */
void
pxy_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (pxy_bev_readcb_preexec_logging_and_stats(bev, ctx) == -1) {
		goto memout;
	}

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	ctx->atime = time(NULL);
	ctx->protoctx->bev_readcb(bev, ctx);

memout:
	if (ctx->term || ctx->enomem) {
		pxy_conn_free(ctx, ctx->term ? ctx->term_requestor : (bev == ctx->src.bev));
	}
}

int
pxy_bev_readcb_preexec_logging_and_stats_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	size_t inbuf_size = evbuffer_get_length(inbuf);

	if (bev == ctx->src.bev) {
		ctx->conn->thr->extif_out_bytes += inbuf_size;
	} else {
		ctx->conn->thr->extif_in_bytes += inbuf_size;
	}

	if (ctx->proto != PROTO_PASSTHROUGH) {
		return pxy_log_content_inbuf((pxy_conn_ctx_t *)ctx, inbuf, (bev == ctx->src.bev));
	}
	return 0;
}

void
pxy_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (pxy_bev_readcb_preexec_logging_and_stats_child(bev, ctx) == -1) {
		goto memout;
	}

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	ctx->conn->atime = time(NULL);
	ctx->protoctx->bev_readcb(bev, ctx);

memout:
	if (ctx->conn->term || ctx->conn->enomem) {
		pxy_conn_free(ctx->conn, ctx->conn->term ? ctx->conn->term_requestor : (bev == ctx->src.bev));
		return;
	}

	if (ctx->term) {
		pxy_conn_free_child(ctx);
	}
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
	ctx->protoctx->bev_writecb(bev, ctx);

	if (ctx->term || ctx->enomem) {
		pxy_conn_free(ctx, ctx->term ? ctx->term_requestor : (bev == ctx->src.bev));
	}
}

void
pxy_bev_writecb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	ctx->conn->atime = time(NULL);
	ctx->protoctx->bev_writecb(bev, ctx);

	if (ctx->conn->term || ctx->conn->enomem) {
		pxy_conn_free(ctx->conn, ctx->conn->term ? ctx->conn->term_requestor : (bev == ctx->src.bev));
		return;
	}

	if (ctx->term) {
		pxy_conn_free_child(ctx);
	}
}

int
pxy_bev_eventcb_postexec_logging_and_stats(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (ctx->term || ctx->enomem) {
		return -1;
	}

	if (events & BEV_EVENT_CONNECTED) {
		// Passthrough proto does its own connect logging
		if (ctx->proto != PROTO_PASSTHROUGH) {
			if (bev == ctx->src.bev) {
				// @todo When do we reach here? If proto is autossl? Otherwise, src is connected in acceptcb.
				pxy_log_connect_src(ctx);
			} else if (ctx->connected) {
				if (pxy_prepare_logging(ctx) == -1) {
					return -1;
				}
				// Doesn't log connect if proto is http, http proto does its own connect logging
				pxy_log_connect_srvdst(ctx);
			}
		}

		if (bev == ctx->srvdst.bev) {
			// src and other fd stats are collected in acceptcb functions
			ctx->srvdst_fd = bufferevent_getfd(ctx->srvdst.bev);
			ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->srvdst_fd);

			// Passthrough proto may have a NULL dst.bev
			if (ctx->dst.bev) {
				ctx->dst_fd = bufferevent_getfd(ctx->dst.bev);
				ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->dst_fd);
			}
		}
	}
	return 0;
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

	if (events & BEV_EVENT_ERROR) {
		log_err_printf("Client-side BEV_EVENT_ERROR\n");
		ctx->thr->errors++;
	}

	ctx->protoctx->bev_eventcb(bev, events, arg);

	pxy_bev_eventcb_postexec_logging_and_stats(bev, events, ctx);

	// Logging functions may set term or enomem too
	// EOF eventcb may call readcb possibly causing enomem
	if (ctx->term || ctx->enomem) {
		pxy_conn_free(ctx, ctx->term ? ctx->term_requestor : (bev == ctx->src.bev));
	}
}

void
pxy_bev_eventcb_postexec_stats_child(short events, pxy_conn_child_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		ctx->conn->thr->max_fd = MAX(ctx->conn->thr->max_fd, MAX(bufferevent_getfd(ctx->src.bev), bufferevent_getfd(ctx->dst.bev)));
	}
}

void
pxy_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	ctx->conn->atime = time(NULL);

	if (events & BEV_EVENT_ERROR) {
		log_err_printf("Server-side BEV_EVENT_ERROR\n");
		ctx->conn->thr->errors++;
	}

	ctx->protoctx->bev_eventcb(bev, events, arg);

	// EOF eventcb may call readcb possibly causing enomem
	if (ctx->conn->term || ctx->conn->enomem) {
		pxy_conn_free(ctx->conn, ctx->conn->term ? ctx->conn->term_requestor : (bev == ctx->src.bev));
		return;
	}

	if (ctx->term) {
		pxy_conn_free_child(ctx);
		return;
	}

	pxy_bev_eventcb_postexec_stats_child(events, ctx);
}

/*
 * Complete the connection.  This gets called after finding out where to
 * connect to.
 */
void
pxy_conn_connect(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_connect: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->dstaddrlen) {
		log_err_level_printf(LOG_CRIT, "No target address; aborting connection\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx, 1);
		return;
	}

	if (OPTS_DEBUG(ctx->opts)) {
		char *host, *port;
		if (sys_sockaddr_str((struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen, &host, &port) == 0) {
			log_dbg_printf("Connecting to [%s]:%s\n", host, port);
			free(host);
			free(port);
		} else {
			log_dbg_printf("Connecting to [?]:?\n");
		}
	}

	ctx->protoctx->connectcb(ctx);

	if (ctx->term || ctx->enomem) {
		pxy_conn_free(ctx, ctx->term ? ctx->term_requestor : 1);
	}
	// @attention Do not do anything else with the ctx after connecting socket, otherwise if pxy_bev_eventcb fires on error, such as due to "No route to host",
	// the conn is closed and freed up, and we get multithreading issues, e.g. signal 11. We are on the thrmgr thread. So, just return.
}

/*
 * The src fd is readable.  This is used to sneak-preview the SNI on SSL
 * connections.  If ctx->ev is NULL, it was called manually for a non-SSL
 * connection.  If ctx->passthrough is set, it was called a second time
 * after the first ssl callout failed because of client cert auth.
 */
void
pxy_fd_readcb(evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_fd_readcb: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->atime = time(NULL);
	ctx->protoctx->fd_readcb(fd, what, arg);
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
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_setup: ENTER, fd=%d\n", fd);

	char *host, *port;
	if (sys_sockaddr_str(peeraddr, peeraddrlen, &host, &port) == 0) {
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_setup: peer addr=[%s]:%s, fd=%d\n", host, port, fd);
		free(host);
		free(port);
	}

	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_conn_setup: descriptor_table_size=%d, current fd count=%d, reserve=%d\n",
			descriptor_table_size, dtable_count, FD_RESERVE);
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
		ctx->dstaddrlen = sizeof(struct sockaddr_storage);
		if (spec->natlookup((struct sockaddr *)&ctx->dstaddr, &ctx->dstaddrlen, fd, peeraddr, peeraddrlen) == -1) {
			log_err_printf("Connection not found in NAT state table, aborting connection\n");
			evutil_closesocket(fd);
			pxy_conn_ctx_free(ctx, 1);
			return;
		}
	} else if (spec->connect_addrlen > 0) {
		/* static forwarding */
		ctx->dstaddrlen = spec->connect_addrlen;
		memcpy(&ctx->dstaddr, &spec->connect_addr, ctx->dstaddrlen);
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
	if (opts->pcaplog
#ifndef WITHOUT_MIRROR
	    || opts->mirrorif
#endif /* !WITHOUT_MIRROR */
#ifdef HAVE_LOCAL_PROCINFO
	    || opts->lprocinfo
#endif /* HAVE_LOCAL_PROCINFO */
	    ) {
		ctx->srcaddrlen = peeraddrlen;
		memcpy(&ctx->srcaddr, peeraddr, ctx->srcaddrlen);
	}

	/* for SSL, defer dst connection setup to initial_readcb */
	if (ctx->spec->ssl) {
		ctx->ev = event_new(ctx->evbase, fd, EV_READ, ctx->protoctx->fd_readcb, ctx);
		if (!ctx->ev)
			goto memout;
		event_add(ctx->ev, NULL);
	} else {
		ctx->protoctx->fd_readcb(fd, 0, ctx);
	}
	return;

memout:
	log_err_level_printf(LOG_CRIT, "Aborting connection setup (out of memory)!\n");
	evutil_closesocket(fd);
	pxy_conn_ctx_free(ctx, 1);
}

/* vim: set noet ft=c: */
