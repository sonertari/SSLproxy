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

#include "protopassthrough.h"
#include "prototcp.h"

#include <sys/param.h>

static int NONNULL(1)
protopassthrough_prepare_logging(pxy_conn_ctx_t *ctx)
{
	/* prepare logging, part 2 */
	if (WANT_CONNECT_LOG(ctx)) {
		return pxy_prepare_logging_local_procinfo(ctx);
	}
	return 0;
}

static void NONNULL(1)
protopassthrough_log_dbg_connect_type(pxy_conn_ctx_t *ctx)
{
	if (OPTS_DEBUG(ctx->opts)) {
		/* for TCP, we get only a dst connect event,
		 * since src was already connected from the
		 * beginning */
		log_dbg_printf("PASSTHROUGH connected to [%s]:%s\n",
					   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str));
		log_dbg_printf("PASSTHROUGH connected from [%s]:%s\n",
					   STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str));
	}
}

static void NONNULL(1)
protopassthrough_log_connect_src(pxy_conn_ctx_t *ctx)
{
	if (WANT_CONNECT_LOG(ctx) || ctx->opts->statslog) {
		pxy_log_connect_nonhttp(ctx);
	}
	protopassthrough_log_dbg_connect_type(ctx);
}

void
protopassthrough_engage(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINE, "protopassthrough_engage: fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// @attention Do not call bufferevent_free_and_close_fd(), otherwise connection stalls due to ssl shutdown
	// We get srvdst writecb while ssl shutdown is still in progress, and srvdst readcb never fires
	//bufferevent_free_and_close_fd(ctx->srvdst.bev, ctx);
	SSL_free(ctx->srvdst.ssl);
	prototcp_bufferevent_free_and_close_fd(ctx->srvdst.bev, ctx);
	ctx->srvdst.bev = NULL;
	ctx->srvdst.ssl = NULL;
	ctx->connected = 0;
	ctx->srvdst_connected = 0;

	// Close and free dst if open
	if (!ctx->dst.closed) {
		ctx->dst.closed = 1;
		prototcp_bufferevent_free_and_close_fd(ctx->dst.bev, ctx);
		ctx->dst.bev = NULL;
		ctx->dst_fd = 0;
	}

	// Free any children of the previous proto
	pxy_conn_free_children(ctx);

	// Free any/all data of the previous proto
	if (ctx->protoctx->proto_free) {
		ctx->protoctx->proto_free(ctx);
	}
	// Disable proto_free callback of the previous proto, or it is called while passthrough is closing too
	ctx->protoctx->proto_free = NULL;

	ctx->proto = protopassthrough_setup(ctx);
	pxy_fd_readcb(ctx->fd, 0, ctx);
}

static void NONNULL(1)
protopassthrough_conn_connect(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_conn_connect: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (prototcp_setup_srvdst(ctx) == -1) {
		return;
	}

	// @attention Sometimes dst write cb fires but not event cb, especially if this listener cb is not finished yet, so the conn stalls.
	bufferevent_setcb(ctx->srvdst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->srvdst.bev, EV_READ|EV_WRITE);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srvdst.bev, (struct sockaddr *)&ctx->addr, ctx->addrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "protopassthrough_conn_connect: bufferevent_socket_connect for srvdst failed\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "protopassthrough_conn_connect: bufferevent_socket_connect for srvdst failed, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	}
}

static void NONNULL(1)
protopassthrough_bev_readcb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_readcb_src: ENTER, size=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd);
#endif /* DEBUG_PROXY */

	// Passthrough packets are transfered between src and srvdst
	if (ctx->srvdst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	evbuffer_add_buffer(bufferevent_get_output(ctx->srvdst.bev), bufferevent_get_input(bev));
	pxy_try_set_watermark(bev, ctx, ctx->srvdst.bev);
}

static void NONNULL(1)
protopassthrough_bev_readcb_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_readcb_srvdst: ENTER, size=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd);
#endif /* DEBUG_PROXY */

	// Passthrough packets are transfered between src and srvdst
	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	evbuffer_add_buffer(bufferevent_get_output(ctx->src.bev), bufferevent_get_input(bev));
	pxy_try_set_watermark(bev, ctx, ctx->src.bev);
}

static void NONNULL(1)
protopassthrough_bev_writecb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_writecb_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// @attention srvdst.bev may be NULL
	if (ctx->srvdst.closed) {
		if (pxy_try_close_conn_end(&ctx->src, ctx, &prototcp_bufferevent_free_and_close_fd)) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_writecb_src: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_term(ctx, 1);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx, &ctx->srvdst);
}

static void NONNULL(1)
protopassthrough_bev_writecb_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_writecb_srvdst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->srvdst_connected) {
		pxy_connect_srvdst(bev, ctx);
	}

	if (ctx->src.closed) {
		if (pxy_try_close_conn_end(&ctx->srvdst, ctx, &prototcp_bufferevent_free_and_close_fd) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_writecb_srvdst: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_term(ctx, 0);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx, &ctx->src);
}

static void NONNULL(1,2)
protopassthrough_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
}

static int NONNULL(1)
protopassthrough_enable_src(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_enable_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (prototcp_setup_src(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protopassthrough_enable_src: Enabling src, child_fd=%d, fd=%d\n", ctx->child_fd, ctx->fd);
#endif /* DEBUG_PROXY */

	// Now open the gates
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void NONNULL(1,2)
protopassthrough_bev_eventcb_connected_srvdst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_connected_srvdst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->srvdst_connected) {
		ctx->srvdst_connected = 1;
	}

	if (ctx->srvdst_connected && !ctx->connected) {
		ctx->connected = 1;

		if (protopassthrough_enable_src(ctx) == -1) {
			return;
		}
	}
}

static void NONNULL(1,2)
protopassthrough_bev_eventcb_eof_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_eof_src: ENTER, fd=%d\n", ctx->fd);
	pxy_log_dbg_evbuf_info(ctx, &ctx->src, &ctx->srvdst);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "protopassthrough_bev_eventcb_eof_src: EOF on outbound connection before connection establishment, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		ctx->srvdst.closed = 1;
	} else if (!ctx->srvdst.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_eof_src: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		pxy_try_consume_last_input(bev, ctx);
		pxy_try_close_conn_end(&ctx->srvdst, ctx, &prototcp_bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect(ctx, &ctx->src, &prototcp_bufferevent_free_and_close_fd, &ctx->srvdst, 1);
}

static void NONNULL(1,2)
protopassthrough_bev_eventcb_eof_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_eof_srvdst: EOF, fd=%d\n", ctx->fd);
	pxy_log_dbg_evbuf_info(ctx, &ctx->srvdst, &ctx->src);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "protopassthrough_bev_eventcb_eof_srvdst: EOF on outbound connection before connection establishment, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_eof_srvdst: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		pxy_try_consume_last_input(bev, ctx);
		pxy_try_close_conn_end(&ctx->src, ctx, &prototcp_bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect(ctx, &ctx->srvdst, &prototcp_bufferevent_free_and_close_fd, &ctx->src, 0);
}

static void NONNULL(1,2)
protopassthrough_bev_eventcb_error_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINE, "protopassthrough_bev_eventcb_error_src: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// Passthrough packets are transfered between src and srvdst
	if (!ctx->connected) {
		ctx->srvdst.closed = 1;
	} else if (!ctx->srvdst.closed) {
		pxy_try_close_conn_end(&ctx->srvdst, ctx, &prototcp_bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect(ctx, &ctx->src, &prototcp_bufferevent_free_and_close_fd, &ctx->srvdst, 1);
}

static void NONNULL(1,2)
protopassthrough_bev_eventcb_error_srvdst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINE, "protopassthrough_bev_eventcb_error_srvdst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// Passthrough packets are transfered between src and srvdst
	if (!ctx->connected) {
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		pxy_try_close_conn_end(&ctx->src, ctx, &prototcp_bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect(ctx, &ctx->srvdst, &prototcp_bufferevent_free_and_close_fd, &ctx->src, 0);
}

static void NONNULL(1)
protopassthrough_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		protopassthrough_bev_readcb_src(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protopassthrough_bev_readcb_srvdst(bev, ctx);
	} else {
		log_err_printf("protopassthrough_bev_readcb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
protopassthrough_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		protopassthrough_bev_writecb_src(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protopassthrough_bev_writecb_srvdst(bev, ctx);
	} else {
		log_err_printf("protopassthrough_bev_writecb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
protopassthrough_bev_eventcb_src(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protopassthrough_bev_eventcb_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		protopassthrough_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		protopassthrough_bev_eventcb_error_src(bev, ctx);
	}
}

static void NONNULL(1)
protopassthrough_bev_eventcb_srvdst(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protopassthrough_bev_eventcb_connected_srvdst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		protopassthrough_bev_eventcb_eof_srvdst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		protopassthrough_bev_eventcb_error_srvdst(bev, ctx);
	}
}

static void NONNULL(1)
protopassthrough_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		protopassthrough_bev_eventcb_src(bev, events, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protopassthrough_bev_eventcb_srvdst(bev, events, ctx);
	} else {
		log_err_printf("protopassthrough_bev_eventcb: UNKWN conn end\n");
		return;
	}

	// The topmost eventcb handles the term and enomem flags, frees the conn
	if (ctx->term || ctx->enomem) {
		return;
	}

	if (events & BEV_EVENT_CONNECTED) {
		if (bev == ctx->src.bev) {
			protopassthrough_log_connect_src(ctx);
		} else if (ctx->connected) {
			// @todo Do we need to set dstaddr here? It must have already been set by the original proto.
			if (pxy_set_dstaddr(ctx) == -1) {
				return;
			}
			if (protopassthrough_prepare_logging(ctx) == -1) {
				return;
			}
			protopassthrough_log_dbg_connect_type(ctx);
		}
	}
}

protocol_t
protopassthrough_setup(pxy_conn_ctx_t *ctx)
{
	// @attention Reset all callbacks while switching to passthrough mode, because we should override any/all protocol settings of the previous protocol.
	// This is different from initial protocol setup, which may choose to keep the default tcp settings.
	ctx->protoctx->proto = PROTO_PASSTHROUGH;
	ctx->protoctx->connectcb = protopassthrough_conn_connect;
	ctx->protoctx->fd_readcb = prototcp_fd_readcb;
	
	ctx->protoctx->bev_readcb = protopassthrough_bev_readcb;
	ctx->protoctx->bev_writecb = protopassthrough_bev_writecb;
	ctx->protoctx->bev_eventcb = protopassthrough_bev_eventcb;

	ctx->protoctx->bufferevent_free_and_close_fd = prototcp_bufferevent_free_and_close_fd;
	return PROTO_PASSTHROUGH;
}

/* vim: set noet ft=c: */
