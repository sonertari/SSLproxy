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

static void
protopassthrough_bev_readcb_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_readcb_src: ENTER, fd=%d, size=%zu\n",
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
protopassthrough_bev_readcb_srv_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_readcb_srv_dst: ENTER, fd=%d, size=%zu\n",
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

static void
protopassthrough_bev_writecb_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	// @attention srv_dst.bev may be NULL
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_writecb_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (ctx->srv_dst.closed) {
		if (pxy_close_conn_end_ifnodata(&ctx->src, ctx, &bufferevent_free_and_close_fd_nonssl)) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_writecb_src: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free(ctx, 1);
		}			
		return;
	}
	pxy_unset_watermark(bev, ctx, &ctx->srv_dst);
}

static void
protopassthrough_bev_writecb_srv_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_writecb_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_connect_srv_dst(bev, ctx);

	if (ctx->src.closed) {
		if (pxy_close_conn_end_ifnodata(&ctx->srv_dst, ctx, &bufferevent_free_and_close_fd_nonssl) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_writecb_srv_dst: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free(ctx, 0);
		}			
		return;
	}
	pxy_unset_watermark(bev, ctx, &ctx->src);
}

static int
protopassthrough_prepare_logging(pxy_conn_ctx_t *ctx)
{
	/* prepare logging, part 2 */
	if (WANT_CONNECT_LOG(ctx)) {
		return pxy_prepare_logging_local_procinfo(ctx);
	}
	return 0;
}

static void
protopassthrough_log_connect_type(pxy_conn_ctx_t *ctx)
{
	if (OPTS_DEBUG(ctx->opts)) {
		/* for TCP, we get only a dst connect event,
		 * since src was already connected from the
		 * beginning; mirror SSL debug output anyway
		 * in order not to confuse anyone who might be
		 * looking closely at the output */
		log_dbg_printf("protopassthrough_log_connect_type: TCP connected to [%s]:%s\n",
					   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str));
		log_dbg_printf("protopassthrough_log_connect_type: TCP connected from [%s]:%s\n",
					   STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str));
	}
}

static void
protopassthrough_log_connect_src(pxy_conn_ctx_t *ctx)
{
	if (WANT_CONNECT_LOG(ctx) || ctx->opts->statslog) {
		pxy_log_connect_nonhttp(ctx);
	}
	protopassthrough_log_connect_type(ctx);
}

static void
protopassthrough_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	protopassthrough_log_connect_src(ctx);
}

static int
protopassthrough_enable_src(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_enable_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->connected = 1;

	if (pxy_setup_src(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	if (pxy_set_dstaddr(ctx) == -1) {
		return -1;
	}

	if (protopassthrough_prepare_logging(ctx) == -1) {
		return -1;
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_enable_src: Enabling src, %s, fd=%d, child_fd=%d\n", ctx->header_str, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
	// Now open the gates
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void
protopassthrough_bev_eventcb_connected_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_connected_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->srv_dst_connected) {
		ctx->srv_dst_connected = 1;
		ctx->srv_dst_fd = bufferevent_getfd(ctx->srv_dst.bev);
		ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->srv_dst_fd);
	}

	if (ctx->srv_dst_connected && !ctx->connected) {
		if (protopassthrough_enable_src(ctx) == -1) {
			return;
		}
	}

	if (ctx->connected) {
		protopassthrough_log_connect_type(ctx);
	}
}

void
protopassthrough_engage(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protopassthrough_engage: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	// @attention Do not call bufferevent_free_and_close_fd(), otherwise connection stalls due to ssl shutdown
	// We get srv_dst writecb while ssl shutdown is still in progress, and srv_dst readcb never fires
	//bufferevent_free_and_close_fd(ctx->srv_dst.bev, ctx);
	SSL_free(ctx->srv_dst.ssl);
	bufferevent_free_and_close_fd_nonssl(ctx->srv_dst.bev, ctx);
	ctx->srv_dst.bev = NULL;
	ctx->srv_dst.ssl = NULL;
	ctx->connected = 0;
	ctx->srv_dst_connected = 0;

	// Close and free dst if open
	if (!ctx->dst.closed) {
		ctx->dst.closed = 1;
		bufferevent_free_and_close_fd_nonssl(ctx->dst.bev, ctx);
		ctx->dst.bev = NULL;
		ctx->dst_fd = 0;
	}

	ctx->proto = protopassthrough_setup(ctx);
	pxy_fd_readcb(ctx->fd, 0, ctx);
}

static void
protopassthrough_bev_eventcb_eof_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_eof_src: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_dbg_evbuf_info(ctx, &ctx->src, &ctx->srv_dst);

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->srv_dst.closed = 1;
	} else if (!ctx->srv_dst.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_eof_src: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_consume_last_input(bev, ctx);
		pxy_close_conn_end_ifnodata(&ctx->srv_dst, ctx, &bufferevent_free_and_close_fd_nonssl);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->src, &bufferevent_free_and_close_fd_nonssl, &ctx->srv_dst, 1);
}

static void
protopassthrough_bev_eventcb_eof_srv_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_eof_srv_dst: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_dbg_evbuf_info(ctx, &ctx->srv_dst, &ctx->src);

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_bev_eventcb_eof_srv_dst: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		pxy_consume_last_input(bev, ctx);
		pxy_close_conn_end_ifnodata(&ctx->src, ctx, &bufferevent_free_and_close_fd_nonssl);
	}

	pxy_log_dbg_disconnect(ctx);

	pxy_disconnect(ctx, &ctx->srv_dst, &bufferevent_free_and_close_fd_nonssl, &ctx->src, 0);
}

static void
protopassthrough_bev_eventcb_error_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	// Passthrough packets are transfered between src and srv_dst
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protopassthrough_bev_eventcb_error_src: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_printf("protopassthrough_bev_eventcb_error_src: Client-side BEV_EVENT_ERROR\n");
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
protopassthrough_bev_eventcb_error_srv_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	// Passthrough packets are transfered between src and srv_dst
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protopassthrough_bev_eventcb_error_srv_dst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_printf("protopassthrough_bev_eventcb_error_srv_dst: Client-side BEV_EVENT_ERROR\n");
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
protopassthrough_conn_connect(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopassthrough_conn_connect: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (pxy_setup_srv_dst(ctx) == -1) {
		return;
	}

	// @attention Sometimes dst write cb fires but not event cb, especially if this listener cb is not finished yet, so the conn stalls.
	bufferevent_setcb(ctx->srv_dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->srv_dst.bev, EV_READ|EV_WRITE);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srv_dst.bev, (struct sockaddr *)&ctx->addr, ctx->addrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "protopassthrough_conn_connect: bufferevent_socket_connect for srv_dst failed\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "protopassthrough_conn_connect: bufferevent_socket_connect for srv_dst failed, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	}
}

void
protopassthrough_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "protopassthrough_bev_readcb: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (bev == ctx->src.bev) {
		protopassthrough_bev_readcb_src(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		protopassthrough_bev_readcb_srv_dst(bev, arg);
	} else {
		log_err_printf("protopassthrough_bev_readcb: UNKWN conn end\n");
	}
}

void
protopassthrough_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (bev == ctx->src.bev) {
		protopassthrough_bev_writecb_src(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		protopassthrough_bev_writecb_srv_dst(bev, arg);
	} else {
		log_err_printf("protopassthrough_bev_writecb: UNKWN conn end\n");
	}
}

static void
protopassthrough_bev_eventcb_src(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		protopassthrough_bev_eventcb_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		protopassthrough_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		protopassthrough_bev_eventcb_error_src(bev, ctx);
	}
}

static void
protopassthrough_bev_eventcb_srv_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		protopassthrough_bev_eventcb_connected_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		protopassthrough_bev_eventcb_eof_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		protopassthrough_bev_eventcb_error_srv_dst(bev, ctx);
	}
}

static void
protopassthrough_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (bev == ctx->src.bev) {
		protopassthrough_bev_eventcb_src(bev, events, arg);
	} else if (bev == ctx->srv_dst.bev) {
		protopassthrough_bev_eventcb_srv_dst(bev, events, arg);
	} else {
		log_err_printf("protopassthrough_bev_eventcb: UNKWN conn end\n");
	}
}

enum protocol
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
