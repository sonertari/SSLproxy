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

#include "prototcp.h"
#include "protopassthrough.h"

#include <sys/param.h>
#include <event2/bufferevent_ssl.h>

void
prototcp_bufferevent_free_and_close_fd(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
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
prototcp_conn_connect(pxy_conn_ctx_t *ctx)
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

void
prototcp_connect_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_connect_tcp_child: ENTER, conn fd=%d, child_fd=%d\n", ctx->conn->fd, ctx->conn->child_fd);
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
prototcp_fd_readcb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_fd_readcb_tcp: ENTER fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	pxy_conn_connect(ctx);
}

static void
prototcp_bev_readcb_src(struct bufferevent *bev, void *arg)
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
prototcp_bev_readcb_dst(struct bufferevent *bev, void *arg)
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
prototcp_bev_readcb_srv_dst(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
	log_err_printf("pxy_bev_readcb_srv_dst: readcb called on srv_dst\n");
}

static void
prototcp_bev_readcb_src_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_src: ENTER, fd=%d, conn fd=%d, size=%zu\n",
			ctx->fd, ctx->conn->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
		
	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child_src: readcb called when other end not connected - aborting.\n");
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
		log_err_printf("pxy_bev_readcb_child_src: src evbuffer_remove failed, fd=%d\n", ctx->fd);
	}

	pxy_remove_sslproxy_header(packet, &packet_size, ctx);

	if (evbuffer_add(outbuf, packet, packet_size) == -1) {
		log_err_printf("pxy_bev_readcb_child_src: src evbuffer_add failed, fd=%d\n", ctx->fd);
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_src: src packet (size=%zu), fd=%d, conn fd=%d:\n%.*s\n",
			packet_size, ctx->fd, ctx->conn->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

	pxy_log_content_buf((pxy_conn_ctx_t *)ctx, packet, packet_size, 1);
	free(packet);

	pxy_set_watermark(bev, ctx->conn, ctx->dst.bev);
}

static void
prototcp_bev_readcb_dst_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_dst: ENTER, fd=%d, conn fd=%d, size=%zu\n",
			ctx->fd, ctx->conn->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
		
	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child_dst: readcb called when other end not connected - aborting.\n");
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
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_dst: dst packet size=%zu, fd=%d\n", inbuf_size, ctx->fd);
#endif /* DEBUG_PROXY */
	pxy_log_content_inbuf((pxy_conn_ctx_t *)ctx, inbuf, 0);
	evbuffer_add_buffer(outbuf, inbuf);

	pxy_set_watermark(bev, ctx->conn, ctx->src.bev);
}

static void
prototcp_bev_writecb_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_src: ENTER, fd=%d\n", ctx->fd);
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
prototcp_connect_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (!ctx->dst_connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_connect_dst: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
		// This is a workaround for this error condition, nothing else seems to work.
		// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
		// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
		ctx->protoctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
	}
}

static void
prototcp_connect_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	if (!ctx->connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_connect_dst_child: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
		// This is a workaround for this error condition, nothing else seems to work.
		// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
		// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
		ctx->protoctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
	}
}

static void
prototcp_bev_writecb_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	prototcp_connect_dst(bev, ctx);

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
prototcp_bev_writecb_srv_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	pxy_connect_srv_dst(bev, ctx);
}

static void
prototcp_bev_writecb_src_child(struct bufferevent *bev, void *arg)
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
prototcp_bev_writecb_dst_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_writecb_child_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->conn->atime = time(NULL);

	prototcp_connect_dst_child(bev, ctx);

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

static int
prototcp_enable_src(pxy_conn_ctx_t *ctx)
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
prototcp_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_connect_src(ctx);
}

void
prototcp_bev_eventcb_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_connected_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->dst_connected = 1;

	if (ctx->srv_dst_connected && ctx->dst_connected && !ctx->connected) {
		prototcp_enable_src(ctx);
	}

	if (ctx->connected) {
		pxy_log_connect_srv_dst(ctx);
	}
}

void
prototcp_bev_eventcb_connected_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
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
		if (prototcp_enable_src(ctx) == -1) {
			return;
		}
	}

	if (ctx->connected) {
		pxy_log_connect_srv_dst(ctx);
	}
}

void
prototcp_bev_eventcb_eof_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
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
prototcp_bev_eventcb_eof_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
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
prototcp_bev_eventcb_eof_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_eof_srv_dst: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment on srv_dst\n");
	pxy_conn_free(ctx, 0);
}

void
prototcp_bev_eventcb_error_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
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
prototcp_bev_eventcb_error_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
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
prototcp_bev_eventcb_error_srv_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
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
			protopassthrough_engage(ctx);
			return;
		}
		pxy_conn_free(ctx, 0);
	}
}

static void
prototcp_bev_eventcb_connected_src_child(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
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
prototcp_bev_eventcb_eof_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
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
prototcp_bev_eventcb_eof_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
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
prototcp_bev_eventcb_error_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
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
prototcp_bev_eventcb_error_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
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
prototcp_bev_eventcb_src_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_src_child(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_src_child(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_src_child(bev, ctx);
	}
}

static void
prototcp_bev_eventcb_dst_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_child_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_dst_child(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_dst_child(bev, ctx);
	}
}

static void
prototcp_bev_eventcb_src(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_src(bev, ctx);
	}
}

static void
prototcp_bev_eventcb_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_dst(bev, ctx);
	}
}

static void
prototcp_bev_eventcb_srv_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_srv_dst(bev, ctx);
	}
}

void
prototcp_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_tcp: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (bev == ctx->src.bev) {
		prototcp_bev_readcb_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_readcb_dst(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		prototcp_bev_readcb_srv_dst(bev, arg);
	} else {
		log_err_printf("pxy_bev_readcb_tcp: UNKWN conn end\n");
	}
}

void
prototcp_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (bev == ctx->src.bev) {
		prototcp_bev_writecb_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_writecb_dst(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		prototcp_bev_writecb_srv_dst(bev, arg);
	} else {
		log_err_printf("pxy_bev_writecb_tcp: UNKWN conn end\n");
	}
}

void
prototcp_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src(bev, events, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_eventcb_dst(bev, events, arg);
	} else if (bev == ctx->srv_dst.bev) {
		prototcp_bev_eventcb_srv_dst(bev, events, arg);
	} else {
		log_err_printf("pxy_bev_eventcb_tcp: UNKWN conn end\n");
	}
}

void
prototcp_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_tcp_child: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (bev == ctx->src.bev) {
		prototcp_bev_readcb_src_child(bev, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_readcb_dst_child(bev, arg);
	} else {
		log_err_printf("pxy_bev_readcb_tcp_child: UNKWN conn end\n");
	}
}

void
prototcp_bev_writecb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (bev == ctx->src.bev) {
		prototcp_bev_writecb_src_child(bev, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_writecb_dst_child(bev, arg);
	} else {
		log_err_printf("pxy_bev_writecb_tcp_child: UNKWN conn end\n");
	}
}

void
prototcp_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src_child(bev, events, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_eventcb_dst_child(bev, events, arg);
	} else {
		log_err_printf("pxy_bev_eventcb_tcp_child: UNKWN conn end\n");
	}
}

enum protocol
prototcp_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_TCP;
	ctx->protoctx->connectcb = prototcp_conn_connect;
	ctx->protoctx->fd_readcb = prototcp_fd_readcb;
	
	ctx->protoctx->bev_readcb = prototcp_bev_readcb;
	ctx->protoctx->bev_writecb = prototcp_bev_writecb;
	ctx->protoctx->bev_eventcb = prototcp_bev_eventcb;

	ctx->protoctx->bufferevent_free_and_close_fd = prototcp_bufferevent_free_and_close_fd;
	return PROTO_TCP;
}

enum protocol
prototcp_setup_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_TCP;
	ctx->protoctx->connectcb = prototcp_connect_child;

	ctx->protoctx->bev_readcb = prototcp_bev_readcb_child;
	ctx->protoctx->bev_writecb = prototcp_bev_writecb_child;
	ctx->protoctx->bev_eventcb = prototcp_bev_eventcb_child;

	ctx->protoctx->bufferevent_free_and_close_fd = prototcp_bufferevent_free_and_close_fd;
	return PROTO_TCP;
}

/* vim: set noet ft=c: */
