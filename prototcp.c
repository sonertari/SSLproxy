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
prototcp_bufferevent_setup(pxy_conn_ctx_t *ctx, evutil_socket_t fd)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bufferevent_setup: ENTER, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	// @todo Do we really need to defer callbacks? BEV_OPT_DEFER_CALLBACKS seems responsible for the issue with srv_dst: We get writecb sometimes, no eventcb for CONNECTED event
	struct bufferevent *bev = bufferevent_socket_new(ctx->evbase, fd, BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
		return NULL;
	}

	// @attention Do not set callbacks here, srv_dst does not set r cb
	//bufferevent_setcb(bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	// @todo Should we enable events here?
	//bufferevent_enable(bev, EV_READ|EV_WRITE);
	return bev;
}

static struct bufferevent * NONNULL(1)
prototcp_bufferevent_setup_child(pxy_conn_child_ctx_t *ctx, evutil_socket_t fd)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bufferevent_setup_child: ENTER, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	struct bufferevent *bev = bufferevent_socket_new(ctx->conn->evbase, fd, BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
		return NULL;
	}

	bufferevent_setcb(bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);

	// @attention We cannot enable events here, because src events will be deferred until after dst is connected
	//bufferevent_enable(bev, EV_READ|EV_WRITE);
	return bev;
}

/*
 * Free bufferenvent and close underlying socket properly.
 */
void
prototcp_bufferevent_free_and_close_fd(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_bufferevent_free_and_close_fd: ENTER i:%zu o:%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(bev)), fd);
#endif /* DEBUG_PROXY */

	bufferevent_free(bev);
	evutil_closesocket(fd);
}

int
prototcp_setup_src(pxy_conn_ctx_t *ctx)
{
	ctx->src.ssl= NULL;
	ctx->src.bev = prototcp_bufferevent_setup(ctx, ctx->fd);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating src bufferevent\n");
		pxy_conn_free(ctx, 1);
		return -1;
	}
	return 0;
}

int
prototcp_setup_dst(pxy_conn_ctx_t *ctx)
{
	ctx->dst.ssl= NULL;
	ctx->dst.bev = prototcp_bufferevent_setup(ctx, -1);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating parent dst\n");
		pxy_conn_free(ctx, 1);
		return -1;
	}
	return 0;
}

int
prototcp_setup_srv_dst(pxy_conn_ctx_t *ctx)
{
	ctx->srv_dst.ssl= NULL;
	ctx->srv_dst.bev = prototcp_bufferevent_setup(ctx, -1);
	if (!ctx->srv_dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating srv_dst\n");
		pxy_conn_free(ctx, 1);
		return -1;
	}
	return 0;
}

static void NONNULL(1)
prototcp_conn_connect(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_conn_connect: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (prototcp_setup_dst(ctx) == -1) {
		return;
	}

	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);

	/* create server-side socket and eventbuffer */
	if (prototcp_setup_srv_dst(ctx) == -1) {
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
		log_err_level_printf(LOG_CRIT, "prototcp_conn_connect: bufferevent_socket_connect for srv_dst failed\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_conn_connect: bufferevent_socket_connect for srv_dst failed, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		// @attention Do not try to close the conn here, otherwise both pxy_conn_connect() and eventcb try to free the conn using pxy_conn_free(),
		// they are running on different threads, causing multithreading issues, e.g. signal 10.
		// @todo Should we use thrmgr->mutex? Can we?
	}
}

int
prototcp_setup_src_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->src.ssl = NULL;
	ctx->src.bev = prototcp_bufferevent_setup_child(ctx, ctx->fd);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating child src\n");
		evutil_closesocket(ctx->fd);
		pxy_conn_free(ctx->conn, 1);
		return -1;
	}
	return 0;
}

int
prototcp_setup_dst_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->dst.ssl = NULL;
	ctx->dst.bev = prototcp_bufferevent_setup_child(ctx, -1);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent\n");
		pxy_conn_free(ctx->conn, 1);
		return -1;
	}
	return 0;
}

static void NONNULL(1)
prototcp_connect_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_connect_child: ENTER, conn fd=%d, child_fd=%d\n", ctx->conn->fd, ctx->conn->child_fd);
#endif /* DEBUG_PROXY */

	/* create server-side socket and eventbuffer */
	prototcp_setup_dst_child(ctx);
}

void
prototcp_fd_readcb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_fd_readcb: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_conn_connect(ctx);
}

static void NONNULL(1)
prototcp_bev_readcb_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_src: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	if (ctx->dst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	if (!ctx->sent_header) {
		size_t packet_size = evbuffer_get_length(inbuf);
		// +2 is for \r\n
		unsigned char *packet = pxy_malloc_packet(packet_size + ctx->header_len + 2, ctx);
		if (!packet) {
			return;
		}

		evbuffer_remove(inbuf, packet, packet_size);

#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_src: ORIG packet (size=%zu), fd=%d:\n%.*s\n",
				packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

		pxy_insert_sslproxy_header(ctx, packet, &packet_size);
		evbuffer_add(outbuf, packet, packet_size);

#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_src: NEW packet (size=%zu), fd=%d:\n%.*s\n",
				packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

		free(packet);
	}
	else {
		evbuffer_add_buffer(outbuf, inbuf);
	}
	pxy_try_set_watermark(bev, ctx, ctx->dst.bev);
}

static void NONNULL(1)
prototcp_bev_readcb_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_dst: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
	
	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);
	evbuffer_add_buffer(outbuf, inbuf);
	pxy_try_set_watermark(bev, ctx, ctx->src.bev);
}

static void NONNULL(1)
prototcp_bev_readcb_srv_dst(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
	log_err_printf("prototcp_bev_readcb_srv_dst: readcb called on srv_dst\n");
}

static void NONNULL(1)
prototcp_bev_readcb_src_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_src_child: ENTER, fd=%d, conn fd=%d, size=%zu\n",
			ctx->fd, ctx->conn->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
		
	if (ctx->dst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	if (!ctx->removed_header) {
		size_t packet_size = evbuffer_get_length(inbuf);
		unsigned char *packet = pxy_malloc_packet(packet_size, ctx->conn);
		if (!packet) {
			return;
		}

		evbuffer_remove(inbuf, packet, packet_size);
		pxy_try_remove_sslproxy_header(ctx, packet, &packet_size);
		evbuffer_add(outbuf, packet, packet_size);

#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_src_child: src packet (size=%zu), fd=%d, conn fd=%d:\n%.*s\n",
				packet_size, ctx->fd, ctx->conn->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

		free(packet);
	} else {
		evbuffer_add_buffer(outbuf, inbuf);
	}
	pxy_try_set_watermark(bev, ctx->conn, ctx->dst.bev);
}

static void NONNULL(1)
prototcp_bev_readcb_dst_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_dst_child: ENTER, fd=%d, conn fd=%d, size=%zu\n",
			ctx->fd, ctx->conn->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
		
	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);
	evbuffer_add_buffer(outbuf, inbuf);
	pxy_try_set_watermark(bev, ctx->conn, ctx->src.bev);
}

static void NONNULL(1)
prototcp_bev_writecb_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (ctx->dst.closed) {
		if (pxy_try_close_conn_end(&ctx->src, ctx, ctx->protoctx->bufferevent_free_and_close_fd) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_src: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_free(ctx, 1);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx, &ctx->dst);
}

static void NONNULL(1,2)
prototcp_try_connect_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (!ctx->dst_connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_try_connect_dst: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
		// This is a workaround for this error condition, nothing else seems to work.
		// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
		// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
		ctx->protoctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
	}
}

static void NONNULL(1)
prototcp_bev_writecb_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	prototcp_try_connect_dst(bev, ctx);

	if (ctx->src.closed) {
		if (pxy_try_close_conn_end(&ctx->dst, ctx, &prototcp_bufferevent_free_and_close_fd) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_dst: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_free(ctx, 0);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx, &ctx->src);
}

static void NONNULL(1)
prototcp_bev_writecb_srv_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_try_connect_srv_dst(bev, ctx);
}

static void NONNULL(1)
prototcp_bev_writecb_src_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_src_child: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (ctx->dst.closed) {
		if (pxy_try_close_conn_end(&ctx->src, ctx->conn, &prototcp_bufferevent_free_and_close_fd) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_src_child: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_free_child(ctx);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx->conn, &ctx->dst);
}

static void NONNULL(1,2)
prototcp_try_connect_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	if (!ctx->connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_try_connect_dst_child: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		// @attention Sometimes dst write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
		// This is a workaround for this error condition, nothing else seems to work.
		// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
		// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
		ctx->protoctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);
	}
}

static void NONNULL(1)
prototcp_bev_writecb_dst_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_dst_child: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	prototcp_try_connect_dst_child(bev, ctx);

	if (ctx->src.closed) {
		if (pxy_try_close_conn_end(&ctx->dst, ctx->conn, ctx->protoctx->bufferevent_free_and_close_fd) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_dst_child: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_free_child(ctx);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx->conn, &ctx->src);
}

static void NONNULL(1)
prototcp_close_srv_dst(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_close_srv_dst: Closing srv_dst, fd=%d, srv_dst fd=%d\n", ctx->fd, bufferevent_getfd(ctx->srv_dst.bev));
#endif /* DEBUG_PROXY */

	// @attention Free the srv_dst of the conn asap, we don't need it anymore, but we need its fd
	// @attention When both eventcb and writecb for srv_dst are enabled, either eventcb or writecb may get a NULL srv_dst bev, causing a crash with signal 10.
	// So, from this point on, we should check if srv_dst is NULL or not.
	prototcp_bufferevent_free_and_close_fd(ctx->srv_dst.bev, ctx);
	ctx->srv_dst.bev = NULL;
	ctx->srv_dst.closed = 1;
}

static int NONNULL(1)
prototcp_enable_src(pxy_conn_ctx_t *ctx)
{
	if (prototcp_setup_src(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	prototcp_close_srv_dst(ctx);

	if (pxy_setup_child_listener(ctx) == -1) {
		return -1;
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_enable_src: Enabling src, %s, fd=%d, child_fd=%d\n", ctx->header_str, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */

	// Now open the gates
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_connected_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->dst_connected = 1;

	if (ctx->srv_dst_connected && ctx->dst_connected && !ctx->connected) {
		ctx->connected = 1;

		if (prototcp_enable_src(ctx) == -1) {
			return;
		}
	}
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_connected_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->srv_dst_connected = 1;

	// @attention Create and enable dst.bev before, but connect here, because we check if dst.bev is NULL elsewhere
	if (bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->spec->conn_dst_addr, ctx->spec->conn_dst_addrlen) == -1) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_bev_eventcb_connected_srv_dst: FAILED bufferevent_socket_connect for dst, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		pxy_conn_free(ctx, 1);
		return;
	}

	if (ctx->srv_dst_connected && ctx->dst_connected && !ctx->connected) {
		ctx->connected = 1;

		if (prototcp_enable_src(ctx) == -1) {
			return;
		}
	}
}

void
prototcp_bev_eventcb_eof_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_src: EOF, fd=%d\n", ctx->fd);
	pxy_log_dbg_evbuf_info(ctx, &ctx->src, &ctx->dst);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_src: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		pxy_try_consume_last_input(bev, ctx);
		pxy_try_close_conn_end(&ctx->dst, ctx, &prototcp_bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect(ctx, &ctx->src, ctx->protoctx->bufferevent_free_and_close_fd, &ctx->dst, 1);
}

void
prototcp_bev_eventcb_eof_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_dst: EOF, fd=%d\n", ctx->fd);
	pxy_log_dbg_evbuf_info(ctx, &ctx->dst, &ctx->src);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_dst: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		pxy_try_consume_last_input(bev, ctx);
		pxy_try_close_conn_end(&ctx->src, ctx, ctx->protoctx->bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect(ctx, &ctx->dst, &prototcp_bufferevent_free_and_close_fd, &ctx->src, 0);
}

void
prototcp_bev_eventcb_eof_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_srv_dst: EOF, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment on srv_dst\n");
	pxy_conn_free(ctx, 0);
}

void
prototcp_bev_eventcb_error_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_bev_eventcb_error_src: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		pxy_try_close_conn_end(&ctx->dst, ctx, &prototcp_bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect(ctx, &ctx->src, ctx->protoctx->bufferevent_free_and_close_fd, &ctx->dst, 1);
}

void
prototcp_bev_eventcb_error_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_bev_eventcb_error_dst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		pxy_try_close_conn_end(&ctx->src, ctx, ctx->protoctx->bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect(ctx, &ctx->dst, &prototcp_bufferevent_free_and_close_fd, &ctx->src, 0);
}

void
prototcp_bev_eventcb_error_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_bev_eventcb_error_srv_dst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_bev_eventcb_error_srv_dst: ERROR !ctx->connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		pxy_conn_free(ctx, 0);
	}
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_src_child(UNUSED struct bufferevent *bev, UNUSED pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_connected_src_child: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_dst_child(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_connected_dst_child: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	ctx->connected = 1;

	// @attention Create and enable src.bev before, but connect here, because we check if dst.bev is NULL elsewhere
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
}

static void NONNULL(1,2)
prototcp_bev_eventcb_eof_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_src_child: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
	pxy_log_dbg_evbuf_info(ctx->conn, &ctx->src, &ctx->dst);
#endif /* DEBUG_PROXY */

	// @todo How to handle the following case?
	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_src_child: !other->closed, terminate conn, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

		pxy_try_consume_last_input_child(bev, ctx);
		pxy_try_close_conn_end(&ctx->dst, ctx->conn, ctx->protoctx->bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect_child(ctx, &ctx->src, &prototcp_bufferevent_free_and_close_fd, &ctx->dst);
}

void
prototcp_bev_eventcb_eof_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_dst_child: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
	pxy_log_dbg_evbuf_info(ctx->conn, &ctx->dst, &ctx->src);
#endif /* DEBUG_PROXY */

	// @todo How to handle the following case?
	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_dst_child: !other->closed, terminate conn, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

		pxy_try_consume_last_input_child(bev, ctx);
		pxy_try_close_conn_end(&ctx->src, ctx->conn, &prototcp_bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect_child(ctx, &ctx->dst, ctx->protoctx->bufferevent_free_and_close_fd, &ctx->src);
}

static void NONNULL(1,2)
prototcp_bev_eventcb_error_src_child(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_bev_eventcb_error_src_child: BEV_EVENT_ERROR, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		/* the callout to the original destination failed,
		 * e.g. because it asked for client cert auth, so
		 * close the accepted socket and clean up */
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		/* if the other end is still open and doesn't have data
		 * to send, close it, otherwise its writecb will close
		 * it after writing what's left in the output buffer */
		pxy_try_close_conn_end(&ctx->dst, ctx->conn, ctx->protoctx->bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect_child(ctx, &ctx->src, &prototcp_bufferevent_free_and_close_fd, &ctx->dst);
}

void
prototcp_bev_eventcb_error_dst_child(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_bev_eventcb_error_dst_child: BEV_EVENT_ERROR, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		/* the callout to the original destination failed,
		 * e.g. because it asked for client cert auth, so
		 * close the accepted socket and clean up */
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		/* if the other end is still open and doesn't have data
		 * to send, close it, otherwise its writecb will close
		 * it after writing what's left in the output buffer */
		pxy_try_close_conn_end(&ctx->src, ctx->conn, &prototcp_bufferevent_free_and_close_fd);
	}

	pxy_try_disconnect_child(ctx, &ctx->dst, ctx->protoctx->bufferevent_free_and_close_fd, &ctx->src);
}

void
prototcp_bev_eventcb_src(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_src(bev, ctx);
	}
}

static void NONNULL(1)
prototcp_bev_eventcb_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_dst(bev, ctx);
	}
}

static void NONNULL(1)
prototcp_bev_eventcb_srv_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_srv_dst(bev, ctx);
	}
}

void
prototcp_bev_eventcb_src_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_src_child(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_src_child(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_src_child(bev, ctx);
	}
}

void
prototcp_bev_eventcb_dst_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_dst_child(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_dst_child(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_dst_child(bev, ctx);
	}
}

static void NONNULL(1)
prototcp_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_readcb_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_readcb_dst(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		prototcp_bev_readcb_srv_dst(bev, arg);
	} else {
		log_err_printf("prototcp_bev_readcb: UNKWN conn end\n");
	}
}

void
prototcp_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_writecb_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_writecb_dst(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		prototcp_bev_writecb_srv_dst(bev, arg);
	} else {
		log_err_printf("prototcp_bev_writecb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
prototcp_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src(bev, events, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_eventcb_dst(bev, events, arg);
	} else if (bev == ctx->srv_dst.bev) {
		prototcp_bev_eventcb_srv_dst(bev, events, arg);
	} else {
		log_err_printf("prototcp_bev_eventcb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
prototcp_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_readcb_src_child(bev, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_readcb_dst_child(bev, arg);
	} else {
		log_err_printf("prototcp_bev_readcb_child: UNKWN conn end\n");
	}
}

void
prototcp_bev_writecb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_writecb_src_child(bev, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_writecb_dst_child(bev, arg);
	} else {
		log_err_printf("prototcp_bev_writecb_child: UNKWN conn end\n");
	}
}

static void NONNULL(1)
prototcp_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src_child(bev, events, arg);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_eventcb_dst_child(bev, events, arg);
	} else {
		log_err_printf("prototcp_bev_eventcb_child: UNKWN conn end\n");
	}
}

protocol_t
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

protocol_t
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
