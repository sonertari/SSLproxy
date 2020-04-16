/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2020, Soner Tari <sonertari@gmail.com>.
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
#include <string.h>

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
	log_finest_va("ENTER, fd=%d", fd);

	struct bufferevent *bev = bufferevent_socket_new(ctx->evbase, fd, BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);
	if (!bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
		log_fine_va("bufferevent_socket_connect failed, fd=%d", fd);
		return NULL;
	}

	// @attention Do not set callbacks here, we do not set r cb for tcp/ssl srvdst
	//bufferevent_setcb(bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	// @attention Do not enable r/w events here, we do not set r cb for tcp/ssl srvdst
	// Also, to avoid r/w cb before connected, we should enable r/w events after the conn is connected
	//bufferevent_enable(bev, EV_READ|EV_WRITE);
	return bev;
}

static struct bufferevent * NONNULL(1)
prototcp_bufferevent_setup_child(pxy_conn_child_ctx_t *ctx, evutil_socket_t fd)
{
	log_finest_va("ENTER, fd=%d", fd);

	struct bufferevent *bev = bufferevent_socket_new(ctx->conn->evbase, fd, BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);
	if (!bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
		log_fine_va("bufferevent_socket_connect failed, fd=%d", fd);
		return NULL;
	}

	bufferevent_setcb(bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);

	// @attention We cannot enable events here, because src events will be deferred until after dst is connected
	// Also, to avoid r/w cb before connected, we should enable r/w events after the conn is connected
	//bufferevent_enable(bev, EV_READ|EV_WRITE);
	return bev;
}

/*
 * Free bufferenvent and close underlying socket properly.
 */
static void
prototcp_bufferevent_free_and_close_fd(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

	log_finer_va("in=%zu, out=%zu, fd=%d", evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(bev)), fd);

	bufferevent_free(bev);
	evutil_closesocket(fd);
}

int
prototcp_setup_src(pxy_conn_ctx_t *ctx)
{
	ctx->src.ssl = NULL;
	ctx->src.bev = prototcp_bufferevent_setup(ctx, ctx->fd);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating src bufferevent\n");
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->src.free = prototcp_bufferevent_free_and_close_fd;
	return 0;
}

int
prototcp_setup_dst(pxy_conn_ctx_t *ctx)
{
	ctx->dst.ssl = NULL;
	ctx->dst.bev = prototcp_bufferevent_setup(ctx, -1);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating parent dst\n");
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->dst.free = prototcp_bufferevent_free_and_close_fd;
	return 0;
}

int
prototcp_setup_srvdst(pxy_conn_ctx_t *ctx)
{
	ctx->srvdst.ssl = NULL;
	ctx->srvdst.bev = prototcp_bufferevent_setup(ctx, -1);
	if (!ctx->srvdst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating srvdst\n");
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->srvdst.free = prototcp_bufferevent_free_and_close_fd;
	return 0;
}

static int NONNULL(1) WUNRES
prototcp_conn_connect(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	/* create server-side socket and eventbuffer */
	if (prototcp_setup_srvdst(ctx) == -1) {
		return -1;
	}

	// Conn setup is successful, so add the conn to the conn list of its thread now
	pxy_thrmgr_add_conn(ctx);

	// Disable and NULL r cb, we do nothing for srvdst in r cb
	bufferevent_setcb(ctx->srvdst.bev, NULL, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srvdst.bev, (struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "prototcp_conn_connect: bufferevent_socket_connect for srvdst failed\n");
		log_fine("bufferevent_socket_connect for srvdst failed");
		// @attention Do not try to term/close conns or do anything else with conn ctx on the thrmgr thread after setting event callbacks and/or socket connect.
		// Otherwise both pxy_conn_connect() and eventcb may try to free the conn using pxy_conn_free(), which are running on different threads.
		// Also, pxy_thrmgr_timer_cb() may try to access conn ctx while printing thr conns.
		// These all may cause multithreading issues, e.g. signal 10 crash. Just return 0.
	}
	return 0;
}

int
prototcp_setup_src_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->src.ssl = NULL;
	ctx->src.bev = prototcp_bufferevent_setup_child(ctx, ctx->fd);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating child src\n");
		pxy_conn_term(ctx->conn, 1);
		return -1;
	}
	ctx->src.free = prototcp_bufferevent_free_and_close_fd;
	return 0;
}

int
prototcp_setup_dst_child(pxy_conn_child_ctx_t *ctx)
{
	if (!ctx->conn->srvdst_xferred) {
		// Reuse srvdst of parent in the first child conn
		ctx->conn->srvdst_xferred = 1;
		ctx->dst = ctx->conn->srvdst;
		bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);
		ctx->protoctx->bev_eventcb(ctx->dst.bev, BEV_EVENT_CONNECTED, ctx);
	} else {
		ctx->dst.ssl = NULL;
		ctx->dst.bev = prototcp_bufferevent_setup_child(ctx, -1);
		if (!ctx->dst.bev) {
			log_err_level_printf(LOG_CRIT, "Error creating bufferevent\n");
			pxy_conn_term(ctx->conn, 1);
			return -1;
		}
		ctx->dst.free = prototcp_bufferevent_free_and_close_fd;
	}
	return 0;
}

static void NONNULL(1)
prototcp_connect_child(pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");

	/* create server-side socket and eventbuffer */
	prototcp_setup_dst_child(ctx);
}

void
prototcp_fd_readcb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	log_finest("ENTER");
	pxy_conn_connect(ctx);
}

int
prototcp_try_send_userauth_msg(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (ctx->spec->opts->user_auth && !ctx->user) {
		log_finest("Sending userauth message");
		pxy_discard_inbuf(bev);
		evbuffer_add_printf(bufferevent_get_output(bev), USERAUTH_MSG, ctx->spec->opts->user_auth_url);
		ctx->sent_userauth_msg = 1;
		return 1;
	}
	return 0;
}

static int NONNULL(1,2,3,4)
prototcp_try_validate_proto(struct bufferevent *bev, pxy_conn_ctx_t *ctx, struct evbuffer *inbuf, struct evbuffer *outbuf)
{
	if (ctx->spec->opts->validate_proto && ctx->protoctx->validatecb && !ctx->protoctx->is_valid) {
		size_t packet_size = evbuffer_get_length(inbuf);
		char *packet = (char *)pxy_malloc_packet(packet_size, ctx);
		if (!packet) {
			return -1;
		}
		if (evbuffer_copyout(inbuf, packet, packet_size) == -1) {
			free(packet);
			return -1;
		}
		if (ctx->protoctx->validatecb(ctx, packet
#ifdef DEBUG_PROXY
				, packet_size
#endif /* DEBUG_PROXY */
				) == -1) {
			// Send message to the client: outbuf of src
			evbuffer_add(bufferevent_get_output(bev), PROTOERROR_MSG, PROTOERROR_MSG_LEN);
			ctx->sent_protoerror_msg = 1;
			// Discard packets from the client: inbuf of src
			pxy_discard_inbuf(bev);
			// Discard packets to the server: outbuf of dst
			evbuffer_drain(outbuf, evbuffer_get_length(outbuf));
			free(packet);
			return 1;
		}
		free(packet);
	}
	return 0;
}

void
prototcp_bev_readcb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));

	if (ctx->dst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	if (prototcp_try_send_userauth_msg(bev, ctx)) {
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);
		
	if (prototcp_try_validate_proto(bev, ctx, inbuf, outbuf) != 0) {
		return;
	}

	if (!ctx->sent_sslproxy_header) {
		size_t packet_size = evbuffer_get_length(inbuf);
		// +2 for \r\n
		unsigned char *packet = pxy_malloc_packet(packet_size + ctx->sslproxy_header_len + 2, ctx);
		if (!packet) {
			return;
		}

		evbuffer_remove(inbuf, packet, packet_size);

		log_finest_va("ORIG packet, size=%zu:\n%.*s", packet_size, (int)packet_size, packet);

		pxy_insert_sslproxy_header(ctx, packet, &packet_size);
		evbuffer_add(outbuf, packet, packet_size);

		log_finest_va("NEW packet, size=%zu:\n%.*s", packet_size, (int)packet_size, packet);

		free(packet);
	}
	else {
		evbuffer_add_buffer(outbuf, inbuf);
	}
	pxy_try_set_watermark(bev, ctx, ctx->dst.bev);
}

void
prototcp_bev_readcb_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));
	
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
prototcp_bev_readcb_srvdst(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	log_err_printf("readcb called on srvdst\n");
	log_fine("readcb called on srvdst");
}

static void NONNULL(1)
prototcp_bev_readcb_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));
		
	if (ctx->dst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	if (!ctx->removed_sslproxy_header) {
		size_t packet_size = evbuffer_get_length(inbuf);
		unsigned char *packet = pxy_malloc_packet(packet_size, ctx->conn);
		if (!packet) {
			return;
		}

		evbuffer_remove(inbuf, packet, packet_size);
		pxy_try_remove_sslproxy_header(ctx, packet, &packet_size);
		evbuffer_add(outbuf, packet, packet_size);

		log_finest_va("NEW packet, size=%zu:\n%.*s", packet_size, (int)packet_size, packet);

		free(packet);
	} else {
		evbuffer_add_buffer(outbuf, inbuf);
	}
	pxy_try_set_watermark(bev, ctx->conn, ctx->dst.bev);
}

static void NONNULL(1)
prototcp_bev_readcb_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));
		
	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);
	evbuffer_add_buffer(outbuf, inbuf);
	pxy_try_set_watermark(bev, ctx->conn, ctx->src.bev);
}

int
prototcp_try_close_unauth_conn(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (ctx->spec->opts->user_auth && !ctx->user) {
		size_t outbuflen = evbuffer_get_length(bufferevent_get_output(bev));
		if (outbuflen > 0) {
			log_finest_va("Not closing unauth conn, outbuflen=%zu", outbuflen);
		} else if (ctx->sent_userauth_msg) {
			log_finest("Closing unauth conn");
			pxy_conn_term(ctx, 1);
		} else {
			log_finest("Not sent userauth msg yet");
		}
		return 1;
	}
	return 0;
}

int
prototcp_try_close_protoerror_conn(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	if (ctx->spec->opts->validate_proto && ctx->sent_protoerror_msg) {
		size_t outbuflen = evbuffer_get_length(bufferevent_get_output(bev));
		if (outbuflen > 0) {
			log_finest_va("Not closing protoerror conn, outbuflen=%zu", outbuflen);
		} else {
			log_finest("Closing protoerror conn");
			pxy_conn_term(ctx, 1);
		}
		return 1;
	}
	return 0;
}

static void NONNULL(1)
prototcp_bev_writecb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	if (prototcp_try_close_unauth_conn(bev, ctx)) {
		return;
	}

	if (prototcp_try_close_protoerror_conn(bev, ctx)) {
		return;
	}

	if (ctx->dst.closed) {
		if (pxy_try_close_conn_end(&ctx->src, ctx) == 1) {
			log_finest("dst.closed, terminate conn");
			pxy_conn_term(ctx, 1);
		}
		return;
	}
	pxy_try_unset_watermark(bev, ctx, &ctx->dst);
}

void
prototcp_bev_writecb_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	if (ctx->src.closed) {
		if (pxy_try_close_conn_end(&ctx->dst, ctx) == 1) {
			log_finest("src.closed, terminate conn");
			pxy_conn_term(ctx, 0);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx, &ctx->src);
}

void
prototcp_bev_writecb_srvdst(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");
}

static void NONNULL(1)
prototcp_bev_writecb_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");

	if (ctx->dst.closed) {
		if (pxy_try_close_conn_end(&ctx->src, ctx->conn) == 1) {
			log_finest("dst.closed, terminate conn");
			pxy_conn_term_child(ctx);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx->conn, &ctx->dst);
}

static void NONNULL(1)
prototcp_bev_writecb_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");

	if (ctx->src.closed) {
		if (pxy_try_close_conn_end(&ctx->dst, ctx->conn) == 1) {
			log_finest("src.closed, terminate conn");
			pxy_conn_term_child(ctx);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx->conn, &ctx->src);
}

int
prototcp_enable_src(pxy_conn_ctx_t *ctx)
{
	if (prototcp_setup_src(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	if (pxy_setup_child_listener(ctx) == -1) {
		return -1;
	}

	log_finer_va("Enabling src, %s", ctx->sslproxy_header);

	// Now open the gates
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	ctx->dst_connected = 1;
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	if (ctx->srvdst_connected && ctx->dst_connected && !ctx->connected) {
		ctx->connected = 1;

		if (prototcp_enable_src(ctx) == -1) {
			return;
		}
	}
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	ctx->srvdst_connected = 1;
	bufferevent_enable(bev, EV_WRITE);

	if (prototcp_setup_dst(ctx) == -1) {
		return;
	}
	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	if (bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->spec->conn_dst_addr, ctx->spec->conn_dst_addrlen) == -1) {
		log_fine("FAILED bufferevent_socket_connect for dst");
		pxy_conn_term(ctx, 1);
		return;
	}

	if (ctx->srvdst_connected && ctx->dst_connected && !ctx->connected) {
		ctx->connected = 1;

		if (prototcp_enable_src(ctx) == -1) {
			return;
		}
	}

	if (!ctx->term && !ctx->enomem) {
		pxy_userauth(ctx);
	}
}

void
prototcp_bev_eventcb_eof_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_finest("ENTER");
	pxy_log_dbg_evbuf_info(ctx, &ctx->src, &ctx->dst);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		log_fine("EOF on outbound connection before connection establishment");
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		log_finest("!dst.closed, terminate conn");
		if (pxy_try_consume_last_input(bev, ctx) == -1) {
			return;
		}
		pxy_try_close_conn_end(&ctx->dst, ctx);
	}

	pxy_try_disconnect(ctx, &ctx->src, &ctx->dst, 1);
}

void
prototcp_bev_eventcb_eof_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_finest("ENTER");
	pxy_log_dbg_evbuf_info(ctx, &ctx->dst, &ctx->src);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		log_fine("EOF on outbound connection before connection establishment");
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		log_finest("!src.closed, terminate conn");
		if (pxy_try_consume_last_input(bev, ctx) == -1) {
			return;
		}
		pxy_try_close_conn_end(&ctx->src, ctx);
	}

	pxy_try_disconnect(ctx, &ctx->dst, &ctx->src, 0);
}

void
prototcp_bev_eventcb_eof_srvdst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment on srvdst\n");
	log_fine("EOF on outbound connection before connection establishment");
	pxy_conn_term(ctx, 0);
}

void
prototcp_bev_eventcb_error_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_fine("ENTER");

	if (!ctx->connected) {
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		pxy_try_close_conn_end(&ctx->dst, ctx);
	}

	pxy_try_disconnect(ctx, &ctx->src, &ctx->dst, 1);
}

void
prototcp_bev_eventcb_error_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_fine("ENTER");

	if (!ctx->connected) {
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		pxy_try_close_conn_end(&ctx->src, ctx);
	}

	pxy_try_disconnect(ctx, &ctx->dst, &ctx->src, 0);
}

void
prototcp_bev_eventcb_error_srvdst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_fine("ENTER");

	if (!ctx->connected) {
		log_fine("!ctx->connected");
		pxy_conn_term(ctx, 0);
	}
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_src_child(UNUSED struct bufferevent *bev, UNUSED pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");

	ctx->connected = 1;
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
}

static void NONNULL(1,2)
prototcp_bev_eventcb_eof_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_finest("ENTER");
	pxy_log_dbg_evbuf_info(ctx->conn, &ctx->src, &ctx->dst);
#endif /* DEBUG_PROXY */

	// @todo How to handle the following case?
	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		log_fine("EOF on outbound connection before connection establishment");

		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		log_finest("!dst.closed, terminate conn");
		if (pxy_try_consume_last_input_child(bev, ctx) == -1) {
			return;
		}
		pxy_try_close_conn_end(&ctx->dst, ctx->conn);
	}

	pxy_try_disconnect_child(ctx, &ctx->src, &ctx->dst);
}

void
prototcp_bev_eventcb_eof_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_finest("ENTER");
	pxy_log_dbg_evbuf_info(ctx->conn, &ctx->dst, &ctx->src);
#endif /* DEBUG_PROXY */

	// @todo How to handle the following case?
	if (!ctx->connected) {
		log_err_level_printf(LOG_WARNING, "EOF on outbound connection before connection establishment\n");
		log_fine("EOF on outbound connection before connection establishment");

		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		log_finest("!src.closed, terminate conn");
		if (pxy_try_consume_last_input_child(bev, ctx) == -1) {
			return;
		}
		pxy_try_close_conn_end(&ctx->src, ctx->conn);
	}

	pxy_try_disconnect_child(ctx, &ctx->dst, &ctx->src);
}

static void NONNULL(1,2)
prototcp_bev_eventcb_error_src_child(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_fine("ENTER");

	if (!ctx->connected) {
		/* the callout to the original destination failed,
		 * e.g. because it asked for client cert auth, so
		 * close the accepted socket and clean up */
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		/* if the other end is still open and doesn't have data
		 * to send, close it, otherwise its writecb will close
		 * it after writing what's left in the output buffer */
		pxy_try_close_conn_end(&ctx->dst, ctx->conn);
	}

	pxy_try_disconnect_child(ctx, &ctx->src, &ctx->dst);
}

void
prototcp_bev_eventcb_error_dst_child(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_fine("ENTER");

	if (!ctx->connected) {
		/* the callout to the original destination failed,
		 * e.g. because it asked for client cert auth, so
		 * close the accepted socket and clean up */
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		/* if the other end is still open and doesn't have data
		 * to send, close it, otherwise its writecb will close
		 * it after writing what's left in the output buffer */
		pxy_try_close_conn_end(&ctx->src, ctx->conn);
	}

	pxy_try_disconnect_child(ctx, &ctx->dst, &ctx->src);
}

void
prototcp_bev_eventcb_src(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_src(bev, ctx);
	}
}

static void NONNULL(1)
prototcp_bev_eventcb_dst(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_dst(bev, ctx);
	}
}

void
prototcp_bev_eventcb_srvdst(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_srvdst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_srvdst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_srvdst(bev, ctx);
	}
}

void
prototcp_bev_eventcb_src_child(struct bufferevent *bev, short events, pxy_conn_child_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		prototcp_bev_eventcb_connected_src_child(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_src_child(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_src_child(bev, ctx);
	}
}

void
prototcp_bev_eventcb_dst_child(struct bufferevent *bev, short events, pxy_conn_child_ctx_t *ctx)
{
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
		prototcp_bev_readcb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_readcb_dst(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		prototcp_bev_readcb_srvdst(bev, ctx);
	} else {
		log_err_printf("prototcp_bev_readcb: UNKWN conn end\n");
	}
}

void
prototcp_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_writecb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_writecb_dst(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		prototcp_bev_writecb_srvdst(bev, ctx);
	} else {
		log_err_printf("prototcp_bev_writecb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
prototcp_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src(bev, events, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_eventcb_dst(bev, events, ctx);
	} else if (bev == ctx->srvdst.bev) {
		prototcp_bev_eventcb_srvdst(bev, events, ctx);
	} else {
		log_err_printf("prototcp_bev_eventcb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
prototcp_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_readcb_src_child(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_readcb_dst_child(bev, ctx);
	} else {
		log_err_printf("prototcp_bev_readcb_child: UNKWN conn end\n");
	}
}

void
prototcp_bev_writecb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_writecb_src_child(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_writecb_dst_child(bev, ctx);
	} else {
		log_err_printf("prototcp_bev_writecb_child: UNKWN conn end\n");
	}
}

static void NONNULL(1)
prototcp_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src_child(bev, events, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_eventcb_dst_child(bev, events, ctx);
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

	return PROTO_TCP;
}

/* vim: set noet ft=c: */
