/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2019, Soner Tari <sonertari@gmail.com>.
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

#include "protoautossl.h"
#include "prototcp.h"
#include "protossl.h"

#include "pxysslshut.h"

#include <string.h>
#include <sys/param.h>
#include <event2/bufferevent_ssl.h>

typedef struct protoautossl_ctx protoautossl_ctx_t;

struct protoautossl_ctx {
	unsigned int clienthello_search : 1;       /* 1 if waiting for hello */
	unsigned int clienthello_found : 1;      /* 1 if conn upgrade to SSL */
};

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
static int NONNULL(1)
protoautossl_peek_and_upgrade(pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

	struct evbuffer *inbuf;
	struct evbuffer_iovec vec_out[1];
	const unsigned char *chello;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_peek_and_upgrade: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Checking for a client hello\n");
	}

	/* peek the buffer */
	inbuf = bufferevent_get_input(ctx->src.bev);
	if (evbuffer_peek(inbuf, 1024, 0, vec_out, 1)) {
		if (ssl_tls_clienthello_parse(vec_out[0].iov_base, vec_out[0].iov_len, 0, &chello, &ctx->sslctx->sni) == 0) {
			if (OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Peek found ClientHello\n");
			}

			// @attention We need srvdst ssl to setup src ssl, otherwise srvdst is closed asap
			if (protossl_setup_srvdst_ssl(ctx) == -1) {
				return -1;
			}
			if (protossl_setup_srvdst_new_bev_ssl_connecting(ctx) == -1) {
				return -1;
			}

#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "protoautossl_peek_and_upgrade: Enabling srvdst, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			bufferevent_setcb(ctx->srvdst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
			bufferevent_enable(ctx->srvdst.bev, EV_READ|EV_WRITE);

			autossl_ctx->clienthello_search = 0;
			autossl_ctx->clienthello_found = 1;
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

static int NONNULL(1) WUNRES
protoautossl_conn_connect(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	// Make a copy of fd, to prevent multithreading issues in case the conn is terminated
	int fd = ctx->fd;
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_conn_connect: ENTER, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	/* create server-side socket and eventbuffer */
	if (prototcp_setup_srvdst(ctx) == -1) {
		return -1;
	}
	
	// Conn setup is successful, so add the conn to the conn list of its thread now
	pxy_thrmgr_add_conn(ctx);

	// Enable srvdst r cb for autossl mode
	bufferevent_setcb(ctx->srvdst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srvdst.bev, (struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "protoautossl_conn_connect: bufferevent_socket_connect for srvdst failed\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "protoautossl_conn_connect: bufferevent_socket_connect for srvdst failed, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

		// @attention Do not try to term/close conns or do anything else with conn ctx on the thrmgr thread after setting event callbacks and/or socket connect. Just return 0.
	}
	return 0;
}

static void NONNULL(1)
protoautossl_connect_child(pxy_conn_child_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_connect_child: ENTER, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	/* create server-side socket and eventbuffer */
	// Children rely on the findings of parent
	if (!autossl_ctx->clienthello_found) {
		prototcp_setup_dst_child(ctx);
	} else {
		protossl_setup_dst_child(ctx);
	}
}

static void NONNULL(1)
protoautossl_bev_readcb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_readcb_src: ENTER, size=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd);
#endif /* DEBUG_PROXY */

	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

	if (prototcp_try_send_userauth_msg(bev, ctx)) {
		return;
	}

	if (autossl_ctx->clienthello_search) {
		if (protoautossl_peek_and_upgrade(ctx)) {
			return;
		}
	}

	if (ctx->dst.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	size_t packet_size = evbuffer_get_length(inbuf);
	// +2 is for \r\n
	unsigned char *packet = pxy_malloc_packet(packet_size + ctx->sslproxy_header_len + 2, ctx);
	if (!packet) {
		return;
	}

	evbuffer_remove(inbuf, packet, packet_size);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_readcb_src: ORIG packet, size=%zu, fd=%d:\n%.*s\n",
			packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

	if (autossl_ctx->clienthello_search) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "protoautossl_bev_readcb_src: clienthello_search Duping packet to srvdst, size=%zu, fd=%d:\n%.*s\n",
				packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

		// Dup packet to server while searching for clienthello in autossl mode, without adding SSLproxy specific header
		evbuffer_add(bufferevent_get_output(ctx->srvdst.bev), packet, packet_size);
		pxy_try_set_watermark(bev, ctx, ctx->srvdst.bev);
	}

	if (!ctx->sent_sslproxy_header) {
		pxy_insert_sslproxy_header(ctx, packet, &packet_size);
	}
	evbuffer_add(outbuf, packet, packet_size);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_readcb_src: NEW packet, size=%zu, fd=%d:\n%.*s\n",
			packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

	free(packet);
	pxy_try_set_watermark(bev, ctx, ctx->dst.bev);
}

static void NONNULL(1)
protoautossl_bev_readcb_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_readcb_dst: ENTER, size=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd);
#endif /* DEBUG_PROXY */

	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

	if (autossl_ctx->clienthello_search) {
		if (protoautossl_peek_and_upgrade(ctx)) {
			return;
		}
	}

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
protoautossl_bev_readcb_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_readcb_srvdst: ENTER, size=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd);
#endif /* DEBUG_PROXY */

	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

	// Make sure src.bev exists
	if (ctx->src.bev) {
		if (prototcp_try_send_userauth_msg(ctx->src.bev, ctx)) {
			return;
		}
		if (autossl_ctx->clienthello_search) {
			if (protoautossl_peek_and_upgrade(ctx)) {
				return;
			}
		}
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	size_t inbuf_size = evbuffer_get_length(inbuf);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protoautossl_bev_readcb_srvdst: clienthello_search Discarding packet, size=%zu, fd=%d\n",
			inbuf_size, ctx->fd);
#endif /* DEBUG_PROXY */

	// Discard packets to client while searching for clienthello in autossl mode, because child conn passes them along already
	// Otherwise client would receive the same packet twice
	evbuffer_drain(inbuf, inbuf_size);
}

static void NONNULL(1,2)
protoautossl_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_eventcb_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
}

static void NONNULL(1)
protoautossl_close_srvdst(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protoautossl_close_srvdst: Closing srvdst, srvdst fd=%d, fd=%d\n", bufferevent_getfd(ctx->srvdst.bev), ctx->fd);
#endif /* DEBUG_PROXY */

	// @attention Free the srvdst of the conn asap, we don't need it anymore, but we need its fd
	// So save its ssl info for logging
	// @todo Do we always have srvdst.ssl or not? Can we use ssl or tcp versions of this function?
	if (ctx->srvdst.ssl) {
		ctx->sslctx->srvdst_ssl_version = strdup(SSL_get_version(ctx->srvdst.ssl));
		ctx->sslctx->srvdst_ssl_cipher = strdup(SSL_get_cipher(ctx->srvdst.ssl));
	}

	// @attention When both eventcb and writecb for srvdst are enabled, either eventcb or writecb may get a NULL srvdst bev, causing a crash with signal 10.
	// So, from this point on, we should check if srvdst is NULL or not.
	ctx->srvdst.free(ctx->srvdst.bev, ctx);
	ctx->srvdst.bev = NULL;
	ctx->srvdst.closed = 1;
}

static int NONNULL(1)
protoautossl_enable_src(pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_enable_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// Create and set up src.bev
	if (!autossl_ctx->clienthello_found) {
		// Create tcp src.bev first
		if (prototcp_setup_src(ctx) == -1) {
			return -1;
		}
	} else {
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Completing autossl upgrade\n");
		}

		// tcp src.bev is already created above
		int rv;
		if ((rv = protossl_setup_src_ssl(ctx)) != 0) {
			return rv;
		}
		// Replace tcp src.bev with ssl version
		if (protossl_setup_src_new_bev_ssl_accepting(ctx) == -1) {
			return -1;
		}
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	// srvdst is not needed after clienthello search is over
	if (ctx->srvdst.bev && !autossl_ctx->clienthello_search) {
		protoautossl_close_srvdst(ctx);
	}

	// Skip child listener setup if completing autossl upgrade, after finding clienthello
	if (autossl_ctx->clienthello_search) {
		if (pxy_setup_child_listener(ctx) == -1) {
			return -1;
		}
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_autossl_enable_src: Enabling src, %s, child_fd=%d, fd=%d\n", ctx->sslproxy_header, ctx->child_fd, ctx->fd);
#endif /* DEBUG_PROXY */

	// Now open the gates, perhaps for a second time in autossl mode
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void NONNULL(1,2)
protoautossl_bev_eventcb_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_eventcb_connected_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->dst_connected = 1;

	// @todo Reduce this if condition
	if (ctx->srvdst_connected && ctx->dst_connected && (!ctx->connected || (autossl_ctx->clienthello_found && ctx->srvdst.bev))) {
		ctx->connected = 1;

		if (protoautossl_enable_src(ctx) == -1) {
			return;
		}
	}
}

static void NONNULL(1,2)
protoautossl_bev_eventcb_connected_srvdst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_eventcb_connected_srvdst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// srvdst may be already connected while upgrading to ssl
	if (!ctx->srvdst_connected) {
		ctx->srvdst_connected = 1;
		bufferevent_enable(ctx->srvdst.bev, EV_READ|EV_WRITE);

		if (prototcp_setup_dst(ctx) == -1) {
			return;
		}
		bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
		if (bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->spec->conn_dst_addr,
				ctx->spec->conn_dst_addrlen) == -1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "protoautossl_bev_eventcb_connected_srvdst: FAILED bufferevent_socket_connect for dst, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_term(ctx, 1);
			return;
		}
	}

	if (ctx->srvdst_connected && ctx->dst_connected && (!ctx->connected || autossl_ctx->clienthello_found)) {
		ctx->connected = 1;

		if (protoautossl_enable_src(ctx) == -1) {
			return;
		}
	}

	if (!ctx->term && !ctx->enomem) {
		pxy_userauth(ctx);
	}
}

static void NONNULL(1)
protoautossl_bev_readcb_complete_upgrade_child(pxy_conn_child_ctx_t *ctx)
{
	if (OPTS_DEBUG(ctx->conn->opts)) {
		log_dbg_printf("Completing autossl upgrade on child conn\n");
	}

	if (protossl_setup_dst_ssl_child(ctx) == -1) {
		return;
	}
	if (protossl_setup_dst_new_bev_ssl_connecting_child(ctx) == -1) {
		return;
	}
	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protoautossl_bev_readcb_complete_upgrade_child: Enabling dst, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);
}

static void NONNULL(1)
protoautossl_bev_readcb_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_readcb_src_child: ENTER, size=%zu, child fd=%d, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;

	// Autossl upgrade on child connections follows the findings of parent
	if (autossl_ctx->clienthello_found && !ctx->dst.ssl) {
		protoautossl_bev_readcb_complete_upgrade_child(ctx);
		return;
	}

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

#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_readcb_src_child: NEW packet, size=%zu, child fd=%d, fd=%d:\n%.*s\n",
				packet_size, ctx->fd, ctx->conn->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

		free(packet);
	} else {
		evbuffer_add_buffer(outbuf, inbuf);
	}
	pxy_try_set_watermark(bev, ctx->conn, ctx->dst.bev);
}

static void NONNULL(1)
protoautossl_bev_readcb_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_readcb_dst_child: ENTER, size=%zu, child fd=%d, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;

	// Autossl upgrade on child connections follows the findings of parent
	if (autossl_ctx->clienthello_found && !ctx->dst.ssl) {
		protoautossl_bev_readcb_complete_upgrade_child(ctx);
		return;
	}

	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);
	evbuffer_add_buffer(outbuf, inbuf);
	pxy_try_set_watermark(bev, ctx->conn, ctx->src.bev);
}

static void NONNULL(1,2)
protoautossl_bev_eventcb_connected_dst_child(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protoautossl_bev_eventcb_connected_dst_child: ENTER, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	ctx->connected = 1;

	// @attention Create and enable src.bev before, but connect here, because we check if dst.bev is NULL elsewhere
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);

	// Check if we have arrived here right after autossl upgrade, which may be triggered by readcb on src
	// Autossl upgrade code leaves readcb without processing any data in input buffer of src
	// So, if we don't call readcb here, the connection would stall
	if (autossl_ctx->clienthello_found && evbuffer_get_length(bufferevent_get_input(ctx->src.bev))) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "protoautossl_bev_eventcb_connected_dst_child: clienthello_found src inbuf len > 0, calling pxy_bev_readcb_child for src, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

		if (pxy_bev_readcb_preexec_logging_and_stats_child(bev, ctx) == -1) {
			return;
		}
		ctx->protoctx->bev_readcb(ctx->src.bev, ctx);
	}
}

static void NONNULL(1)
protoautossl_bev_eventcb_src(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protoautossl_bev_eventcb_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_src(bev, ctx);
	}
}

static void NONNULL(1)
protoautossl_bev_eventcb_dst(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protoautossl_bev_eventcb_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_dst(bev, ctx);
	}
}

static void NONNULL(1)
protoautossl_bev_eventcb_srvdst(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protoautossl_bev_eventcb_connected_srvdst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_srvdst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_srvdst(bev, ctx);
	}
}

static void NONNULL(1)
protoautossl_bev_eventcb_dst_child(struct bufferevent *bev, short events, pxy_conn_child_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protoautossl_bev_eventcb_connected_dst_child(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_dst_child(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_dst_child(bev, ctx);
	}
}

static void NONNULL(1)
protoautossl_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		protoautossl_bev_readcb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		protoautossl_bev_readcb_dst(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protoautossl_bev_readcb_srvdst(bev, ctx);
	} else {
		log_err_printf("protoautossl_bev_readcb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
protoautossl_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		protoautossl_bev_readcb_src_child(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		protoautossl_bev_readcb_dst_child(bev, ctx);
	} else {
		log_err_printf("protoautossl_bev_readcb_child: UNKWN conn end\n");
	}
}

static void NONNULL(1)
protoautossl_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

	if ((events & BEV_EVENT_ERROR) && autossl_ctx->clienthello_found) {
		protossl_log_ssl_error(bev, ctx);
	}

	if (bev == ctx->src.bev) {
		protoautossl_bev_eventcb_src(bev, events, ctx);
	} else if (bev == ctx->dst.bev) {
		protoautossl_bev_eventcb_dst(bev, events, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protoautossl_bev_eventcb_srvdst(bev, events, ctx);
	} else {
		log_err_printf("protoautossl_bev_eventcb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
protoautossl_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src_child(bev, events, ctx);
	} else if (bev == ctx->dst.bev) {
		protoautossl_bev_eventcb_dst_child(bev, events, ctx);
	} else {
		log_err_printf("protoautossl_bev_eventcb_child: UNKWN conn end\n");
	}
}

static void NONNULL(1)
protoautossl_free(pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
	free(autossl_ctx);
	protossl_free(ctx);
}

protocol_t
protoautossl_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_AUTOSSL;
	ctx->protoctx->connectcb = protoautossl_conn_connect;
	ctx->protoctx->fd_readcb = prototcp_fd_readcb;
	
	ctx->protoctx->bev_readcb = protoautossl_bev_readcb;
	ctx->protoctx->bev_writecb = prototcp_bev_writecb;
	ctx->protoctx->bev_eventcb = protoautossl_bev_eventcb;

	ctx->protoctx->proto_free = protoautossl_free;

	ctx->protoctx->arg = malloc(sizeof(protoautossl_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protoautossl_ctx_t));
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
	autossl_ctx->clienthello_search = 1;

	ctx->sslctx = malloc(sizeof(ssl_ctx_t));
	if (!ctx->sslctx) {
		free(ctx->protoctx->arg);
		return PROTO_ERROR;
	}
	memset(ctx->sslctx, 0, sizeof(ssl_ctx_t));

	return PROTO_AUTOSSL;
}

protocol_t
protoautossl_setup_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_AUTOSSL;
	ctx->protoctx->connectcb = protoautossl_connect_child;

	ctx->protoctx->bev_readcb = protoautossl_bev_readcb_child;
	ctx->protoctx->bev_writecb = prototcp_bev_writecb_child;
	ctx->protoctx->bev_eventcb = protoautossl_bev_eventcb_child;

	return PROTO_AUTOSSL;
}

/* vim: set noet ft=c: */
