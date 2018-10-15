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

#include "protoautossl.h"
#include "pxysslshut.h"

#include <string.h>
#include <sys/param.h>
#include <event2/bufferevent_ssl.h>

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
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

	struct evbuffer *inbuf;
	struct evbuffer_iovec vec_out[1];
	const unsigned char *chello;

	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Checking for a client hello\n");
	}
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_autossl_peek_and_upgrade: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	/* peek the buffer */
	inbuf = bufferevent_get_input(ctx->src.bev);
	if (evbuffer_peek(inbuf, 1024, 0, vec_out, 1)) {
		if (ssl_tls_clienthello_parse(vec_out[0].iov_base, vec_out[0].iov_len, 0, &chello, &ctx->sslctx->sni) == 0) {
			if (OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Peek found ClientHello\n");
			}

			ctx->srv_dst.ssl = pxy_dstssl_create(ctx);
			if (!ctx->srv_dst.ssl) {
				log_err_level_printf(LOG_CRIT, "Error creating SSL for upgrade\n");
				// @todo Should we close the connection?
				return 0;
			}

			ctx->srv_dst.bev = bufferevent_openssl_filter_new(ctx->evbase, ctx->srv_dst.bev, ctx->srv_dst.ssl,
					BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
			if (!ctx->srv_dst.bev) {
				log_err_level_printf(LOG_CRIT, "Error creating bufferevent\n");
				if (ctx->srv_dst.ssl) {
					SSL_free(ctx->srv_dst.ssl);
					ctx->srv_dst.ssl = NULL;
				}
				// @todo Should we close the connection?
				return 0;
			}

			bufferevent_setcb(ctx->srv_dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_autossl_peek_and_upgrade: Enabling srv_dst, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			bufferevent_enable(ctx->srv_dst.bev, EV_READ|EV_WRITE);

			if (OPTS_DEBUG(ctx->opts)) {
				log_err_level_printf(LOG_INFO, "Replaced srv_dst bufferevent, new one is %p\n", (void *)ctx->srv_dst.bev);
			}

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

static void
pxy_bev_eventcb_autossl_connected_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_autossl_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_log_connect_src(ctx);
}

static int
pxy_autossl_enable_src(pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_autossl_enable_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->connected = 1;

	// Create and set up src.bev
	if (autossl_ctx->clienthello_found) {
		// ctx->src.bev must have already been created at this point
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Completing autossl upgrade\n");
		}
		int rv;
		if ((rv = pxy_setup_src_ssl(ctx)) != 0) {
			return rv;
		}
		if (pxy_setup_new_src(ctx) == -1) {
			return -1;
		}
	} else {
		if (pxy_setup_src(ctx) == -1) {
			return -1;
		}
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	if (pxy_set_dstaddr(ctx) == -1) {
		return -1;
	}

	if (pxy_prepare_logging(ctx) == -1) {
		return -1;
	}

	// srv_dst is not needed after clienthello search is over
	if (ctx->srv_dst.bev && !autossl_ctx->clienthello_search) {
		pxy_close_srv_dst(ctx);
	}

	// Skip child listener setup if completing autossl upgrade, after finding clienthello
	if (autossl_ctx->clienthello_search) {
		if (pxy_setup_child_listener(ctx) == -1) {
			return -1;
		}
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_autossl_enable_src: Enabling src, %s, fd=%d, child_fd=%d\n", ctx->header_str, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */
	// Now open the gates, perhaps for a second time in autossl mode
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void
pxy_bev_eventcb_autossl_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_autossl_connected_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->dst_connected = 1;

	if (ctx->srv_dst_connected && ctx->dst_connected && (!ctx->connected || (autossl_ctx->clienthello_found && ctx->srv_dst.bev))) {
		if (pxy_autossl_enable_src(ctx) == -1) {
			return;
		}
	}

	if (ctx->connected) {
		pxy_log_connect_srv_dst(ctx);
	}
}

static void
pxy_bev_eventcb_autossl_connected_srv_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_autossl_connected_srv_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// srv_dst may be already connected while upgrading to ssl
	if (!ctx->srv_dst_connected) {
		ctx->srv_dst_connected = 1;
		ctx->srv_dst_fd = bufferevent_getfd(ctx->srv_dst.bev);
		ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->srv_dst_fd);

		// @attention Create and enable dst.bev before, but connect here, because we check if dst.bev is NULL elsewhere
		if (bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->spec->conn_dst_addr,
				ctx->spec->conn_dst_addrlen) == -1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "pxy_bev_eventcb_autossl_connected_srv_dst: FAILED bufferevent_socket_connect for dst, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			pxy_conn_free(ctx, 1);
			return;
		}
		ctx->dst_fd = bufferevent_getfd(ctx->dst.bev);
		ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->dst_fd);
	}

	if (ctx->srv_dst_connected && ctx->dst_connected && (!ctx->connected || (autossl_ctx->clienthello_found && ctx->srv_dst.bev))) {
		if (pxy_autossl_enable_src(ctx) == -1) {
			return;
		}
	}

	if (ctx->connected) {
		pxy_log_connect_srv_dst(ctx);
	}
}

static void
pxy_bev_readcb_autossl_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_autossl_src: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	if (autossl_ctx->clienthello_search) {
		if (pxy_conn_autossl_peek_and_upgrade(ctx)) {
			return;
		}
	}

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
		log_err_printf("pxy_bev_readcb_autossl_src: evbuffer_remove failed, fd=%d\n", ctx->fd);
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_autossl_src: ORIG packet (size=%zu), fd=%d:\n%.*s\n",
			packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

	if (autossl_ctx->clienthello_search) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_autossl_src: clienthello_search Duping packet to srv_dst (size=%zu), fd=%d:\n%.*s\n",
				packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */
		// Dup packet to server while searching for clienthello in autossl mode, without adding SSLproxy specific header
		if (evbuffer_add(bufferevent_get_output(ctx->srv_dst.bev), packet, packet_size) == -1) {
			log_err_printf("pxy_bev_readcb_autossl_src: clienthello_search srv_dst evbuffer_add failed, fd=%d\n", ctx->fd);
		}
	}

	pxy_insert_sslproxy_header(ctx, packet, &packet_size);

	if (evbuffer_add(outbuf, packet, packet_size) == -1) {
		log_err_printf("pxy_bev_readcb_autossl_src: evbuffer_add failed, fd=%d\n", ctx->fd);
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_autossl_src: NEW packet (size=%zu), fd=%d:\n%.*s\n",
			packet_size, ctx->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */
	free(packet);
	pxy_set_watermark(bev, ctx, ctx->dst.bev);
}

static void
pxy_bev_readcb_autossl_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_autossl_dst: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	if (autossl_ctx->clienthello_search) {
		if (pxy_conn_autossl_peek_and_upgrade(ctx)) {
			return;
		}
	}

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
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_autossl_dst: dst packet size=%zu, fd=%d\n", inbuf_size, ctx->fd);
#endif /* DEBUG_PROXY */
	evbuffer_add_buffer(outbuf, inbuf);
	pxy_set_watermark(bev, ctx, ctx->src.bev);
}

static void
pxy_bev_readcb_autossl_srv_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_autossl_srv_dst: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	if (autossl_ctx->clienthello_search) {
		if (pxy_conn_autossl_peek_and_upgrade(ctx)) {
			return;
		}
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	size_t inbuf_size = evbuffer_get_length(inbuf);

	// Discard packets to client while searching for clienthello in autossl mode, because child conn passes them along already
	// Otherwise client would receive the same packet twice
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_autossl_srv_dst: clienthello_search Discarding packet, size=%zu, fd=%d\n",
			inbuf_size, ctx->fd);
#endif /* DEBUG_PROXY */
	if (evbuffer_drain(inbuf, inbuf_size) == -1) {
		log_err_printf("pxy_bev_readcb_autossl_srv_dst: clienthello_search evbuffer_drain failed, fd=%d\n", ctx->fd);
	}
	return;
}

static void
pxy_bev_readcb_child_complete_autossl(pxy_conn_child_ctx_t *ctx)
{
	if (OPTS_DEBUG(ctx->conn->opts)) {
		log_dbg_printf("Completing autossl upgrade on child conn\n");
	}

	ctx->dst.ssl = pxy_dstssl_create(ctx->conn);
	if (!ctx->dst.ssl) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child_complete_autossl: Error creating SSL for upgrade\n");
		ctx->conn->enomem = 1;
		pxy_conn_free(ctx->conn, 1);
		return;
	}
	ctx->dst.bev = bufferevent_openssl_filter_new(ctx->conn->evbase, ctx->dst.bev, ctx->dst.ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child_complete_autossl: Error creating bufferevent\n");
		ctx->conn->enomem = 1;
		if (ctx->dst.ssl) {
			SSL_free(ctx->dst.ssl);
			ctx->dst.ssl = NULL;
		}
		pxy_conn_free(ctx->conn, 1);
		return;
	}
	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_complete_autossl: Enabling dst, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);
	if (OPTS_DEBUG(ctx->conn->opts)) {
		log_err_level_printf(LOG_INFO, "pxy_bev_readcb_child_complete_autossl: Replaced dst bufferevent, new one is %p\n", (void *)ctx->dst.bev);
	}
}

static void
pxy_bev_readcb_child_autossl_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_autossl_src: ENTER, fd=%d, conn fd=%d, size=%zu\n",
			ctx->fd, ctx->conn->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
		
	// Autossl upgrade on child connections follows the findings of parent
	if (autossl_ctx->clienthello_found && !ctx->dst.ssl) {
		pxy_bev_readcb_child_complete_autossl(ctx);
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
		log_err_printf("pxy_bev_readcb_child_autossl_src: src evbuffer_remove failed, fd=%d\n", ctx->fd);
	}

	pxy_remove_sslproxy_header(packet, &packet_size, ctx);

	if (evbuffer_add(outbuf, packet, packet_size) == -1) {
		log_err_printf("pxy_bev_readcb_child_autossl_src: src evbuffer_add failed, fd=%d\n", ctx->fd);
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_autossl_src: src packet (size=%zu), fd=%d, conn fd=%d:\n%.*s\n",
			packet_size, ctx->fd, ctx->conn->fd, (int)packet_size, packet);
#endif /* DEBUG_PROXY */

	pxy_log_content_buf((pxy_conn_ctx_t *)ctx, packet, packet_size, 1);
	free(packet);

	pxy_set_watermark(bev, ctx->conn, ctx->dst.bev);
}

static void
pxy_bev_readcb_child_autossl_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_autossl_dst: ENTER, fd=%d, conn fd=%d, size=%zu\n",
			ctx->fd, ctx->conn->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */
		
	// Autossl upgrade on child connections follows the findings of parent
	if (autossl_ctx->clienthello_found && !ctx->dst.ssl) {
		pxy_bev_readcb_child_complete_autossl(ctx);
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
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_readcb_child_autossl_dst: dst packet size=%zu, fd=%d\n", inbuf_size, ctx->fd);
#endif /* DEBUG_PROXY */
	pxy_log_content_inbuf((pxy_conn_ctx_t *)ctx, inbuf, 0);

	evbuffer_add_buffer(outbuf, inbuf);
}

static void
protoautossl_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "protoautossl_bev_readcb: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (bev == ctx->src.bev) {
		pxy_bev_readcb_autossl_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_readcb_autossl_dst(bev, arg);
	} else if (bev == ctx->srv_dst.bev) {
		pxy_bev_readcb_autossl_srv_dst(bev, arg);
	} else {
		log_err_printf("protoautossl_bev_readcb: UNKWN conn end\n");
	}
}

static void
pxy_bev_readcb_child_autossl(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (!ctx->connected) {
		log_err_level_printf(LOG_CRIT, "pxy_bev_readcb_child_autossl: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
	}

	if (bev == ctx->src.bev) {
		pxy_bev_readcb_child_autossl_src(bev, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_readcb_child_autossl_dst(bev, arg);
	} else {
		log_err_printf("pxy_bev_readcb_child_autossl: UNKWN conn end\n");
	}
}

static void
pxy_bev_eventcb_child_autossl_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;
	ctx->conn->atime = time(NULL);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child_autossl_connected_dst: ENTER, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	ctx->connected = 1;

	// @attention Create and enable src.bev before, but connect here, because we check if dst.bev is NULL elsewhere
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);

	// Check if we have come here right after autossl upgrade, which may be triggered by readcb on src
	// Autossl upgrade code leaves readcb without processing any data in input buffer of src
	// So, if we don't call readcb here, the connection would stall
	if (autossl_ctx->clienthello_found && evbuffer_get_length(bufferevent_get_input(ctx->src.bev))) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_bev_eventcb_child_autossl_connected_dst: clienthello_found src inbuf len > 0, Calling pxy_bev_readcb_child for src, fd=%d, conn fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */
		pxy_bev_readcb_child(ctx->src.bev, ctx);
	}
	ctx->conn->thr->max_fd = MAX(ctx->conn->thr->max_fd, MAX(bufferevent_getfd(ctx->src.bev), bufferevent_getfd(ctx->dst.bev)));
}

static void
pxy_conn_connect_autossl(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_conn_connect_autossl: ENTER fd=%d\n", ctx->fd);
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
	
	// Enable srv_dst r cb for autossl modes
	bufferevent_setcb(ctx->srv_dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->srv_dst.bev, EV_READ|EV_WRITE);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srv_dst.bev, (struct sockaddr *)&ctx->addr, ctx->addrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "pxy_conn_connect_autossl: bufferevent_socket_connect for srv_dst failed\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINER, "pxy_conn_connect_autossl: bufferevent_socket_connect for srv_dst failed, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
	}
}

static void
pxy_connect_child_autossl(pxy_conn_child_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "pxy_connect_child_autossl: ENTER, conn fd=%d, child_fd=%d\n", ctx->conn->fd, ctx->conn->child_fd);
#endif /* DEBUG_PROXY */

	/* create server-side socket and eventbuffer */
	// Children rely on the findings of parent
	if (autossl_ctx->clienthello_found) {
		ctx->dst.ssl = pxy_dstssl_create(ctx->conn);
		if (!ctx->dst.ssl) {
			log_err_level_printf(LOG_CRIT, "Error creating SSL\n");
			// pxy_conn_free()>pxy_conn_free_child() will close the fd, since we have a non-NULL src.bev now
			pxy_conn_free(ctx->conn, 1);
			return;
		}
	}

	ctx->dst.bev = pxy_bufferevent_setup_child(ctx, -1, ctx->dst.ssl);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent\n");
		if (ctx->dst.ssl) {
			SSL_free(ctx->dst.ssl);
			ctx->dst.ssl = NULL;
		}
		pxy_conn_free(ctx->conn, 1);
		return;
	}
}

static void
pxy_bev_eventcb_src_autossl(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_autossl_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_src(bev, ctx);
	}
}

static void
pxy_bev_eventcb_dst_autossl(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_autossl_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_dst(bev, ctx);
	}
}

static void
pxy_bev_eventcb_srv_dst_autossl(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_autossl_connected_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_srv_dst(bev, ctx);
	}
}

static void
pxy_bev_eventcb_autossl(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (bev == ctx->src.bev) {
		pxy_bev_eventcb_src_autossl(bev, events, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_eventcb_dst_autossl(bev, events, arg);
	} else if (bev == ctx->srv_dst.bev) {
		pxy_bev_eventcb_srv_dst_autossl(bev, events, arg);
	} else {
		log_err_printf("pxy_bev_eventcb_autossl: UNKWN conn end\n");
	}
}

static void
pxy_bev_eventcb_child_dst_autossl(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_child_autossl_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_child_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_child_error_dst(bev, ctx);
	}
}

static void
pxy_bev_eventcb_autossl_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	ctx->conn->atime = time(NULL);

	if (bev == ctx->src.bev) {
		pxy_bev_eventcb_child_src(bev, events, arg);
	} else if (bev == ctx->dst.bev) {
		pxy_bev_eventcb_child_dst_autossl(bev, events, arg);
	} else {
		log_err_printf("pxy_bev_eventcb_autossl_child: UNKWN conn end\n");
	}
}

static void
bufferevent_free_and_close_fd_autossl(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "bufferevent_free_and_close_fd_autossl: ENTER i:%zu o:%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(bev)), fd);
#endif /* DEBUG_PROXY */

	SSL *ssl = NULL;

	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
	if (autossl_ctx->clienthello_found) {
		ssl = bufferevent_openssl_get_ssl(bev); /* does not inc refc */
	}

	// @todo Check if we need to NULL all cbs?
	// @see https://stackoverflow.com/questions/31688709/knowing-all-callbacks-have-run-with-libevent-and-bufferevent-free
	//bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	bufferevent_free(bev); /* does not free SSL unless the option BEV_OPT_CLOSE_ON_FREE was set */
	if (ssl) {
		pxy_ssl_shutdown(ctx->opts, ctx->evbase, ssl, fd);
	} else {
		if (evutil_closesocket(fd) == -1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "bufferevent_free_and_close_fd_autossl: evutil_closesocket FAILED, fd=%d\n", fd);
#endif /* DEBUG_PROXY */
		}
	}
}

static void
protoautossl_free(pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
	free(autossl_ctx);
	protossl_free(ctx);
}

enum protocol
protoautossl_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_AUTOSSL;
	ctx->protoctx->connectcb = pxy_conn_connect_autossl;
	ctx->protoctx->fd_readcb = pxy_fd_readcb_tcp;
	
	ctx->protoctx->bev_readcb = protoautossl_bev_readcb;
	ctx->protoctx->bev_writecb = pxy_bev_writecb_tcp;
	ctx->protoctx->bev_eventcb = pxy_bev_eventcb_autossl;

	ctx->protoctx->bufferevent_free_and_close_fd = bufferevent_free_and_close_fd_autossl;
	ctx->protoctx->proto_free = protoautossl_free;

	ctx->protoctx->arg = malloc(sizeof(protoautossl_ctx_t));
	if (!ctx->protoctx->arg) {
		free(ctx->protoctx);
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protoautossl_ctx_t));
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
	autossl_ctx->clienthello_search = 1;

	ctx->sslctx = malloc(sizeof(ssl_ctx_t));
	if (!ctx->sslctx) {
		free(ctx->protoctx->arg);
		free(ctx->protoctx);
		return PROTO_ERROR;
	}
	memset(ctx->sslctx, 0, sizeof(ssl_ctx_t));

	return PROTO_AUTOSSL;
}

enum protocol
protoautossl_setup_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_AUTOSSL;
	ctx->protoctx->connectcb = pxy_connect_child_autossl;

	ctx->protoctx->bev_readcb = pxy_bev_readcb_child_autossl;
	ctx->protoctx->bev_writecb = pxy_bev_writecb_tcp_child;
	ctx->protoctx->bev_eventcb = pxy_bev_eventcb_autossl_child;

	ctx->protoctx->bufferevent_free_and_close_fd = bufferevent_free_and_close_fd_autossl;
	return PROTO_AUTOSSL;
}

/* vim: set noet ft=c: */
