/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2025, Soner Tari <sonertari@gmail.com>.
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

#include <string.h>
#include <sys/param.h>
#include <event2/bufferevent_ssl.h>

typedef struct protoautossl_ctx protoautossl_ctx_t;

struct protoautossl_ctx {
	unsigned int clienthello_search : 1;       /* 1 if waiting for hello */
	unsigned int clienthello_found : 1;      /* 1 if conn upgrade to SSL */
};

#ifdef DEBUG_PROXY
static void NONNULL(1,2,3)
protoautossl_log_dbg_evbuf_info(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this, pxy_conn_desc_t *other)
{
	// This function is used by child conns too, they pass ctx->conn instead of ctx
	if (OPTS_DEBUG(ctx->global)) {
		prototcp_log_dbg_evbuf_info(ctx, &ctx->src, &ctx->dst);

		struct bufferevent *ubev = bufferevent_get_underlying(this->bev);
		struct bufferevent *ubev_other = other->closed ? NULL : bufferevent_get_underlying(other->bev);
		if (ubev || ubev_other)
			log_dbg_printf("underlying evbuffer size at EOF: i:%zu o:%zu i:%zu o:%zu\n",
							ubev ? evbuffer_get_length(bufferevent_get_input(ubev)) : 0,
							ubev ? evbuffer_get_length(bufferevent_get_output(ubev)) : 0,
							ubev_other ? evbuffer_get_length(bufferevent_get_input(ubev_other)) : 0,
							ubev_other ? evbuffer_get_length(bufferevent_get_output(ubev_other)) : 0);
	}
}
#endif /* DEBUG_PROXY */

/*
 * Free bufferevent and close underlying socket properly.
 * For OpenSSL bufferevents, this will shutdown the SSL connection.
 */
static void
protoautossl_bufferevent_free_and_close_fd(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	SSL *ssl = bufferevent_openssl_get_ssl(bev); /* does not inc refc */
	struct bufferevent *ubev = bufferevent_get_underlying(bev);
	evutil_socket_t fd;

	if (ubev) {
		fd = bufferevent_getfd(ubev);
	} else {
		fd = bufferevent_getfd(bev);
	}

	log_finer_va("in=%zu (ubev in=%zu), out=%zu (ubev out=%zu), fd=%d",
		evbuffer_get_length(bufferevent_get_input(bev)), ubev ? evbuffer_get_length(bufferevent_get_input(ubev)) : 0,
		evbuffer_get_length(bufferevent_get_output(bev)), ubev ? evbuffer_get_length(bufferevent_get_output(ubev)) : 0, fd);

	// @see https://stackoverflow.com/questions/31688709/knowing-all-callbacks-have-run-with-libevent-and-bufferevent-free
	bufferevent_disable(bev, EV_READ|EV_WRITE);
	bufferevent_setcb(bev, NULL, NULL, NULL, NULL);

	/*
	 * See the comments in protossl_bufferevent_free_and_close_fd()
	 *
	 * Note that in the case of autossl, the SSL object operates on
	 * a BIO wrapper around the underlying bufferevent.
	 */
	SSL_set_shutdown(ssl, SSL_RECEIVED_SHUTDOWN);
	SSL_shutdown(ssl);

	if (ubev) {
		bufferevent_disable(ubev, EV_READ|EV_WRITE);
		bufferevent_setcb(ubev, NULL, NULL, NULL, NULL);
		bufferevent_setfd(ubev, -1);
		bufferevent_free(ubev);
	}
	bufferevent_free(bev);

	if (OPTS_DEBUG(ctx->global)) {
		char *str = ssl_ssl_state_to_str(ssl, "SSL_free() in state ", 1);
		if (str)
			log_dbg_print_free(str);
	}
#ifdef DEBUG_PROXY
	char *str = ssl_ssl_state_to_str(ssl, "SSL_free() in state ", 0);
	if (str) {
		log_finer_va("fd=%d, %s", fd, str);
		free(str);
	}
#endif /* DEBUG_PROXY */

	SSL_free(ssl);
	/* bufferevent_getfd() returns -1 if no file descriptor is associated
	 * with the bufferevent */
	if (fd >= 0)
		evutil_closesocket(fd);
}

static int NONNULL(1) WUNRES
protoautossl_setup_src_new_bev_ssl_accepting(pxy_conn_ctx_t *ctx)
{
	ctx->src.bev = bufferevent_openssl_filter_new(ctx->thr->evbase, ctx->src.bev, ctx->src.ssl,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating src bufferevent\n");
		SSL_free(ctx->src.ssl);
		ctx->src.ssl = NULL;
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->src.free = protoautossl_bufferevent_free_and_close_fd;
	return 0;
}

static int NONNULL(1) WUNRES
protoautossl_setup_dst_new_bev_ssl_connecting(pxy_conn_ctx_t *ctx)
{
	ctx->dst.bev = bufferevent_openssl_filter_new(ctx->thr->evbase, ctx->dst.bev, ctx->dst.ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating dst bufferevent\n");
		SSL_free(ctx->dst.ssl);
		ctx->dst.ssl = NULL;
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->dst.free = protoautossl_bufferevent_free_and_close_fd;
	return 0;
}

static int NONNULL(1) WUNRES
protoautossl_upgrade_dst(pxy_conn_ctx_t *ctx)
{
	if (protossl_setup_dst_ssl(ctx) == -1) {
		return -1;
	}
	if (protoautossl_setup_dst_new_bev_ssl_connecting(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	return 0;
}

static int NONNULL(1) WUNRES
protoautossl_setup_srvdst_new_bev_ssl_connecting(pxy_conn_ctx_t *ctx)
{
	ctx->srvdst.bev = bufferevent_openssl_filter_new(ctx->thr->evbase, ctx->srvdst.bev, ctx->srvdst.ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->srvdst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating srvdst bufferevent\n");
		SSL_free(ctx->srvdst.ssl);
		ctx->srvdst.ssl = NULL;
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->srvdst.free = protoautossl_bufferevent_free_and_close_fd;
	return 0;
}

static int NONNULL(1) WUNRES
protoautossl_upgrade_srvdst(pxy_conn_ctx_t *ctx)
{
	if (protossl_setup_srvdst_ssl(ctx) == -1) {
		return -1;
	}
	if (protoautossl_setup_srvdst_new_bev_ssl_connecting(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->srvdst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	return 0;
}

static int NONNULL(1) WUNRES
protoautossl_setup_dst_new_bev_ssl_connecting_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->dst.bev = bufferevent_openssl_filter_new(ctx->conn->thr->evbase, ctx->dst.bev, ctx->dst.ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating dst bufferevent\n");
		SSL_free(ctx->dst.ssl);
		ctx->dst.ssl = NULL;
		pxy_conn_term(ctx->conn, 1);
		return -1;
	}
	ctx->dst.free = protoautossl_bufferevent_free_and_close_fd;
	return 0;
}

static int NONNULL(1) WUNRES
protoautossl_upgrade_dst_child(pxy_conn_child_ctx_t *ctx)
{
	if (protossl_setup_dst_ssl_child(ctx) == -1) {
		return -1;
	}
	if (protoautossl_setup_dst_new_bev_ssl_connecting_child(ctx) == -1) {
		return -1;
	}
	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);
	return 0;
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
static int NONNULL(1)
protoautossl_peek_and_upgrade(pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

	struct evbuffer *inbuf;
	struct evbuffer_iovec vec_out[1];
	const unsigned char *chello;

	log_finest("ENTER");

	if (OPTS_DEBUG(ctx->global)) {
		log_dbg_printf("Checking for a client hello\n");
	}

	/* peek the buffer */
	inbuf = bufferevent_get_input(ctx->src.bev);
	if (evbuffer_peek(inbuf, 2048, 0, vec_out, 1)) {
		if (ssl_tls_clienthello_parse(vec_out[0].iov_base, vec_out[0].iov_len, 0, &chello, &ctx->sslctx->sni) == 0) {
			if (OPTS_DEBUG(ctx->global)) {
				log_dbg_printf("Peek found ClientHello\n");
			}

			if (ctx->divert) {
				if (!ctx->children) {
					// This means that there was no autossl handshake prior to ClientHello, e.g. no STARTTLS message
					// This is perhaps the SSL handshake of a direct SSL connection
					log_fine("Upgrading srvdst, no child conn set up yet");
					if (protoautossl_upgrade_srvdst(ctx) == -1) {
						return -1;
					}
					bufferevent_enable(ctx->srvdst.bev, EV_READ|EV_WRITE);
				}
				else {
					// @attention Autossl protocol should never have multiple children.
					log_fine("Upgrading child dst");
					if (protoautossl_upgrade_dst_child(ctx->children) == -1) {
						return -1;
					}
				}

				// Change p in sslproxy_header to s
				if (ctx->sslproxy_header) {
					free(ctx->sslproxy_header);
					ctx->sslproxy_header = NULL;
					ctx->sslproxy_header_len = 0;
					if (pxy_set_sslproxy_header(ctx, 1) == -1) {
						return -1;
					}
				} else {
					log_err_level(LOG_CRIT, "No sslproxy_header set up in divert mode in autossl");
					return -1;
				}
			} else {
				// srvdst == dst in split mode
				if (protoautossl_upgrade_dst(ctx) == -1) {
					return -1;
				}
				bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);
			}

			autossl_ctx->clienthello_search = 0;
			autossl_ctx->clienthello_found = 1;
			return 1;
		} else {
			if (OPTS_DEBUG(ctx->global)) {
				log_dbg_printf("Peek found no ClientHello\n");
			}
		}
	}
	return 0;
}

static int NONNULL(1) WUNRES
protoautossl_conn_connect(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	/* create server-side socket and eventbuffer */
	if (prototcp_setup_srvdst(ctx) == -1) {
		return -1;
	}
	
	// Enable srvdst r cb for autossl mode
	bufferevent_setcb(ctx->srvdst.bev, pxy_bev_readcb, NULL, pxy_bev_eventcb, ctx);
	return 0;
}

static void
protoautossl_try_set_watermark(struct bufferevent *bev, pxy_conn_ctx_t *ctx, struct bufferevent *other)
{
	struct bufferevent *ubev_other = bufferevent_get_underlying(other);
	if (evbuffer_get_length(bufferevent_get_output(other)) >= OUTBUF_LIMIT ||
			(ubev_other && evbuffer_get_length(bufferevent_get_output(ubev_other)) >= OUTBUF_LIMIT)) {
		log_fine_va("%s", prototcp_get_event_name(bev, ctx));

		/* temporarily disable data source;
		 * set an appropriate watermark. */
		bufferevent_setwatermark(other, EV_WRITE, OUTBUF_LIMIT/2, OUTBUF_LIMIT);
		bufferevent_disable(bev, EV_READ);

		/* The watermark for ubev_other may be already set, see pxy_try_unset_watermark,
		 * but getting is equally expensive as setting */
		if (ubev_other)
			bufferevent_setwatermark(ubev_other, EV_WRITE, OUTBUF_LIMIT/2, OUTBUF_LIMIT);

		ctx->thr->set_watermarks++;
	}
}

static void
protoautossl_try_unset_watermark(struct bufferevent *bev, pxy_conn_ctx_t *ctx, pxy_conn_desc_t *other)
{
	if (other->bev && !(bufferevent_get_enabled(other->bev) & EV_READ)) {
		log_fine_va("%s", prototcp_get_event_name(bev, ctx));

		/* data source temporarily disabled;
		 * re-enable and reset watermark to 0. */
		bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
		bufferevent_enable(other->bev, EV_READ);

		/* Do not reset the watermark for ubev without checking its buf len,
		 * because the current write event may be due to the buf len of bev
		 * falling below OUTBUF_LIMIT/2, not that of ubev */
		struct bufferevent *ubev = bufferevent_get_underlying(bev);
		if (ubev && evbuffer_get_length(bufferevent_get_output(ubev)) < OUTBUF_LIMIT/2)
			bufferevent_setwatermark(ubev, EV_WRITE, 0, 0);

		ctx->thr->unset_watermarks++;
	}
}

static void NONNULL(1)
protoautossl_try_discard_inbuf(struct bufferevent *bev)
{
	prototcp_try_discard_inbuf(bev);

	struct bufferevent *ubev = bufferevent_get_underlying(bev);
	if (ubev) {
		struct evbuffer *ubev_inbuf = bufferevent_get_input(ubev);
		size_t ubev_inbuf_size = evbuffer_get_length(ubev_inbuf);
		if (ubev_inbuf_size) {
			log_dbg_printf("Warning: Drained %zu bytes from inbuf underlying\n", ubev_inbuf_size);
			evbuffer_drain(ubev_inbuf, ubev_inbuf_size);
		}
	}
}

static void NONNULL(1)
protoautossl_try_discard_outbuf(struct bufferevent *bev)
{
	prototcp_try_discard_outbuf(bev);

	struct bufferevent *ubev = bufferevent_get_underlying(bev);
	if (ubev) {
		struct evbuffer *ubev_outbuf = bufferevent_get_output(ubev);
		size_t ubev_outbuf_size = evbuffer_get_length(ubev_outbuf);
		if (ubev_outbuf_size) {
			log_dbg_printf("Warning: Drained %zu bytes from outbuf underlying\n", ubev_outbuf_size);
			evbuffer_drain(ubev_outbuf, ubev_outbuf_size);
		}
	}
}

static void NONNULL(1)
protoautossl_bev_readcb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));

	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

#ifndef WITHOUT_USERAUTH
	if (prototcp_try_send_userauth_msg(bev, ctx)) {
		return;
	}
#endif /* !WITHOUT_USERAUTH */

	if (pxy_conn_apply_deferred_block_action(ctx)) {
		return;
	}

	if (autossl_ctx->clienthello_search) {
		if (protoautossl_peek_and_upgrade(ctx) != 0) {
			return;
		}
	}

	if (ctx->dst.closed) {
		ctx->protoctx->discard_inbufcb(bev);
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	// @todo Validate proto?

	if (pxy_try_prepend_sslproxy_header(ctx, inbuf, outbuf) != 0) {
		return;
	}

	ctx->protoctx->set_watermarkcb(bev, ctx, ctx->dst.bev);
}

static void NONNULL(1)
protoautossl_bev_readcb_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));

	// @todo We should validate the response from the server to protect the client,
	// as we do with the smtp protocol, @see protosmtp_bev_readcb_srvdst()

	if (ctx->src.closed) {
		ctx->protoctx->discard_inbufcb(bev);
		return;
	}

#ifndef WITHOUT_USERAUTH
	if (prototcp_try_send_userauth_msg(ctx->src.bev, ctx)) {
		return;
	}
#endif /* !WITHOUT_USERAUTH */

	evbuffer_add_buffer(bufferevent_get_output(ctx->src.bev), bufferevent_get_input(bev));
	ctx->protoctx->set_watermarkcb(bev, ctx, ctx->src.bev);
}

static int NONNULL(1) WUNRES
protoautossl_outbuf_has_data(struct bufferevent *bev
#ifdef DEBUG_PROXY
	, char *reason, pxy_conn_ctx_t *ctx
#endif /* DEBUG_PROXY */
	)
{
	size_t outbuflen = evbuffer_get_length(bufferevent_get_output(bev));
	struct bufferevent *ubev = bufferevent_get_underlying(bev);
	if (outbuflen || (ubev && evbuffer_get_length(bufferevent_get_output(ubev)))) {
		log_finest_va("Not closing %s, outbuflen=%zu, ubev outbuflen=%zu", reason,
				outbuflen, ubev ? evbuffer_get_length(bufferevent_get_output(ubev)) : 0);
		return 1;
	}
	return 0;
}

static void NONNULL(1,2)
protoautossl_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");
}

static int NONNULL(1)
protoautossl_enable_src(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	// Create and set up tcp src.bev first
	if (prototcp_setup_src(ctx) == -1) {
		return -1;
	}

	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	if (pxy_setup_child_listener(ctx) == -1) {
		return -1;
	}

	log_finer("Enabling tcp src");
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static int NONNULL(1)
protoautossl_enable_conn_src(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	// Create and set up src.bev
	if (OPTS_DEBUG(ctx->global)) {
		log_dbg_printf("Completing autossl upgrade\n");
	}

	// tcp src.bev was already created before
	int rv;
	if ((rv = protossl_setup_src_ssl_from_dst(ctx)) != 0) {
		return rv;
	}
	// Replace tcp src.bev with ssl version
	if (protoautossl_setup_src_new_bev_ssl_accepting(ctx) == -1) {
		return -1;
	}
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	bufferevent_openssl_set_allow_dirty_shutdown(ctx->src.bev, 1);
#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	// Save the ssl info for logging, srvdst == dst in split mode
	ctx->sslctx->srvdst_ssl_version = strdup(SSL_get_version(ctx->srvdst.ssl ? ctx->srvdst.ssl : ctx->dst.ssl));
	ctx->sslctx->srvdst_ssl_cipher = strdup(SSL_get_cipher(ctx->srvdst.ssl ? ctx->srvdst.ssl : ctx->dst.ssl));

	// Now open the gates for a second time after autossl upgrade
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);

	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;
	autossl_ctx->clienthello_found = 0;
	return 0;
}

static void NONNULL(1,2)
protoautossl_bev_eventcb_connected_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->protoctx->arg;

	log_finest("ENTER");

	if (!ctx->connected) {
		ctx->connected = 1;
		bufferevent_enable(bev, EV_READ|EV_WRITE);

		// srvdst.bev is NULL in split mode
		if (ctx->srvdst.bev)
			bufferevent_enable(ctx->srvdst.bev, EV_READ);

		if (protoautossl_enable_src(ctx) == -1) {
			return;
		}
	}

	if (autossl_ctx->clienthello_found) {
		if (protoautossl_enable_conn_src(ctx) != 0) {
			return;
		}

		// Check if we have arrived here right after autossl upgrade, which may be triggered by readcb on src
		// Autossl upgrade code leaves readcb without processing any data in input buffer of src
		// So, if we don't call readcb here, the connection could stall
		if (evbuffer_get_length(bufferevent_get_input(ctx->src.bev))) {
			log_finer("clienthello_found and src inbuf len > 0, calling bev_readcb for src");

			if (pxy_bev_readcb_preexec_logging_and_stats(ctx->src.bev, ctx) == -1) {
				return;
			}
			ctx->protoctx->bev_readcb(ctx->src.bev, ctx);
		}
	}
}

#ifndef WITHOUT_USERAUTH
static void NONNULL(1)
protoautossl_classify_user(pxy_conn_ctx_t *ctx)
{
	// Do not engage passthrough mode in autossl
	if (ctx->spec->opts->divertusers && !pxy_is_listuser(ctx->spec->opts->divertusers, ctx->user
#ifdef DEBUG_PROXY
			, ctx, "DivertUsers"
#endif /* DEBUG_PROXY */
			)) {
		log_fine_va("User %s not in DivertUsers; terminating connection", ctx->user);
		pxy_conn_term(ctx, 1);
	}
}
#endif /* !WITHOUT_USERAUTH */

static int NONNULL(1)
protoautossl_enable_conn_src_child(pxy_conn_child_ctx_t *ctx)
{
	log_finest("ENTER");

	// Create and set up src.bev
	if (OPTS_DEBUG(ctx->conn->global)) {
		log_dbg_printf("Completing autossl upgrade\n");
	}

	// tcp src.bev was already created before
	int rv;
	if ((rv = protossl_setup_src_ssl_from_child_dst(ctx)) != 0) {
		return rv;
	}
	// Replace tcp src.bev with ssl version
	if (protoautossl_setup_src_new_bev_ssl_accepting(ctx->conn) == -1) {
		return -1;
	}
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
	bufferevent_openssl_set_allow_dirty_shutdown(ctx->conn->src.bev, 1);
#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */
	bufferevent_setcb(ctx->conn->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx->conn);

	// srvdst is xferred to the first child conn, so save the ssl info for logging
	ctx->conn->sslctx->srvdst_ssl_version = strdup(SSL_get_version(ctx->conn->srvdst.ssl ? ctx->conn->srvdst.ssl : ctx->dst.ssl));
	ctx->conn->sslctx->srvdst_ssl_cipher = strdup(SSL_get_cipher(ctx->conn->srvdst.ssl ? ctx->conn->srvdst.ssl : ctx->dst.ssl));

	log_finer_va("Enabling ssl src, %s", ctx->conn->sslproxy_header);

	// Now open the gates for a second time after autossl upgrade
	bufferevent_enable(ctx->conn->src.bev, EV_READ|EV_WRITE);

	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;
	autossl_ctx->clienthello_found = 0;
	return 0;
}

static void NONNULL(1,2)
protoautossl_bev_eventcb_connected_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	protoautossl_ctx_t *autossl_ctx = ctx->conn->protoctx->arg;

	log_finest("ENTER");

	ctx->connected = 1;
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);

	if (autossl_ctx->clienthello_found) {
		if (protoautossl_enable_conn_src_child(ctx) != 0) {
			return;
		}

		// Check if we have arrived here right after autossl upgrade, which may be triggered by readcb on src
		// Autossl upgrade code leaves readcb without processing any data in input buffer of src
		// So, if we don't call readcb here, the connection could stall
		if (evbuffer_get_length(bufferevent_get_input(ctx->src.bev))) {
			log_finer("clienthello_found and src inbuf len > 0, calling bev_readcb for src");

			if (pxy_bev_readcb_preexec_logging_and_stats_child(bev, ctx) == -1) {
				return;
			}
			ctx->protoctx->bev_readcb(ctx->src.bev, ctx);
		}
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
		prototcp_bev_readcb_dst(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protoautossl_bev_readcb_srvdst(bev, ctx);
	} else {
		log_err_printf("protoautossl_bev_readcb: UNKWN conn end\n");
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
		prototcp_bev_eventcb_srvdst(bev, events, ctx);
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

// @attention Called by thrmgr thread
protocol_t
protoautossl_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_AUTOSSL;
	ctx->protoctx->connectcb = protoautossl_conn_connect;
	ctx->protoctx->init_conn = prototcp_init_conn;

	ctx->protoctx->bev_readcb = protoautossl_bev_readcb;
	ctx->protoctx->bev_writecb = prototcp_bev_writecb;
	ctx->protoctx->bev_eventcb = protoautossl_bev_eventcb;

	ctx->protoctx->proto_free = protoautossl_free;

#ifndef WITHOUT_USERAUTH
	ctx->protoctx->classify_usercb = protoautossl_classify_user;
#endif /* !WITHOUT_USERAUTH */

	ctx->protoctx->set_watermarkcb = protoautossl_try_set_watermark;
	ctx->protoctx->unset_watermarkcb = protoautossl_try_unset_watermark;
	ctx->protoctx->discard_inbufcb = protoautossl_try_discard_inbuf;
	ctx->protoctx->discard_outbufcb = protoautossl_try_discard_outbuf;
	ctx->protoctx->outbuf_has_datacb = protoautossl_outbuf_has_data;
#ifdef DEBUG_PROXY
	ctx->protoctx->log_dbg_evbuf_infocb = protoautossl_log_dbg_evbuf_info;
#endif /* DEBUG_PROXY */

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

	ctx->protoctx->bev_writecb = prototcp_bev_writecb_child;
	ctx->protoctx->bev_eventcb = protoautossl_bev_eventcb_child;

	return PROTO_AUTOSSL;
}

/* vim: set noet ft=c: */
