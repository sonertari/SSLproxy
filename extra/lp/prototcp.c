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

#include "prototcp.h"
#include "sys.h"

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
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bufferevent_setup: ENTER, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	// @todo Do we really need to defer callbacks? BEV_OPT_DEFER_CALLBACKS seems responsible for the issue with dst: We get writecb sometimes, no eventcb for CONNECTED event
	struct bufferevent *bev = bufferevent_socket_new(ctx->evbase, fd, BEV_OPT_DEFER_CALLBACKS|BEV_OPT_THREADSAFE);
	if (!bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_bufferevent_setup: bufferevent_socket_connect failed, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

		return NULL;
	}
	return bev;
}

/*
 * Free bufferenvent and close underlying socket properly.
 */
static void
prototcp_bufferevent_free_and_close_fd(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_bufferevent_free_and_close_fd: in=%zu, out=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(bev)), fd);
#endif /* DEBUG_PROXY */

	bufferevent_free(bev);
	evutil_closesocket(fd);
}

static int NONNULL(1)
prototcp_setup_src(pxy_conn_ctx_t *ctx)
{
	ctx->src.bev = prototcp_bufferevent_setup(ctx, ctx->fd);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating src bufferevent\n");
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->src.free = prototcp_bufferevent_free_and_close_fd;
	return 0;
}

static int NONNULL(1)
prototcp_setup_dst(pxy_conn_ctx_t *ctx)
{
	ctx->dst.bev = prototcp_bufferevent_setup(ctx, -1);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating parent dst\n");
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->dst.free = prototcp_bufferevent_free_and_close_fd;
	return 0;
}

static int NONNULL(1) WUNRES
prototcp_conn_connect(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_conn_connect: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (prototcp_setup_src(ctx) == -1) {
		return -1;
	}

	if (prototcp_setup_dst(ctx) == -1) {
		return -1;
	}

	// Conn setup is successful, so add the conn to the conn list of its thread now
	pxy_thrmgr_add_conn(ctx);

	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "prototcp_conn_connect: Enabling src, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// Now open the gates
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void
prototcp_fd_readcb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_fd_readcb: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	pxy_conn_connect(ctx);
}

static int
prototcp_parse_sslproxy_line(char *line, pxy_conn_ctx_t *ctx)
{
#define MAX_IPADDR_LEN 45
#define MAX_PORT_LEN 5

	// SSLproxy: [127.0.0.1]:34649,[192.168.3.24]:47286,[74.125.206.108]:465,s,soner
	if (!strncasecmp(line, "SSLproxy:", 9)) {
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("%s\n", line);
		}

		char *ip_start = strchr(line, '[') + 1;
		char *ip_end = strchr(ip_start, ']');
		char *port_start = strchr(ip_end, ':') + 1;
		char *port_end = strchr(port_start, ',');

		if (!ip_start || !ip_end || !port_start || !port_end) {
			log_err_level_printf(LOG_ERR, "Unable to find sslproxy addr: %s", line);
			return -1;
		}

		int addr_len = ip_end - ip_start;
		if (addr_len > MAX_IPADDR_LEN) {
			log_err_level_printf(LOG_ERR, "sslproxy addr_len larger than MAX_IPADDR_LEN: %d\n", addr_len);
			return -1;
		}

		char addr[MAX_IPADDR_LEN + 1];
		strncpy(addr, ip_start, addr_len);
		addr[addr_len] = '\0';

		int port_len = port_end - port_start;
		if (port_len > MAX_PORT_LEN) {
			log_err_level_printf(LOG_ERR, "sslproxy port_len larger than MAX_PORT_LEN: %d\n", port_len);
			return -1;
		}

		char port[MAX_PORT_LEN + 1];
		strncpy(port, port_start, port_len);
		port[port_len] = '\0';

		if (sys_sockaddr_parse(&ctx->dstaddr,
								&ctx->dstaddrlen,
								addr, port,
								sys_get_af(addr),
								EVUTIL_AI_PASSIVE) == -1) {
			log_err_level_printf(LOG_ERR, "Cannot convert sslproxy addr to sockaddr: [%s]:%s\n", addr, port);
			return -1;
		}

		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Connecting to [%s]:%s\n", addr, port);
			ctx->dsthost_str = strdup(addr);
			ctx->dstport_str = strdup(port);
			if (!ctx->dsthost_str || !ctx->dstport_str) {
				log_err_level_printf(LOG_ERR, "Cannot dup addr or port: [%s]:%s\n", addr, port);
				return -1;
			}
		}

		ctx->seen_sslproxy_line = 1;
	}
	return 0;
}

static void NONNULL(1,2)
prototcp_bev_readcb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_src: ENTER, size=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd);
#endif /* DEBUG_PROXY */

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	if (!ctx->seen_sslproxy_line) {
		char *line;
		while (!ctx->seen_sslproxy_line && (line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF))) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_src: %s, fd=%d\n", line, ctx->fd);
#endif /* DEBUG_PROXY */

			if (prototcp_parse_sslproxy_line(line, ctx) == -1) {
				free(line);
				pxy_conn_term(ctx, 1);
				return;
			}

			if (ctx->seen_sslproxy_line) {
				/* initiate connection */
				if (bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen) == -1) {
					log_err_level_printf(LOG_CRIT, "prototcp_bev_readcb_src: bufferevent_socket_connect for dst failed\n");
#ifdef DEBUG_PROXY
					log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_bev_readcb_src: bufferevent_socket_connect for dst failed, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
				}
			}

			evbuffer_add_printf(outbuf, "%s\r\n", line);
			free(line);
		}

		if (evbuffer_get_length(inbuf) == 0) {
			goto out;
		}
	} else {
		if (ctx->dst.closed) {
			pxy_discard_inbuf(bev);
			return;
		}
	}

	evbuffer_add_buffer(outbuf, inbuf);
out:
	pxy_try_set_watermark(bev, ctx, ctx->dst.bev);
}

static void NONNULL(1)
prototcp_bev_readcb_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_readcb_dst: ENTER, size=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), ctx->fd);
#endif /* DEBUG_PROXY */
	
	if (!ctx->dst_connected) {
		log_err_level_printf(LOG_CRIT, "prototcp_bev_readcb_dst: readcb called when not connected - aborting.\n");
		log_exceptcb();
		return;
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

static int NONNULL(1,2)
prototcp_connect_conn_end(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_connect_conn_end: writecb before connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// @attention Sometimes write cb fires but not event cb, especially if the listener cb is not finished yet, so the conn stalls.
	// This is a workaround for this error condition, nothing else seems to work.
	// @attention Do not try to free the conn here, since the listener cb may not be finished yet, which causes multithreading issues
	// XXX: Workaround, should find the real cause: BEV_OPT_DEFER_CALLBACKS?
	ctx->protoctx->bev_eventcb(bev, BEV_EVENT_CONNECTED, ctx);

	return pxy_bev_eventcb_postexec_logging_and_stats(bev, BEV_EVENT_CONNECTED, ctx);
}

static void NONNULL(1)
prototcp_bev_writecb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->src_connected) {
		if (prototcp_connect_conn_end(bev, ctx) == -1) {
			return;
		}
	}

	if (ctx->dst.closed) {
		if (pxy_try_close_conn_end(&ctx->src, ctx) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_src: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_term(ctx, 1);
		}
		return;
	}
	pxy_try_unset_watermark(bev, ctx, &ctx->dst);
}

static void NONNULL(1)
prototcp_bev_writecb_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->dst_connected) {
		if (prototcp_connect_conn_end(bev, ctx) == -1) {
			return;
		}
	}

	if (ctx->src.closed) {
		if (pxy_try_close_conn_end(&ctx->dst, ctx) == 1) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_writecb_dst: other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

			pxy_conn_term(ctx, 0);
		}			
		return;
	}
	pxy_try_unset_watermark(bev, ctx, &ctx->src);
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_src(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_connected_src: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->src_connected = 1;
}

static void NONNULL(1,2)
prototcp_bev_eventcb_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_connected_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->dst_connected = 1;
}

static void NONNULL(1,2)
prototcp_bev_eventcb_eof_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_src: ENTER, fd=%d\n", ctx->fd);
	pxy_log_dbg_evbuf_info(ctx, &ctx->src, &ctx->dst);
#endif /* DEBUG_PROXY */

	if (!ctx->src_connected) {
		log_err_level_printf(LOG_WARNING, "EOF on connection before connection establishment\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_bev_eventcb_eof_src: EOF on connection before connection establishment, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_src: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		if (pxy_try_consume_last_input(bev, ctx) == -1) {
			return;
		}
		pxy_try_close_conn_end(&ctx->dst, ctx);
	}

	pxy_try_disconnect(ctx, &ctx->src, &ctx->dst, 1);
}

static void NONNULL(1,2)
prototcp_bev_eventcb_eof_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_dst: ENTER, fd=%d\n", ctx->fd);
	pxy_log_dbg_evbuf_info(ctx, &ctx->dst, &ctx->src);
#endif /* DEBUG_PROXY */

	if (!ctx->dst_connected) {
		log_err_level_printf(LOG_WARNING, "EOF on connection before connection establishment\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_bev_eventcb_eof_dst: EOF on connection before connection establishment, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "prototcp_bev_eventcb_eof_dst: !other->closed, terminate conn, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		if (pxy_try_consume_last_input(bev, ctx) == -1) {
			return;
		}
		pxy_try_close_conn_end(&ctx->src, ctx);
	}

	pxy_try_disconnect(ctx, &ctx->dst, &ctx->src, 0);
}

static void NONNULL(1,2)
prototcp_bev_eventcb_error_src(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_bev_eventcb_error_src: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->src_connected) {
		ctx->dst.closed = 1;
	} else if (!ctx->dst.closed) {
		pxy_try_close_conn_end(&ctx->dst, ctx);
	}

	pxy_try_disconnect(ctx, &ctx->src, &ctx->dst, 1);
}

static void NONNULL(1,2)
prototcp_bev_eventcb_error_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINE, "prototcp_bev_eventcb_error_dst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->dst_connected) {
		ctx->src.closed = 1;
	} else if (!ctx->src.closed) {
		pxy_try_close_conn_end(&ctx->src, ctx);
	}

	pxy_try_disconnect(ctx, &ctx->dst, &ctx->src, 0);
}

static void NONNULL(1,3)
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

static void NONNULL(1)
prototcp_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_readcb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_readcb_dst(bev, ctx);
	} else {
		log_err_printf("prototcp_bev_readcb: UNKWN conn end\n");
	}
}

static void NONNULL(1)
prototcp_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_writecb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_writecb_dst(bev, ctx);
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
	} else {
		log_err_printf("prototcp_bev_eventcb: UNKWN conn end\n");
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

/* vim: set noet ft=c: */
