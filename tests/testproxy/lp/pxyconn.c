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

#include "pxyconn.h"

#include "prototcp.h"

#include "privsep.h"
#include "sys.h"
#include "log.h"
#include "attrib.h"

#include <string.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <assert.h>
#include <errno.h>

#include <event2/listener.h>

#ifdef __linux__
#include <glob.h>
#endif /* __linux__ */

#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include <netinet/if_ether.h>
#ifdef __OpenBSD__
#include <net/if_dl.h>
#endif /* __OpenBSD__ */

/*
 * Maximum size of data to buffer per connection direction before
 * temporarily stopping to read data from the other end.
 */
#define OUTBUF_LIMIT	(128*1024)

int descriptor_table_size = 0;

// @attention The order of names should match the order in protocol enum
char *protocol_names[] = {
	// ERROR = -1
	"TCP", // = 0
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
	protocol_t proto = prototcp_setup(ctx);

	if (proto == PROTO_ERROR) {
		free(ctx->protoctx);
	}
	return proto;
}

static pxy_conn_ctx_t * MALLOC NONNULL(2,3)
pxy_conn_ctx_new(evutil_socket_t fd,
                 pxy_thrmgr_ctx_t *thrmgr, opts_t *opts)
{
	log_finest_main_va("ENTER, fd=%d", fd);

	pxy_conn_ctx_t *ctx = malloc(sizeof(pxy_conn_ctx_t));
	if (!ctx) {
		return NULL;
	}
	memset(ctx, 0, sizeof(pxy_conn_ctx_t));

	ctx->id = thrmgr->conn_count++;

	log_finest_main_va("id=%llu, fd=%d", ctx->id, fd);
	
	ctx->fd = fd;
	ctx->thrmgr = thrmgr;

	ctx->proto = pxy_setup_proto(ctx);
	if (ctx->proto == PROTO_ERROR) {
		free(ctx);
		return NULL;
	}

	ctx->opts = opts;

	ctx->ctime = time(NULL);
	ctx->atime = ctx->ctime;

	ctx->next = NULL;

	pxy_thrmgr_attach(ctx);
	return ctx;
}

void
pxy_conn_ctx_free(pxy_conn_ctx_t *ctx, int by_requestor)
{
	log_finest("ENTER");

	if (WANT_CONTENT_LOG(ctx)) {
		if (log_content_close(&ctx->logctx, by_requestor) == -1) {
			log_err_level_printf(LOG_WARNING, "Content log close failed\n");
		}
	}

	if (ctx->thr_locked) {
		pxy_thrmgr_detach_unlocked(ctx);
	} else {
		pxy_thrmgr_detach(ctx);
	}

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
	log_finest("ENTER");

	// We always assign NULL to bevs after freeing them
	if (ctx->src.bev) {
		ctx->src.free(ctx->src.bev, ctx);
		ctx->src.bev = NULL;
	} else if (!ctx->src.closed) {
		log_fine("evutil_closesocket on NULL src.bev");
		// @attention early in the conn setup, src fd may be open, although src.bev is NULL
		evutil_closesocket(ctx->fd);
	}

	if (ctx->dst.bev) {
		ctx->dst.free(ctx->dst.bev, ctx);
		ctx->dst.bev = NULL;
	}

	pxy_conn_ctx_free(ctx, by_requestor);
}

void
pxy_conn_term(pxy_conn_ctx_t *ctx, int by_requestor)
{
	log_finest("ENTER");
	ctx->term = 1;
	ctx->term_requestor = by_requestor;
}

void
pxy_log_connect_nonhttp(pxy_conn_ctx_t *ctx)
{
	char *msg;
	int rv;

	/*
	 * The following ifdef's within asprintf arguments list generates
	 * warnings with -Wembedded-directive on some compilers.
	 * Not fixing the code in order to avoid more code duplication.
	 */

	rv = asprintf(&msg, "CONN: tcp %s %s %s %s\n",
				  STRORDASH(ctx->srchost_str),
				  STRORDASH(ctx->srcport_str),
				  STRORDASH(ctx->dsthost_str),
				  STRORDASH(ctx->dstport_str));

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
	return;
}

int
pxy_log_content_inbuf(pxy_conn_ctx_t *ctx, struct evbuffer *inbuf, int req)
{
	size_t sz = evbuffer_get_length(inbuf);
	unsigned char *buf = malloc(sz);
	if (!buf) {
		ctx->enomem = 1;
		return -1;
	}
	if (evbuffer_copyout(inbuf, buf, sz) == -1) {
		free(buf);
		return -1;
	}
	logbuf_t *lb = logbuf_new_alloc(sz, NULL);
	if (!lb) {
		free(buf);
		ctx->enomem = 1;
		return -1;
	}
	memcpy(lb->buf, buf, lb->sz);
	free(buf);
	if (log_content_submit(&ctx->logctx, lb, req) == -1) {
		logbuf_free(lb);
		log_err_level_printf(LOG_WARNING, "Content log submission failed\n");
		return -1;
	}
	return 0;
}

static int
pxy_prepare_logging(pxy_conn_ctx_t *ctx)
{
	/* prepare logging, part 2 */
	if (WANT_CONTENT_LOG(ctx)) {
		if (log_content_open(&ctx->logctx, ctx->opts,
							 STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str),
							 STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
							 NULL, NULL, NULL
							) == -1) {
			if (errno == ENOMEM)
				ctx->enomem = 1;
			pxy_conn_term(ctx, 1);
			return -1;
		}
	}
	return 0;
}

static void NONNULL(1)
pxy_log_dbg_connect_type(pxy_conn_ctx_t *ctx)
{
	if (OPTS_DEBUG(ctx->opts)) {
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

void
pxy_log_connect(pxy_conn_ctx_t *ctx)
{
	/* log connection if we don't analyze any headers */
	if (WANT_CONNECT_LOG(ctx)) {
		pxy_log_connect_nonhttp(ctx);
	}

	pxy_log_dbg_connect_type(ctx);
}

static void
pxy_log_dbg_disconnect(pxy_conn_ctx_t *ctx)
{
	/* we only get a single disconnect event here for both connections */
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("%s disconnected to [%s]:%s\n",
					   protocol_names[ctx->proto],
					   STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str));
		log_dbg_printf("%s disconnected from [%s]:%s\n",
					   protocol_names[ctx->proto],
					   STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str));
	}
}

#ifdef DEBUG_PROXY
void
pxy_log_dbg_evbuf_info(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this, pxy_conn_desc_t *other)
{
	// Use ctx->conn, because this function is used by child conns too
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("evbuffer size at EOF: i:%zu o:%zu i:%zu o:%zu\n",
						evbuffer_get_length(bufferevent_get_input(this->bev)),
						evbuffer_get_length(bufferevent_get_output(this->bev)),
						other->closed ? 0 : evbuffer_get_length(bufferevent_get_input(other->bev)),
						other->closed ? 0 : evbuffer_get_length(bufferevent_get_output(other->bev)));
	}
}
#endif /* DEBUG_PROXY */

#ifdef DEBUG_PROXY
char *bev_names[] = {
	"src",
	"dst",
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
	} else if (bev == NULL) {
		log_fine("event_name=NULL");
		return bev_names[2];
	} else {
		log_fine("event_name=UNKWN");
		return bev_names[3];
	}
}
#endif /* DEBUG_PROXY */

void
pxy_try_set_watermark(struct bufferevent *bev, pxy_conn_ctx_t *ctx, struct bufferevent *other)
{
	if (evbuffer_get_length(bufferevent_get_output(other)) >= OUTBUF_LIMIT) {
		log_fine_va("%s", pxy_get_event_name(bev, ctx));

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
		log_fine_va("%s", pxy_get_event_name(bev, ctx));

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

#if defined(__APPLE__) || defined(__FreeBSD__)
#define getdtablecount() 0

/*
 * Copied from:
 * opensmtpd-201801101641p1/openbsd-compat/imsg.c
 * 
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
static int
available_fds(unsigned int n)
{
	unsigned int i;
	int ret, fds[256];

	if (n > (sizeof(fds)/sizeof(fds[0])))
		return -1;

	ret = 0;
	for (i = 0; i < n; i++) {
		fds[i] = -1;
		if ((fds[i] = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			ret = -1;
			break;
		}
	}

	for (i = 0; i < n && fds[i] >= 0; i++)
		close(fds[i]);

	return ret;
}
#endif /* __APPLE__ || __FreeBSD__ */

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

/*
 * Check if we are out of file descriptors to close the conn, or else libevent will crash us
 * @attention We cannot guess the number of children in a connection at conn setup time. So, FD_RESERVE is just a ball park figure.
 * But what if a connection passes the check below, but eventually tries to create more children than FD_RESERVE allows for? This will crash us the same.
 * Beware, this applies to all current conns, not just the last connection setup.
 * For example, 20x conns pass the check below before creating any children, at which point we reach the last FD_RESERVE fds,
 * then they all start creating children, which crashes us again.
 * So, no matter how large an FD_RESERVE we choose, there will always be a risk of running out of fds, if we check the number of fds during parent conn setup only.
 * If we are left with less than FD_RESERVE fds, we should not create more children than FD_RESERVE allows for either.
 * Therefore, we check if we are out of fds in pxy_listener_acceptcb_child() and close the conn there too.
 * @attention These checks are expected to slow us further down, but it is critical to avoid a crash in case we run out of fds.
 */
static int
check_fd_usage(
#ifdef DEBUG_PROXY
	evutil_socket_t fd
#endif /* DEBUG_PROXY */
	)
{
	int dtable_count = getdtablecount();

	log_finer_main_va("descriptor_table_size=%d, dtablecount=%d, reserve=%d, fd=%d", descriptor_table_size, dtable_count, FD_RESERVE, fd);

	if (dtable_count + FD_RESERVE >= descriptor_table_size) {
		goto out;
	}

#if defined(__APPLE__) || defined(__FreeBSD__)
	if (available_fds(FD_RESERVE) == -1) {
		goto out;
	}
#endif /* __APPLE__ || __FreeBSD__ */

	return 0;
out:
	errno = EMFILE;
	log_err_level_printf(LOG_CRIT, "Out of file descriptors\n");
	return -1;
}

int
pxy_try_close_conn_end(pxy_conn_desc_t *conn_end, pxy_conn_ctx_t *ctx)
{
	/* if the other end is still open and doesn't have data
	 * to send, close it, otherwise its writecb will close
	 * it after writing what's left in the output buffer */
	if (evbuffer_get_length(bufferevent_get_output(conn_end->bev)) == 0) {
		log_finest("evbuffer_get_length(outbuf) == 0, terminate conn");
		conn_end->free(conn_end->bev, ctx);
		conn_end->bev = NULL;
		conn_end->closed = 1;
		return 1;
	}
	return 0;
}

void
pxy_try_disconnect(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this, pxy_conn_desc_t *other, int is_requestor)
{
	// @attention srvdst should never reach here unless in passthrough mode, its bev may be NULL
	this->closed = 1;
	this->free(this->bev, ctx);
	this->bev = NULL;
	if (other->closed) {
		log_finest("other->closed, terminate conn");
		// Uses only ctx to log disconnect, never any of the bevs
		pxy_log_dbg_disconnect(ctx);
		pxy_conn_term(ctx, is_requestor);
	}
}

int
pxy_try_consume_last_input(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	/* if there is data pending in the closed connection,
	 * handle it here, otherwise it will be lost. */
	if (evbuffer_get_length(bufferevent_get_input(bev))) {
		log_fine("evbuffer_get_length(inbuf) > 0, terminate conn");
		if (pxy_bev_readcb_preexec_logging_and_stats(bev, ctx) == -1) {
			return -1;
		}
		ctx->protoctx->bev_readcb(bev, ctx);
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

		if (WANT_CONTENT_LOG(ctx)) {
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
		goto out;
	}

	ctx->atime = time(NULL);
	ctx->protoctx->bev_readcb(bev, ctx);

out:
	if (ctx->term || ctx->enomem) {
		pxy_conn_free(ctx, ctx->term ? ctx->term_requestor : (bev == ctx->src.bev));
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

int
pxy_bev_eventcb_postexec_logging_and_stats(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (ctx->term || ctx->enomem) {
		return -1;
	}

	if (events & BEV_EVENT_CONNECTED) {
		if (bev == ctx->dst.bev) {
			pxy_log_connect(ctx);
			ctx->dst_fd = bufferevent_getfd(ctx->dst.bev);
			ctx->thr->max_fd = MAX(ctx->thr->max_fd, ctx->dst_fd);
		}
		if (ctx->src_connected && ctx->dst_connected) {
			if (pxy_prepare_logging(ctx) == -1) {
				return -1;
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
		log_err_printf("BEV_EVENT_ERROR\n");
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

/*
 * Complete the connection.
 */
void
pxy_conn_connect(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	if (ctx->protoctx->connectcb(ctx) == -1) {
		// @attention Do not try to close conns or do anything else with conn ctx on the thrmgr thread after setting event callbacks and/or socket connect.
		// The return value of -1 from connectcb indicates that there was a fatal error before event callbacks were set, so we can terminate the connection.
		// Otherwise, it is up to the event callbacks to terminate the connection. This is necessary to avoid multithreading issues.
		if (ctx->term || ctx->enomem) {
			pxy_conn_free(ctx, ctx->term ? ctx->term_requestor : 1);
		}
	}
	// @attention Do not do anything with the conn ctx after this point on the thrmgr thread
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
               pxy_thrmgr_ctx_t *thrmgr, opts_t *opts)
{
#ifdef DEBUG_PROXY
	log_finest_main_va("ENTER, fd=%d", fd);

	char *host, *port;
	if (sys_sockaddr_str(peeraddr, peeraddrlen, &host, &port) == 0) {
		log_finest_main_va("peer addr=[%s]:%s, fd=%d", host, port, fd);
		free(host);
		free(port);
	}
#endif /* DEBUG_PROXY */

	if (check_fd_usage(
#ifdef DEBUG_PROXY
			fd
#endif /* DEBUG_PROXY */
			) == -1) {
		evutil_closesocket(fd);
		return;
	}

	/* create per connection state and attach to thread */
	pxy_conn_ctx_t *ctx = pxy_conn_ctx_new(fd, thrmgr, opts);
	if (!ctx) {
		log_err_level_printf(LOG_CRIT, "Error allocating memory\n");
		evutil_closesocket(fd);
		return;
	}

	ctx->af = peeraddr->sa_family;

	if (sys_sockaddr_str(peeraddr, peeraddrlen, &ctx->srchost_str, &ctx->srcport_str) != 0) {
		log_err_level_printf(LOG_CRIT, "Aborting connection setup (out of memory)!\n");
		goto out;
	}

	ctx->protoctx->fd_readcb(ctx->fd, 0, ctx);
	return;

out:
	evutil_closesocket(fd);
	pxy_conn_ctx_free(ctx, 1);
}

/* vim: set noet ft=c: */
