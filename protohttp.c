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

#include "protohttp.h"

#include "util.h"
#include "base64.h"
#include "url.h"

#include <string.h>
#include <event2/bufferevent.h>

/*
 * Return 1 if uri is an OCSP GET URI, 0 if not.
 */
static int
protohttp_ocsp_is_valid_uri(const char *uri, pxy_conn_ctx_t *ctx)
{
	char *buf_url;
	size_t sz_url;
	char *buf_b64;
	size_t sz_b64;
	unsigned char *buf_asn1;
	size_t sz_asn1;
	int ret;

	buf_url = strrchr(uri, '/');
	if (!buf_url)
		return 0;
	buf_url++;

	/*
	 * Do some quick checks to avoid unnecessary buffer allocations and
	 * decoding URL, Base64 and ASN.1:
	 * -   OCSP requests begin with a SEQUENCE (0x30), so the first Base64
	 *     byte is 'M' or, unlikely but legal, the URL encoding thereof.
	 * -   There should be no query string in OCSP GET requests.
	 * -   Encoded OCSP request ASN.1 blobs are longer than 32 bytes.
	 */
	if (buf_url[0] != 'M' && buf_url[0] != '%')
		return 0;
	if (strchr(uri, '?'))
		return 0;
	sz_url = strlen(buf_url);
	if (sz_url < 32)
		return 0;
	buf_b64 = url_dec(buf_url, sz_url, &sz_b64);
	if (!buf_b64) {
		ctx->enomem = 1;
		return 0;
	}
	buf_asn1 = base64_dec(buf_b64, sz_b64, &sz_asn1);
	if (!buf_asn1) {
		ctx->enomem = 1;
		free(buf_b64);
		return 0;
	}
	ret = ssl_is_ocspreq(buf_asn1, sz_asn1);
	free(buf_asn1);
	free(buf_b64);
	return ret;
}

static const char ocspresp[] =
	"HTTP/1.0 200 OK\r\n"
	"Content-Type: application/ocsp-response\r\n"
	"Content-Length: 5\r\n"
	"Connection: close\r\n"
	"\r\n"
	"\x30\x03"      /* OCSPResponse: SEQUENCE */
	"\x0a\x01"      /* OCSPResponseStatus: ENUMERATED */
	"\x03";         /* tryLater (3) */

/*
 * Called after a request header was completely read.
 * If the request is an OCSP request, deny the request by sending an
 * OCSP response of type tryLater and close the connection to the server.
 *
 * Reference:
 * RFC 2560: X.509 Internet PKI Online Certificate Status Protocol (OCSP)
 */
static void
protohttp_ocsp_deny(pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

	struct evbuffer *inbuf, *outbuf;

	if (!http_ctx->http_method)
		return;
	if (!strncasecmp(http_ctx->http_method, "GET", 3) &&
	    protohttp_ocsp_is_valid_uri(http_ctx->http_uri, ctx))
		goto deny;
	if (!strncasecmp(http_ctx->http_method, "POST", 4) &&
	    http_ctx->http_content_type &&
	    !strncasecmp(http_ctx->http_content_type,
	                 "application/ocsp-request", 24))
		goto deny;
	return;

deny:
	inbuf = bufferevent_get_input(ctx->src.bev);
	outbuf = bufferevent_get_output(ctx->src.bev);

	if (evbuffer_get_length(inbuf) > 0) {
		evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
	}
	pxy_close_dst(ctx);
	evbuffer_add_printf(outbuf, ocspresp);
	http_ctx->ocsp_denied = 1;
}

/*
 * Filter a single line of HTTP request headers.
 * Also fills in some context fields for logging.
 *
 * Returns NULL if the current line should be deleted from the request.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns `line' if the line should be kept.
 */
static char *
protohttp_filter_request_header_line(const char *line, pxy_conn_ctx_t *ctx,
		// XXX: Remove is_child param, child conns should have a child filter function
		int is_child)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

	/* parse information for connect log */
	if (!http_ctx->http_method) {
		/* first line */
		char *space1, *space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1) {
			/* not HTTP */
			http_ctx->seen_req_header = 1;
		} else {
			http_ctx->http_method = malloc(space1 - line + 1);
			if (http_ctx->http_method) {
				memcpy(http_ctx->http_method, line, space1 - line);
				http_ctx->http_method[space1 - line] = '\0';
			} else {
				ctx->enomem = 1;
				return NULL;
			}
			space1++;
			if (!space2) {
				/* HTTP/0.9 */
				http_ctx->seen_req_header = 1;
				space2 = space1 + strlen(space1);
			}
			http_ctx->http_uri = malloc(space2 - space1 + 1);
			if (http_ctx->http_uri) {
				memcpy(http_ctx->http_uri, space1, space2 - space1);
				http_ctx->http_uri[space2 - space1] = '\0';
			} else {
				ctx->enomem = 1;
				return NULL;
			}
		}
	} else {
		/* not first line */
		char *newhdr;

		if (!http_ctx->http_host && !strncasecmp(line, "Host:", 5)) {
			http_ctx->http_host = strdup(util_skipws(line + 5));
			if (!http_ctx->http_host) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (!strncasecmp(line, "Content-Type:", 13)) {
			http_ctx->http_content_type = strdup(util_skipws(line + 13));
			if (!http_ctx->http_content_type) {
				ctx->enomem = 1;
				return NULL;
			}
		/* Override Connection: keepalive and Connection: upgrade */
		} else if (!strncasecmp(line, "Connection:", 11)) {
			http_ctx->sent_http_conn_close = 1;
			if (!(newhdr = strdup("Connection: close"))) {
				ctx->enomem = 1;
				return NULL;
			}
			return newhdr;
		// @attention Always use conn ctx for opts, child ctx does not have opts, see the comments in pxy_conn_child_ctx
		} else if (ctx->conn->opts->remove_http_accept_encoding && !strncasecmp(line, "Accept-Encoding:", 16)) {
			return NULL;
		} else if (ctx->conn->opts->remove_http_referer && !strncasecmp(line, "Referer:", 8)) {
			return NULL;
		/* Suppress upgrading to SSL/TLS, WebSockets or HTTP/2,
		 * unsupported encodings, and keep-alive */
		} else if (!strncasecmp(line, "Upgrade:", 8) ||
		           !strncasecmp(line, "Accept-Encoding:", 16) ||
		           !strncasecmp(line, "Keep-Alive:", 11)) {
			return NULL;
		} else if (is_child && (!strncasecmp(line, SSLPROXY_KEY, SSLPROXY_KEY_LEN) ||
				   // @attention flickr keeps redirecting to https with 301 unless we remove the Via line of squid
				   // Apparently flickr assumes the existence of Via header field or squid keyword a sign of plain http, even if we are using https
		           !strncasecmp(line, "Via:", 4) ||
				   // Also do not send the loopback address to the Internet
		           !strncasecmp(line, "X-Forwarded-For:", 16))) {
			return NULL;
		} else if (line[0] == '\0') {
			http_ctx->seen_req_header = 1;
			if (!http_ctx->sent_http_conn_close) {
				newhdr = strdup("Connection: close\r\n");
				if (!newhdr) {
					ctx->enomem = 1;
					return NULL;
				}
				return newhdr;
			}
		}
	}

	return (char*)line;
}

void
protohttp_filter_request_header(struct evbuffer *inbuf, struct evbuffer *outbuf, pxy_conn_ctx_t *ctx,
		// XXX: Remove is_child param, child conns should have a child filter function
		int is_child)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

	char *line;

	while (!http_ctx->seen_req_header && (line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF))) {
		char *replace = protohttp_filter_request_header_line(line, ctx, is_child);
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_filter_request_header: line, fd=%d: %s\n", ctx->fd, line);
#endif /* DEBUG_PROXY */
		if (replace == line) {
			evbuffer_add_printf(outbuf, "%s\r\n", line);
		} else if (replace) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "protohttp_filter_request_header: REPLACED line, fd=%d: %s\n", ctx->fd, replace);
#endif /* DEBUG_PROXY */
			evbuffer_add_printf(outbuf, "%s\r\n", replace);
			free(replace);
		} else {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "protohttp_filter_request_header: REMOVED line, fd=%d: %s\n", ctx->fd, line);
#endif /* DEBUG_PROXY */
		}
		free(line);

		if (!is_child && !ctx->sent_header) {
			ctx->sent_header = 1;
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "protohttp_filter_request_header: INSERT header_str line, fd=%d: %s\n", ctx->fd, ctx->header_str);
#endif /* DEBUG_PROXY */
			evbuffer_add_printf(outbuf, "%s\r\n", ctx->header_str);
		}
	}

	if (http_ctx->seen_req_header) {
		/* request header complete */
		if (ctx->conn->opts->deny_ocsp) {
			protohttp_ocsp_deny(ctx);
		}

		// @todo Fix this
		/* out of memory condition? */
		if (ctx->enomem) {
			pxy_conn_free(ctx->conn, 1);
			return;
		}

		/* no data left after parsing headers? */
		if (evbuffer_get_length(inbuf) == 0) {
			return;
		}
		evbuffer_add_buffer(outbuf, inbuf);
	}
}

static int
protohttp_bev_readcb_src_log_preexec(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_src_log_content_preexec: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// HTTP content logging at this point may record certain headers twice if have not seen all header lines yet
	if (pxy_log_content_inbuf(ctx, bufferevent_get_input(bev), 1) == -1) {
		return -1;
	}
	http_ctx->seen_req_header_on_entry = http_ctx->seen_req_header;
	return 0;
}

static void
protohttp_bev_readcb_src_log_postexec(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_src_log_content_postexec: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!http_ctx->seen_req_header_on_entry && http_ctx->seen_req_header && http_ctx->ocsp_denied) {
		pxy_log_content_buf(ctx, (unsigned char *)ocspresp, sizeof(ocspresp) - 1, 0/*resp*/);
	}
}

static int
protohttp_bev_readcb_src_exec(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_src_exec: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	ctx->thr->intif_in_bytes += evbuffer_get_length(inbuf);

	if (ctx->dst.closed) {
		pxy_discard_inbuf(bev);
		return -1;
	}

	// We insert our special header line to the first packet we get, e.g. right after the first \r\n in the case of http
	// @todo Should we look for GET/POST or Host header lines to detect the first packet?
	// But there is no guarantee that they will exist, due to fragmentation.
	// @attention We cannot append the ssl proxy address at the end of the packet or in between the header and the content,
	// because (1) the packet may be just the first fragment split somewhere not appropriate for appending a header,
	// and (2) there may not be any content.
	// And we are dealing pop3 and smtp also, not just http.

	/* request header munging */
	if (!http_ctx->seen_req_header) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_src: HTTP Request Header size=%zu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
		protohttp_filter_request_header(inbuf, outbuf, ctx, 0);
	} else {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_src: HTTP Request Body size=%zu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
		evbuffer_add_buffer(outbuf, inbuf);
	}
	pxy_set_watermark(bev, ctx, ctx->dst.bev);
	return 0;
}

static void
protohttp_bev_readcb_src(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (protohttp_bev_readcb_src_log_preexec(bev, ctx) == -1) {
		return;
	}
	if (protohttp_bev_readcb_src_exec(bev, ctx) == -1) {
		return;
	}
	protohttp_bev_readcb_src_log_postexec(bev, ctx);
}

/*
 * Filter a single line of HTTP response headers.
 *
 * Returns NULL if the current line should be deleted from the response.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns `line' if the line should be kept.
 */
static char *
protohttp_filter_response_header_line(const char *line, pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

	/* parse information for connect log */
	if (!http_ctx->http_status_code) {
		/* first line */
		char *space1, *space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1 || !!strncmp(line, "HTTP", 4)) {
			/* not HTTP or HTTP/0.9 */
			http_ctx->seen_resp_header = 1;
		} else {
			size_t len_code, len_text;

			if (space2) {
				len_code = space2 - space1 - 1;
				len_text = strlen(space2 + 1);
			} else {
				len_code = strlen(space1 + 1);
				len_text = 0;
			}
			http_ctx->http_status_code = malloc(len_code + 1);
			http_ctx->http_status_text = malloc(len_text + 1);
			if (!http_ctx->http_status_code || !http_ctx->http_status_text) {
				ctx->enomem = 1;
				return NULL;
			}
			memcpy(http_ctx->http_status_code, space1 + 1, len_code);
			http_ctx->http_status_code[len_code] = '\0';
			if (space2) {
				memcpy(http_ctx->http_status_text,
				       space2 + 1, len_text);
			}
			http_ctx->http_status_text[len_text] = '\0';
		}
	} else {
		/* not first line */
		if (!http_ctx->http_content_length &&
		    !strncasecmp(line, "Content-Length:", 15)) {
			http_ctx->http_content_length =
				strdup(util_skipws(line + 15));
			if (!http_ctx->http_content_length) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (
		    /* HPKP: Public Key Pinning Extension for HTTP
		     * (draft-ietf-websec-key-pinning)
		     * remove to prevent public key pinning */
		    !strncasecmp(line, "Public-Key-Pins:", 16) ||
		    !strncasecmp(line, "Public-Key-Pins-Report-Only:", 28) ||
		    /* HSTS: HTTP Strict Transport Security (RFC 6797)
		     * remove to allow users to accept bad certs */
		    !strncasecmp(line, "Strict-Transport-Security:", 26) ||
		    /* Expect-CT: Expect Certificate Transparency
		     * (draft-ietf-httpbis-expect-ct-latest)
		     * remove to prevent failed CT log lookups */
		    !strncasecmp(line, "Expect-CT:", 10) ||
		    /* Alternate Protocol
		     * remove to prevent switching to QUIC, SPDY et al */
		    !strncasecmp(line, "Alternate-Protocol:", 19) ||
		    /* Upgrade header
		     * remove to prevent upgrading to HTTPS in unhandled ways,
		     * and more importantly, WebSockets and HTTP/2 */
		    !strncasecmp(line, "Upgrade:", 8)) {
			return NULL;
		} else if (line[0] == '\0') {
			http_ctx->seen_resp_header = 1;
		}
	}

	return (char*)line;
}

void
protohttp_filter_response_header(struct evbuffer *inbuf, struct evbuffer *outbuf, pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

	char *line;

	while (!http_ctx->seen_resp_header && (line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF))) {
		char *replace = protohttp_filter_response_header_line(line, ctx);
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_filter_response_header: line, fd=%d: %s\n", ctx->fd, line);
#endif /* DEBUG_PROXY */
		if (replace == line) {
			evbuffer_add_printf(outbuf, "%s\r\n", line);
		} else if (replace) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "protohttp_filter_response_header: REPLACED line, fd=%d: %s\n", ctx->fd, replace);
#endif /* DEBUG_PROXY */
			evbuffer_add_printf(outbuf, "%s\r\n", replace);
			free(replace);
		} else {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINER, "protohttp_filter_response_header: REMOVED line, fd=%d: %s\n", ctx->fd, line);
#endif /* DEBUG_PROXY */
		}
		free(line);
	}

	if (http_ctx->seen_resp_header) {
		// @todo Fix this
		/* out of memory condition? */
		if (ctx->enomem) {
			pxy_conn_free(ctx->conn, 0);
			return;
		}

		/* no data left after parsing headers? */
		if (evbuffer_get_length(inbuf) == 0) {
			return;
		}
		evbuffer_add_buffer(outbuf, inbuf);
	}
}

static void
protohttp_log_connect(pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

	char *msg;
#ifdef HAVE_LOCAL_PROCINFO
	char *lpi = NULL;
#endif /* HAVE_LOCAL_PROCINFO */
	int rv;

#ifdef DEBUG_PROXY
	if (ctx->passthrough) {
		log_err_level_printf(LOG_WARNING, "protohttp_log_connect called while in "
		               "passthrough mode\n");
		return;
	}
#endif

#ifdef HAVE_LOCAL_PROCINFO
	if (ctx->opts->lprocinfo) {
		rv = asprintf(&lpi, "lproc:%i:%s:%s:%s",
		              ctx->lproc.pid,
		              STRORDASH(ctx->lproc.user),
		              STRORDASH(ctx->lproc.group),
		              STRORDASH(ctx->lproc.exec_path));
		if ((rv < 0) || !lpi) {
			ctx->enomem = 1;
			goto out;
		}
	}
#endif /* HAVE_LOCAL_PROCINFO */

	/*
	 * The following ifdef's within asprintf arguments list generates
	 * warnings with -Wembedded-directive on some compilers.
	 * Not fixing the code in order to avoid more code duplication.
	 */

	if (!ctx->spec->ssl) {
		rv = asprintf(&msg, "CONN: http %s %s %s %s %s %s %s %s %s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "%s\n",
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str),
		              STRORDASH(http_ctx->http_host),
		              STRORDASH(http_ctx->http_method),
		              STRORDASH(http_ctx->http_uri),
		              STRORDASH(http_ctx->http_status_code),
		              STRORDASH(http_ctx->http_content_length),
#ifdef HAVE_LOCAL_PROCINFO
		              lpi,
#endif /* HAVE_LOCAL_PROCINFO */
		              http_ctx->ocsp_denied ? " ocsp:denied" : "");
	} else {
		rv = asprintf(&msg, "CONN: https %s %s %s %s %s %s %s %s %s "
		              "sni:%s names:%s "
		              "sproto:%s:%s dproto:%s:%s "
		              "origcrt:%s usedcrt:%s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "%s\n",
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str),
		              STRORDASH(http_ctx->http_host),
		              STRORDASH(http_ctx->http_method),
		              STRORDASH(http_ctx->http_uri),
		              STRORDASH(http_ctx->http_status_code),
		              STRORDASH(http_ctx->http_content_length),
		              STRORDASH(ctx->sni),
		              STRORDASH(ctx->ssl_names),
		              SSL_get_version(ctx->src.ssl),
		              SSL_get_cipher(ctx->src.ssl),
		              !ctx->srv_dst.closed ? SSL_get_version(ctx->srv_dst.ssl):ctx->srv_dst_ssl_version,
		              !ctx->srv_dst.closed ? SSL_get_cipher(ctx->srv_dst.ssl):ctx->srv_dst_ssl_cipher,
		              STRORDASH(ctx->origcrtfpr),
		              STRORDASH(ctx->usedcrtfpr),
#ifdef HAVE_LOCAL_PROCINFO
		              lpi,
#endif /* HAVE_LOCAL_PROCINFO */
		              http_ctx->ocsp_denied ? " ocsp:denied" : "");
	}
	if ((rv < 0 ) || !msg) {
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
#ifdef HAVE_LOCAL_PROCINFO
	if (lpi) {
		free(lpi);
	}
#endif /* HAVE_LOCAL_PROCINFO */
	return;
}


static int
protohttp_bev_readcb_dst_log_preexec(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_dst_log_content_preexec: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	// HTTP content logging at this point may record certain headers twice if we have not seen all header lines yet
	if (pxy_log_content_inbuf(ctx, bufferevent_get_input(bev), 1) == -1) {
		return -1;
	}
	http_ctx->seen_resp_header_on_entry = http_ctx->seen_resp_header;
	return 0;
}

static void
protohttp_bev_readcb_dst_log_postexec(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_dst_log_content_postexec: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!http_ctx->seen_resp_header_on_entry && http_ctx->seen_resp_header) {
		/* response header complete: log connection */
		if (WANT_CONNECT_LOG(ctx->conn) || ctx->opts->statslog) {
			protohttp_log_connect(ctx);
		}
	}
}

static int
protohttp_bev_readcb_dst_exec(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_dst_exec: ENTER, fd=%d, size=%zu\n",
			ctx->fd, evbuffer_get_length(bufferevent_get_input(bev)));
#endif /* DEBUG_PROXY */

	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);

	ctx->thr->intif_out_bytes += evbuffer_get_length(inbuf);

	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return -1;
	}

	if (!http_ctx->seen_resp_header) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_dst_exec: HTTP Response Header size=%zu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
		protohttp_filter_response_header(inbuf, outbuf, ctx);
	} else {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protohttp_bev_readcb_dst_exec: HTTP Response Body size=%zu, fd=%d\n", evbuffer_get_length(inbuf), ctx->fd);
#endif /* DEBUG_PROXY */
		evbuffer_add_buffer(outbuf, inbuf);
	}
	pxy_set_watermark(bev, ctx, ctx->src.bev);
	return 0;
}

static void
protohttp_bev_readcb_dst(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (protohttp_bev_readcb_dst_log_preexec(bev, ctx) == -1) {
		return;
	}
	if (protohttp_bev_readcb_dst_exec(bev, ctx) == -1) {
		return;
	}
	protohttp_bev_readcb_dst_log_postexec(bev, ctx);
}

static void
protohttp_bev_readcb_srv_dst(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
	log_err_printf("protohttp_bev_readcb_srv_dst: readcb called on srv_dst\n");
}

static void
protohttp_bev_eventcb_src(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_connected_src(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_src(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_src(bev, ctx);
	}
}

static void
protohttp_bev_eventcb_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_dst(bev, ctx);
	}
}

static void
protohttp_bev_eventcb_srv_dst(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	ctx->atime = time(NULL);

	if (events & BEV_EVENT_CONNECTED) {
		pxy_bev_eventcb_connected_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		pxy_bev_eventcb_eof_srv_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		pxy_bev_eventcb_error_srv_dst(bev, ctx);
	}
}

static void
protohttp_bev_setcb_src(pxy_conn_ctx_t *ctx)
{
	bufferevent_setcb(ctx->src.bev, protohttp_bev_readcb_src, pxy_bev_writecb_src, protohttp_bev_eventcb_src, ctx);
}

static void
protohttp_bev_setcb_dst(pxy_conn_ctx_t *ctx)
{
	bufferevent_setcb(ctx->dst.bev, protohttp_bev_readcb_dst, pxy_bev_writecb_dst, protohttp_bev_eventcb_dst, ctx);
}

static void
protohttp_bev_setcb_srv_dst(pxy_conn_ctx_t *ctx)
{
	bufferevent_setcb(ctx->srv_dst.bev, protohttp_bev_readcb_srv_dst, pxy_bev_writecb_srv_dst, protohttp_bev_eventcb_srv_dst, ctx);
}

void
protohttp_free(pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->proto_ctx->arg;

	if (http_ctx->http_method) {
		free(http_ctx->http_method);
	}
	if (http_ctx->http_uri) {
		free(http_ctx->http_uri);
	}
	if (http_ctx->http_host) {
		free(http_ctx->http_host);
	}
	if (http_ctx->http_content_type) {
		free(http_ctx->http_content_type);
	}
	if (http_ctx->http_status_code) {
		free(http_ctx->http_status_code);
	}
	if (http_ctx->http_status_text) {
		free(http_ctx->http_status_text);
	}
	if (http_ctx->http_content_length) {
		free(http_ctx->http_content_length);
	}
	free(http_ctx);
	free(ctx->proto_ctx);
}

enum protocol
protohttp_setup(pxy_conn_ctx_t *ctx)
{
	ctx->proto_ctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->proto_ctx) {
		return PROTO_ERROR;
	}
	ctx->proto_ctx->proto = PROTO_HTTP;
	ctx->proto_ctx->conn_connectcb = pxy_conn_connect_tcp;
	ctx->proto_ctx->fd_readcb = pxy_fd_readcb_tcp;
	ctx->proto_ctx->bev_setcb_src = protohttp_bev_setcb_src;
	ctx->proto_ctx->bev_setcb_dst = protohttp_bev_setcb_dst;
	ctx->proto_ctx->bev_setcb_srv_dst = protohttp_bev_setcb_srv_dst;
	ctx->proto_ctx->proto_free = protohttp_free;

	// XXX: Use a different proto arg for child conns
	ctx->proto_ctx->arg = malloc(sizeof(protohttp_ctx_t));
	if (!ctx->proto_ctx->arg) {
		free(ctx->proto_ctx);
		return PROTO_ERROR;
	}
	memset(ctx->proto_ctx->arg, 0, sizeof(protohttp_ctx_t));
	return PROTO_HTTP;
}

enum protocol
protohttps_setup(pxy_conn_ctx_t *ctx) {
	ctx->proto_ctx = malloc(sizeof(proto_ctx_t));
	if (!ctx->proto_ctx) {
		return PROTO_ERROR;
	}
	ctx->proto_ctx->proto = PROTO_HTTPS;
	ctx->proto_ctx->conn_connectcb = pxy_conn_connect_tcp;
	ctx->proto_ctx->fd_readcb = pxy_fd_readcb_ssl;
	ctx->proto_ctx->bev_setcb_src = protohttp_bev_setcb_src;
	ctx->proto_ctx->bev_setcb_dst = protohttp_bev_setcb_dst;
	ctx->proto_ctx->bev_setcb_srv_dst = protohttp_bev_setcb_srv_dst;
	ctx->proto_ctx->proto_free = protohttp_free;

	// XXX: Use a different proto arg for child conns
	ctx->proto_ctx->arg = malloc(sizeof(protohttp_ctx_t));
	if (!ctx->proto_ctx->arg) {
		free(ctx->proto_ctx);
		return PROTO_ERROR;
	}
	memset(ctx->proto_ctx->arg, 0, sizeof(protohttp_ctx_t));
	return PROTO_HTTPS;
}

/* vim: set noet ft=c: */
