/*-
 * SSLproxy
 *
 * Copyright (c) 2017-2026, Soner Tari <sonertari@gmail.com>.
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
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
#include "protohttp2.h"
#include "protohttp3.h"
#include "prototcp.h"
#include "protossl.h"
#include "protopassthrough.h"

#ifndef WITHOUT_ICAP
#include "icap.h"
#endif /* !WITHOUT_ICAP */

#include "util.h"
#include "base64.h"
#include "url.h"

#include <string.h>
#include <event2/bufferevent.h>

void NONNULL(1)
protohttp_log_connect(pxy_conn_ctx_t *ctx, protohttp_ctx_t *http_ctx, unsigned int log_connect)
{
	if (!log_connect)
		return;

	char *msg;
#ifdef HAVE_LOCAL_PROCINFO
	char *lpi = NULL;
#endif /* HAVE_LOCAL_PROCINFO */
	int rv;

#ifdef HAVE_LOCAL_PROCINFO
	if (ctx->global->lprocinfo) {
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
		rv = asprintf(&msg, "%s: %s %s %s %s %s %s %s %s %s %s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "%s"
#ifndef WITHOUT_USERAUTH
		              " user:%s"
#endif /* !WITHOUT_USERAUTH */
		              "\n",
#ifndef WITHOUT_HTTP3
		              ctx->spec->h3 ? "STREAM" : "CONN",
		              ctx->spec->h3 ? "h3" : "http",
#else /* WITHOUT_HTTP3 */
		              "CONN",
		              "http",
#endif /* !WITHOUT_HTTP3 */
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
		              http_ctx->ocsp_denied ? " ocsp:denied" : ""
#ifndef WITHOUT_USERAUTH
		              , STRORDASH(ctx->user)
#endif /* !WITHOUT_USERAUTH */
		              );
	} else {
		rv = asprintf(&msg, "%s: %s %s %s %s %s %s %s %s %s %s "
		              "sni:%s names:%s "
		              "sproto:%s:%s dproto:%s:%s "
		              "origcrt:%s usedcrt:%s"
#ifdef HAVE_LOCAL_PROCINFO
		              " %s"
#endif /* HAVE_LOCAL_PROCINFO */
		              "%s"
#ifndef WITHOUT_USERAUTH
		              " user:%s"
#endif /* !WITHOUT_USERAUTH */
		              "\n",
#ifndef WITHOUT_HTTP3
		              ctx->sslctx->h2 || ctx->spec->h3 ? "STREAM" : "CONN",
		              ctx->sslctx->h2 ? "h2" : (ctx->spec->h3 ? "h3" : "https"),
#else /* WITHOUT_HTTP3 */
		              ctx->sslctx->h2 ? "STREAM" : "CONN",
		              ctx->sslctx->h2 ? "h2" : "https",
#endif /* !WITHOUT_HTTP3 */
		              STRORDASH(ctx->srchost_str),
		              STRORDASH(ctx->srcport_str),
		              STRORDASH(ctx->dsthost_str),
		              STRORDASH(ctx->dstport_str),
		              STRORDASH(http_ctx->http_host),
		              STRORDASH(http_ctx->http_method),
		              STRORDASH(http_ctx->http_uri),
		              STRORDASH(http_ctx->http_status_code),
		              STRORDASH(http_ctx->http_content_length),
		              STRORDASH(ctx->sslctx->sni),
		              STRORDASH(ctx->sslctx->ssl_names),
		              ctx->src.ssl ? SSL_get_version(ctx->src.ssl) : "-",
		              ctx->src.ssl ? SSL_get_cipher(ctx->src.ssl) : "-",
		              STRORDASH(ctx->sslctx->srvdst_ssl_version),
		              STRORDASH(ctx->sslctx->srvdst_ssl_cipher),
		              STRORDASH(ctx->sslctx->origcrtfpr),
		              STRORDASH(ctx->sslctx->usedcrtfpr),
#ifdef HAVE_LOCAL_PROCINFO
		              lpi,
#endif /* HAVE_LOCAL_PROCINFO */
		              http_ctx->ocsp_denied ? " ocsp:denied" : ""
#ifndef WITHOUT_USERAUTH
		              , STRORDASH(ctx->user)
#endif /* !WITHOUT_USERAUTH */
		              );
	}
	if ((rv < 0 ) || !msg) {
		ctx->enomem = 1;
		goto out;
	}
	if (!ctx->global->detach) {
		log_err_printf("%s", msg);
	} else if (ctx->global->statslog) {
		if (log_conn(msg) == -1) {
			log_err_level_printf(LOG_WARNING, "Conn logging failed\n");
		}
	}
	if (ctx->global->connectlog) {
		if (log_connect_print_free(msg) == -1) {
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

/*
 * Return 1 if uri is an OCSP GET URI, 0 if not.
 */
static int NONNULL(1,2)
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

/*
 * Called after a request header was completely read.
 * If the request is an OCSP request, deny the request by sending an
 * OCSP response of type tryLater and close the connection to the server.
 *
 * Reference:
 * RFC 2560: X.509 Internet PKI Online Certificate Status Protocol (OCSP)
 */
static void NONNULL(1,2)
protohttp_ocsp_deny(pxy_conn_ctx_t *ctx, protohttp_ctx_t *http_ctx)
{
	static const char ocspresp[] =
		"HTTP/1.0 200 OK\r\n"
		"Content-Type: application/ocsp-response\r\n"
		"Content-Length: 5\r\n"
		"Connection: close\r\n"
		"\r\n"
		"\x30\x03"      /* OCSPResponse: SEQUENCE */
		"\x0a\x01"      /* OCSPResponseStatus: ENUMERATED */
		"\x03";         /* tryLater (3) */

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
	ctx->protoctx->discard_inbufcb(ctx->src.bev);

	// Do not send anything to the child conns
	ctx->protoctx->discard_outbufcb(ctx->dst.bev);

	// Do not send duplicate OCSP denied responses
	if (http_ctx->ocsp_denied)
		return;

	log_finer("Sending OCSP denied response");
	evbuffer_add_printf(bufferevent_get_output(ctx->src.bev), ocspresp);
	http_ctx->ocsp_denied = 1;
}

/*
 * Filter a single line of HTTP request headers.
 * Also fills in some context fields for logging.
 *
 * Returns NULL if the current line should be deleted from the request.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns 'line' if the line should be kept.
 */
static char * NONNULL(1,2,4)
protohttp_filter_request_header_line(const char *line, protohttp_ctx_t *http_ctx, enum conn_type type, pxy_conn_ctx_t *ctx)
{
	/* parse information for connect log */
	if (!http_ctx->http_method) {
		/* first line */
		char *space1, *space2;

		space1 = strchr(line, ' ');
		space2 = space1 ? strchr(space1 + 1, ' ') : NULL;
		if (!space1) {
			/* not HTTP */
			http_ctx->seen_req_header = 1;
			http_ctx->not_valid = 1;
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

		if (!strncasecmp(line, "Content-Length:", 15)) {
			if (http_ctx->http_content_length) {
				free(http_ctx->http_content_length);
			}
			http_ctx->http_content_length =
				strdup(util_skipws(line + 15));
			if (!http_ctx->http_content_length) {
				ctx->enomem = 1;
				return NULL;
			}
		} else if (!http_ctx->http_host && !strncasecmp(line, "Host:", 5)) {
			http_ctx->http_host = strdup(util_skipws(line + 5));
			if (!http_ctx->http_host) {
				ctx->enomem = 1;
				return NULL;
			}
			http_ctx->seen_keyword_count++;
		} else if (!strncasecmp(line, "Content-Type:", 13)) {
			http_ctx->http_content_type = strdup(util_skipws(line + 13));
			if (!http_ctx->http_content_type) {
				ctx->enomem = 1;
				return NULL;
			}
			http_ctx->seen_keyword_count++;
		/* Override Connection: keepalive and Connection: upgrade */
		} else if (!strncasecmp(line, "Connection:", 11)) {
			http_ctx->sent_http_conn_close = 1;
			if (!(newhdr = strdup("Connection: close"))) {
				ctx->enomem = 1;
				return NULL;
			}
			http_ctx->seen_keyword_count++;
			return newhdr;
		// @attention Always use conn ctx for opts, child ctx does not have opts, see the comments in pxy_conn_child_ctx
		} else if (ctx->conn_opts->remove_http_accept_encoding && !strncasecmp(line, "Accept-Encoding:", 16)) {
			http_ctx->seen_keyword_count++;
			return NULL;
		} else if (ctx->conn_opts->remove_http_referer && !strncasecmp(line, "Referer:", 8)) {
			http_ctx->seen_keyword_count++;
			return NULL;
		/* Suppress upgrading to SSL/TLS, WebSockets or HTTP/2 and keep-alive */
		} else if (!strncasecmp(line, "Upgrade:", 8) || !strncasecmp(line, "Keep-Alive:", 11)) {
			http_ctx->seen_keyword_count++;
			return NULL;
		} else if ((type == CONN_TYPE_CHILD) && (
				   // @attention flickr keeps redirecting to https with 301 unless we remove the Via line of squid
				   // Apparently flickr assumes the existence of Via header field or squid keyword a sign of plain http, even if we are using https
		           !strncasecmp(line, "Via:", 4) ||
				   // Also do not send the loopback address to the Internet
		           !strncasecmp(line, "X-Forwarded-For:", 16))) {
			http_ctx->seen_keyword_count++;
			return NULL;
		} else if (!strncasecmp(line, SSLPROXY_KEY, SSLPROXY_KEY_LEN)) {
			// Remove any SSLproxy line, parent or child
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

static filter_action_t * NONNULL(1,2)
protohttp_filter_match_host(protohttp_ctx_t *http_ctx, filter_list_t *list, unsigned int filter_precedence)
{
	pxy_conn_ctx_t *ctx = http_ctx->ctx;

	filter_site_t *site = filter_site_find(list->host_btree, list->host_acm, list->host_all, http_ctx->http_host);
	if (!site)
		return NULL;

#ifndef WITHOUT_USERAUTH
	log_fine_va("Found site (line=%d): %s for %s:%s, %s:%s, %s, %s, %s", site->action.line_num, site->site,
		STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
		STRORDASH(ctx->user), STRORDASH(ctx->desc), STRORDASH(http_ctx->http_host));
#else /* WITHOUT_USERAUTH */
	log_fine_va("Found site (line=%d): %s for %s:%s, %s:%s, %s", site->action.line_num, site->site,
		STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
		STRORDASH(http_ctx->http_host));
#endif /* WITHOUT_USERAUTH */

	if (!site->port_btree && !site->port_acm && (site->action.precedence < filter_precedence)) {
		log_finest_va("Rule precedence lower than conn filter precedence %d < %d (line=%d): %s, %s", site->action.precedence, filter_precedence, site->action.line_num, site->site, http_ctx->http_host);
		return NULL;
	}

#ifdef DEBUG_PROXY
	if (site->all_sites)
		log_finest_va("Match all host (line=%d): %s, %s", site->action.line_num, site->site, http_ctx->http_host);
	else if (site->exact)
		log_finest_va("Match exact with host (line=%d): %s, %s", site->action.line_num, site->site, http_ctx->http_host);
	else
		log_finest_va("Match substring in host (line=%d): %s, %s", site->action.line_num, site->site, http_ctx->http_host);
#endif /* DEBUG_PROXY */

	// Port filter does not need stream ctx, because it is only used for connection filtering, not stream filtering
	filter_action_t *port_action = pxy_conn_filter_port(ctx, NULL, site);
	if (port_action)
		return port_action;

	return &site->action;
}

static filter_action_t * NONNULL(1,2)
protohttp_filter_match_uri(protohttp_ctx_t *http_ctx, filter_list_t *list, unsigned int filter_precedence)
{
	pxy_conn_ctx_t *ctx = http_ctx->ctx;

	filter_site_t *site = filter_site_find(list->uri_btree, list->uri_acm, list->uri_all, http_ctx->http_uri);
	if (!site)
		return NULL;

#ifndef WITHOUT_USERAUTH
	log_fine_va("Found site (line=%d): %s for %s:%s, %s:%s, %s, %s, %s", site->action.line_num, site->site,
		STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
		STRORDASH(ctx->user), STRORDASH(ctx->desc), STRORDASH(http_ctx->http_uri));
#else /* WITHOUT_USERAUTH */
	log_fine_va("Found site (line=%d): %s for %s:%s, %s:%s, %s", site->action.line_num, site->site,
		STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
		STRORDASH(http_ctx->http_uri));
#endif /* WITHOUT_USERAUTH */

	if (!site->port_btree && !site->port_acm && (site->action.precedence < filter_precedence)) {
		log_finest_va("Rule precedence lower than conn filter precedence %d < %d (line=%d): %s, %s", site->action.precedence, filter_precedence, site->action.line_num, site->site, http_ctx->http_uri);
		return NULL;
	}

#ifdef DEBUG_PROXY
	if (site->all_sites)
		log_finest_va("Match all uri (line=%d): %s, %s", site->action.line_num, site->site, http_ctx->http_uri);
	else if (site->exact)
		log_finest_va("Match exact with uri (line=%d): %s, %s", site->action.line_num, site->site, http_ctx->http_uri);
	else
		log_finest_va("Match substring in uri (line=%d): %s, %s", site->action.line_num, site->site, http_ctx->http_uri);
#endif /* DEBUG_PROXY */

	// Port filter does not need stream ctx, because it is only used for connection filtering, not stream filtering
	filter_action_t *port_action = pxy_conn_filter_port(ctx, NULL, site);
	if (port_action)
		return port_action;

	return &site->action;
}

static filter_action_t * NONNULL(1,2)
protohttp_filter(pxy_conn_ctx_t *ctx, protohttpx_stream_ctx_t *s, filter_list_t *list)
{
	protohttp_ctx_t *http_ctx = NULL;
	unsigned int filter_precedence = 0;
	if (ctx->proto == PROTO_HTTP2 || ctx->proto == PROTO_HTTP3) {
		http_ctx = s->http_ctx;
		filter_precedence = s->filter_precedence;
	}
	else {
		http_ctx = ctx->protoctx->arg;
		filter_precedence = ctx->filter_precedence;
	}

	filter_action_t *action_host = NULL;
	filter_action_t *action_uri = NULL;

	if (http_ctx->http_host) {
		if (!(action_host = protohttp_filter_match_host(http_ctx, list, filter_precedence))) {
#ifndef WITHOUT_USERAUTH
			log_finest_va("No filter match with host: %s:%s, %s:%s, %s, %s, %s, %s",
				STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
				STRORDASH(ctx->user), STRORDASH(ctx->desc), STRORDASH(http_ctx->http_host), STRORDASH(http_ctx->http_uri));
#else /* WITHOUT_USERAUTH */
			log_finest_va("No filter match with host: %s:%s, %s:%s, %s, %s",
				STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
				STRORDASH(http_ctx->http_host), STRORDASH(http_ctx->http_uri));
#endif /* !WITHOUT_USERAUTH */
		}
	}

	if (http_ctx->http_uri) {
		if (!(action_uri = protohttp_filter_match_uri(http_ctx, list, filter_precedence))) {
#ifndef WITHOUT_USERAUTH
			log_finest_va("No filter match with uri: %s:%s, %s:%s, %s, %s, %s, %s",
				STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
				STRORDASH(ctx->user), STRORDASH(ctx->desc), STRORDASH(http_ctx->http_host), STRORDASH(http_ctx->http_uri));
#else /* WITHOUT_USERAUTH */
			log_finest_va("No filter match with uri: %s:%s, %s:%s, %s, %s",
				STRORDASH(ctx->srchost_str), STRORDASH(ctx->srcport_str), STRORDASH(ctx->dsthost_str), STRORDASH(ctx->dstport_str),
				STRORDASH(http_ctx->http_host), STRORDASH(http_ctx->http_uri));
#endif /* !WITHOUT_USERAUTH */
		}
	}

	if (action_host ||  action_uri)
		return pxy_conn_set_filter_action(action_host, action_uri
#ifdef DEBUG_PROXY
				, ctx, http_ctx->http_host, http_ctx->http_uri
#endif /* DEBUG_PROXY */
				);

	return NULL;
}

static int
protohttp_apply_filter(pxy_conn_ctx_t *ctx)
{
	int rv = 0;
	filter_action_t *a;
	// H1 filter is a conn filter, but H2/H3 stream filter calls protohttpx_apply_filter() with stream ctx
	if ((a = pxy_conn_filter(ctx, NULL, protohttp_filter))) {
		unsigned int action = pxy_conn_translate_filter_action(ctx, a);

		ctx->filter_precedence = action & FILTER_PRECEDENCE;

		if (action & FILTER_ACTION_DIVERT) {
			if (ctx->divert) {
				// Override any deferred block action, if already in divert mode (keep divert mode)
				ctx->deferred_action = FILTER_ACTION_NONE;
			} else {
				log_fine("HTTP filter cannot enable divert mode");
			}
		}
		else if (action & FILTER_ACTION_SPLIT) {
			if (!ctx->divert) {
				// Override any deferred block action, if already in split mode (keep split mode)
				ctx->deferred_action = FILTER_ACTION_NONE;
			} else {
				log_fine("HTTP filter cannot enable split mode");
			}
		}
		else if (action & FILTER_ACTION_PASS) {
			log_fine("HTTP filter cannot take pass action");
		}
		else if (action & FILTER_ACTION_BLOCK) {
			ctx->deferred_action = FILTER_ACTION_NONE;
			pxy_conn_term(ctx, 1);
			rv = 1;
		}
		//else { /* FILTER_ACTION_MATCH */ }

		if (action & (FILTER_LOG_CONTENT | FILTER_LOG_PCAP
#ifndef WITHOUT_MIRROR
				| FILTER_LOG_MIRROR
#endif /* !WITHOUT_MIRROR */
				)) {
#ifndef WITHOUT_MIRROR
			log_fine("HTTP filter cannot enable content, pcap, or mirror logging");
#else /* !WITHOUT_MIRROR */
			log_fine("HTTP filter cannot enable content or pcap logging");
#endif /* WITHOUT_MIRROR */
		}

		// Note that connect, master, and cert logs have already been written by now
		// so enabling or disabling those logs here will not have any effect
		if (action & FILTER_LOG_CONNECT)
			ctx->log_connect = 1;
		else if (action & FILTER_LOG_NOCONNECT)
			ctx->log_connect = 0;
		if (action & FILTER_LOG_MASTER)
			ctx->log_master = 1;
		else if (action & FILTER_LOG_NOMASTER)
			ctx->log_master = 0;
		if (action & FILTER_LOG_CERT)
			ctx->log_cert = 1;
		else if (action & FILTER_LOG_NOCERT)
			ctx->log_cert = 0;

		// content, pcap, and mirror logging can be disabled only
		// loggers will stop writing further contents
		if (action & FILTER_LOG_NOCONTENT)
			ctx->log_content = 0;
		if (action & FILTER_LOG_NOPCAP)
			ctx->log_pcap = 0;
#ifndef WITHOUT_MIRROR
		if (action & FILTER_LOG_NOMIRROR)
			ctx->log_mirror = 0;
#endif /* !WITHOUT_MIRROR */

		if (a->conn_opts) {
			ctx->conn_opts = a->conn_opts;
#ifndef WITHOUT_ICAP
			if (a->conn_opts->icap_chain) {
				ctx->icap_ctx = icap_init(ctx, NULL, NULL, a->conn_opts->icap_chain);
				if (!ctx->icap_ctx) {
					ctx->enomem = 1;
					return 1;
				}
			}
#endif /* !WITHOUT_ICAP */
		}
	}

	// Cannot defer block action any longer
	// Match action should not override any deferred action, hence no 'else if'
	if (pxy_conn_apply_deferred_block_action(ctx))
		rv = 1;

	return rv;
}

int
protohttpx_apply_filter(protohttpx_stream_ctx_t *s)
{
	pxy_conn_ctx_t *ctx = s->ctx;
	log_finest("ENTER");

	// H2/H3 filter is a stream filter
	// Stream filters can only take block or match actions, not divert, split, or pass actions
	int rv = 0;
	filter_action_t *a;
	if ((a = pxy_conn_filter(ctx, s, protohttp_filter))) {
		unsigned int action = pxy_conn_translate_filter_action(ctx, a);

		// H2/H3 stream filter_precedence is for http filters only
		s->filter_precedence = action & FILTER_PRECEDENCE;

		if (action & (FILTER_ACTION_DIVERT | FILTER_ACTION_SPLIT)) {
			log_fine("H2/H3 filter cannot enable/disable divert or split mode");
		}
		else if (action & FILTER_ACTION_PASS) {
			log_fine("H2/H3 filter cannot take pass action");
		}
		else if (action & FILTER_ACTION_BLOCK) {
			if (ctx->proto == PROTO_HTTP2) {
				protohttp2_close_stream((protohttp2_stream_ctx_t *)s);
			}
#ifndef WITHOUT_HTTP3
			else /* if (proto == PROTO_HTTP3) */ {
				protohttp3_close_stream((protohttp3_stream_ctx_t *)s);
			}
#endif /* !WITHOUT_HTTP3 */
			rv = 1;
		}
		//else { /* FILTER_ACTION_MATCH */ }

		if (action & (FILTER_LOG_CONTENT | FILTER_LOG_PCAP
#ifndef WITHOUT_MIRROR
				| FILTER_LOG_MIRROR
#endif /* !WITHOUT_MIRROR */
				)) {
#ifndef WITHOUT_MIRROR
			log_fine("H2/H3 filter cannot enable content, pcap, or mirror logging");
#else /* !WITHOUT_MIRROR */
			log_fine("H2/H3 filter cannot enable content or pcap logging");
#endif /* WITHOUT_MIRROR */
		}

		// Note that connect, master, and cert logs have already been written by now
		// so enabling or disabling those logs here will not have any effect
		if (action & FILTER_LOG_CONNECT)
			s->log_connect = 1;
		else if (action & FILTER_LOG_NOCONNECT)
			s->log_connect = 0;

		// Streams cannot log master or cert, because those logs are only written once per connection

		// content, pcap, and mirror logging can be disabled only
		// loggers will stop writing further contents
		if (action & FILTER_LOG_NOCONTENT)
			s->log_content = 0;
		if (action & FILTER_LOG_NOPCAP)
			s->log_pcap = 0;
#ifndef WITHOUT_MIRROR
		if (action & FILTER_LOG_NOMIRROR)
			s->log_mirror = 0;
#endif /* !WITHOUT_MIRROR */

		if (a->conn_opts) {
			s->conn_opts = a->conn_opts;
#ifndef WITHOUT_ICAP
			if (a->conn_opts->icap_chain) {
				s->icap_ctx = icap_init(ctx, s, ctx->protoctx->arg, a->conn_opts->icap_chain);
				if (!s->icap_ctx) {
					ctx->enomem = 1;
					return 1;
				}
			}
#endif /* !WITHOUT_ICAP */
		}
	}

	// ATTENTION: Block is a conn filter action, so streams in conn should be blocked too
	// Cannot defer block action any longer
	if (ctx->deferred_action & FILTER_ACTION_BLOCK) {
		log_fine("Applying deferred block action");
		if (ctx->proto == PROTO_HTTP2) {
			protohttp2_close_stream((protohttp2_stream_ctx_t *)s);
		}
#ifndef WITHOUT_HTTP3
		else /* if (proto == PROTO_HTTP3) */ {
			protohttp3_close_stream((protohttp3_stream_ctx_t *)s);
		}
#endif /* !WITHOUT_HTTP3 */
		rv = 1;
	}

	return rv;
}

static inline protohttpx_nv_t
protohttpx_get_nv(void *headers, protocol_t proto, size_t idx)
{
    protohttpx_nv_t nv;
    if (proto == PROTO_HTTP2) {
        nghttp2_nv *h2_nv = &((nghttp2_nv *)headers)[idx];
        nv.name = h2_nv->name;
        nv.namelen = h2_nv->namelen;
        nv.value = h2_nv->value;
        nv.valuelen = h2_nv->valuelen;
    } else {
        nghttp3_nv *h3_nv = &((nghttp3_nv *)headers)[idx];
        nv.name = h3_nv->name;
        nv.namelen = h3_nv->namelen;
        nv.value = h3_nv->value;
        nv.valuelen = h3_nv->valuelen;
    }
    return nv;
}

int WUNRES NONNULL(1)
protohttpx_filter_request_header(protohttpx_stream_ctx_t *s, void *headers,
    delete_nv_cb_t delete_nv_cb, UNUSED add_nv_header_t add_nv_header)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);

    size_t count = s->headers_count;
    protohttp_ctx_t *http_ctx = s->http_ctx;
    conn_opts_t *conn_opts = s->conn_opts ? s->conn_opts : ctx->conn_opts;

    for (size_t i = 0; i < count; i++) {
        protohttpx_nv_t nv = protohttpx_get_nv(headers, ctx->proto, i);

        log_finest_va("Processing header '%.*s=%.*s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
            (int)nv.namelen, nv.name, (int)nv.valuelen, nv.value, i, s->src_stream_id, s->dst_stream_id);

        if (nv.namelen == 7 && !memcmp(nv.name, ":method", 7)) {
            if (http_ctx->http_method) {
                free(http_ctx->http_method);
            }
            http_ctx->http_method = malloc(nv.valuelen + 1);
            if (!http_ctx->http_method) {
                s->ctx->enomem = 1;
                return -1;
            }
            memcpy(http_ctx->http_method, nv.value, nv.valuelen);
            http_ctx->http_method[nv.valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http method '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_method, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (nv.namelen == 5 && !memcmp(nv.name, ":path", 5)) {
            if (http_ctx->http_uri) {
                free(http_ctx->http_uri);
            }
            http_ctx->http_uri = malloc(nv.valuelen + 1);
            if (!http_ctx->http_uri) {
                s->ctx->enomem = 1;
                return -1;
            }
            memcpy(http_ctx->http_uri, nv.value, nv.valuelen);
            http_ctx->http_uri[nv.valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http URI '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_uri, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (nv.namelen == 10 && !memcmp(nv.name, ":authority", 10)) {
            if (http_ctx->http_host) {
                free(http_ctx->http_host);
            }
            http_ctx->http_host = malloc(nv.valuelen + 1);
            if (!http_ctx->http_host) {
                s->ctx->enomem = 1;
                return -1;
            }
            memcpy(http_ctx->http_host, nv.value, nv.valuelen);
            http_ctx->http_host[nv.valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http host '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_host, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (nv.namelen == 14 && !memcmp(nv.name, "content-length", 14)) {
			if (http_ctx->http_content_length) {
				free(http_ctx->http_content_length);
			}
			http_ctx->http_content_length = malloc(nv.valuelen + 1);
			if (!http_ctx->http_content_length) {
				s->ctx->enomem = 1;
				return -1;
			}
			memcpy(http_ctx->http_content_length, nv.value, nv.valuelen);
			http_ctx->http_content_length[nv.valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http content-length '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_content_length, i, s->src_stream_id, s->dst_stream_id);
		}
        else if (nv.namelen == 12 && !memcmp(nv.name, "content-type", 12)) {
			if (http_ctx->http_content_type) {
				free(http_ctx->http_content_type);
			}
			http_ctx->http_content_type = malloc(nv.valuelen + 1);
			if (!http_ctx->http_content_type) {
				s->ctx->enomem = 1;
				return -1;
			}
            memcpy(http_ctx->http_content_type, nv.value, nv.valuelen);
            http_ctx->http_content_type[nv.valuelen] = '\0';
			http_ctx->seen_keyword_count++;

            log_finest_va("Http content-type '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_content_type, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (conn_opts->remove_http_accept_encoding && (nv.namelen == 15 && !memcmp(nv.name, "accept-encoding", 15))) {
            delete_nv_cb(s, i);
			http_ctx->seen_keyword_count++;
        }
        else if (conn_opts->remove_http_referer && (nv.namelen == 7 && !memcmp(nv.name, "referer", 7))) {
            delete_nv_cb(s, i);
			http_ctx->seen_keyword_count++;
		}
		         // Not possible in HTTP/2
        else if ((nv.namelen == 4 && !memcmp(nv.name, "host", 4)) ||
                 (nv.namelen == 10 && !memcmp(nv.name, "connection", 10)) ||
                 (nv.namelen == 8 && !memcmp(nv.name, "keep-alive", 8)) ||
                 (nv.namelen == 7 && !memcmp(nv.name, "upgrade", 7)) ||
		         // ATTENTION: flickr keeps redirecting to https with 301 unless we remove the Via line of squid
                 // Apparently flickr assumes the existence of Via header field or squid keyword a sign of plain http, even if we are using https
		         (nv.namelen == 4 && !memcmp(nv.name, "via", 4)) ||
				 // Also do not send the loopback address to the Internet
		         (nv.namelen == 15 && !memcmp(nv.name, "x-forwarded-for", 15))) {
            delete_nv_cb(s, i);
        }
    }

	if (http_ctx->seen_req_header) {
        // ATTENTION: Do not return -1 if protohttpx_apply_filter() fails, ignore the retval.
        // Otherwise with h2, the caller nghttp2_session_mem_recv() in protohttp2_bev_readcb() fails.
        // Otherwise with h3, the caller h3_on_end_headers() returns NGHTTP3_ERR_CALLBACK_FAILURE,
        // which is a fatal error after ngtcp2_conn_read_pkt() in protohttp3_process_packet_cb(),
        // a reason to close the connection altogether
        protohttpx_apply_filter(s);

        // TODO: Implement deny OCSP at TLS level in H2/H3?
        // if (ctx->conn_opts->deny_ocsp) {
        //     protohttp_ocsp_deny(ctx, http_ctx);
        // }
	}

    if (s->ctx->enomem) {
        return -1;
    }
	return 0;
}

int WUNRES NONNULL(1)
protohttpx_filter_response_header(protohttpx_stream_ctx_t *s, void *headers,
    delete_nv_cb_t delete_nv_cb, add_nv_header_t add_nv_header)
{
    UNUSED pxy_conn_ctx_t *ctx = s->ctx;
    log_finest_va("ENTER, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64, s->src_stream_id, s->dst_stream_id);

    // nghttp3_nv *headers = s->headers;
    size_t count = s->headers_count;
    protohttp_ctx_t *http_ctx = s->http_ctx;
    conn_opts_t *conn_opts = s->conn_opts ? s->conn_opts : ctx->conn_opts;

    for (size_t i = 0; i < count; i++) {
        protohttpx_nv_t nv = protohttpx_get_nv(headers, ctx->proto, i);

        log_finest_va("Processing header '%.*s=%.*s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
            (int)nv.namelen, nv.name, (int)nv.valuelen, nv.value, i, s->src_stream_id, s->dst_stream_id);

        if (nv.namelen == 7 && !memcmp(nv.name, ":status", 7)) {
            if (http_ctx->http_status_code) {
                free(http_ctx->http_status_code);
            }
            http_ctx->http_status_code = malloc(nv.valuelen + 1);
            if (!http_ctx->http_status_code) {
                s->ctx->enomem = 1;
                return -1;
            }
            memcpy(http_ctx->http_status_code, nv.value, nv.valuelen);
            http_ctx->http_status_code[nv.valuelen] = '\0';

            log_finest_va("Http status '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_status_code, i, s->src_stream_id, s->dst_stream_id);
        }
        else if (nv.namelen == 14 && !memcmp(nv.name, "content-length", 14)) {
			if (http_ctx->http_content_length) {
				free(http_ctx->http_content_length);
			}
			http_ctx->http_content_length = malloc(nv.valuelen + 1);
			if (!http_ctx->http_content_length) {
				s->ctx->enomem = 1;
				return -1;
			}
			memcpy(http_ctx->http_content_length, nv.value, nv.valuelen);
			http_ctx->http_content_length[nv.valuelen] = '\0';

            log_finest_va("Http content-length '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_content_length, i, s->src_stream_id, s->dst_stream_id);
		}
        else if (nv.namelen == 12 && !memcmp(nv.name, "content-type", 12)) {
			if (http_ctx->http_content_type) {
				free(http_ctx->http_content_type);
			}
			http_ctx->http_content_type = malloc(nv.valuelen + 1);
			if (!http_ctx->http_content_type) {
				s->ctx->enomem = 1;
				return -1;
			}
            memcpy(http_ctx->http_content_type, nv.value, nv.valuelen);
            http_ctx->http_content_type[nv.valuelen] = '\0';

            log_finest_va("Http content-type '%s', idx=%zu, src_stream_id=%" PRId64 ", dst_stream_id=%" PRId64,
                http_ctx->http_content_type, i, s->src_stream_id, s->dst_stream_id);
        }
        // Normally not possible in response
        else if (conn_opts->remove_http_referer && (nv.namelen == 7 && !memcmp(nv.name, "referer", 7))) {
            delete_nv_cb(s, i);
		}
        else if ((nv.namelen == 15 && !memcmp(nv.name, "public-key-pins", 15)) ||
                 (nv.namelen == 27 && !memcmp(nv.name, "public-key-pins-report-only", 27)) ||
                 (nv.namelen == 26 && !memcmp(nv.name, "strict-transport-security", 26)) ||
                 (nv.namelen == 9 && !memcmp(nv.name, "expect-ct", 9)) ||
                 (nv.namelen == 18 && !memcmp(nv.name, "alternate-protocol", 18)) ||
                 (nv.namelen == 7 && !memcmp(nv.name, "upgrade", 7))) {
            delete_nv_cb(s, i);
        }
        // We should not receive alt-svc on an already h3 stream, but if we do, rewrite it to the configured port
        // And h3 proxyspecs should not be configured to rewrite alt-svc anyway
        else if (conn_opts->rewrite_alt_svc_port && !memcmp(nv.name, "alt-svc", 7)) {
            // TODO: Rewrite only the port number in the alt-svc header, keep the rest
            delete_nv_cb(s, i);

            size_t len = strlen("h3=\"\":") + strlen(conn_opts->rewrite_alt_svc_port) + strlen("; ma=86400") + 1;
			char *new_value = malloc(len);
			if (!new_value) {
				s->ctx->enomem = 1;
				return -1;
			}
			snprintf(new_value, len, "h3=\":%s\"; ma=86400", conn_opts->rewrite_alt_svc_port);

            add_nv_header((protohttpx_stream_ctx_t *)s, "alt-svc", strlen("alt-svc"), new_value, strlen(new_value));
            free(new_value);
        }
    }

    if (s->ctx->enomem) {
        return -1;
    }
	return 0;
}

int WUNRES NONNULL(1,2,3,5)
protohttp_filter_request_header(struct evbuffer *inbuf, struct evbuffer *outbuf, protohttp_ctx_t *http_ctx, enum conn_type type, pxy_conn_ctx_t *ctx)
{
	char *line;

	while (!http_ctx->seen_req_header && (line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF))) {
		log_finest_va("%s", line);

		char *replace = protohttp_filter_request_header_line(line, http_ctx, type, ctx);
		if (replace == line) {
			evbuffer_add_printf(outbuf, "%s\r\n", line);
		} else if (replace) {
			log_finer_va("REPLACE= %s", replace);
			evbuffer_add_printf(outbuf, "%s\r\n", replace);
			free(replace);
		} else {
			log_finer_va("REMOVE= %s", line);
			if (ctx->enomem) {
				return -1;
			}
		}
		free(line);

		if ((type == CONN_TYPE_PARENT) && ctx->divert && !ctx->sent_sslproxy_header) {
			ctx->sent_sslproxy_header = 1;
			log_finer_va("INSERT= %s", ctx->sslproxy_header);
			evbuffer_add_printf(outbuf, "%s\r\n", ctx->sslproxy_header);
		}
	}

	if (http_ctx->seen_req_header) {
		if (type == CONN_TYPE_PARENT) {
			if (protohttp_apply_filter(ctx)) {
				return -1;
			}

			/* request header complete */
			if (ctx->conn_opts->deny_ocsp) {
				protohttp_ocsp_deny(ctx, http_ctx);
			}
		}

		if (ctx->enomem) {
			return -1;
		}

		/* no data left after parsing headers? */
		log_finest_va("Buffer length after parsing headers: %zu", evbuffer_get_length(inbuf));
	}
	return 0;
}

#ifndef WITHOUT_USERAUTH
static char * NONNULL(1,2)
protohttp_get_url(struct evbuffer *inbuf, pxy_conn_ctx_t *ctx)
{
	char *line;
	char *path = NULL;
	char *host = NULL;
	char *url = NULL;

	while ((!host || !path) && (line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF))) {
		log_finest_va("%s", line);

		//GET / HTTP/1.1
		if (!path && !strncasecmp(line, "GET ", 4)) {
			path = strdup(util_skipws(line + 4));
			if (!path) {
				ctx->enomem = 1;
				free(line);
				goto memout;
			}
			path = strsep(&path, " \t");
			log_finest_va("path=%s", path);
		//Host: example.com
		} else if (!host && !strncasecmp(line, "Host:", 5)) {
			host = strdup(util_skipws(line + 5));
			if (!host) {
				ctx->enomem = 1;
				free(line);
				goto memout;
			}
			log_finest_va("host=%s", host);
		}
		free(line);
	}

	if (host && path) {
		// Assume that path will always have a leading /, so do not insert an extra / in between host and path
		// Don't care about computing the exact url size for plain or secure http (http or https)
		// http  s   ://  example.com  + /            + NULL
		// 4  +  1 + 3  + strlen(host) + strlen(path) + 1
		size_t url_size = strlen(host) + strlen(path) + 9;
		url = malloc(url_size);
		if (!url) {
			ctx->enomem = 1;
			goto memout;
		}
		
		if (snprintf(url, url_size, "http%s://%s%s", ctx->spec->ssl ? "s": "", host, path) < 0) {
			ctx->enomem = 1;
			free(url);
			url = NULL;
			goto memout;
		}
		log_finest_va("url=%s", url);
	}
memout:
	if (host)
		free(host);
	if (path)
		free(path);
	return url;
}
#endif /* !WITHOUT_USERAUTH */

// Size = 39
static char *http_methods[] = { "GET", "PUT", "ICY", "COPY", "HEAD", "LOCK", "MOVE", "POLL", "POST", "BCOPY", "BMOVE", "MKCOL", "TRACE", "LABEL", "MERGE", "DELETE",
	"SEARCH", "UNLOCK", "REPORT", "UPDATE", "NOTIFY", "BDELETE", "CONNECT", "OPTIONS", "CHECKIN", "PROPFIND", "CHECKOUT", "CCM_POST", "SUBSCRIBE",
	"PROPPATCH", "BPROPFIND", "BPROPPATCH", "UNCHECKOUT", "MKACTIVITY", "MKWORKSPACE", "UNSUBSCRIBE", "RPC_CONNECT", "VERSION-CONTROL", "BASELINE-CONTROL" };

static int NONNULL(1)
protohttp_validate_method(char *method
#ifdef DEBUG_PROXY
	, pxy_conn_ctx_t *ctx
#endif /* DEBUG_PROXY */
	)
{
	size_t method_len = strlen(method);

	unsigned int i;
	for (i = 0; i < sizeof(http_methods)/sizeof(char *); i++) {
		char *m = http_methods[i];
		if (strlen(m) == method_len && !strncasecmp(method, m, method_len)) {
			log_finest_va("Passed method validation: %s", method);
			return 0;
		}
	}
	return -1;
}

int
protohttp_validate(pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	if (http_ctx->not_valid) {
		log_finest("Not http, validation failed previously");
		return -1;
	}
	if (http_ctx->http_method) {
		if (protohttp_validate_method(http_ctx->http_method
#ifdef DEBUG_PROXY
				, ctx
#endif /* DEBUG_PROXY */
				) == -1) {
			http_ctx->not_valid = 1;
			log_finest_va("Failed method validation: %s", http_ctx->http_method);
			return -1;
		}
	}
	if (http_ctx->seen_keyword_count) {
		// The first line has been processed successfully
		// Pass validation if we have seen at least one http keyword
		ctx->protoctx->is_valid = 1;
		log_finest("Passed validation");
		return 0;
	}
	if (http_ctx->seen_bytes > ctx->conn_opts->max_http_header_size) {
		// Fail validation if still cannot pass as http after reaching max header size
		http_ctx->not_valid = 1;
		log_finest_va("Reached max header size, size=%llu", http_ctx->seen_bytes);
		return -1;
	}
	return 0;
}

static void NONNULL(1,2)
protohttp_bev_readcb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifndef WITHOUT_USERAUTH
	static const char redirect[] =
		"HTTP/1.1 302 Found\r\n"
		"Location: %s\r\n"
		"\r\n";
	static const char redirect_url[] =
		"HTTP/1.1 302 Found\r\n"
		"Location: %s?SSLproxy=%s\r\n"
		"\r\n";
#endif /* !WITHOUT_USERAUTH */
	static const char proto_error[] =
		"HTTP/1.1 400 Bad request\r\n"
		"Cache-Control: no-cache\r\n"
		"Connection: close\r\n"
		"Content-Type: text/html\r\n"
		"\r\n";

	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));

	if (ctx->dst.closed) {
		ctx->protoctx->discard_inbufcb(bev);
		return;
	}

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

#ifndef WITHOUT_USERAUTH
	if (ctx->conn_opts->user_auth && !ctx->user) {
		log_finest("Redirecting conn");
		char *url = protohttp_get_url(inbuf, ctx);
		ctx->protoctx->discard_inbufcb(bev);
		if (url) {
			evbuffer_add_printf(bufferevent_get_output(bev), redirect_url, ctx->conn_opts->user_auth_url, url);
			free(url);
		} else {
			evbuffer_add_printf(bufferevent_get_output(bev), redirect, ctx->conn_opts->user_auth_url);
		}
		ctx->sent_userauth_msg = 1;
		return;
	}
#endif /* !WITHOUT_USERAUTH */

	if (ctx->conn_opts->validate_proto && !ctx->protoctx->is_valid) {
		http_ctx->seen_bytes += evbuffer_get_length(inbuf);
	}

	// We insert our special header line to the first packet we get, e.g. right after the first \r\n in the case of http
	// @todo Should we look for GET/POST or Host header lines to detect the first packet?
	// But there is no guarantee that they will exist, due to fragmentation.
	// @attention We cannot append the ssl proxy address at the end of the packet or in between the header and the content,
	// because (1) the packet may be just the first fragment split somewhere not appropriate for appending a header,
	// and (2) there may not be any content.
	// And we are dealing with pop3 and smtp also, not just http.

	/* request header munging */
	if (!http_ctx->seen_req_header) {
		log_finest_va("HTTP Request Header, size=%zu", evbuffer_get_length(inbuf));

		// Use a local pointer to the output buffer
		struct evbuffer *outbuf_ptr = outbuf;
#ifndef WITHOUT_ICAP
		// ATTENTION: Filter rule application in protohttp_filter_request_header() may reinit icap_ctx and change the icap services along with their in_hdr,
		// so we cannot use the in_hdr of first service here. This is only for http requests, not responses, because we don't apply filters to responses.
		// outbuf_ptr = icap_get_first_service_in_hdr(ctx->icap_ctx);
		log_finest_va("Using http_ctx->in_hdr, size=%zu", evbuffer_get_length(http_ctx->in_hdr));
		outbuf_ptr = http_ctx->in_hdr;
#endif /* !WITHOUT_ICAP */

		if (protohttp_filter_request_header(inbuf, outbuf_ptr, http_ctx, ctx->type, ctx) == -1) {
			return;
		}

#ifndef WITHOUT_ICAP
		if (http_ctx->seen_req_header) {
			ctx->icap_ctx->reqmod = 1;
			outbuf_ptr = icap_enabled(ctx->icap_ctx) ? icap_get_first_service_in_hdr(ctx->icap_ctx) : outbuf;
			evbuffer_add_buffer(outbuf_ptr, http_ctx->in_hdr);
		}
#endif /* !WITHOUT_ICAP */
	}

	// There may or may not be data left after parsing headers, but we should send ICAP requests for HTTP headers accumulated too
	if (http_ctx->seen_req_header) {
		log_finest_va("HTTP Request Body, size=%zu", evbuffer_get_length(inbuf));
#ifndef WITHOUT_ICAP
		if (!icap_enabled(ctx->icap_ctx)) {
#endif /* !WITHOUT_ICAP */
			evbuffer_add_buffer(outbuf, inbuf);
#ifndef WITHOUT_ICAP
		}
		else {
			ctx->icap_ctx->reqmod = 1;
			icap_process_data(inbuf, ctx->icap_ctx);
		}
#endif /* !WITHOUT_ICAP */
	}

	if (ctx->conn_opts->validate_proto && !ctx->protoctx->is_valid) {
		if (protohttp_validate(ctx) == -1) {
			evbuffer_add(bufferevent_get_output(bev), proto_error, strlen(proto_error));
			ctx->sent_protoerror_msg = 1;
			ctx->protoctx->discard_inbufcb(bev);
			ctx->protoctx->discard_outbufcb(ctx->dst.bev);
			return;
		}
	}

	// TODO: Watermarking may not be needed if ICAP is enabled, because we disable reads on the source side until ICAP is done.
	// So we should not have too much data buffered on the source side if ICAP is enabled.
	// But we may still want to use watermarking to avoid buffering too much data on the destination side if the client is slow in receiving data.
	ctx->protoctx->set_watermarkcb(bev, ctx, ctx->dst.bev);
}

/*
 * Filter a single line of HTTP response headers.
 *
 * Returns NULL if the current line should be deleted from the response.
 * Returns a newly allocated string if the current line should be replaced.
 * Returns `line' if the line should be kept.
 */
static char * NONNULL(1,2,3)
protohttp_filter_response_header_line(const char *line, protohttp_ctx_t *http_ctx, pxy_conn_ctx_t *ctx)
{
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
		if (!strncasecmp(line, "Content-Length:", 15)) {
			if (http_ctx->http_content_length) {
				free(http_ctx->http_content_length);
			}
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
		} else if (ctx->conn_opts->rewrite_alt_svc_port && !strncasecmp(line, "Alt-Svc:", 8)) {
			// TODO: Rewrite only the port number in the Alt-Svc header, keep the rest
			// Alt-Svc: h3=":8443"; ma=86400
			size_t len = strlen("Alt-Svc: h3=\"\":") + strlen(ctx->conn_opts->rewrite_alt_svc_port) + strlen("; ma=86400") + 1;
			char *new_line = malloc(len);
			if (!new_line) {
				ctx->enomem = 1;
				return NULL;
			}
			snprintf(new_line, len, "Alt-Svc: h3=\":%s\"; ma=86400", ctx->conn_opts->rewrite_alt_svc_port);
			return new_line;
		} else if (line[0] == '\0') {
			http_ctx->seen_resp_header = 1;
		}
	}

	return (char*)line;
}

void NONNULL(1,2,3,4)
protohttp_filter_response_header(struct evbuffer *inbuf, struct evbuffer *outbuf, protohttp_ctx_t *http_ctx, pxy_conn_ctx_t *ctx)
{
	char *line;

	while (!http_ctx->seen_resp_header && (line = evbuffer_readln(inbuf, NULL, EVBUFFER_EOL_CRLF))) {
		log_finest_va("%s", line);

		char *replace = protohttp_filter_response_header_line(line, http_ctx, ctx);
		if (replace == line) {
			evbuffer_add_printf(outbuf, "%s\r\n", line);
		} else if (replace) {
			log_finer_va("REPLACE= %s", replace);
			evbuffer_add_printf(outbuf, "%s\r\n", replace);
			free(replace);
		} else {
			log_finer_va("REMOVE= %s", line);
			if (ctx->enomem) {
				return;
			}
		}
		free(line);
	}

	/* no data left after parsing headers? */
	log_finest_va("Buffer length after parsing headers: %zu", evbuffer_get_length(inbuf));
}

static void NONNULL(1)
protohttp_bev_readcb_dst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));

	if (ctx->src.closed) {
		ctx->protoctx->discard_inbufcb(bev);
		return;
	}

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);

	if (!http_ctx->seen_resp_header) {
		log_finest_va("HTTP Response Header, size=%zu", evbuffer_get_length(inbuf));

		// Use a local pointer to the output buffer
		struct evbuffer *outbuf_ptr = outbuf;
#ifndef WITHOUT_ICAP
		if (icap_enabled(ctx->icap_ctx)) {
			ctx->icap_ctx->reqmod = 0;
			outbuf_ptr = icap_get_first_service_in_hdr(ctx->icap_ctx);
		}
#endif /* !WITHOUT_ICAP */

		protohttp_filter_response_header(inbuf, outbuf_ptr, http_ctx, ctx);
		if (ctx->enomem) {
			return;
		}
	}

	// There may or may not be data left after parsing headers, but we should send ICAP requests for HTTP headers accumulated too
	if (http_ctx->seen_resp_header) {
		log_finest_va("HTTP Response Body, size=%zu", evbuffer_get_length(inbuf));
#ifndef WITHOUT_ICAP
		if (!icap_enabled(ctx->icap_ctx)) {
#endif /* !WITHOUT_ICAP */
			evbuffer_add_buffer(outbuf, inbuf);
#ifndef WITHOUT_ICAP
		}
		else {
			ctx->icap_ctx->reqmod = 0;
			icap_process_data(inbuf, ctx->icap_ctx);
		}
#endif /* !WITHOUT_ICAP */
	}

	// TODO: Watermarking may not be needed if ICAP is enabled, because we disable reads on the source side until ICAP is done.
	// So we should not have too much data buffered on the source side if ICAP is enabled.
	// But we may still want to use watermarking to avoid buffering too much data on the destination side if the client is slow in receiving data.
	ctx->protoctx->set_watermarkcb(bev, ctx, ctx->src.bev);
}

static void NONNULL(1)
protohttp_bev_readcb_srvdst(UNUSED struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	log_err_level(LOG_ERR, "readcb called on srvdst");
}

static void NONNULL(1)
protohttp_bev_readcb_src_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));

	if (ctx->dst.closed) {
		ctx->conn->protoctx->discard_inbufcb(bev);
		return;
	}

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->dst.bev);

	if (!http_ctx->seen_req_header) {
		log_finest_va("HTTP Request Header, size=%zu", evbuffer_get_length(inbuf));
		// @todo Just remove SSLproxy line, do not filter request on the server side?
		if (protohttp_filter_request_header(inbuf, outbuf, http_ctx, ctx->type, ctx->conn) == -1) {
			return;
		}
	}

	if (http_ctx->seen_req_header && evbuffer_get_length(inbuf) > 0) {
		log_finest_va("HTTP Request Body, size=%zu", evbuffer_get_length(inbuf));
		evbuffer_add_buffer(outbuf, inbuf);
	}

	ctx->conn->protoctx->set_watermarkcb(bev, ctx->conn, ctx->dst.bev);
}

static void NONNULL(1)
protohttp_bev_readcb_dst_child(struct bufferevent *bev, pxy_conn_child_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));
		
	if (ctx->src.closed) {
		ctx->conn->protoctx->discard_inbufcb(bev);
		return;
	}

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);

	if (!http_ctx->seen_resp_header) {
		log_finest_va("HTTP Response Header, size=%zu", evbuffer_get_length(inbuf));
		// @todo Do not filter response on the server side?
		protohttp_filter_response_header(inbuf, outbuf, http_ctx, ctx->conn);
		if (ctx->conn->enomem) {
			return;
		}
	}

	if (http_ctx->seen_resp_header && evbuffer_get_length(inbuf) > 0) {
		log_finest_va("HTTP Response Body, size=%zu", evbuffer_get_length(inbuf));
		evbuffer_add_buffer(outbuf, inbuf);
	}

	ctx->conn->protoctx->set_watermarkcb(bev, ctx->conn, ctx->src.bev);
}

static void NONNULL(1)
protohttp_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	int seen_resp_header_on_entry = http_ctx->seen_resp_header;

	if (bev == ctx->src.bev) {
		protohttp_bev_readcb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		protohttp_bev_readcb_dst(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protohttp_bev_readcb_srvdst(bev, ctx);
	} else {
		log_err_printf("protohttp_bev_readcb: UNKWN conn end\n");
		return;
	}

	if (ctx->enomem) {
		return;
	}

	if (!seen_resp_header_on_entry && http_ctx->seen_resp_header) {
		/* response header complete: log connection */
		if (WANT_CONNECT_LOG(ctx->conn)) {
			protohttp_log_connect(ctx, http_ctx, ctx->log_connect);
		}
	}
}

static void NONNULL(1)
protohttp_bev_readcb_child(struct bufferevent *bev, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		protohttp_bev_readcb_src_child(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		protohttp_bev_readcb_dst_child(bev, ctx);
	} else {
		log_err_printf("protohttp_bev_readcb_child: UNKWN conn end\n");
	}
}

static void NONNULL(1)
protohttp_bev_writecb_src(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

#ifndef WITHOUT_USERAUTH
	if (prototcp_try_close_unauth_conn(bev, ctx)) {
		return;
	}
#endif /* !WITHOUT_USERAUTH */

	if (prototcp_try_close_protoerror_conn(bev, ctx)) {
		return;
	}

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	if (ctx->dst.closed || http_ctx->ocsp_denied) {
		if (pxy_try_close_conn_end(&ctx->src, ctx) == 1) {
			log_finest("dst.closed or ocsp_denied, terminate conn");
			pxy_conn_term(ctx, 1);
		}
		return;
	}

#ifndef WITHOUT_ICAP
	// TODO: Watermarking may not be needed if ICAP is enabled, because we disable reads on the source side until ICAP is done.
	// So we should not have too much data buffered on the source side if ICAP is enabled.
	// But we may still want to use watermarking to avoid buffering too much data on the destination side if the client is slow in receiving data.
	// TODO: Should we wait for both src and dst icap to be done before unsetting watermarkcb, or dst only?
	if (!icap_enabled(ctx->icap_ctx)) {
#endif /* !WITHOUT_ICAP */
		ctx->protoctx->unset_watermarkcb(bev, ctx, &ctx->dst);
#ifndef WITHOUT_ICAP
	}
#endif /* !WITHOUT_ICAP */
}

static void NONNULL(1)
protohttp_bev_writecb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		protohttp_bev_writecb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_writecb_dst(bev, ctx);
	} else {
		log_err_printf("protohttp_bev_writecb: UNKWN conn end\n");
	}
}


void
protohttps_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	log_finest("ENTER");

	if (events & BEV_EVENT_ERROR) {
		protossl_log_ssl_error(bev, ctx);
	}

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src(bev, events, ctx);

		if (events & BEV_EVENT_CONNECTED) {
			if (ctx->sslctx->h2) {
				// We set ctx->enomem to 1 on error in protohttp2_setup(), and cannot do anything more here
				ctx->proto = protohttp2_setup(ctx);
			}
		}
	} else if (bev == ctx->dst.bev) {
		protossl_bev_eventcb_dst(bev, events, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protossl_bev_eventcb_srvdst(bev, events, ctx);

		if (events & BEV_EVENT_CONNECTED) {
			if (ctx->sslctx->h2) {
				ctx->proto = protohttp2_setup(ctx);
			}
		}
	} else {
		log_finest("protohttps_bev_eventcb: UNKWN conn end\n");
	}
}

void
protohttps_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;
	log_finest("ENTER");

	if (events & BEV_EVENT_ERROR) {
		protossl_log_ssl_error(bev, ctx->conn);
	}

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src_child(bev, events, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_eventcb_dst_child(bev, events, ctx);
	} else {
		log_finest("protohttps_bev_eventcb_child: UNKWN conn end\n");
	}
}

void NONNULL(1)
protohttp_free_ctx(protohttp_ctx_t *http_ctx)
{
	// log_dbg_printf("protohttp_free_ctx: ENTER\n");

	if (http_ctx->http_method) {
		free(http_ctx->http_method);
		http_ctx->http_method = NULL;
	}
	if (http_ctx->http_uri) {
		free(http_ctx->http_uri);
		http_ctx->http_uri = NULL;
	}
	if (http_ctx->http_host) {
		free(http_ctx->http_host);
		http_ctx->http_host = NULL;
	}
	if (http_ctx->http_content_type) {
		free(http_ctx->http_content_type);
		http_ctx->http_content_type = NULL;
	}
	if (http_ctx->http_status_code) {
		free(http_ctx->http_status_code);
		http_ctx->http_status_code = NULL;
	}
	if (http_ctx->http_status_text) {
		free(http_ctx->http_status_text);
		http_ctx->http_status_text = NULL;
	}
	if (http_ctx->http_content_length) {
		free(http_ctx->http_content_length);
		http_ctx->http_content_length = NULL;
	}
#ifndef WITHOUT_ICAP
	if (http_ctx->in_hdr) {
		evbuffer_free(http_ctx->in_hdr);
		http_ctx->in_hdr = NULL;
	}
#endif /* !WITHOUT_ICAP */
	free(http_ctx);
}

static void NONNULL(1)
protohttp_free(pxy_conn_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	if (http_ctx) {
		protohttp_free_ctx(http_ctx);
		ctx->protoctx->arg = NULL;
	}
}

void NONNULL(1)
protohttps_free(pxy_conn_ctx_t *ctx)
{
	protohttp_free(ctx);
	protossl_free(ctx);
}

void NONNULL(1)
protohttp_free_child(pxy_conn_child_ctx_t *ctx)
{
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	if (http_ctx) {
		protohttp_free_ctx(http_ctx);
		ctx->protoctx->arg = NULL;
	}
}

// @attention Called by thrmgr thread
protocol_t
protohttp_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_HTTP;
	
	ctx->protoctx->bev_readcb = protohttp_bev_readcb;
	ctx->protoctx->bev_writecb = protohttp_bev_writecb;
	ctx->protoctx->proto_free = protohttp_free;

	ctx->protoctx->arg = malloc(sizeof(protohttp_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protohttp_ctx_t));

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	http_ctx->ctx = ctx;

#ifndef WITHOUT_ICAP
	http_ctx->in_hdr = evbuffer_new();
	if (!http_ctx->in_hdr) {
		free(ctx->protoctx->arg);
		return PROTO_ERROR;
	}
#endif /* !WITHOUT_ICAP */

	return PROTO_HTTP;
}

// @attention Called by thrmgr thread
protocol_t
protohttps_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_HTTPS;
	ctx->protoctx->connectcb = protossl_conn_connect;
	ctx->protoctx->init_conn = protossl_init_conn;

	ctx->protoctx->bev_readcb = protohttp_bev_readcb;
	ctx->protoctx->bev_writecb = protohttp_bev_writecb;
	ctx->protoctx->bev_eventcb = protohttps_bev_eventcb;

	ctx->protoctx->proto_free = protohttps_free;

	ctx->protoctx->arg = malloc(sizeof(protohttp_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protohttp_ctx_t));

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	http_ctx->ctx = ctx;

#ifndef WITHOUT_ICAP
	http_ctx->in_hdr = evbuffer_new();
	if (!http_ctx->in_hdr) {
		free(ctx->protoctx->arg);
		return PROTO_ERROR;
	}
#endif /* !WITHOUT_ICAP */

	ctx->sslctx = malloc(sizeof(ssl_ctx_t));
	if (!ctx->sslctx) {
#ifndef WITHOUT_ICAP
		evbuffer_free(http_ctx->in_hdr);
#endif /* !WITHOUT_ICAP */
		free(ctx->protoctx->arg);
		return PROTO_ERROR;
	}
	memset(ctx->sslctx, 0, sizeof(ssl_ctx_t));

	return PROTO_HTTPS;
}

protocol_t
protohttp_setup_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_HTTP;

	// @todo Should HTTP child conns do any http related processing, so use tcp defaults instead?
	ctx->protoctx->bev_readcb = protohttp_bev_readcb_child;
	ctx->protoctx->proto_free = protohttp_free_child;

	ctx->protoctx->arg = malloc(sizeof(protohttp_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protohttp_ctx_t));

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	http_ctx->ctx = ctx->conn;

	return PROTO_HTTP;
}

protocol_t
protohttps_setup_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_HTTPS;
	ctx->protoctx->connectcb = protossl_connect_child;

	ctx->protoctx->bev_readcb = protohttp_bev_readcb_child;
	ctx->protoctx->bev_eventcb = protohttps_bev_eventcb_child;

	ctx->protoctx->proto_free = protohttp_free_child;

	ctx->protoctx->arg = malloc(sizeof(protohttp_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protohttp_ctx_t));

	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
	http_ctx->ctx = ctx->conn;

	return PROTO_HTTPS;
}

#define HTTP_STATUS_REASONS_LEN (sizeof(http_status_reasons) / sizeof(http_status_reasons[0]))

// Returns the standard reason phrase for a given status code.
// If the code is not in our mapping table, falls back to a generic default
// based on the HTTP status class (e.g., "Success", "Client Error").
const char *
http_get_reason_phrase(int status_code)
{
    int low = 0;
    int high = HTTP_STATUS_REASONS_LEN - 1;

    while (low <= high) {
        int mid = low + (high - low) / 2;
        if (http_status_reasons[mid].code == status_code) {
            return http_status_reasons[mid].reason;
        }
        if (http_status_reasons[mid].code < status_code) {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    // Fallback classes if we encounter custom/unlisted status codes
    if (status_code >= 100 && status_code < 200) return "Informational";
    if (status_code >= 200 && status_code < 300) return "Success";
    if (status_code >= 300 && status_code < 400) return "Redirection";
    if (status_code >= 400 && status_code < 500) return "Client Error";
    if (status_code >= 500 && status_code < 600) return "Server Error";

    return "Unknown Status";
}

/* vim: set noet ft=c: */
