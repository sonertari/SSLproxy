/*-
 * SSLproxy
 *
 * Copyright (c) 2017-2026, Soner Tari <sonertari@gmail.com>.
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

#ifndef WITHOUT_ICAP

#include "icap.h"
#include "log.h"
#include "opts.h"
#include "pxyconn.h"
#include "protohttp.h"
#include "util.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

/* Helper to select the src or dst state based on reqmod flag */
#define ICAP_STATE(svc, reqmod) ((reqmod) ? &(svc)->src : &(svc)->dst)

/*
 * Forward declarations of static callbacks
 */
static void icap_bev_readcb(struct bufferevent *, void *);
static void icap_bev_writecb(UNUSED struct bufferevent *, UNUSED void *);
static void icap_bev_eventcb(UNUSED struct bufferevent *, short, void *);
static void icap_process_done(struct evbuffer *, struct evbuffer *, icap_ctx_t *);
static void icap_disconnect(icap_ctx_t *);
static void icap_handle_service_error(icap_service_ctx_t *);
static int icap_build_request(icap_service_ctx_t *);
static int icap_is_content_complete(icap_ctx_t *, int);
static int icap_is_nullbody(icap_service_ctx_t *);
static void icap_process_chain(icap_ctx_t *, int);

/*
 * Helpers to copy data between evbuffers and bufferevents without
 * forcing large contiguous allocations via evbuffer_pullup().
 */
static int
icap_evbuffer_write_bev(struct bufferevent *bev, struct evbuffer *src, size_t len)
{
	struct evbuffer_iovec v[16];
	size_t written = 0;

	while (written < len) {
		int n = evbuffer_peek(src, len - written, NULL, v, 16);
		if (n <= 0)
			return -1;
		for (int i = 0; i < n && written < len; i++) {
			size_t to_write = v[i].iov_len;
			if (to_write > len - written)
				to_write = len - written;
			if (bufferevent_write(bev, v[i].iov_base, to_write) < 0)
				return -1;
			written += to_write;
		}
	}
	return 0;
}

static int
icap_evbuffer_add_evbuf(struct evbuffer *dst, struct evbuffer *src, size_t len)
{
	struct evbuffer_iovec v[16];
	size_t copied = 0;

	while (copied < len) {
		int n = evbuffer_peek(src, len - copied, NULL, v, 16);
		if (n <= 0)
			return -1;
		for (int i = 0; i < n && copied < len; i++) {
			size_t to_copy = v[i].iov_len;
			if (to_copy > len - copied)
				to_copy = len - copied;
			if (evbuffer_add(dst, v[i].iov_base, to_copy) < 0)
				return -1;
			copied += to_copy;
		}
	}
	return 0;
}

/*
 * Read one line from an evbuffer, stripping the EOL terminator.
 *
 * Unlike evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF), this function
 * reports the actual EOL size (1 for bare LF, 2 for CRLF) through *eol_len
 * without requiring callers to measure buffer lengths before and after the
 * call.  It uses evbuffer_search_eol() so the EOL length is a direct result
 * of the search, not derived arithmetic.
 *
 * Returns a malloc'd, NUL-terminated line string (caller must free).
 * Returns buffer contents if no complete line is available in the buffer yet.
 */
static char *
icap_evbuffer_readline(struct evbuffer *input, size_t *eol_len)
{
	size_t eol_sz = 0;
	struct evbuffer_ptr ptr = evbuffer_search_eol(input, NULL, &eol_sz, EVBUFFER_EOL_CRLF);

	size_t line_len = 0;
	if (ptr.pos < 0) {
		line_len = evbuffer_get_length(input);
	}
	else {
		line_len = (size_t)ptr.pos;
	}

	char *line = malloc(line_len + 1);
	if (!line)
		return NULL;

	evbuffer_copyout(input, line, line_len);
	line[line_len] = '\0';
	evbuffer_drain(input, line_len + eol_sz);

	if (eol_len)
		*eol_len = eol_sz;
	return line;
}

static void NONNULL(1)
icap_service_ctx_free(icap_service_ctx_t *service_ctx)
{
	UNUSED pxy_conn_ctx_t *ctx = service_ctx->icap_ctx->conn_ctx;
	log_finest_icap("ENTER");

	if (service_ctx->src.in_hdr) {
		evbuffer_free(service_ctx->src.in_hdr);
	}
	if (service_ctx->src.in_body) {
		evbuffer_free(service_ctx->src.in_body);
	}
	if (service_ctx->src.sent_hdr) {
		evbuffer_free(service_ctx->src.sent_hdr);
	}
	if (service_ctx->src.sent_body) {
		evbuffer_free(service_ctx->src.sent_body);
	}
	if (service_ctx->src.out_hdr) {
		evbuffer_free(service_ctx->src.out_hdr);
	}
	if (service_ctx->src.out_body) {
		evbuffer_free(service_ctx->src.out_body);
	}
	if (service_ctx->dst.in_hdr) {
		evbuffer_free(service_ctx->dst.in_hdr);
	}
	if (service_ctx->dst.in_body) {
		evbuffer_free(service_ctx->dst.in_body);
	}
	if (service_ctx->dst.sent_hdr) {
		evbuffer_free(service_ctx->dst.sent_hdr);
	}
	if (service_ctx->dst.sent_body) {
		evbuffer_free(service_ctx->dst.sent_body);
	}
	if (service_ctx->dst.out_hdr) {
		evbuffer_free(service_ctx->dst.out_hdr);
	}
	if (service_ctx->dst.out_body) {
		evbuffer_free(service_ctx->dst.out_body);
	}
	if (service_ctx->echo_header) {
		free(service_ctx->echo_header);
	}
	free(service_ctx);
}

icap_service_ctx_t *
icap_service_ctx_new(icap_service_t *svc, icap_ctx_t *icap_ctx, int idx)
{
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
	log_finest("ENTER");

	icap_service_ctx_t *service_ctx = malloc(sizeof(icap_service_ctx_t));
	if (!service_ctx) {
		log_err_printf("ICAP service context allocation failed\n");
		return NULL;
	}
	memset(service_ctx, 0, sizeof(icap_service_ctx_t));

	service_ctx->idx = idx;
	service_ctx->svc = svc;
	service_ctx->icap_ctx = icap_ctx;

	service_ctx->src.in_hdr = evbuffer_new();
	if (!service_ctx->src.in_hdr) {
		goto err;
	}
	service_ctx->src.in_body = evbuffer_new();
	if (!service_ctx->src.in_body) {
		goto err;
	}

	service_ctx->src.sent_hdr = evbuffer_new();
	if (!service_ctx->src.sent_hdr) {
		goto err;
	}
	service_ctx->src.sent_body = evbuffer_new();
	if (!service_ctx->src.sent_body) {
		goto err;
	}

	service_ctx->src.out_hdr = evbuffer_new();
	if (!service_ctx->src.out_hdr) {
		goto err;
	}
	service_ctx->src.out_body = evbuffer_new();
	if (!service_ctx->src.out_body) {
		goto err;
	}

	service_ctx->dst.in_hdr = evbuffer_new();
	if (!service_ctx->dst.in_hdr) {
		goto err;
	}
	service_ctx->dst.in_body = evbuffer_new();
	if (!service_ctx->dst.in_body) {
		goto err;
	}

	service_ctx->dst.sent_hdr = evbuffer_new();
	if (!service_ctx->dst.sent_hdr) {
		goto err;
	}
	service_ctx->dst.sent_body = evbuffer_new();
	if (!service_ctx->dst.sent_body) {
		goto err;
	}

	service_ctx->dst.out_hdr = evbuffer_new();
	if (!service_ctx->dst.out_hdr) {
		goto err;
	}
	service_ctx->dst.out_body = evbuffer_new();
	if (!service_ctx->dst.out_body) {
		goto err;
	}

	return service_ctx;
err:
	log_err_printf("ICAP service evbuffer_new failed\n");
	icap_service_ctx_free(service_ctx);
	return NULL;
}

static void NONNULL(1)
icap_conn_term(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	// ATTENTION: Do not set term, we free icap_ctx before firing the eof event below, so eof eventcb will terminate the connection
	// otherwise, we cannot flush the remaining data
	// pxy_conn_term(ctx, 1);

	// ATTENTION: Trigger eof event for the other side to ensure any pending data is flushed out
	if (ctx->src.bev) {
		// pxy_bev_eventcb(ctx->src.bev, BEV_EVENT_EOF, ctx);
		pxy_bev_eventcb(ctx->dst.bev, BEV_EVENT_EOF, ctx);
	}
	else if (ctx->dst.bev) {
		// pxy_bev_eventcb(ctx->dst.bev, BEV_EVENT_EOF, ctx);
		pxy_bev_eventcb(ctx->src.bev, BEV_EVENT_EOF, ctx);
	}
	else {
		log_finest("No bev to trigger eventcb with BEV_EVENT_EOF");
	}
}

void
icap_ctx_free(icap_ctx_t *icap_ctx)
{
	if (!icap_ctx) {
		log_dbg_printf("No ICAP context to free\n");
		return;
	}
	log_dbg_printf("ICAP context free\n");

	if (icap_ctx->chain_ev) {
		event_free(icap_ctx->chain_ev);
		icap_ctx->chain_ev = NULL;
	}

	/* Disconnect if connected */
	icap_disconnect(icap_ctx);

	/* Free buffers */
	if (icap_ctx->veto_page) {
		evbuffer_free(icap_ctx->veto_page);
	}
	if (icap_ctx->icap_extended_headers) {
		free(icap_ctx->icap_extended_headers);
	}

	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
	free(icap_ctx);
	ctx->icap_ctx = NULL;

	icap_conn_term(ctx);
}

static icap_ctx_t *
icap_ctx_new(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	icap_ctx_t *icap_ctx = malloc(sizeof(icap_ctx_t));
	if (!icap_ctx) {
		log_err_printf("ICAP context allocation failed\n");
		return NULL;
	}
	memset(icap_ctx, 0, sizeof(icap_ctx_t));

	ctx->icap_ctx = icap_ctx;
	icap_ctx->conn_ctx = ctx;

	icap_service_t *svc = ctx->conn_opts->icap_chain;
	icap_ctx->service_count = 0;

	while (svc && icap_ctx->service_count < ICAP_MAX_SERVICES) {
		icap_ctx->services[icap_ctx->service_count] = icap_service_ctx_new(svc, icap_ctx, icap_ctx->service_count);
		if (!icap_ctx->services[icap_ctx->service_count]) {
			log_err_printf("ICAP service context allocation failed\n");
			icap_ctx_free(icap_ctx);
			return NULL;
		}
		svc = svc->next;
		icap_ctx->service_count++;
	}

	return icap_ctx;
}

icap_ctx_t *
icap_init(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	icap_ctx_t *icap_ctx = icap_ctx_new(ctx);
	if (!icap_ctx)
		return NULL;

	if (icap_set_extended_headers(icap_ctx, 0) == -1) {
		log_err_printf("Failed to set ICAP extended headers\n");
		icap_ctx_free(icap_ctx);
		return NULL;
	}

	return icap_ctx;
}

/*
 * Free an ICAP service chain
 */
void
icap_service_free(icap_service_t *chain)
{
	while (chain) {
		icap_service_t *next = chain->next;
		if (chain->server) free(chain->server);
		if (chain->uri) free(chain->uri);
		if (chain->reqmod) free(chain->reqmod);
		if (chain->respmod) free(chain->respmod);
		if (chain->echo_header) free(chain->echo_header);
		free(chain);
		chain = next;
	}
}

/*
 * Copy an ICAP service chain
 */
icap_service_t *
icap_service_copy(icap_service_t *chain)
{
	icap_service_t *new_chain = NULL, *last = NULL;
	while (chain) {
		icap_service_t *svc = malloc(sizeof(icap_service_t));
		if (!svc) {
			icap_service_free(new_chain);
			return NULL;
		}
		memset(svc, 0, sizeof(*svc));
		svc->server = chain->server ? strdup(chain->server) : NULL;
		svc->port = chain->port;
		svc->uri = chain->uri ? strdup(chain->uri) : NULL;
		svc->reqmod = chain->reqmod ? strdup(chain->reqmod) : NULL;
		svc->respmod = chain->respmod ? strdup(chain->respmod) : NULL;
		svc->icap_fail_open = chain->icap_fail_open;
		svc->conn_fail_open = chain->conn_fail_open;
		svc->timeout = chain->timeout;
		svc->preview_size = chain->preview_size;
		svc->max_body_size = chain->max_body_size;
		svc->allow_204 = chain->allow_204;
		svc->allow_206 = chain->allow_206;
		svc->echo_header = chain->echo_header ? strdup(chain->echo_header) : NULL;
		svc->next = NULL;

		if ((chain->server && !svc->server) ||
		    (chain->uri && !svc->uri) ||
		    (chain->reqmod && !svc->reqmod) ||
		    (chain->respmod && !svc->respmod) ||
		    (chain->echo_header && !svc->echo_header)) {
			icap_service_free(svc);
			icap_service_free(new_chain);
			return NULL;
		}
		
		if (!new_chain) new_chain = svc;
		else last->next = svc;
		last = svc;
		
		chain = chain->next;
	}
	return new_chain;
}

static int NONNULL(1)
icap_chain_size(conn_opts_t *conn_opts)
{
	icap_service_t *curr = conn_opts->icap_chain;
	int count = 0;
	while (curr) {
		count++;
		curr = curr->next;
	}
	return count;
}

/*
 * Parse an ICAP service specification string
 * Format: icap://<host>:<port>,<reqmod>,<respmod>,<mode>,<conn_mode>,<timeout>,<preview>,<max_body_size>,<allow_204>,<allow_206>,<echo_header>
 * Example: icap://127.0.0.1:1344,echo,echo,open,open,3,1024,4096,yes,no
 * Example: icap://127.0.0.1:1345,reqmod,respmod,close,close,30,4096,8192,yes,yes,X-ICAP-E2G
 */
int NONNULL(1, 2)
icap_chain_parse_spec(conn_opts_t *conn_opts, const char *spec)
{
	if (icap_chain_size(conn_opts) >= ICAP_MAX_SERVICES) {
		log_err_printf("ICAP Config Error: Maximum number of services (%d) already configured\n", ICAP_MAX_SERVICES);
		return -1;
	}

	/* Create and initialize a new service */
	icap_service_t *svc = malloc(sizeof(icap_service_t));
	if (!svc) return -1;
	memset(svc, 0, sizeof(icap_service_t));
	
	/* Defaults */
	svc->port = 1344;
	svc->icap_fail_open = conn_opts->icap_fail_open;
	svc->conn_fail_open = conn_opts->icap_conn_fail_open;
	svc->timeout = conn_opts->icap_timeout;
	svc->preview_size = conn_opts->icap_preview_size;
	svc->max_body_size = conn_opts->icap_max_body_size;
	svc->allow_204 = conn_opts->icap_allow_204;
	svc->allow_206 = conn_opts->icap_allow_206;

	/* Make a local copy to tokenize */
	char *spec_copy = strdup(spec);
	if (!spec_copy) {
		goto err;
	}

	char *saveptr = NULL;
	char *uri = strtok_r(spec_copy, ",", &saveptr);
	char *reqmod = strtok_r(NULL, ",", &saveptr);
	char *respmod = strtok_r(NULL, ",", &saveptr);
	char *mode = strtok_r(NULL, ",", &saveptr);
	char *conn_mode = strtok_r(NULL, ",", &saveptr);
	char *timeout = strtok_r(NULL, ",", &saveptr);
	char *preview = strtok_r(NULL, ",", &saveptr);
	char *max_body_size = strtok_r(NULL, ",", &saveptr);
	char *allow_204 = strtok_r(NULL, ",", &saveptr);
	char *allow_206 = strtok_r(NULL, ",", &saveptr);
	char *echo_header = strtok_r(NULL, ",", &saveptr);
	char *trailing = strtok_r(NULL, ",", &saveptr);

	if (!uri) {
		log_err_printf("ICAP Config Error: Missing URI in spec '%s'\n", spec);
		goto err;
	}

	/* Parse URI: icap://<host>:<port> */
	svc->uri = strdup(uri);
	if (!svc->uri) {
		goto err;
	}

	char *host_start = NULL;
	if (strncmp(uri, "icap://", 7) == 0) {
		host_start = uri + 7;
	} else if (strncmp(uri, "icaps://", 8) == 0) {
		host_start = uri + 8;
	} else {
		log_err_printf("ICAP Config Error: URI must start with icap:// or icaps://\n");
		goto err;
	}

	/* isolate host and port from trailing path */
	char *reqmod_start = strchr(host_start, '/');
	if (reqmod_start) {
		log_err_printf("ICAP Config Error: URI path not allowed '%s'\n", reqmod_start + 1);
		goto err;
	}

	char *port_delim = strchr(host_start, ':');
	if (port_delim) {
		*port_delim = '\0';
		char *port = port_delim + 1;
		#define ICAP_PORT_MAX_DIGITS 5
		if (strlen(port) <= ICAP_PORT_MAX_DIGITS && strspn(port, "0123456789") == strlen(port)) {
			char *endptr;
			unsigned long val = strtoul(port, &endptr, 10);
			if (endptr == port || *endptr != '\0' || val > 65535) {
				log_err_printf("ICAP Config Error: Invalid port '%s'\n", port);
				goto err;
			}
			svc->port = (int)val;
		}
		else {
			log_err_printf("ICAP Config Error: Port invalid in URI '%s'\n", uri);
			goto err;
		}
	}
	
	svc->server = strdup(host_start);
	if (!svc->server) {
		goto err;
	}

	if (reqmod) {
		svc->reqmod = strdup(reqmod);
	}

	if (respmod) {
		svc->respmod = strdup(respmod);
	}

	/* Parse Mode */
	if (mode) {
		if (strcasecmp(mode, "close") == 0) {
			svc->icap_fail_open = ICAP_FAIL_CLOSE;
		} else if (strcasecmp(mode, "open") == 0) {
			svc->icap_fail_open = ICAP_FAIL_OPEN;
		} else {
			log_err_printf("ICAP Config Error: Unknown fail mode '%s'\n", mode);
			goto err;
		}
	}

	/* Parse Conn Mode */
	if (conn_mode) {
		if (strcasecmp(conn_mode, "close") == 0) {
			svc->conn_fail_open = ICAP_FAIL_CLOSE;
		} else if (strcasecmp(conn_mode, "open") == 0) {
			svc->conn_fail_open = ICAP_FAIL_OPEN;
		} else {
			log_err_printf("ICAP Config Error: Unknown fail mode '%s'\n", conn_mode);
			goto err;
		}
	}

	if (timeout) {
		#define ICAP_TIMEOUT_MAX_DIGITS 2
		if (strlen(timeout) <= ICAP_TIMEOUT_MAX_DIGITS && strspn(timeout, "0123456789") == strlen(timeout)) {
			char *endptr;
			unsigned long val = strtoul(timeout, &endptr, 10);
			if (endptr == timeout || *endptr != '\0' || val > 60) {
				log_err_printf("ICAP Config Error: Invalid timeout '%s'\n", timeout);
				goto err;
			}
			svc->timeout = (int)val;
		}
		else {
			log_err_printf("ICAP Config Error: Invalid timeout '%s'\n", timeout);
			goto err;
		}
	}

	if (preview) {
		#define ICAP_PREVIEW_MAX_DIGITS 8
		if (strlen(preview) <= ICAP_PREVIEW_MAX_DIGITS && strspn(preview, "0123456789") == strlen(preview)) {
			char *endptr;
			unsigned long val = strtoul(preview, &endptr, 10);
			if (endptr == preview || *endptr != '\0' || val > 16777216) {
				log_err_printf("ICAP Config Error: Invalid preview size '%s'\n", preview);
				goto err;
			}
			svc->preview_size = (int)val;
		}
		else {
			log_err_printf("ICAP Config Error: Invalid preview size '%s'\n", preview);
			goto err;
		}
	}

	if (max_body_size) {
		#define ICAP_MAX_BODY_SIZE_MAX_DIGITS 8
		if (strlen(max_body_size) <= ICAP_MAX_BODY_SIZE_MAX_DIGITS && strspn(max_body_size, "0123456789") == strlen(max_body_size)) {
			char *endptr;
			unsigned long val = strtoul(max_body_size, &endptr, 10);
			if (endptr == max_body_size || *endptr != '\0' || val > 16777216) {
				log_err_printf("ICAP Config Error: Invalid max body size '%s'\n", max_body_size);
				goto err;
			}
			svc->max_body_size = (int)val;
		}
		else {
			log_err_printf("ICAP Config Error: Invalid max body size '%s'\n", max_body_size);
			goto err;
		}
	}

	if (allow_204) {
		if (strcasecmp(allow_204, "yes") == 0) {
			svc->allow_204 = 1;
		} else if (strcasecmp(allow_204, "no") == 0) {
			svc->allow_204 = 0;
		} else {
			log_err_printf("ICAP Config Error: Unknown allow 204 value '%s'\n", allow_204);
			goto err;
		}
	}

	if (allow_206) {
		if (strcasecmp(allow_206, "yes") == 0) {
			svc->allow_206 = 1;
		} else if (strcasecmp(allow_206, "no") == 0) {
			svc->allow_206 = 0;
		} else {
			log_err_printf("ICAP Config Error: Unknown allow 206 value '%s'\n", allow_206);
			goto err;
		}
	}

	if (echo_header) {
		svc->echo_header = strdup(echo_header);
	}

	if (trailing) {
		log_err_printf("ICAP Config Error: Extra fields in spec '%s'\n", spec);
		goto err;
	}

	free(spec_copy);

	/* Append to chain */
	if (!conn_opts->icap_chain) {
		conn_opts->icap_chain = svc;
	} else {
		icap_service_t *curr = conn_opts->icap_chain;
		while (curr->next) curr = curr->next;
		curr->next = svc;
	}

	return 0;
err:
	if (svc->uri) free(svc->uri);
	if (svc->server) free(svc->server);
	if (svc->reqmod) free(svc->reqmod);
	if (svc->respmod) free(svc->respmod);
	if (svc->echo_header) free(svc->echo_header);
	if (spec_copy) free(spec_copy);
	free(svc);
	return -1;
}

struct evbuffer * NONNULL(1)
icap_get_first_service_in_hdr(pxy_conn_ctx_t *ctx, int reqmod)
{
	icap_ctx_t *icap_ctx = ctx->icap_ctx;
	return reqmod ? icap_ctx->services[0]->src.in_hdr : icap_ctx->services[0]->dst.in_hdr;
}

int NONNULL(1)
icap_set_extended_headers(icap_ctx_t *icap_ctx, int upgraded)
{
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
	log_finest("ENTER");

	/* Build the ICAP meta headers (X-Src, X-Dst, X-Proto, X-User) */
	const char *proto = "tcp";
	if (ctx->spec->http) proto = ctx->spec->ssl || upgraded ? "https" : "http";
	else if (ctx->spec->pop3) proto = ctx->spec->ssl || upgraded ? "pop3s" : "pop3";
	else if (ctx->spec->smtp) proto = ctx->spec->ssl || upgraded ? "smtps" : "smtp";
	else if (ctx->spec->upgrade) proto = upgraded ? "autossl-tls" : "autossl";
	else if (ctx->spec->ssl || upgraded) proto = "ssl";

	#define ICAP_USER_HEADER_MAX_LEN 256
	char user_hdr[ICAP_USER_HEADER_MAX_LEN];
	user_hdr[0] = '\0';
#ifndef WITHOUT_USERAUTH
	if (ctx->conn_opts->user_auth && ctx->user) {
		snprintf(user_hdr, sizeof(user_hdr), "X-User: %s\r\n", ctx->user);
	}
#endif /* !WITHOUT_USERAUTH */

	// Estimate string length
	size_t len = snprintf(NULL, 0,
		"X-Src: [%s]:%s\r\n"
		"X-Dst: [%s]:%s\r\n"
		"X-Proto: %s\r\n"
		"%s",
		STRORNONE(ctx->srchost_str), STRORNONE(ctx->srcport_str),
		STRORNONE(ctx->dsthost_str), STRORNONE(ctx->dstport_str),
		proto, user_hdr);

	if (len == SIZE_MAX || len + 1 > SIZE_MAX / sizeof(char)) {
		icap_conn_term(ctx);
		return -1;
	}

	icap_ctx->icap_extended_headers = malloc(len + 1);
	if (!icap_ctx->icap_extended_headers) {
		icap_conn_term(ctx);
		return -1;
	}

	if (snprintf(icap_ctx->icap_extended_headers, len + 1,
		"X-Src: [%s]:%s\r\n"
		"X-Dst: [%s]:%s\r\n"
		"X-Proto: %s\r\n"
		"%s",
		STRORNONE(ctx->srchost_str), STRORNONE(ctx->srcport_str),
		STRORNONE(ctx->dsthost_str), STRORNONE(ctx->dstport_str),
		proto, user_hdr) < 0) {

		icap_conn_term(ctx);
		return -1;
	}
	return 0;
}

/*
 * Setup and dispatch a connection to an explicit ICAP service
 */
static int
icap_service_connect(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	// TODO: Do we need to check failopen state if no progress, otherwise do we go into an infinite loop?
	// if (service_ctx->failopen && icap_ctx->made_progress) {
	if (service_ctx->failopen) {
		log_finer_icap("ICAP service in failopen state");
		return -1;
	}

	if (!service_ctx->bev) {
		struct bufferevent *bev = bufferevent_socket_new(ctx->thr->evbase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
		if (!bev) {
			log_fine_icap("ICAP bufferevent allocation failed");
			return -1;
		}
		service_ctx->bev = bev;

		bufferevent_setcb(bev, icap_bev_readcb, icap_bev_writecb, icap_bev_eventcb, service_ctx);
		bufferevent_setwatermark(bev, EV_READ, 0, 0);

		struct timeval tv;
		tv.tv_sec = service_ctx->svc->timeout;
		tv.tv_usec = 0;
		bufferevent_set_timeouts(bev, &tv, &tv);

		if (bufferevent_socket_connect_hostname(bev, NULL, AF_UNSPEC, service_ctx->svc->server, service_ctx->svc->port) < 0) {
			log_finest_icap_va("ICAP connection failed to %s:%d", service_ctx->svc->server, service_ctx->svc->port);
			bufferevent_free(bev);
			return -1;
		}

		bufferevent_enable(bev, EV_READ | EV_WRITE);
		log_finest_icap_va("ICAP connecting to %s:%d", service_ctx->svc->server, service_ctx->svc->port);
	}
	else {
		log_finest_icap_va("ICAP already connected to %s:%d", service_ctx->svc->server, service_ctx->svc->port);

		int rv = icap_build_request(service_ctx);
		if (rv < 0) {
			log_finest_icap_va("ICAP failed to build and send request to %s:%d", service_ctx->svc->server, service_ctx->svc->port);
			icap_handle_service_error(service_ctx);
			return -1;
		}
		else if (rv == 0) {
			log_finest_icap_va("ICAP request sent to service at %s:%d", service_ctx->svc->server, service_ctx->svc->port);
		}
	}

	return 0;
}

void NONNULL(1)
icap_service_disconnect(icap_service_ctx_t *service_ctx, icap_ctx_t *icap_ctx)
{
	// ATTENTION: Check ctx before calling log macros in this function, as ctx may be NULL
	// ATTENTION: Do not get icap_ctx from service_ctx here, because service_ctx may be already freed and its pointer may be dangling,
	// so we pass ctx->icap_ctx as a parameter to this function
	// icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	if (!icap_ctx) {
		log_dbg_printf("No ICAP context in icap_service_disconnect(), idx=%d\n", service_ctx->idx);
		return;
	}

	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (service_ctx->bev) {
		if (ctx) log_finest_icap("Disable bufferevents");
		else log_dbg_printf("Disable bufferevents for service idx=%d\n", service_ctx->idx);
		
		bufferevent_disable(service_ctx->bev, EV_READ | EV_WRITE);
		bufferevent_setcb(service_ctx->bev, NULL, NULL, NULL, NULL);
		bufferevent_set_timeouts(service_ctx->bev, NULL, NULL);

		evutil_socket_t fd = bufferevent_getfd(service_ctx->bev);
		if (fd >= 0) {
			if (ctx) log_finest_icap_va("Closing ICAP socket fd=%d", fd);
			else log_dbg_printf("Closing ICAP socket fd=%d for service idx=%d\n", fd, service_ctx->idx);

			// Don't close the socket here, let bufferevent_free handle it, otherwise we get Epoll Bad file descriptor errors.
			// evutil_closesocket(fd);
		}

		bufferevent_free(service_ctx->bev);
		service_ctx->bev = NULL;
	}

	// ATTENTION: Do not free service_ctx here, just disconnect

	if (ctx) log_finest_icap("ICAP service disconnected");
	else log_dbg_printf("ICAP service disconnected, svc idx=%d\n", service_ctx->idx);
}

static int NONNULL(1)
icap_have_data_to_process(icap_ctx_t *icap_ctx, int *service_idx)
{
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	// TODO: This may not be needed, as we move source data to the first service's in_hdr and in_body buffers as soon as it arrives
	// so if there is data in src or dst bev input buffers, its readcb should fire soon or its watermark may be activated, so we can just wait for that instead of busy checking here
	// if (evbuffer_get_length(bufferevent_get_input(ctx->src.bev)) > 0 || evbuffer_get_length(bufferevent_get_input(ctx->dst.bev)) > 0) {
	// 	log_finest_va("Source has data, src=%zu, dst=%zu, go to first service, return idx=0",
	// 		evbuffer_get_length(bufferevent_get_input(ctx->src.bev)),
	// 		evbuffer_get_length(bufferevent_get_input(ctx->dst.bev)));
	// 	*service_idx = 0;
	// 	return 1;
	// }

	for (int i = 0; i < icap_ctx->service_count; i++) {
		if (icap_ctx->services[i] && icap_ctx->services[i]->bev) {
			// TODO: Do we need to check the bev input buffer for data to process, but if we do, then chain goes into an infinite loop
			// struct evbuffer *input = bufferevent_get_input(icap_ctx->services[i]->bev);
			// if (evbuffer_get_length(input) > 0) {
			// 	log_finest_va("Service has data, input=%zu, service idx=%d", evbuffer_get_length(input), i);
			// 	*service_idx = i;
			// 	return 1;
			// }

			// TODO: Do we need to check in_hdr and out_hdr for data to process, but if we do, then chain goes into an infinite loop,
			// because the ith service is waiting for in_body data to arrive, hence never processes in_hdr data, even if it is present
			// if (evbuffer_get_length(icap_ctx->services[i]->src.in_hdr) > 0 || evbuffer_get_length(icap_ctx->services[i]->dst.in_hdr) > 0) {
			// 	log_finest_va("Service has in_hdr data, src.in_hdr=%zu, dst.in_hdr=%zu, service idx=%d",
			// 		evbuffer_get_length(icap_ctx->services[i]->src.in_hdr), evbuffer_get_length(icap_ctx->services[i]->dst.in_hdr), i);

			// 	unsigned int wait_preview_continue = icap_ctx->services[i]->src.wait_preview_continue | icap_ctx->services[i]->dst.wait_preview_continue;
			// 	if (!wait_preview_continue) {
			// 		*service_idx = i;
			// 		return 1;
			// 	}
			// 	else {
			// 		log_finest_va("Service is waiting for preview continue, do not process in_hdr data yet, service idx=%d", i);
			// 	}
			// }

			if (evbuffer_get_length(icap_ctx->services[i]->src.in_body) > 0 || evbuffer_get_length(icap_ctx->services[i]->dst.in_body) > 0) {
				log_finest_va("Service has in_body data, src.in_body=%zu, dst.in_body=%zu, service idx=%d",
					evbuffer_get_length(icap_ctx->services[i]->src.in_body), evbuffer_get_length(icap_ctx->services[i]->dst.in_body), i);

				unsigned int wait_preview_continue = icap_ctx->services[i]->src.wait_preview_continue | icap_ctx->services[i]->dst.wait_preview_continue;
				unsigned int detected_204 = icap_ctx->services[i]->src.detected_204 | icap_ctx->services[i]->dst.detected_204;
				unsigned int detected_206 = icap_ctx->services[i]->src.detected_206 | icap_ctx->services[i]->dst.detected_206;
				if (!wait_preview_continue || detected_204 || detected_206) {
					*service_idx = i;
					return 1;
				}
				else {
					if (icap_ctx->services[i]->failopen) {
						log_finest_va("Service is in failopen state, ignore wait_preview_continue and process in_body data, service idx=%d", i);
						*service_idx = i;
						return 1;
					}
					log_finest_va("Service is waiting for preview continue, do not process in_body data yet, service idx=%d", i);
				}
			}

			if (evbuffer_get_length(icap_ctx->services[i]->src.out_hdr) > 0 || evbuffer_get_length(icap_ctx->services[i]->dst.out_hdr) > 0) {
				log_finest_va("Service has out_hdr data, src.out_hdr=%zu, dst.out_hdr=%zu, service idx=%d",
					evbuffer_get_length(icap_ctx->services[i]->src.out_hdr), evbuffer_get_length(icap_ctx->services[i]->dst.out_hdr), i);
				*service_idx = i;
				return 1;
			}

			if (evbuffer_get_length(icap_ctx->services[i]->src.out_body) > 0 || evbuffer_get_length(icap_ctx->services[i]->dst.out_body) > 0) {
				log_finest_va("Service has out_body data, src.out_body=%zu, dst.out_body=%zu, service idx=%d",
					evbuffer_get_length(icap_ctx->services[i]->src.out_body), evbuffer_get_length(icap_ctx->services[i]->dst.out_body), i);
				*service_idx = i;
				return 1;
			}
		}
	}
	log_finest("No service has data to process");
	return 0;
}

static void
icap_send_data(icap_ctx_t *icap_ctx)
{
	if (!icap_ctx) {
		log_dbg_printf("No ICAP context in icap_send_data()\n");
		return;
	}

	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	// TODO: We may not have ctx and/or bevs, if the connection is terminated
	if (ctx && ctx->src.bev && ctx->dst.bev) {
		struct bufferevent *in_bev = icap_ctx->reqmod ? ctx->src.bev : ctx->dst.bev;
		struct evbuffer *inbuf = bufferevent_get_input(in_bev);

		icap_service_ctx_t *service_ctx = icap_ctx->services[icap_ctx->service_count - 1];

		UNUSED struct evbuffer *out_hdr = icap_ctx->reqmod ? service_ctx->src.out_hdr : service_ctx->dst.out_hdr;
		UNUSED struct evbuffer *out_body = icap_ctx->reqmod ? service_ctx->src.out_body : service_ctx->dst.out_body;

		log_finest_va("End of chain reached, send data to destination, out_hdr=%zu, out_body=%zu, inbuf=%zu",
			evbuffer_get_length(out_hdr), evbuffer_get_length(out_body), evbuffer_get_length(inbuf));

		struct evbuffer *outbuf = bufferevent_get_output(icap_ctx->reqmod ? ctx->dst.bev : ctx->src.bev);
		icap_process_done(inbuf, outbuf, icap_ctx);

		unsigned int made_progress = icap_ctx->made_progress;

		log_finest_va("Reset made_progress: %s", made_progress ? "MADE PROGRESS" : "NO PROGRESS");
		icap_ctx->made_progress = 0;

		// No need to check inbuf, let its readcb fire if there is data to read, prevent busy loop
		// TODO: Should we check inbuf if made_progress, but it causes infinite loop
		// if (made_progress && evbuffer_get_length(inbuf) > 0) {
		// if (evbuffer_get_length(inbuf) > 0) {
		// 	log_finest_va("Continue processing data in inbuf=%zu, do not resume flow yet", evbuffer_get_length(inbuf));
		// 	icap_process_data(inbuf, ctx, icap_ctx->reqmod);
		// 	return;
		// }

		int service_idx = 0;
		if (!made_progress || icap_have_data_to_process(icap_ctx, &service_idx) == 0) {
			log_finest("Enable reading from source, resume flow");

			// TODO: Should we enable the current conn_bev only?
			bufferevent_enable(in_bev, EV_READ);
			// bufferevent_enable(ctx->src.bev, EV_READ);
			// bufferevent_enable(ctx->dst.bev, EV_READ);
		}
		else {
			log_finest("Do not enable reading from source");
			icap_process_chain(icap_ctx, service_idx);
		}

		if (made_progress && icap_is_content_complete(icap_ctx, 1) && icap_is_content_complete(icap_ctx, 0)) {
			// ATTENTION: Pass ctx->icap_ctx to the free function, because the icap_ctx param is actually service_ctx->icap_ctx,
			// which may not be NULL even if ctx->icap_ctx is NULL
			icap_ctx_free(ctx->icap_ctx);
		}
	}
	else {
		if (ctx) log_finest("No connection context to resume flow");
		else log_dbg_printf("No connection context to resume flow\n");
	}
}

static size_t NONNULL(1)
icap_get_http_content_length(icap_ctx_t *icap_ctx)
{
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	// TODO: What to return for non-http protocols, should we return 0 or SIZE_MAX? But if we return SIZE_MAX,
	// then content complete check will never be true and connection will never terminate
	if (!ctx->spec->http) {
		return 0;
	}

	size_t *http_content_length = icap_ctx->reqmod ? &icap_ctx->src_http_content_length : &icap_ctx->dst_http_content_length;

	unsigned int http_content_length_set = icap_ctx->reqmod ? icap_ctx->src_http_content_length_set : icap_ctx->dst_http_content_length_set;
	if (http_content_length_set == 0) {
		protohttp_ctx_t *http_ctx = ctx->protoctx->arg;
		if (http_ctx && http_ctx->http_content_length) {
			*http_content_length = (size_t)strtoull(http_ctx->http_content_length, NULL, 10);
			log_finest_va("Set HTTP content length, http_content_length=%zu", *http_content_length);

			if (icap_ctx->reqmod) {
				icap_ctx->src_http_content_length_set = 1;
			} else {
				icap_ctx->dst_http_content_length_set = 1;
			}
		}
		else {
			log_finest("HTTP content length not found, return 0");
		}
	}

	log_finest_va("Get HTTP content length, http_content_length=%zu", *http_content_length);
	return *http_content_length;
}

static void NONNULL(1)
icap_failopen_to_next_service(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	// TODO: Determine content_complete on failopen and terminate connection, otherwise connection remains open since icap_ctx still exists

	struct evbuffer *in_hdr = icap_ctx->reqmod ? service_ctx->src.in_hdr : service_ctx->dst.in_hdr;
	struct evbuffer *in_body = icap_ctx->reqmod ? service_ctx->src.in_body : service_ctx->dst.in_body;
	struct evbuffer *sent_hdr = icap_ctx->reqmod ? service_ctx->src.sent_hdr : service_ctx->dst.sent_hdr;
	struct evbuffer *sent_body = icap_ctx->reqmod ? service_ctx->src.sent_body : service_ctx->dst.sent_body;

	log_finest_icap_va("ENTER, sent_hdr=%zu, sent_body=%zu, in_hdr=%zu, in_body=%zu",
		evbuffer_get_length(sent_hdr), evbuffer_get_length(sent_body), evbuffer_get_length(in_hdr), evbuffer_get_length(in_body));

	if (icap_is_nullbody(service_ctx)) {
		log_finest_icap("Content complete: null-body");
		ICAP_STATE(service_ctx, icap_ctx->reqmod)->content_complete = 1;
	}

	int next_idx = service_ctx->idx + 1;

	size_t *sent_body_size = icap_ctx->reqmod ? &service_ctx->src.sent_body_size : &service_ctx->dst.sent_body_size;

	// ATTENTION: Handle sent_body_size in failopen, since we are not actually sending the body to the service,
	// so we count it towards the content complete check for HTTP services,
	// otherwise we may never mark content complete and cannot terminate the connection (until it expires)
	*sent_body_size += (evbuffer_get_length(in_body) + evbuffer_get_length(sent_body));

	log_finest_icap_va("Updated sent_body_size=%zu", *sent_body_size);

	size_t http_content_length = icap_get_http_content_length(icap_ctx);

	log_finest_icap_va("Checking if HTTP content complete, sent_body_size=%zu, http_content_length=%zu", *sent_body_size, http_content_length);
	if (*sent_body_size >= http_content_length) {
		ICAP_STATE(service_ctx, icap_ctx->reqmod)->content_complete = 1;
	}

	if (next_idx < icap_ctx->service_count) {
		log_finest_icap_va("Failopen to next service, next_idx=%d", next_idx);

		struct evbuffer *next_in_hdr = icap_ctx->reqmod ? icap_ctx->services[next_idx]->src.in_hdr : icap_ctx->services[next_idx]->dst.in_hdr;
		struct evbuffer *next_in_body = icap_ctx->reqmod ? icap_ctx->services[next_idx]->src.in_body : icap_ctx->services[next_idx]->dst.in_body;

		// TODO: Drain sent_hdr and sent_body after moving all content to next service
		// TODO: Non-http protocols do not have hdr
		if (evbuffer_get_length(sent_hdr) > 0) {
			evbuffer_add_buffer(next_in_hdr, sent_hdr);
			icap_ctx->made_progress = 1;
		}
		if (evbuffer_get_length(sent_body) > 0) {
			evbuffer_add_buffer(next_in_body, sent_body);
			icap_ctx->made_progress = 1;
		}
		if (evbuffer_get_length(in_hdr) > 0) {
			evbuffer_add_buffer(next_in_hdr, in_hdr);
			icap_ctx->made_progress = 1;
		}
		if (evbuffer_get_length(in_body) > 0) {
			evbuffer_add_buffer(next_in_body, in_body);
			icap_ctx->made_progress = 1;
		}
	}
	else {
		log_finest_icap("Failopen to destination");

		struct evbuffer *outbuf = bufferevent_get_output(icap_ctx->reqmod ? ctx->dst.bev : ctx->src.bev);

		// TODO: Non-http protocols do not have hdr
		if (evbuffer_get_length(sent_hdr) > 0) {
			evbuffer_add_buffer(outbuf, sent_hdr);
			icap_ctx->made_progress = 1;
		}
		if (evbuffer_get_length(sent_body) > 0) {
			evbuffer_add_buffer(outbuf, sent_body);
			icap_ctx->made_progress = 1;
		}
		if (evbuffer_get_length(in_hdr) > 0) {
			evbuffer_add_buffer(outbuf, in_hdr);
			icap_ctx->made_progress = 1;
		}
		if (evbuffer_get_length(in_body) > 0) {
			evbuffer_add_buffer(outbuf, in_body);
			icap_ctx->made_progress = 1;
		}
		bufferevent_enable(icap_ctx->reqmod ? ctx->src.bev : ctx->dst.bev, EV_READ);
	}
}

static void NONNULL(1)
icap_advance_to_next_service(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	int next_idx = service_ctx->idx + 1;
	log_finest_icap_va("ENTER, service_count=%d, next_idx=%d", icap_ctx->service_count, next_idx);

	if (next_idx >= icap_ctx->service_count) {
		log_finest_icap("No next service to advance to");
		return;
	}

	struct evbuffer *out_hdr = icap_ctx->reqmod ? service_ctx->src.out_hdr : service_ctx->dst.out_hdr;
	struct evbuffer *out_body = icap_ctx->reqmod ? service_ctx->src.out_body : service_ctx->dst.out_body;

	icap_service_ctx_t *next_service = icap_ctx->services[next_idx];
	struct evbuffer *next_in_hdr = icap_ctx->reqmod ? next_service->src.in_hdr : next_service->dst.in_hdr;
	struct evbuffer *next_in_body = icap_ctx->reqmod ? next_service->src.in_body : next_service->dst.in_body;

	if (evbuffer_get_length(out_hdr) > 0) {
		evbuffer_add_buffer(next_in_hdr, out_hdr);
		icap_ctx->made_progress = 1;
	}
	if (evbuffer_get_length(out_body) > 0) {
		evbuffer_add_buffer(next_in_body, out_body);
		icap_ctx->made_progress = 1;
	}
}

static void NONNULL(1)
icap_disconnect(icap_ctx_t *icap_ctx)
{
	// ATTENTION: Check ctx before calling log macros in this function, as ctx may be NULL
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	for (int i = 0; i < icap_ctx->service_count; i++) {
		if (icap_ctx->services[i]) {
			icap_service_disconnect(icap_ctx->services[i], ctx->icap_ctx);
			icap_service_ctx_free(icap_ctx->services[i]);
			icap_ctx->services[i] = NULL;
		}
	}

	if (ctx) log_finest("ICAP chain disconnected");
	else log_dbg_printf("ICAP chain disconnected\n");
}

static void NONNULL(1)
icap_handle_service_error(icap_service_ctx_t *service_ctx)
{
	// ATTENTION: Check ctx before calling log macros in this function, as ctx may be NULL?
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (ctx) log_finest_icap_va("ICAP service in error state, conn_opts conn_fail_open=%s, conn_opts icap_fail_open=%s, svc conn_fail_open=%s, svc icap_fail_open=%s",
		ctx->conn_opts->icap_conn_fail_open == ICAP_FAIL_CLOSE ? "fail-close" : "fail-open",
		ctx->conn_opts->icap_fail_open == ICAP_FAIL_CLOSE ? "fail-close" : "fail-open",
		service_ctx->svc->conn_fail_open == ICAP_FAIL_CLOSE ? "fail-close" : "fail-open",
		service_ctx->svc->icap_fail_open == ICAP_FAIL_CLOSE ? "fail-close" : "fail-open");
	else log_dbg_printf("ICAP service idx=%d in error state, conn_opts conn_fail_open=-, conn_opts icap_fail_open=-, svc conn_fail_open=%s, svc icap_fail_open=%s\n",
		service_ctx->idx,
		service_ctx->svc->conn_fail_open == ICAP_FAIL_CLOSE ? "fail-close" : "fail-open",
		service_ctx->svc->icap_fail_open == ICAP_FAIL_CLOSE ? "fail-close" : "fail-open");

	// Connection fail mode
	// TODO: Check if conn_opts->icap_conn_fail_open is always copied to service_ctx->svc->conn_fail_open
	// if ((ctx && ctx->conn_opts->icap_conn_fail_open == ICAP_FAIL_CLOSE) || (service_ctx->svc->conn_fail_open == ICAP_FAIL_CLOSE)) {
	if (service_ctx->svc->conn_fail_open == ICAP_FAIL_CLOSE) {
		if (ctx) log_finest_icap("ICAP service in error state, terminate connection as fail-close");
		else log_dbg_printf("ICAP service in error state, terminate connection as fail-close\n");

		icap_conn_term(ctx);
		return;
	}
	// ICAP service fail mode
	// TODO: Check if conn_opts->icap_fail_open is always copied to service_ctx->svc->icap_fail_open
	// else if ((ctx && ctx->conn_opts->icap_fail_open == ICAP_FAIL_OPEN) || (service_ctx->svc->icap_fail_open == ICAP_FAIL_OPEN)) {
	else if (service_ctx->svc->icap_fail_open == ICAP_FAIL_OPEN) {
		service_ctx->failopen = 1;

		icap_failopen_to_next_service(service_ctx);

		int next_idx = service_ctx->idx + 1;
		if (next_idx < icap_ctx->service_count) {
			if (ctx) log_finest_icap_va("ICAP in error state, continue with next ICAP service in chain, next_idx=%d", next_idx);
			else log_dbg_printf("ICAP in error state, continue with next ICAP service in chain\n");

			icap_process_chain(icap_ctx, next_idx);
		}
		else {
			if (ctx) log_finest_icap_va("ICAP in error state, no more services to try, next_idx=%d", next_idx);
			else log_dbg_printf("ICAP in error state, no more services to try\n");
		}
	}
	else {
		if (ctx) log_finest_icap("ICAP in error state, will not try further services");
		else log_dbg_printf("ICAP in error state, will not try further services\n");
	}

	icap_service_disconnect(service_ctx, ctx->icap_ctx);
}

static int NONNULL(1)
icap_preview_enabled(icap_service_t *svc)
{
	return svc->preview_size > 0;
}

// We need separate null_body functions for sending request to and processing response from service
static int
icap_is_icap_response_nullbody(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	int null_body = icap_ctx->reqmod ? service_ctx->src.null_body : service_ctx->dst.null_body;
	if (null_body) {
		log_finest_icap("Service response null body");
		return 1;
	}

	int has_body = icap_ctx->reqmod ? service_ctx->src.has_body : service_ctx->dst.has_body;
	if (has_body) {
		log_finest_icap("Encapsulated header indicates has_body");
		return 0;
	}

	return 0;
}

static int
icap_is_nullbody(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	struct evbuffer *in_body = icap_ctx->reqmod ? service_ctx->src.in_body : service_ctx->dst.in_body;
	size_t in_body_len = evbuffer_get_length(in_body);

	if (icap_ctx->is_veto) {
		log_finest_icap_va("Veto detected, assume not null body, in_body_len=%zu", in_body_len);
		return 0;
	}

	if (!ctx->spec->http) {
		log_finest_icap("Non-http connection, assume not null body");
		return 0;
	}

	// TODO: Do we need has_body check, or is null_body check below enough?
	// int has_body = icap_ctx->reqmod ? service_ctx->src.has_body : service_ctx->dst.has_body;
	// if (has_body) {
	// 	log_finest_icap("Service has body");
	// 	return 0;
	// }

	// ATTENTION: The null_body flag may be misleading, due to 204 and 206 responses
	// int null_body = icap_ctx->reqmod ? icap_ctx->services[0]->src.null_body : icap_ctx->services[0]->dst.null_body;
	// if (null_body) {
	// 	log_finest_icap("First service input null body");
	// 	return 1;
	// }

	size_t sent_body_size = icap_ctx->reqmod ? icap_ctx->services[0]->src.sent_body_size : icap_ctx->services[0]->dst.sent_body_size;
	if (sent_body_size > 0) {
		log_finest_icap_va("First service sent_body_size > 0, assume not null body, sent_body_size=%zu", sent_body_size);
		return 0;
	}

	// ATTENTION: Move this check after null_body check, otherwise breaks 204 bypass with c-icap echo service
	// TODO: Do we need to check detected_204? Because if we got 204, then in_body_len > 0
	// if (in_body_len > 0 && !ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_204) {
	if (in_body_len > 0) {
		log_finest_icap_va("Not null body, in_body_len=%zu", in_body_len);
		return 0;
	}

	size_t http_content_length = icap_get_http_content_length(icap_ctx);
	log_finest_icap_va("HTTP content length=%zu, null_body=%u", http_content_length,
		icap_ctx->reqmod ? service_ctx->src.null_body : service_ctx->dst.null_body);
	return http_content_length == 0;
}

static void NONNULL(1)
icap_service_content_complete(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	ICAP_STATE(service_ctx, icap_ctx->reqmod)->content_complete = 1;

	if (icap_ctx->is_veto) {
		icap_ctx->sent_veto_page = 1;
	}

	if (!ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206) {
		struct evbuffer *sent_hdr = icap_ctx->reqmod ? service_ctx->src.sent_hdr : service_ctx->dst.sent_hdr;
		struct evbuffer *sent_body = icap_ctx->reqmod ? service_ctx->src.sent_body : service_ctx->dst.sent_body;

		log_finest_icap_va("Service finished, drain sent_hdr=%zu, sent_body=%zu, sent_veto_page=%u",
			evbuffer_get_length(sent_hdr), evbuffer_get_length(sent_body), icap_ctx->sent_veto_page);

		evbuffer_drain(sent_hdr, evbuffer_get_length(sent_hdr));
		evbuffer_drain(sent_body, evbuffer_get_length(sent_body));
	}
}

static void
icap_service_bypass(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	struct evbuffer *sent_hdr = icap_ctx->reqmod ? service_ctx->src.sent_hdr : service_ctx->dst.sent_hdr;
	struct evbuffer *out_hdr = icap_ctx->reqmod ? service_ctx->src.out_hdr : service_ctx->dst.out_hdr;

	if (evbuffer_get_length(sent_hdr) > 0) {
		log_finest_icap_va("Move sent_hdr to out_hdr, sent_hdr=%zu, out_hdr=%zu", evbuffer_get_length(sent_hdr), evbuffer_get_length(out_hdr));
		evbuffer_add_buffer(out_hdr, sent_hdr);
		icap_ctx->made_progress = 1;
	}

	struct evbuffer *in_hdr = icap_ctx->reqmod ? service_ctx->src.in_hdr : service_ctx->dst.in_hdr;

	if (evbuffer_get_length(in_hdr) > 0) {
		log_finest_icap_va("Move in_hdr to out_hdr, in_hdr=%zu, out_hdr=%zu", evbuffer_get_length(in_hdr), evbuffer_get_length(out_hdr));
		evbuffer_add_buffer(out_hdr, in_hdr);
		icap_ctx->made_progress = 1;
	}

	struct evbuffer *sent_body = icap_ctx->reqmod ? service_ctx->src.sent_body : service_ctx->dst.sent_body;
	struct evbuffer *out_body = icap_ctx->reqmod ? service_ctx->src.out_body : service_ctx->dst.out_body;

	size_t *sent_body_size = icap_ctx->reqmod ? &service_ctx->src.sent_body_size : &service_ctx->dst.sent_body_size;

	if (evbuffer_get_length(sent_body) > 0) {
		// ATTENTION: We have already added existing sent_body in sent_body_size, so do not count it again here
		// *sent_body_size += evbuffer_get_length(sent_body);

		log_finest_icap_va("Move sent_body to out_body, sent_body=%zu, out_body=%zu", evbuffer_get_length(sent_body), evbuffer_get_length(out_body));
		evbuffer_add_buffer(out_body, sent_body);
		icap_ctx->made_progress = 1;
	}

	struct evbuffer *in_body = icap_ctx->reqmod ? service_ctx->src.in_body : service_ctx->dst.in_body;

	if (evbuffer_get_length(in_body) > 0) {
		*sent_body_size += evbuffer_get_length(in_body);

		log_finest_icap_va("Move in_body to out_body, in_body=%zu, out_body=%zu", evbuffer_get_length(in_body), evbuffer_get_length(out_body));
		evbuffer_add_buffer(out_body, in_body);
		icap_ctx->made_progress = 1;
	}

	size_t http_content_length = icap_get_http_content_length(icap_ctx);
	log_finest_icap_va("Checking if HTTP content complete, sent_body_size=%zu, http_content_length=%zu", *sent_body_size, http_content_length);

	if (http_content_length == 0 || *sent_body_size >= http_content_length) {
		icap_service_content_complete(service_ctx);
	}
}

static int
parse_encapsulated_field(icap_service_ctx_t *service_ctx, const char *line, const char *field, size_t *offset)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

    const char *p = strstr(line, field);
    if (!p) return 0;

    p += strlen(field);

    // Skip optional whitespace
    while (*p == ' ' || *p == '\t') p++;

    if (*p++ != '=') {
		log_finest_icap_va("Failed validating encapsulated field, missing '=', line='%s'", line);
		return -1;
	}

    // Skip optional whitespace
    while (*p == ' ' || *p == '\t') p++;

    char *endptr;
    unsigned long val = strtoul(p, &endptr, 10);

    // Validate: should end at newline, comma, or whitespace
    if (endptr == p || (*endptr != '\0' && *endptr != ',' && *endptr != '\r' && *endptr != '\n')) {
		log_finest_icap_va("Failed validating encapsulated field, line='%s'", line);
        return -1;
    }

    *offset = (size_t)val;
    return 1;
}

static int NONNULL(1)
icap_extract_icap_headers(icap_service_ctx_t *service_ctx, struct evbuffer *input)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	size_t *body_offset = icap_ctx->reqmod ? &service_ctx->src.body_offset : &service_ctx->dst.body_offset;
	size_t *header_offset = icap_ctx->reqmod ? &service_ctx->src.header_offset : &service_ctx->dst.header_offset;

	log_finest_icap_va("ENTER, header_offset=%zu, body_offset=%zu, null_body=%u", *header_offset, *body_offset,
		icap_ctx->reqmod ? service_ctx->src.null_body : service_ctx->dst.null_body);

	int rv = 0;

	/* Parse ICAP Headers to find Encapsulated offsets and Veto detection */
	while (1) {
		size_t line_eol = 0;
		char *line = icap_evbuffer_readline(input, &line_eol);
		if (!line) {
			log_finest_icap("Failed reading ICAP header line, stop parsing headers");
			rv = -1;
			break;
		}

		if (strlen(line) == 0) {
			log_finest_icap("End of ICAP headers, stop parsing headers");
			free(line);
			break;
		}

		if (line_eol == 0) {
			log_finest_icap("No EOL in line, reinject line back to input buffer, stop parsing headers");
			evbuffer_add(input, line, strlen(line));
			free(line);
			break;
		}

		/* Check for Veto: X-Response-Info: Blocked */
		if (strncasecmp(line, "X-Response-Info:", 16) == 0) {
			if (strcasestr(line, "Blocked")) {
				log_finest_icap("ICAP Veto detected: X-Response-Info: Blocked");
				icap_ctx->is_veto = 1;
			}
		}
		
		if (strncasecmp(line, "Encapsulated:", 13) == 0) {
			if (parse_encapsulated_field(service_ctx, line, "req-body", body_offset) == 1 ||
				parse_encapsulated_field(service_ctx, line, "res-body", body_offset) == 1) {
				ICAP_STATE(service_ctx, icap_ctx->reqmod)->has_body = 1;
			}
			else if (parse_encapsulated_field(service_ctx, line, "null-body", body_offset) == 1) {
				log_finest_icap_va("ICAP detected null-body=%zu", *body_offset);
				ICAP_STATE(service_ctx, icap_ctx->reqmod)->null_body = 1;
			}

			if (parse_encapsulated_field(service_ctx, line, "req-hdr", header_offset) != 1) {
				if (parse_encapsulated_field(service_ctx, line, "res-hdr", header_offset) == 1) {
					if (icap_ctx->reqmod) {
						log_finest_icap("ICAP Veto detected: res-hdr in reqmod response");
						icap_ctx->is_veto = 1;
					}
				}
			}
		}

		if (service_ctx->svc->echo_header &&
			strncasecmp(line, service_ctx->svc->echo_header, strlen(service_ctx->svc->echo_header)) == 0) {
			log_finest_icap_va("Found echo header='%s'", line);

			// The echo header value cannot contain CRLF or LF, as we read the line by icap_evbuffer_readline(),
			// so it cannot inject arbitrary ICAP headers into the subsequent requests (Header injection)
			char *value = strcasestr(line, ":");
			if (value && strlen(value) > 1) {
				if (service_ctx->echo_header) {
					log_finest_icap_va("Overwriting existing echo_header='%s'", service_ctx->echo_header);
					free(service_ctx->echo_header);
				}

				// Set the whole line, both key and value as echo header, plus CRLF
				#define ICAP_ECHO_HEADER_MAX_LEN 128
				service_ctx->echo_header = malloc(ICAP_ECHO_HEADER_MAX_LEN);
				if (!service_ctx->echo_header) {
					log_finest_icap_va("Failed malloc echo header='%s'", line);
					free(line);
					rv = -1;
					break;
				}

				snprintf(service_ctx->echo_header, ICAP_ECHO_HEADER_MAX_LEN, "%s\r\n", line);

				log_finest_icap_va("Set echo_header with CRLF='%s'", service_ctx->echo_header);
			}
			else {
				log_finest_icap("No value in echo header");
			}
		}

		free(line);
	}

	/* Validate offset values to prevent underflow */
	if (*body_offset < *header_offset) {
		log_finest_icap_va("Invalid ICAP offsets: body_offset (%zu) < header_offset (%zu)", *body_offset, *header_offset);
		rv = -1;
	}

	log_finest_icap_va("EXIT, header_offset=%zu, body_offset=%zu, null_body=%u", *header_offset, *body_offset,
		icap_ctx->reqmod ? service_ctx->src.null_body : service_ctx->dst.null_body);
	return rv;
}

static int NONNULL(1,2)
icap_update_http_content_length(icap_service_ctx_t *service_ctx, struct evbuffer *outbuf)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	/* Update http_content_length from Content-Length in new HTTP headers */
	size_t hdrlen = evbuffer_get_length(outbuf);
	char *hdr_buf = malloc(hdrlen + 1);
	if (!hdr_buf) {
		log_finest("Failed to allocate header buffer for HTTP content length update");
		return -1;
	}

	evbuffer_copyout(outbuf, hdr_buf, hdrlen);
	hdr_buf[hdrlen] = '\0';
	
	char *content_length_line = strstr(hdr_buf, "Content-Length:");
	if (content_length_line) {
		char *content_length_str = util_skipws(content_length_line + 15);
		size_t len = strspn(content_length_str, "0123456789");

		// 4GB (4294967295 bytes) limit to prevent overflow, Content-Length > 4294967295 is unlikely
		#define ICAP_CONTENT_MAX_DIGITS 10
		if (len <= ICAP_CONTENT_MAX_DIGITS) {
			content_length_str[len] = '\0';
			size_t *http_content_length = icap_ctx->reqmod ? &icap_ctx->src_http_content_length : &icap_ctx->dst_http_content_length;
			*http_content_length = (size_t)strtoull(content_length_str, NULL, 10);
			log_finest_icap_va("Updated HTTP content length: %zu", *http_content_length);

			// Set content_length_set flag to prevent overwriting http_content_length from protohttp_ctx in icap_get_http_content_length()
			if (icap_ctx->reqmod) {
				icap_ctx->src_http_content_length_set = 1;
			} else {
				icap_ctx->dst_http_content_length_set = 1;
			}
		}
		else {
			log_finest_icap_va("Content-Length value too long to parse: '%s'", content_length_str);
		}
	}
	else {
		log_finest_icap("No Content-Length line found in HTTP headers");
	}
	free(hdr_buf);
	return 0;
}

// Returns 1 if HTTP headers are fully received and extracted, 0 if still waiting for more data
static int NONNULL(1,2)
icap_extract_http_headers(icap_service_ctx_t *service_ctx, struct evbuffer *input)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (!ctx->spec->http) {
		log_finest_icap("Non-http connection, skip extracting HTTP headers");
		return 1;
	}

	unsigned int received_http_headers = icap_ctx->reqmod ? service_ctx->src.received_http_headers : service_ctx->dst.received_http_headers;
	if (received_http_headers) {
		log_finest_icap("Already received HTTP headers in ICAP response");
		return 1;
	}

	size_t body_offset = icap_ctx->reqmod ? service_ctx->src.body_offset : service_ctx->dst.body_offset;
	size_t header_offset = icap_ctx->reqmod ? service_ctx->src.header_offset : service_ctx->dst.header_offset;
	size_t hdrlen = body_offset - header_offset;
	if (hdrlen == 0) {
		log_finest_icap("No HTTP headers indicated in ICAP encapsulated header");

		if (icap_is_icap_response_nullbody(service_ctx)) {
			log_finest_icap("Null body with no http headers, assume 204 response, stream data from sent_hdr to out_hdr");
			ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_204 = 1;
			icap_service_bypass(service_ctx);
		}
		return 1;
	}

	if (icap_ctx->is_veto && !icap_ctx->veto_page) {
		icap_ctx->veto_page = evbuffer_new();
		if (!icap_ctx->veto_page) {
			log_finest_icap("Failed to allocate veto page buffer");
			return -1;
		}
	}

	unsigned int wait_http_headers = icap_ctx->reqmod ? service_ctx->src.wait_http_headers : service_ctx->dst.wait_http_headers;
	if (!wait_http_headers) {
		// TODO: Check if hdrlen can be 0, otherwise evbuffer_get_length(input) == 0 may not be necessary
		if (evbuffer_get_length(input) == 0 || evbuffer_get_length(input) < hdrlen) {
			log_finest_icap_va("No or not enough content left in ICAP response after icap headers, wait for HTTP headers, hdrlen=%zu, input=%zu", hdrlen, evbuffer_get_length(input));
			ICAP_STATE(service_ctx, icap_ctx->reqmod)->wait_http_headers = 1;
			return 0;
		}
	}
	else {
		log_finest_icap_va("WAIT for headers hdrlen=%zu, input=%zu", hdrlen, evbuffer_get_length(input));

		size_t *received_hdr_size = icap_ctx->reqmod ? &service_ctx->src.received_hdr_size : &service_ctx->dst.received_hdr_size;
		size_t remaining_hdr_size = hdrlen - *received_hdr_size;

		if (evbuffer_get_length(input) < remaining_hdr_size) {
			log_finest_icap_va("Keep waiting for headers, hdrlen=%zu, remaining=%zu, available=%zu", hdrlen, remaining_hdr_size, evbuffer_get_length(input));
			return 0;
		}

		hdrlen = remaining_hdr_size;
		log_finest_icap_va("AFTER WAIT for headers, will move remaining_hdr_size=%zu, input=%zu", remaining_hdr_size, evbuffer_get_length(input));

		ICAP_STATE(service_ctx, icap_ctx->reqmod)->wait_http_headers = 0;
	}

	received_http_headers = icap_ctx->reqmod ? service_ctx->src.received_http_headers : service_ctx->dst.received_http_headers;
	if (!received_http_headers) {
		size_t *received_hdr_size = icap_ctx->reqmod ? &service_ctx->src.received_hdr_size : &service_ctx->dst.received_hdr_size;
		*received_hdr_size = body_offset - header_offset;

		struct evbuffer *outbuf = NULL;
		if (icap_ctx->is_veto) {
			outbuf = icap_ctx->veto_page;
			log_finest_icap_va("Save hdr to veto page, hdrlen(offset diff)=%zu", hdrlen);
		}
		else {
			outbuf = icap_ctx->reqmod ? service_ctx->src.out_hdr : service_ctx->dst.out_hdr;
			log_finest_icap_va("Update headers, hdrlen(offset diff)=%zu", hdrlen);
		}
		evbuffer_remove_buffer(input, outbuf, hdrlen);
		
		if (ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206) {
			struct evbuffer *sent_hdr = icap_ctx->reqmod ? service_ctx->src.sent_hdr : service_ctx->dst.sent_hdr;
			log_finest_icap_va("Discard sent_hdr with 206 response, sent_hdr=%zu", evbuffer_get_length(sent_hdr));
			evbuffer_drain(sent_hdr, evbuffer_get_length(sent_hdr));
		}
		ICAP_STATE(service_ctx, icap_ctx->reqmod)->received_http_headers = 1;

		/* Update http_content_length from Content-Length in new HTTP headers */
		if (icap_update_http_content_length(service_ctx, outbuf) < 0) {
			return -1;
		}
	}

	// TODO: Do we need to check for HTTP 4xx/5xx in encapsulated HTTP status line?
	// But it doesn't seem like icap services use HTTP status codes for veto
	// /* Check for HTTP 4xx/5xx in encapsulated HTTP status (for REQMOD) */
	// if (icap_ctx->reqmod) {
	// 	/* Only check for HTTP errors in REQMOD mode */
	// 	char *hdr_buf = malloc(hdrlen + 1);
	// 	if (!hdr_buf) {
	// 		log_finest("Failed to allocate header buffer for HTTP error check");
	// 	}
	// 	else {
	// 		evbuffer_copyout(out_hdr, hdr_buf, hdrlen);
	// 		hdr_buf[hdrlen] = '\0';
			
	// 		/* Look for HTTP status line with 4xx or 5xx */
	// 		char *status_line = strstr(hdr_buf, "HTTP/");
	// 		if (status_line) {
	// 			/* Check for 4xx or 5xx status codes more precisely */
	// 			if ((strncmp(status_line + 9, "4", 1) == 0 && strlen(status_line) > 12) ||
	// 			    (strncmp(status_line + 9, "5", 1) == 0 && strlen(status_line) > 12)) {
	// 				log_finest_icap_va("ICAP Veto detected: Encapsulated HTTP error response: %.*s", 
	// 					(int)(strlen(status_line) > 50 ? 50 : strlen(status_line)), status_line);
	// 				icap_ctx->is_veto = 1;
	// 			}
	// 		}
	// 		else {
	// 			log_finest_icap("No HTTP status line found in encapsulated headers");
	// 		}
	// 		free(hdr_buf);
	// 	}
	// }

#ifdef DEBUG_PROXY
	/* Log extracted headers for debugging */
	struct evbuffer *out_hdr = icap_ctx->reqmod ? service_ctx->src.out_hdr : service_ctx->dst.out_hdr;
	size_t len = evbuffer_get_length(out_hdr);
	size_t log_len = len < 400 ? len : 400;
	char log_buf[401];  // Stack allocation
	evbuffer_copyout(out_hdr, log_buf, log_len);
	log_buf[log_len] = '\0';
	log_finest_icap_va("Extracted headers (first %zu bytes, orig %zu bytes): %s", log_len, len, log_buf);
#endif /* DEBUG_PROXY */

	return 1;
}

static int
icap_try_discard_terminator(icap_service_ctx_t *service_ctx, struct evbuffer *input)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (evbuffer_get_length(input) > 1) {
		struct evbuffer_ptr term_ptr = evbuffer_search(input, "\r\n", 2, NULL);
		if (term_ptr.pos == 0) {
			log_finest_icap("Discard CRLF terminator");
			evbuffer_drain(input, 2);
			return 1;
		}
	}
	return 0;
}

static void
icap_get_use_original_body_ext(icap_service_ctx_t *service_ctx, char *line)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	char *p = strstr(line, "use-original-body=");
	if (p) {
		p += 18;
		size_t use_original_body = (size_t)strtoull(p, NULL, 10);

		struct evbuffer *sent_body = icap_ctx->reqmod ? service_ctx->src.sent_body : service_ctx->dst.sent_body;
		log_finest_icap_va("Found use-original-body extension, use_original_body=%zu, sent_body=%zu", use_original_body, evbuffer_get_length(sent_body));

		if (use_original_body > 0) {
			evbuffer_drain(sent_body, use_original_body);
			log_finest_icap_va("Discard original body chunk, use_original_body=%zu, sent_body=%zu", use_original_body, evbuffer_get_length(sent_body));

			size_t *sent_body_size = icap_ctx->reqmod ? &service_ctx->src.sent_body_size : &service_ctx->dst.sent_body_size;
			*sent_body_size += ICAP_STATE(service_ctx, icap_ctx->reqmod)->body_chunk_len_206;

			// TODO: Check possible underflow? But we always send preview in 206, so sent_body_size should be at least preview_size
			*sent_body_size -= use_original_body;
			log_finest_icap_va("Updated sent_body_size=%zu, use_original_body=%zu, body_chunk_len_206=%zu",
				*sent_body_size, use_original_body, ICAP_STATE(service_ctx, icap_ctx->reqmod)->body_chunk_len_206);
		}

		ICAP_STATE(service_ctx, icap_ctx->reqmod)->use_original_body = use_original_body;
	}
	else {
		log_finest_icap("No use-original-body extension found in 206 response");
	}
}

static int
icap_parse_chunk_header(icap_service_ctx_t *service_ctx, struct evbuffer *input, size_t *chunk_size)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	int rv = 0;
	*chunk_size = 0;

	size_t eol_size = 0;
	char *line = icap_evbuffer_readline(input, &eol_size);
	if (!line) {
		log_finest_icap("Failed reading chunk size line");
		return -1;
	}

	log_finest_icap_va("Chunk size line='%s', CRLF size=%zu", line, eol_size);

	if (strlen(line) == 0) {
		// This is most probably the CRLF after the chunk data
		log_finest_icap("Empty chunk header line, wait for more data");
		goto out;
	}

	char *ext = NULL;

	// TODO: We assume chunk size is always < 0x1000000 (16 MB)
	#define ICAP_CHUNK_SIZE_MAX_DIGITS 6
	if (strlen(line) <= ICAP_CHUNK_SIZE_MAX_DIGITS && strspn(line, "0123456789abcdefABCDEF") == strlen(line)) {
		*chunk_size = (size_t)strtoull(line, NULL, 16);
	}
	else {
		// Chunk header may have chunk extensions, for example: "1a; use-original-body=12345"
		size_t chunk_size_len = strspn(line, "0123456789abcdefABCDEF;");
		char *semicolon = NULL;

		if (chunk_size_len > 0 && chunk_size_len <= ICAP_CHUNK_SIZE_MAX_DIGITS + 1 &&
			(semicolon = strchr(line, ';')) &&
			semicolon > line && semicolon - line == (long int)(chunk_size_len - 1)) {
			// No need to null-terminate the chunk size part, since strtoull() will stop parsing at the semicolon
			*chunk_size = (size_t)strtoull(line, NULL, 16);
			ext = semicolon + 1;
			log_finest_icap_va("Parsed chunk size with extensions, chunk_size=%zu, extensions=%s", *chunk_size, ext);

			// We only support parsing the "use-original-body" extension for 206 response, and ignore other extensions for now
			if (*chunk_size == 0 && ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206) {
				log_finest_icap("FOUND 0 chunk size with extensions in 206 response");
				icap_get_use_original_body_ext(service_ctx, ext);
			}
		}
		else {
			log_finest_icap_va("Invalid chunk size line: '%s'", line);
			rv = -1;
			goto out;
		}
	}

	if (*chunk_size == 0) {
		// Mark content complete after receiving xfer terminator, not just after 0 chunk size terminator
		if (icap_try_discard_terminator(service_ctx, input) > 0) {
			log_finest_icap("FOUND terminator after 0 chunk size, discard it and set content complete");
			icap_service_content_complete(service_ctx);
		}
		else {
			log_finest_icap_va("No terminator after 0 chunk size, wait for xfer terminator, detected_206=%u", ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206);
			ICAP_STATE(service_ctx, icap_ctx->reqmod)->wait_terminator = 1;
		}
	}
out:
	free(line);
	return rv;
}

static void
icap_try_service_bypass_206(icap_service_ctx_t *service_ctx, size_t body_chunk_len)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206) {
		if (ICAP_STATE(service_ctx, icap_ctx->reqmod)->use_original_body > 0 || ICAP_STATE(service_ctx, icap_ctx->reqmod)->content_complete) {
			size_t *sent_body_size = icap_ctx->reqmod ? &service_ctx->src.sent_body_size : &service_ctx->dst.sent_body_size;
			log_finest_icap_va("Update sent_body_size=%zu, body_chunk=%zu", *sent_body_size, body_chunk_len);
			*sent_body_size += body_chunk_len;

			icap_service_bypass(service_ctx);
		}
		else {
			// Wait for 206 response to tell us whether we should use original body or not
			log_finest_icap_va("Update body_chunk_len_206=%zu, body_chunk=%zu", ICAP_STATE(service_ctx, icap_ctx->reqmod)->body_chunk_len_206, body_chunk_len);
			ICAP_STATE(service_ctx, icap_ctx->reqmod)->body_chunk_len_206 += body_chunk_len;
		}
	}
}

static int
icap_extract_body_chunk(icap_service_ctx_t *service_ctx, struct evbuffer *input)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (ICAP_STATE(service_ctx, icap_ctx->reqmod)->wait_terminator) {
		if (icap_try_discard_terminator(service_ctx, input) > 0) {
			log_finest_icap("FOUND terminator while waiting");
			ICAP_STATE(service_ctx, icap_ctx->reqmod)->wait_terminator = 0;

			icap_service_content_complete(service_ctx);

			if (ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206) {
				icap_try_service_bypass_206(service_ctx, 0);
			}

			icap_ctx->made_progress = 1;
		}
		else {
			log_finest_icap("Still waiting for terminator, keep waiting");
		}
		return 0;
	}

	if (icap_is_icap_response_nullbody(service_ctx)) {
		if (ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_204 || ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206) {
			log_finest_icap_va("No modified body with 204 or 206 response, stream data from sent_body to out_body, 204=%u, 206=%u", 
				ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_204, ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206);
			icap_service_bypass(service_ctx);
		}
		else {
			log_finest_icap("No modified body, content complete");
			/* Drain the rest since we don't have a body to extract */
			evbuffer_drain(input, evbuffer_get_length(input));

			struct evbuffer *sent_body = icap_ctx->reqmod ? service_ctx->src.sent_body : service_ctx->dst.sent_body;
			struct evbuffer *out_body = icap_ctx->reqmod ? service_ctx->src.out_body : service_ctx->dst.out_body;

			if (evbuffer_get_length(sent_body) > 0) {
				// ATTENTION: We have already added existing sent_body in sent_body_size, so do not count it again here
				// *sent_body_size += evbuffer_get_length(sent_body);

				log_finest_icap_va("Move sent_body to out_body, sent_body=%zu, out_body=%zu", evbuffer_get_length(sent_body), evbuffer_get_length(out_body));
				evbuffer_add_buffer(out_body, sent_body);
				icap_ctx->made_progress = 1;
			}

			icap_service_content_complete(service_ctx);
		}
		return 0;
	}

	if (evbuffer_get_length(input) == 0) {
		log_finest_icap("No content left in ICAP response before body chunk");
		return 0;
	}

	size_t *remaining_chunk_size = icap_ctx->reqmod ? &service_ctx->src.remaining_chunk_size : &service_ctx->dst.remaining_chunk_size;
	log_finest_icap_va("ENTER, *remaining_chunk_size=%zu", *remaining_chunk_size);

	if (*remaining_chunk_size > evbuffer_get_length(input)) {
		log_finest_icap_va("Not enough data, keep waiting, remaining_chunk_size=%zu, input=%zu", *remaining_chunk_size, evbuffer_get_length(input));
		return 0;
	}

	// Now input contains the body, chunked encoded by ICAP.

	struct evbuffer *body_chunk = evbuffer_new();
	if (!body_chunk) {
		log_finest_icap("Failed to allocate body_chunk buffer");
		return -1;
	}

	int rv = 0;

	if (*remaining_chunk_size > 0) {
		log_finest_icap_va("BEFORE Remaining chunk size=%zu, input=%zu", *remaining_chunk_size, evbuffer_get_length(input));

		size_t to_remove = *remaining_chunk_size < evbuffer_get_length(input) ? *remaining_chunk_size : evbuffer_get_length(input);
		evbuffer_remove_buffer(input, body_chunk, to_remove);

		*remaining_chunk_size -= to_remove;

		if (*remaining_chunk_size == 0) {
			icap_try_discard_terminator(service_ctx, input);
		}

		log_finest_icap_va("MOVED Remaining chunk=%zu, input=%zu", *remaining_chunk_size, evbuffer_get_length(input));
		icap_ctx->made_progress = 1;
	}
	else {
		log_finest_icap_va("NO Remaining chunk size=%zu, input=%zu", *remaining_chunk_size, evbuffer_get_length(input));
	}

	while (evbuffer_get_length(input) > 0) {
		size_t chunk_size = 0;
		if (icap_parse_chunk_header(service_ctx, input, &chunk_size) < 0) {
			rv = -1;
			goto err;
		}

		if (evbuffer_get_length(input) == 0) {
			// The last line in the segment was the chunk size line, there is no content after it yet, so save the chunk size.
			*remaining_chunk_size = chunk_size;
			log_finest_icap_va("No content left in ICAP response after chunk size line, remaining chunk size=%zu", *remaining_chunk_size);
			break;
		}

#ifdef DEBUG_PROXY
		/* Log first 400 bytes for debugging */
		size_t len = evbuffer_get_length(input);
		size_t log_len = len < 400 ? len : 400;
		char log_buf[401];  // Stack allocation
		evbuffer_copyout(input, log_buf, log_len);
		log_buf[log_len] = '\0';
		log_finest_icap_va("Chunk rest (first %zu bytes, orig %zu bytes): %s", log_len, len, log_buf);
#endif /* DEBUG_PROXY */

		log_finest_icap_va("CURRENT remaining chunk size=%zu, input=%zu", *remaining_chunk_size, evbuffer_get_length(input));

		/* Read chunk data */
		if (chunk_size > 0) {
			size_t avail = evbuffer_get_length(input);

			size_t to_read = 0;
			int chunk_complete = 0;

			if (chunk_size > avail) {
				*remaining_chunk_size = chunk_size - avail;
				to_read = avail;
				log_finest_icap_va("SEGMENTED chunk, remaining=%zu, chunk_size=%zu, avail=%zu, to_read=%zu", *remaining_chunk_size, chunk_size, avail, to_read);
			}
			else {
				to_read = chunk_size;
				chunk_complete = 1;
				log_finest_icap_va("COMPLETE chunk, remaining=%zu, chunk_size=%zu, avail=%zu, to_read=%zu, input=%zu", *remaining_chunk_size, chunk_size, avail, to_read, evbuffer_get_length(input));
			}
			
			/* Move data to body_chunk */
			evbuffer_remove_buffer(input, body_chunk, to_read);
			
			chunk_size -= to_read;

			if (chunk_complete) {
				icap_try_discard_terminator(service_ctx, input);
			}
		}

		log_finest_icap_va("AFTER chunk processing, input=%zu, remaining_chunk_size=%zu", evbuffer_get_length(input), *remaining_chunk_size);
	}

	size_t body_chunk_len = evbuffer_get_length(body_chunk);
	log_finest_icap_va("Extracted %zu bytes of unchunked body, input=%zu", body_chunk_len, evbuffer_get_length(input));

	if (body_chunk_len > 0) {
		struct evbuffer *outbuf = NULL;
		if (icap_ctx->is_veto) {
			if (!icap_ctx->veto_page) {
				icap_ctx->veto_page = evbuffer_new();
				if (!icap_ctx->veto_page) {
					log_finest_icap("Failed to allocate veto page buffer");
					rv = -1;
					goto err;
				}
			}

			outbuf = icap_ctx->veto_page;
			log_finest_icap_va("Save body to veto page, out_body=%zu, body_chunk=%zu", evbuffer_get_length(outbuf), body_chunk_len);
		}
		else {
			outbuf = icap_ctx->reqmod ? service_ctx->src.out_body : service_ctx->dst.out_body;
			log_finest_icap_va("Update body, out_body=%zu, body_chunk=%zu", evbuffer_get_length(outbuf), body_chunk_len);
		}

		evbuffer_add_buffer(outbuf, body_chunk);
	}

	icap_try_service_bypass_206(service_ctx, body_chunk_len);

	icap_ctx->made_progress = 1;
err:
	evbuffer_free(body_chunk);
	return rv;
}

/*
 * Helper function to handle chain orchestration after ICAP service completes
 */
static void
icap_handle_chain_continuation(icap_service_ctx_t *service_ctx, icap_ctx_t *icap_ctx)
{
	// ATTENTION: Do not get icap_ctx from service_ctx here, because service_ctx may be already freed and its pointer may be dangling,
	// so we pass ctx->icap_ctx as a parameter to this function
	// icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	if (!icap_ctx) {
		log_dbg_printf("No ICAP context in icap_handle_chain_continuation(), idx=%d\n", service_ctx->idx);
		return;
	}
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	/* Move to the next service in the chain or resume connection */
	int next_idx = service_ctx->idx + 1;

	if (next_idx >= icap_ctx->service_count) {
		log_finest_icap("ICAP service chain finished");
		icap_send_data(ctx->icap_ctx);
		return;
	}

	log_finest_icap_va("Current service done for now, service_count=%d, next_idx=%d", icap_ctx->service_count, next_idx);

	icap_advance_to_next_service(service_ctx);
	icap_process_chain(ctx->icap_ctx, next_idx);
}

/*
 * ICAP bufferevent read callback - handle RESPMOD response
 */
static void
icap_bev_readcb(struct bufferevent *bev, void *arg)
{
	icap_service_ctx_t *service_ctx = (icap_service_ctx_t *)arg;
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	int received_icap_headers = icap_ctx->reqmod ? service_ctx->src.received_icap_headers : service_ctx->dst.received_icap_headers;

	struct evbuffer *input = bufferevent_get_input(bev);
	log_finest_icap_va("ENTER, inbuf=%zu, received_icap_headers=%d", evbuffer_get_length(input), received_icap_headers);

#ifdef DEBUG_PROXY
	/* Log first 400 bytes for debugging */
	size_t len = evbuffer_get_length(input);
	size_t log_len = len < 400 ? len : 400;
	char log_buf[401];  // Stack allocation
	evbuffer_copyout(input, log_buf, log_len);
	log_buf[log_len] = '\0';
	log_finest_icap_va("ICAP response (first %zu bytes, orig %zu bytes): %s", log_len, len, log_buf);
#endif /* DEBUG_PROXY */

	char *status_line = NULL;
	size_t eol_size = 0;

	if (!received_icap_headers) {
		struct evbuffer_ptr ptr = evbuffer_search(input, "\r\n\r\n", 4, NULL);
		if (ptr.pos == -1) {
			log_finest_icap("Waiting for complete ICAP headers");
			return;
		}

		/* Look for ICAP response status line; eol_size is 1 (LF) or 2 (CRLF) */
		status_line = icap_evbuffer_readline(input, &eol_size);
		if (!status_line) {
			log_finest_icap("Failed reading status line");
			goto err;
		}

		ICAP_STATE(service_ctx, icap_ctx->reqmod)->received_icap_headers = 1;
	}

	if (status_line) {
		log_finest_icap_va("EOL size=%zu, status_line len=%zu, status_line=%s", eol_size, strlen(status_line), status_line);

		/* Check for response code - use strncmp for proper prefix matching */
		if (strncmp(status_line, "ICAP/1.0 200", 12) == 0) {
			log_finest_icap("ICAP 200 OK - body modified, extracting...");

			if (icap_extract_icap_headers(service_ctx, input) == -1) {
				goto err;
			}
			goto stream;
		}
		else if (strncmp(status_line, "ICAP/1.0 206", 12) == 0) {
			log_finest_icap("ICAP 206 Partial Content - body modified, extracting...");
			ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206 = 1;

			if (icap_extract_icap_headers(service_ctx, input) == -1) {
				goto err;
			}
			goto stream;
		}
		else if (strncmp(status_line, "ICAP/1.0 204", 12) == 0) {
			log_finest_icap("ICAP 204 No Content - no modification needed, bypassing");
			if (icap_extract_icap_headers(service_ctx, input) == -1) {
				goto err;
			}
			evbuffer_drain(input, evbuffer_get_length(input));
			icap_service_bypass(service_ctx);
		}
		else if (strncmp(status_line, "ICAP/1.0 100", 12) == 0) {
			/* Drain the entire 100 Continue response (including trailing CRLFs) */
			log_finest_icap_va("ICAP 100 Continue, drain eol, input=%zu", evbuffer_get_length(input));
			evbuffer_drain(input, eol_size);

			if (icap_preview_enabled(service_ctx->svc)) {
				log_finest_icap("Reset wait for ICAP 100 preview continue");
				ICAP_STATE(service_ctx, icap_ctx->reqmod)->wait_preview_continue = 0;

				log_finest_icap("Reset received_icap_headers");
				ICAP_STATE(service_ctx, icap_ctx->reqmod)->received_icap_headers = 0;

				log_finest_icap("Preview accepted, sending remainder");
				/* Send the remainder of the body */
				int rv = icap_build_request(service_ctx);
				if (rv < 0) {
					log_finest_icap_va("ICAP failed to build and send request to %s", service_ctx->svc->server);
					goto err;
				}
				else if (rv == 0) {
					log_finest_icap_va("ICAP request sent to %s", service_ctx->svc->server);
				}
			}
			else {
				log_finest_icap("Received 100 Continue when preview not enabled, treating as error");
				goto err;
			}
		}
		else if ((strncmp(status_line, "ICAP/1.0 4", 10) == 0) || (strncmp(status_line, "ICAP/1.0 5", 10) == 0)) {
			log_finest_icap_va("ICAP server returned error response: %s", status_line);
			goto err;
		}
		goto out;
	}
	else {
		log_finest_icap("Already received ICAP headers, assume hdr/body stream");
	}

	int rv = 0;
stream:
	if ((rv = icap_extract_http_headers(service_ctx, input)) < 1) {
		if (rv == -1) {
			goto err;
		}
		goto out;
	}

	if (icap_extract_body_chunk(service_ctx, input) == -1) {
		goto err;
	}
	goto out;
err:
	evbuffer_drain(input, evbuffer_get_length(input));
	icap_handle_service_error(service_ctx);
out:
	if (status_line) {
		free(status_line);
	}

	icap_handle_chain_continuation(service_ctx, ctx->icap_ctx);
}

/*
 * ICAP bufferevent write callback - stub for now
 */
static void
icap_bev_writecb(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
	icap_service_ctx_t *service_ctx = (icap_service_ctx_t *)arg;
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
	log_finest_icap("ICAP write callback called");
}

/*
 * Add standard X-headers to ICAP request
 */
static void
icap_add_standard_x_headers(pxy_conn_ctx_t *ctx, struct evbuffer *icap_buf)
{
	log_finest("ENTER");
	#define ICAP_X_HEADER_MAX_LEN 256
	char x_hdr[ICAP_X_HEADER_MAX_LEN];
	
	/* X-Client-IP header */
	snprintf(x_hdr, sizeof(x_hdr), "X-Client-IP: %s\r\n", STRORNONE(ctx->srchost_str));
	evbuffer_add(icap_buf, x_hdr, strlen(x_hdr));
	
	/* X-Server-IP header */
	snprintf(x_hdr, sizeof(x_hdr), "X-Server-IP: %s\r\n", STRORNONE(ctx->dsthost_str));
	evbuffer_add(icap_buf, x_hdr, strlen(x_hdr));
	
#ifndef WITHOUT_USERAUTH
	/* X-Authenticated-User header if available */
	if (ctx->user) {
		snprintf(x_hdr, sizeof(x_hdr), "X-Authenticated-User: %s\r\n", STRORNONE(ctx->user));
		evbuffer_add(icap_buf, x_hdr, strlen(x_hdr));
	}
#endif /* !WITHOUT_USERAUTH */
}

static int NONNULL(1)
icap_max_body_size_enabled(icap_service_ctx_t *service_ctx)
{
	return service_ctx->svc->max_body_size > 0;
}

/*
 * Build and send ICAP request
 * return 1 if not sent yet (waiting for more data), 0 if sent, -1 on error
 */
static int NONNULL(1)
icap_build_request(icap_service_ctx_t *service_ctx)
{
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	struct bufferevent *bev = service_ctx->bev;

	struct evbuffer *in_hdr = icap_ctx->reqmod ? service_ctx->src.in_hdr : service_ctx->dst.in_hdr;
	struct evbuffer *in_body = icap_ctx->reqmod ? service_ctx->src.in_body : service_ctx->dst.in_body;
	int reqmod = icap_ctx->reqmod;

	size_t in_hdr_len = evbuffer_get_length(in_hdr);
	size_t in_body_len = evbuffer_get_length(in_body);

	log_finest_icap_va("ENTER, in_hdr_len=%zu, in_body_len=%zu", in_hdr_len, in_body_len);

	if (service_ctx->failopen) {
		log_finest_icap("ICAP service in failopen state");
		return -1;
	}

	if (in_hdr_len == 0 && in_body_len == 0) {
		log_finest_icap_va("NO hdr or body to send, wait for data, in_hdr_len=%zu, in_body_len=%zu", in_hdr_len, in_body_len);
		return 1;
	}

	struct evbuffer *sent_hdr = icap_ctx->reqmod ? service_ctx->src.sent_hdr : service_ctx->dst.sent_hdr;
	struct evbuffer *sent_body = icap_ctx->reqmod ? service_ctx->src.sent_body : service_ctx->dst.sent_body;

	size_t sent_body_size = icap_ctx->reqmod ? service_ctx->src.sent_body_size : service_ctx->dst.sent_body_size;
	size_t sent_hdr_size = icap_ctx->reqmod ? service_ctx->src.sent_hdr_size : service_ctx->dst.sent_hdr_size;

	int content_complete = 0;
	size_t preview_size = 0;

	/* 1. Send ICAP Header */
	if (sent_hdr_size == 0 && sent_body_size == 0) {
		/* Calculate Encapsulated lengths */
		char *req_or_res = reqmod ? "req" : "res";
		#define ICAP_MAX_ENCAPSULATED_HEADER_SIZE 128
		char encapsulated_hdr[ICAP_MAX_ENCAPSULATED_HEADER_SIZE];

		int null_body = icap_is_nullbody(service_ctx);

		if (!null_body && in_body_len == 0) {
			log_finest_icap_va("NOT null body but no body yet, do not send icap headers, wait for body, in_hdr_len=%zu", in_hdr_len);
			return 1;
		}

		if (ctx->spec->http) {
			snprintf(encapsulated_hdr, sizeof(encapsulated_hdr), "%s-hdr=0, %s-body=%zu",
				// req_or_res, body_len > 0 ? req_or_res : "null", hdr_len);
				req_or_res, null_body ? "null" : req_or_res, in_hdr_len);
		} else {
			/* Non-HTTP protocols: treat as pure body */
			snprintf(encapsulated_hdr, sizeof(encapsulated_hdr), "%s-body=0", req_or_res);
		}

		#define ICAP_MAX_HEADER_SIZE 2048
		char icap_hdr_str[ICAP_MAX_HEADER_SIZE];
		#define ICAP_MAX_PREVIEW_HEADER_SIZE 64
		char preview_hdr[ICAP_MAX_PREVIEW_HEADER_SIZE] = "";

		/* Add Preview header if configured */
		if (icap_preview_enabled(service_ctx->svc) && in_body_len > 0) {
			preview_size = service_ctx->svc->preview_size;

			if (icap_max_body_size_enabled(service_ctx) && preview_size > service_ctx->svc->max_body_size) {
				log_finest_icap_va("Max body size enabled, truncating preview size, preview_size=%zu, max_body_size=%zu", preview_size, service_ctx->svc->max_body_size);
				preview_size = service_ctx->svc->max_body_size;
			}

			size_t content_length = icap_get_http_content_length(icap_ctx);
			if (preview_size >= content_length) {
				content_complete = 1;
			}
			else if (in_body_len < preview_size) {
				log_finest_icap_va("NOT enough body in preview mode, do not send icap headers, wait for body, content_length=%zu, in_body_len=%zu, preview_size=%zu",
					content_length, in_body_len, preview_size);
				return 1;
			}

			snprintf(preview_hdr, sizeof(preview_hdr), "Preview: %zu\r\n", preview_size);
			log_finest_icap_va("Adding Preview header: %zu bytes, content_complete=%d", preview_size, content_complete);
		}

		// strlen("Allow: 204, 206\r\n") = 17, so 18 bytes is enough for this header
		#define ICAP_ALLOW_HEADER_MAX_LEN 18
		char allow_hdr[ICAP_ALLOW_HEADER_MAX_LEN] = "";

		if (service_ctx->svc->allow_204 || service_ctx->svc->allow_206) {
			snprintf(allow_hdr, sizeof(allow_hdr), "Allow: %s%s\r\n",
				service_ctx->svc->allow_204 ? "204" : "",
				service_ctx->svc->allow_206 ? (service_ctx->svc->allow_204 ? ", 206" : "206") : "");
			log_finest_icap_va("Adding Allow header: %s", allow_hdr);
		}

		char *echo_hdr = NULL;
		if (!reqmod && service_ctx->echo_header) {
			echo_hdr = service_ctx->echo_header;
			log_finest_icap_va("Adding echo header: %s", echo_hdr);
		}

		snprintf(icap_hdr_str, sizeof(icap_hdr_str),
			"%s icap://%s/%s ICAP/1.0\r\n"
			"Host: %s\r\n"
			"User-Agent: SSLproxy\r\n"
			"%s"
			"%s"
			"%s"
			"Encapsulated: %s\r\n",
			reqmod ? "REQMOD" : "RESPMOD",
			service_ctx->svc->server,
			reqmod ? (service_ctx->svc->reqmod ? service_ctx->svc->reqmod : "") : (service_ctx->svc->respmod ? service_ctx->svc->respmod : ""),
			service_ctx->svc->server,
			allow_hdr,
			preview_hdr,
			echo_hdr ? echo_hdr : "",
			encapsulated_hdr
			);

		struct evbuffer *icap_buf = evbuffer_new();
		if (!icap_buf) {
			log_finest("Failed to allocate ICAP buffer for header");
			return -1;
		}

		log_finest_icap_va("Generated ICAP Header: %s", icap_hdr_str);
		evbuffer_add(icap_buf, icap_hdr_str, strlen(icap_hdr_str));

		/* Add standard X-headers */
		icap_add_standard_x_headers(ctx, icap_buf);
		
		/* Add custom ICAP meta headers if any */
		if (service_ctx->icap_ctx->icap_extended_headers) {
			evbuffer_add(icap_buf, service_ctx->icap_ctx->icap_extended_headers, strlen(service_ctx->icap_ctx->icap_extended_headers));
		}
		
		/* Final CRLF to end headers */
		evbuffer_add(icap_buf, "\r\n", 2);

		if (bufferevent_write_buffer(bev, icap_buf) < 0) {
			log_finest("Failed to send ICAP header");
			evbuffer_free(icap_buf);
			return -1;
		}
		evbuffer_free(icap_buf);

		if (icap_preview_enabled(service_ctx->svc) && in_body_len > 0 && !content_complete) {
			log_finest_icap("Set wait for ICAP 100 preview continue");
			ICAP_STATE(service_ctx, icap_ctx->reqmod)->wait_preview_continue = 1;
		}

		ICAP_STATE(service_ctx, icap_ctx->reqmod)->received_icap_headers = 0;
	}
	else {
		log_finest_icap_va("Do not send ICAP header, already sent, sent_hdr_size=%zu, sent_body_size=%zu", sent_hdr_size, sent_body_size);
	}

	/* 2. Send Headers (HTTP only) */
	if (ctx->spec->http && in_hdr_len > 0) {
		log_finest_icap_va("Sending HTTP headers to ICAP server, in_hdr_len=%zu", in_hdr_len);

		if (icap_evbuffer_write_bev(bev, in_hdr, in_hdr_len) < 0) {
			log_finest_icap("Failed to write ICAP headers");
			return -1;
		}

		evbuffer_remove_buffer(in_hdr, sent_hdr, in_hdr_len);

		size_t *sent_hdr_size_new = icap_ctx->reqmod ? &service_ctx->src.sent_hdr_size : &service_ctx->dst.sent_hdr_size;
		*sent_hdr_size_new += in_hdr_len;

		log_finest_icap_va("Moved in_hdr to sent_hdr, in_hdr=%zu, sent_hdr=%zu, sent_hdr_size=%zu", evbuffer_get_length(in_hdr), evbuffer_get_length(sent_hdr), *sent_hdr_size_new);
		icap_ctx->made_progress = 1;
	}

	/* 3. Send Body (Chunked) */
	if (in_body_len > 0) {
		/* Format as chunked for ICAP */
		struct evbuffer *chunk_buf = evbuffer_new();
		if (!chunk_buf) {
			log_finest_icap("Failed to allocate chunk buffer for body");
			return -1;
		}

		size_t chunk_len = in_body_len;

		if (icap_preview_enabled(service_ctx->svc) && sent_body_size == 0) {
			chunk_len = in_body_len < service_ctx->svc->preview_size ? in_body_len : preview_size;
			log_finest_icap_va("Sending body preview to ICAP service, in_body_len=%zu, chunk_len=%zu, preview_size=%zu", in_body_len, chunk_len, service_ctx->svc->preview_size);
		}

		if (icap_max_body_size_enabled(service_ctx)) {
			if (chunk_len > service_ctx->svc->max_body_size) {
				chunk_len = service_ctx->svc->max_body_size;
				log_finest_icap_va("Max body size enabled, truncating body chunk, in_body_len=%zu, chunk_len=%zu, max_body_size=%zu", in_body_len, chunk_len, service_ctx->svc->max_body_size);
			}
		}

		evbuffer_add_printf(chunk_buf, "%zx\r\n", chunk_len);

		if (icap_evbuffer_add_evbuf(chunk_buf, in_body, chunk_len) < 0) {
			log_finest_icap("Failed to add ICAP body data to chunk buffer");
			evbuffer_free(chunk_buf);
			return -1;
		}

		// TODO: Check if service config is fail-open before copying
		// Make a copy of sent data, to use for fail-open in case the service errors out
		// struct evbuffer *sent_body = icap_ctx->reqmod ? service_ctx->src.sent_body : service_ctx->dst.sent_body;
		log_finest_icap_va("Moving in_body to sent_body, in_body=%zu, sent_body=%zu, chunk_len=%zu", evbuffer_get_length(in_body), evbuffer_get_length(sent_body), chunk_len);
		evbuffer_remove_buffer(in_body, sent_body, chunk_len);

		evbuffer_add_printf(chunk_buf, "\r\n");

		size_t *sent_body_size_new = icap_ctx->reqmod ? &service_ctx->src.sent_body_size : &service_ctx->dst.sent_body_size;
		*sent_body_size_new += chunk_len;

		log_finest_icap_va("Sending body chunk to ICAP server, sent_body_size=%zu, sent_body=%zu, chunk_len=%zu",
			*sent_body_size_new, evbuffer_get_length(sent_body), chunk_len);

		size_t http_content_length = icap_get_http_content_length(icap_ctx);
		log_finest_icap_va("Checking if HTTP content complete, sent_body_size=%zu, http_content_length=%zu", *sent_body_size_new, http_content_length);
		if (*sent_body_size_new >= http_content_length) {
			content_complete = 1;
		}

		if (icap_preview_enabled(service_ctx->svc) && sent_hdr_size == 0 && sent_body_size == 0) {
			log_finest_icap_va("Terminating preview, sent_hdr=%zu, sent_body=%zu, content_complete=%d", evbuffer_get_length(sent_hdr), evbuffer_get_length(sent_body), content_complete);
			// 0; ieof\r\n\r\n is a mechanism to signal the early end of a message body: preview >= in_body_len
			evbuffer_add_printf(chunk_buf, content_complete ? "0; ieof\r\n\r\n" : "0\r\n\r\n");
		}
		else if (content_complete) {
			log_finest_icap_va("Content complete, adding terminator, preview_enabled=%d, sent_hdr=%zu, sent_body=%zu",
				icap_preview_enabled(service_ctx->svc), evbuffer_get_length(sent_hdr), evbuffer_get_length(sent_body));
			evbuffer_add_printf(chunk_buf, "0\r\n\r\n");
		}

		if (bufferevent_write_buffer(bev, chunk_buf) < 0) {
			log_finest_icap("Failed to send ICAP body chunk");
			evbuffer_free(chunk_buf);
			return -1;
		}

		evbuffer_free(chunk_buf);
		icap_ctx->made_progress = 1;
	}

	return 0;
}

/*
 * ICAP bufferevent event callback
 */
static void
icap_bev_eventcb(UNUSED struct bufferevent *bev, short events, void *arg)
{
	icap_service_ctx_t *service_ctx = (icap_service_ctx_t *)arg;
	icap_ctx_t *icap_ctx = service_ctx->icap_ctx;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	log_finest_icap_va("ICAP event 0x%x", events);

	if (events & BEV_EVENT_CONNECTED) {
		log_finest_icap_va("ICAP connected to %s, sending request", service_ctx->svc->server);

		int rv = icap_build_request(service_ctx);
		if (rv < 0) {
			log_finest_icap_va("ICAP failed to build and send request to %s", service_ctx->svc->server);
			goto err;
		}
		else if (rv == 0) {
			log_finest_icap_va("ICAP request sent to %s", service_ctx->svc->server);
		}
		return;
	}

	// events can have multiple flags set, so check each flag separately
	if (events & BEV_EVENT_ERROR) {
		log_finest_icap("ICAP connection error");
	}

	if (events & BEV_EVENT_EOF) {
		log_finest_icap("ICAP connection closed (eof)");
	}

	if (events & BEV_EVENT_TIMEOUT) {
		log_finest_icap("ICAP connection timeout");
	}
err:
	icap_handle_service_error(service_ctx);
}

static void
icap_process_chain_cb(UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	icap_ctx_t *icap_ctx = (icap_ctx_t *)arg;
	if (!icap_ctx) {
		log_dbg_printf("No ICAP context in icap_process_chain_cb()\n");
		return;
	}

	int service_idx = icap_ctx->chain_service_idx;
	event_free(icap_ctx->chain_ev);
	icap_ctx->chain_ev = NULL;

	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	/* Check for Veto: abort chain immediately if a previous service blocked the content */
	if (icap_ctx->is_veto) {
		log_finest("ICAP Veto detected in chain, aborting remaining services");
		// Go to the last service to send the veto page
		icap_handle_chain_continuation(icap_ctx->services[icap_ctx->service_count - 1], ctx->icap_ctx);
		return;
	}

	if (service_idx < 0 || service_idx >= icap_ctx->service_count) {
		log_finest_va("Invalid service index %d, count=%d", service_idx, icap_ctx->service_count);
		return;
	}

	icap_service_ctx_t *service_ctx = icap_ctx->services[service_idx];
	if (!service_ctx) {
		log_finest_va("NULL service context at idx=%d", service_idx);
		return;
	}

	unsigned int wait_preview_continue = icap_ctx->reqmod ? service_ctx->src.wait_preview_continue : service_ctx->dst.wait_preview_continue;
	// TODO: Do we need to check detected_204 here to bypass waiting for preview continue?
	// if (!wait_preview_continue || ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_204) {
	if (!wait_preview_continue) {
		log_finest_icap_va("Triggering service, server=%s", service_ctx->svc->server);

		if (icap_service_connect(service_ctx) < 0) {
			icap_handle_service_error(service_ctx);
		}
	}
	else {
		if (service_ctx->failopen) {
			log_finest_icap("Preview enabled but service in fail-open, failopen to next service");
			icap_failopen_to_next_service(service_ctx);
		}
		else {
			log_finest_icap("Wait for ICAP 100 preview continue, proceed to next service");

			if (icap_is_icap_response_nullbody(service_ctx) && (ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_204 || ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206)) {
				log_finest_icap_va("Preview mode with 204 or 206, streaming data, 204=%d, 206=%d",
					ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_204, ICAP_STATE(service_ctx, icap_ctx->reqmod)->detected_206);
				icap_service_bypass(service_ctx);
			}
		}
	}

	/* Only continue chain processing if the connection is still alive */
	if (ctx && !ctx->term) {
		// Stream data to icap services as it comes, continue chain processing with or without preview
		// (E2guardian expects this behavior and does not respond until it receives all body data)
		icap_handle_chain_continuation(service_ctx, ctx->icap_ctx);
	}
}

static void
icap_process_chain(icap_ctx_t *icap_ctx, int service_idx)
{
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (!icap_ctx->chain_ev) {
		log_finest_va("Add and activate chain event, chain_service_idx=%d", icap_ctx->chain_service_idx);

		icap_ctx->chain_service_idx = service_idx;

		icap_ctx->chain_ev = event_new(ctx->thr->evbase, -1, 0, icap_process_chain_cb, icap_ctx);
		if (!icap_ctx->chain_ev) {
			log_finest_va("Error creating chain_ev, service_idx=%d", service_idx);
			return;
		}

		// Do not immediately dispatch with event_active(),
		// instead use a zero timeout to prevent reentrant callback issues
		struct timeval tv = {0, 0};
		if (event_add(icap_ctx->chain_ev, &tv) == -1) {
			log_finest_va("Error adding chain_ev, service_idx=%d", service_idx);
			event_free(icap_ctx->chain_ev);
			icap_ctx->chain_ev = NULL;
			return;
		}
	}
	else {
		log_finest_va("Chain event already active, do not add or activate again, chain_service_idx=%d, service_idx=%d",
			icap_ctx->chain_service_idx, service_idx);

		// Update chain service idx if the new service idx is earlier in the chain
		if (icap_ctx->chain_service_idx > service_idx) {
			icap_ctx->chain_service_idx = service_idx;
		}
	}
}

/*
 * Check if ICAP is enabled for this connection
 */
int NONNULL(1)
icap_enabled(pxy_conn_ctx_t *ctx)
{
	return ctx->conn_opts->icap_chain != NULL;
}

int NONNULL(1)
icap_is_finished(pxy_conn_ctx_t *ctx)
{
	icap_ctx_t *icap_ctx = ctx->icap_ctx;

	if (!icap_ctx) {
		log_finest("No ICAP context, assume finished");
		return 1;
	}

	if (!icap_is_content_complete(icap_ctx, 1) || !icap_is_content_complete(icap_ctx, 0)) {
		for (int i = 0; i < icap_ctx->service_count; i++) {
			icap_service_ctx_t *service_ctx = icap_ctx->services[i];
			if (service_ctx && (service_ctx->bev || service_ctx->failopen)) {
				log_finest_va("Service still connected, service idx=%d", i);
				return 0;
			}
		}
	}

	log_finest("All ICAP services finished");
	return 1;
}

static int NONNULL(1)
icap_is_content_complete(icap_ctx_t *icap_ctx, int reqmod)
{
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (icap_ctx->is_veto && icap_ctx->sent_veto_page) {
		log_finest("Veto page sent, assume all content COMPLETE");
		return 1;
	}

	for (int i = 0; i < icap_ctx->service_count; i++) {
		if (icap_ctx->services[i]) {
			unsigned int content_complete = reqmod ? icap_ctx->services[i]->src.content_complete : icap_ctx->services[i]->dst.content_complete;
			if (content_complete == 0) {
				log_finest_va("%s content NOT complete, service idx=%d", reqmod ? "REQMOD" : "RESPMOD", i);
				return 0;
			}
			else {
				log_finest_va("%s content complete for service idx=%d, content_complete=%u", reqmod ? "REQMOD" : "RESPMOD", i, content_complete);
			}
		}
	}
	log_finest_va("All %s content COMPLETE", reqmod ? "REQMOD" : "RESPMOD");
	return 1;
}

static void NONNULL(1,2,3)
icap_process_done(struct evbuffer *inbuf, struct evbuffer *outbuf, icap_ctx_t *icap_ctx)
{
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
	UNUSED int reqmod = icap_ctx->reqmod;

	icap_service_ctx_t *service_ctx = icap_ctx->services[icap_ctx->service_count - 1];

	struct evbuffer *out_hdr = icap_ctx->reqmod ? service_ctx->src.out_hdr : service_ctx->dst.out_hdr;
	struct evbuffer *out_body = icap_ctx->reqmod ? service_ctx->src.out_body : service_ctx->dst.out_body;

	log_finest_icap_va("ENTER, inbuf=%zu, outbuf=%zu, out_hdr=%zu, out_body=%zu, is_veto=%d",
		evbuffer_get_length(inbuf), evbuffer_get_length(outbuf),
		evbuffer_get_length(out_hdr), evbuffer_get_length(out_body),
		icap_ctx->is_veto);

	if (icap_ctx->is_veto) {
		log_finest_icap("Content vetoed by ICAP service");

		if (icap_ctx->veto_page) {
			log_finest_icap_va("Sending veto page to client, veto_page=%zu", evbuffer_get_length(icap_ctx->veto_page));

#ifdef DEBUG_PROXY
			/* Log veto page for debugging */
			size_t len = evbuffer_get_length(icap_ctx->veto_page);
			size_t log_len = len < 400 ? len : 400;
			char log_buf[401];  // Stack allocation
			evbuffer_copyout(icap_ctx->veto_page, log_buf, log_len);
			log_buf[log_len] = '\0';
			log_finest_icap_va("Veto page (first %zu bytes, orig %zu bytes): %s", log_len, len, log_buf);
#endif /* DEBUG_PROXY */

			// Send block page to src (client), not dst (server)
			if (ctx->src.bev) {
				evbuffer_add_buffer(bufferevent_get_output(ctx->src.bev), icap_ctx->veto_page);
				icap_ctx->made_progress = 1;
			}
			else {
				log_finest_icap("Src connection already closed, cannot send veto page");
			}
		}

		// ATTENTION: Do NOT reset is_veto here - it must remain set until context is freed
		evbuffer_drain(inbuf, evbuffer_get_length(inbuf));
		evbuffer_drain(outbuf, evbuffer_get_length(outbuf));

		evbuffer_drain(out_hdr, evbuffer_get_length(out_hdr));
		evbuffer_drain(out_body, evbuffer_get_length(out_body));
	}
	else {
		// Send the data in the out buffers of the last service to their destination
		if (ctx->spec->http && evbuffer_get_length(out_hdr) > 0) {
			log_finest_icap_va("Send hdr to destination, out_hdr=%zu", evbuffer_get_length(out_hdr));
			evbuffer_add_buffer(outbuf, out_hdr);
			icap_ctx->made_progress = 1;
		}

		if (evbuffer_get_length(out_body) > 0) {
			log_finest_icap_va("Send body to destination, out_body=%zu", evbuffer_get_length(out_body));
			evbuffer_add_buffer(outbuf, out_body);
			icap_ctx->made_progress = 1;
		}
	}
}

void NONNULL(1,2)
icap_process_data(struct evbuffer *inbuf, pxy_conn_ctx_t *ctx, int reqmod)
{
	icap_ctx_t *icap_ctx = ctx->icap_ctx;

	if (!icap_ctx) {
		log_finest_va("No ICAP context in %s, skipping ICAP processing, inbuf=%zu", reqmod ? "REQMOD" : "RESPMOD", evbuffer_get_length(inbuf));
		return;
	}

	icap_ctx->reqmod = reqmod;

	struct evbuffer *in_hdr = icap_get_first_service_in_hdr(ctx, reqmod);

	log_finest_va("ENTER for ICAP %s data, hdr=%zu, inbuf=%zu, is_veto=%d",
		icap_ctx->reqmod ? "REQMOD" : "RESPMOD", evbuffer_get_length(in_hdr), evbuffer_get_length(inbuf), icap_ctx->is_veto);

	// The hdr buffer is filled by protocol layer, if any (e.g. HTTP headers)
	if (evbuffer_get_length(inbuf) > 0 || evbuffer_get_length(in_hdr) > 0) {
		struct evbuffer *in_body = icap_ctx->reqmod ? icap_ctx->services[0]->src.in_body : icap_ctx->services[0]->dst.in_body;

		if (evbuffer_get_length(in_hdr) == 0) {
			// TODO: Non-http protocols do not have hdr
			log_finest("No new hdr data to process");
		}

		if (evbuffer_get_length(inbuf) > 0) {
			evbuffer_add_buffer(in_body, inbuf);
		}
		else {
			log_finest("No new body data to process");
		}

		/* Pause reading from src or dst: disable read callback temporarily */
		// TODO: Should we disable the current conn_bev only?
		bufferevent_disable(icap_ctx->reqmod ? ctx->src.bev : ctx->dst.bev, EV_READ);
		// bufferevent_disable(ctx->src.bev, EV_READ);
		// bufferevent_disable(ctx->dst.bev, EV_READ);

		log_finest_va("Triggering ICAP for %s, hdr=%zu, inbuf=%zu", icap_ctx->reqmod ? "REQMOD" : "RESPMOD", evbuffer_get_length(in_hdr), evbuffer_get_length(inbuf));
		icap_process_chain(icap_ctx, 0);
	}
	else {
		log_finest("No new data to process");
	}
}
#endif /* !WITHOUT_ICAP */

typedef int dummy_declaration_to_avoid_empty_translation_unit;

/* vim: set noet ft=c: */
