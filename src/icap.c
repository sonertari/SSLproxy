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

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

/*
 * Forward declarations of static callbacks
 */
static void icap_bev_readcb(struct bufferevent *, void *);
static void icap_bev_writecb(struct bufferevent *, void *);
static void icap_bev_eventcb(struct bufferevent *, short, void *);
static void icap_send_remainder(icap_ctx_t *, struct bufferevent *);
static void icap_process_done(struct evbuffer *, struct evbuffer *, pxy_conn_ctx_t *, icap_ctx_t *, int);

/*
 * Allocate and initialize ICAP context
 */
icap_ctx_t *
icap_ctx_new(void)
{
	icap_ctx_t *icap_ctx = malloc(sizeof(icap_ctx_t));
	if (!icap_ctx) {
		log_err_printf("ICAP context allocation failed\n");
		return NULL;
	}
	memset(icap_ctx, 0, sizeof(icap_ctx_t));

	icap_ctx->state = ICAP_STATE_IDLE;

	/* Create ICAP protocol buffer */
	icap_ctx->icap_buf = evbuffer_new();
	if (!icap_ctx->icap_buf) {
		log_err_printf("ICAP evbuffer allocation failed\n");
		free(icap_ctx);
		return NULL;
	}

	return icap_ctx;
}

/*
 * Free all ICAP context resources
 */
void
icap_ctx_free(icap_ctx_t *icap_ctx)
{
	log_err_printf("ICAP context free\n");

	/* Disconnect if connected */
	if (icap_ctx->bev) {
		icap_disconnect(icap_ctx);
	}

	/* Free buffers */
	if (icap_ctx->icap_buf) {
		evbuffer_free(icap_ctx->icap_buf);
	}
	if (icap_ctx->body) {
		evbuffer_free(icap_ctx->body);
	}
	if (icap_ctx->hdr) {
		evbuffer_free(icap_ctx->hdr);
	}
	if (icap_ctx->veto_page) {
		evbuffer_free(icap_ctx->veto_page);
	}

	/* Free strings */
	if (icap_ctx->server)
		free(icap_ctx->server);

	free(icap_ctx);
}

/*
 * Initialize ICAP context
 */
icap_ctx_t *
icap_init()
{
	icap_ctx_t *icap_ctx = icap_ctx_new();
	if (!icap_ctx)
		return NULL;

	icap_ctx->body = evbuffer_new();
	if (!icap_ctx->body) {
		log_err_printf("ICAP evbuffer_new failed\n");
		icap_ctx_free(icap_ctx);
		return NULL;
	}

	icap_ctx->hdr = evbuffer_new();
	if (!icap_ctx->hdr) {
		log_err_printf("ICAP evbuffer_new failed\n");
		evbuffer_free(icap_ctx->body);
		icap_ctx_free(icap_ctx);
		return NULL;
	}

	icap_ctx->reqmod = 1;
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
		if (!svc) break;
		memset(svc, 0, sizeof(*svc));
		svc->server = chain->server ? strdup(chain->server) : NULL;
		svc->port = chain->port;
		svc->uri = chain->uri ? strdup(chain->uri) : NULL;
		svc->type = chain->type;
		svc->fail_mode = chain->fail_mode;
		svc->next = NULL;
		
		if (!new_chain) new_chain = svc;
		else last->next = svc;
		last = svc;
		
		chain = chain->next;
	}
	return new_chain;
}

/*
 * Parse an ICAP service specification string
 * Format: icap://<host>:<port>/<path>,<type>,<mode>
 * Example: icap://127.0.0.1:1344/av,parallel,bypass
 */
int NONNULL(1, 2)
icap_chain_parse_spec(conn_opts_t *conn_opts, const char *spec)
{
	/* Create and initialize a new service */
	icap_service_t *svc = malloc(sizeof(icap_service_t));
	if (!svc) return -1;
	memset(svc, 0, sizeof(icap_service_t));
	
	/* Defaults */
	svc->port = 1344;
	svc->type = ICAP_SERVICE_SERIAL_MODIFYING;
	svc->fail_mode = conn_opts->icap_fail_open;

	/* Make a local copy to tokenize */
	char *spec_copy = strdup(spec);
	if (!spec_copy) {
		free(svc);
		return -1;
	}

	char *uri_part = strtok(spec_copy, ",");
	char *type_part = strtok(NULL, ",");
	char *mode_part = strtok(NULL, ",");

	if (!uri_part) {
		log_err_printf("ICAP Config Error: Missing URI in spec '%s'\n", spec);
		free(spec_copy);
		free(svc);
		return -1;
	}

	/* Parse URI: icap://<host>:<port>/<path> */
	svc->uri = strdup(uri_part);

	char *host_start = NULL;
	if (strncmp(uri_part, "icap://", 7) == 0) {
		host_start = uri_part + 7;
	} else if (strncmp(uri_part, "icaps://", 8) == 0) {
		host_start = uri_part + 8;
	} else {
		log_err_printf("ICAP Config Error: URI must start with icap:// or icaps://\n");
		free(svc->uri);
		free(spec_copy);
		free(svc);
		return -1;
	}

	/* isolate host and port from path */
	char *path_start = strchr(host_start, '/');
	if (path_start) {
		*path_start = '\0'; /* Temporarily terminate host:port part */
	}

	char *port_delim = strchr(host_start, ':');
	if (port_delim) {
		*port_delim = '\0';
		svc->port = atoi(port_delim + 1);
		if (svc->port <= 0 || svc->port > 65535) svc->port = 1344;
	}
	
	svc->server = strdup(host_start);

	/* Parse Type */
	if (type_part) {
		if (strcasecmp(type_part, "parallel") == 0) {
			svc->type = ICAP_SERVICE_PARALLEL_INSPECT;
		} else if (strcasecmp(type_part, "serial") == 0) {
			svc->type = ICAP_SERVICE_SERIAL_MODIFYING;
		} else {
			log_err_printf("ICAP Config Warning: Unknown type '%s', defaulting to serial\n", type_part);
		}
	}

	/* Parse Mode */
	if (mode_part) {
		if (strcasecmp(mode_part, "block") == 0) {
			svc->fail_mode = ICAP_FAIL_CLOSED;
		} else if (strcasecmp(mode_part, "bypass") == 0) {
			svc->fail_mode = ICAP_FAIL_OPEN;
		} else {
			log_err_printf("ICAP Config Warning: Unknown fail mode '%s', defaulting to %s\n",
				mode_part, svc->fail_mode == ICAP_FAIL_CLOSED ? "fail-closed" : "fail-open");
		}
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
}

int NONNULL(1)
icap_set_extended_headers(pxy_conn_ctx_t *ctx, int upgraded)
{
	/* Build the ICAP meta headers (X-Src, X-Dst, X-Proto, X-User) */
	const char *proto = "tcp";
	if (ctx->spec->http) proto = ctx->spec->ssl || upgraded ? "https" : "http";
	else if (ctx->spec->pop3) proto = ctx->spec->ssl || upgraded ? "pop3s" : "pop3";
	else if (ctx->spec->smtp) proto = ctx->spec->ssl || upgraded ? "smtps" : "smtp";
	else if (ctx->spec->upgrade) proto = upgraded ? "autossl-tls" : "autossl";
	else if (ctx->spec->ssl || upgraded) proto = "ssl";

	char user_hdr[256];
	user_hdr[0] = '\0';
#ifndef WITHOUT_USERAUTH
	if (ctx->conn_opts->user_auth && ctx->user) {
		snprintf(user_hdr, sizeof(user_hdr), "X-User: %s\r\n", ctx->user);
	}
#endif /* !WITHOUT_USERAUTH */

	// Estimate string length
	ctx->icap_meta_header_len = snprintf(NULL, 0,
		"X-Src: [%s]:%s\r\n"
		"X-Dst: [%s]:%s\r\n"
		"X-Proto: %s\r\n"
		"%s",
		STRORNONE(ctx->srchost_str), STRORNONE(ctx->srcport_str),
		STRORNONE(ctx->dsthost_str), STRORNONE(ctx->dstport_str),
		proto, user_hdr);

	ctx->icap_meta_header = malloc(ctx->icap_meta_header_len + 1);
	if (!ctx->icap_meta_header) {
		pxy_conn_term(ctx, 1);
		return -1;
	}

	if (snprintf(ctx->icap_meta_header, ctx->icap_meta_header_len + 1,
		"X-Src: [%s]:%s\r\n"
		"X-Dst: [%s]:%s\r\n"
		"X-Proto: %s\r\n"
		"%s",
		STRORNONE(ctx->srchost_str), STRORNONE(ctx->srcport_str),
		STRORNONE(ctx->dsthost_str), STRORNONE(ctx->dstport_str),
		proto, user_hdr) < 0) {

		pxy_conn_term(ctx, 1);
		return -1;
	}
	return 0;
}

/*
 * Setup and dispatch a connection to an explicit ICAP service
 */
static int
icap_service_connect(icap_ctx_t *icap_ctx, icap_service_t *svc, int parallel_idx)
{
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	struct bufferevent *bev = bufferevent_socket_new(ctx->thr->evbase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		log_finest_va("ICAP bufferevent allocation failed for %s", svc->server);
		return -1;
	}

	bufferevent_setcb(bev, icap_bev_readcb, icap_bev_writecb, icap_bev_eventcb, icap_ctx);
	bufferevent_setwatermark(bev, EV_READ, 0, 0);

	struct timeval tv;
	tv.tv_sec = icap_ctx->timeout / 1000;
	tv.tv_usec = (icap_ctx->timeout % 1000) * 1000;
	bufferevent_set_timeouts(bev, &tv, &tv);

	if (svc->type == ICAP_SERVICE_SERIAL_MODIFYING) {
		if (icap_ctx->bev) {
			evutil_socket_t fd = bufferevent_getfd(icap_ctx->bev);
			// Don't close the socket here, let bufferevent_free handle it, otherwise we get Epoll Bad file descriptor errors.
			if (fd >= 0) {
				log_finest_va("Closing ICAP socket fd=%d for %s", fd, icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
				// evutil_closesocket(fd);
			}
			bufferevent_free(icap_ctx->bev);
		}
		icap_ctx->bev = bev;
	} else {
		if (parallel_idx >= 0 && parallel_idx < ICAP_MAX_PARALLEL) {
			icap_ctx->parallel_bevs[parallel_idx] = bev;
			icap_ctx->parallel_svcs[parallel_idx] = svc;
			icap_ctx->parallel_read_state[parallel_idx] = ICAP_READ_STATE_WAIT_HEADERS;
		} else {
			bufferevent_free(bev);
			return -1;
		}
	}

	if (bufferevent_socket_connect_hostname(bev, NULL, AF_UNSPEC, svc->server, svc->port) < 0) {
		log_finest_va("ICAP connection failed to %s:%d", svc->server, svc->port);
		bufferevent_free(bev);
		if (svc->type == ICAP_SERVICE_SERIAL_MODIFYING) icap_ctx->bev = NULL;
		else {
			icap_ctx->parallel_bevs[parallel_idx] = NULL;
			icap_ctx->parallel_svcs[parallel_idx] = NULL;
			icap_ctx->parallel_read_state[parallel_idx] = ICAP_READ_STATE_WAIT_HEADERS;
		}
		return -1;
	}

	bufferevent_enable(bev, EV_READ | EV_WRITE);
	log_finest_va("ICAP connecting to %s:%d for %s, %s, parallel_idx=%d", svc->server, svc->port, icap_ctx->reqmod ? "REQMOD" : "RESPMOD",
		svc->type == ICAP_SERVICE_SERIAL_MODIFYING ? "ICAP_SERVICE_SERIAL_MODIFYING" : "ICAP_SERVICE_PARALLEL_INSPECT", parallel_idx);
	return 0;
}

/*
 * Connect to ICAP server
 */
int
icap_connect(icap_ctx_t *icap_ctx)
{
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	icap_ctx->current_service = ctx->conn_opts->icap_chain;

	/* Fallback setting primary scalar server context for logs/compatibility */
	if (icap_ctx->server)
		free(icap_ctx->server);
	icap_ctx->server = strdup(ctx->conn_opts->icap_chain->server);
	icap_ctx->port = ctx->conn_opts->icap_chain->port;
	
	icap_ctx->timeout = ctx->conn_opts->icap_timeout;
	icap_ctx->fail_open = ctx->conn_opts->icap_fail_open;
	icap_ctx->preview_size = ctx->conn_opts->icap_preview_size;
	icap_ctx->max_body_size = ctx->conn_opts->icap_max_body_size;

	icap_ctx->state = ICAP_STATE_CONNECTING;
	
	icap_process_chain(icap_ctx);
	return 0;
}

/*
 * Disconnect from ICAP server
 * return 0 if flow is resumed,
 * 1 if still pending data in inbuf and flow is not resumed yet,
 */
int NONNULL(1)
icap_disconnect(icap_ctx_t *icap_ctx)
{
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	if (icap_ctx->bev) {
		log_finest_va("Disable bufferevents for %s, ICAP_SERVICE_SERIAL_MODIFYING", icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
		bufferevent_disable(icap_ctx->bev, EV_READ | EV_WRITE);
		bufferevent_setcb(icap_ctx->bev, NULL, NULL, NULL, NULL);
		bufferevent_set_timeouts(icap_ctx->bev, NULL, NULL);

		evutil_socket_t fd = bufferevent_getfd(icap_ctx->bev);
		if (fd >= 0) {
			log_finest_va("Closing ICAP socket fd=%d for %s, ICAP_SERVICE_SERIAL_MODIFYING", fd, icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
			// Don't close the socket here, let bufferevent_free handle it, otherwise we get Epoll Bad file descriptor errors.
			// evutil_closesocket(fd);
		}

		bufferevent_free(icap_ctx->bev);
		icap_ctx->bev = NULL;
	}

	for (int i=0; i < ICAP_MAX_PARALLEL; i++) {
		if (icap_ctx->parallel_bevs[i]) {
			log_finest_va("Disable bufferevents for %s, ICAP_SERVICE_PARALLEL_INSPECT", icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
			bufferevent_disable(icap_ctx->parallel_bevs[i], EV_READ | EV_WRITE);
			bufferevent_setcb(icap_ctx->parallel_bevs[i], NULL, NULL, NULL, NULL);
			bufferevent_set_timeouts(icap_ctx->parallel_bevs[i], NULL, NULL);

			evutil_socket_t fd = bufferevent_getfd(icap_ctx->parallel_bevs[i]);
			if (fd >= 0) {
				log_finest_va("Closing ICAP socket fd=%d for %s, ICAP_SERVICE_PARALLEL_INSPECT", fd, icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
				// Don't close the socket here, let bufferevent_free handle it, otherwise we get Epoll Bad file descriptor errors.
				// evutil_closesocket(fd);
			}

			bufferevent_free(icap_ctx->parallel_bevs[i]);
			icap_ctx->parallel_bevs[i] = NULL;
			icap_ctx->parallel_svcs[i] = NULL;
			icap_ctx->parallel_read_state[i] = ICAP_READ_STATE_WAIT_HEADERS;
		}
	}
	icap_ctx->parallel_idx = 0;

	log_finest("ICAP disconnected");

	// TODO: We may not have ctx and/or bevs, if the connection is terminated
	if (ctx && ctx->src.bev && ctx->dst.bev) {
		log_finest_va("ICAP done, send data to destination, hdr=%zu, body=%zu, inbuf=%zu",
			evbuffer_get_length(icap_ctx->hdr), evbuffer_get_length(icap_ctx->body), evbuffer_get_length(bufferevent_get_input(icap_ctx->conn_bev)));

		struct evbuffer *inbuf = bufferevent_get_input(icap_ctx->conn_bev);
		struct evbuffer *outbuf = bufferevent_get_output(icap_ctx->conn_bev == ctx->src.bev  ? ctx->dst.bev : ctx->src.bev);
		icap_process_done(inbuf, outbuf, ctx, icap_ctx, icap_ctx->reqmod);

		if (evbuffer_get_length(inbuf) == 0) {
			log_finest("Enable reading from source, resuming flow");
			// TODO: Should we enable the current conn_bev only?
			bufferevent_enable(icap_ctx->conn_bev, EV_READ);
			// bufferevent_enable(ctx->src.bev, EV_READ);
			// bufferevent_enable(ctx->dst.bev, EV_READ);
		}
		else {
			log_finest_va("Data still pending in inbuf=%zu, do not resume flow yet", evbuffer_get_length(inbuf));
			return 1;
		}
	}
	else {
		log_finest("No connection context to resume flow");
	}
	return 0;
}

static int NONNULL(1)
icap_preview_enabled(icap_ctx_t *icap_ctx)
{
	return icap_ctx->preview_size > 0;
}

/*
 * Extract modified payload from 200 OK response and update icap_ctx->body
 */
static int
icap_extract_200_ok(icap_ctx_t *icap_ctx, struct evbuffer *input)
{
	char *line;
	int is_body = 0;
	int is_veto = 0;
	size_t body_offset = 0;
	size_t header_offset = 0;
	
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	/* Parse ICAP Headers to find Encapsulated offsets and Veto detection */
	while ((line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF))) {
		if (strlen(line) == 0) {
			free(line);
			log_finest("End of ICAP headers");
			break;
		}
		
		/* Check for Veto: X-Response-Info: Blocked */
		if (strncasecmp(line, "X-Response-Info:", 16) == 0) {
			if (strcasestr(line, "Blocked")) {
				log_finest("ICAP Veto detected: X-Response-Info: Blocked");
				is_veto = 1;
			}
		}
		
		if (strncasecmp(line, "Encapsulated:", 13) == 0) {
			/* Simplistic parse for req-body / res-body offsets */
			char *p = strstr(line, "req-body=");
			if (!p) p = strstr(line, "res-body=");
			
			if (p) {
				p += 9;
				body_offset = (size_t)strtoull(p, NULL, 10);
				is_body = 1;
			}
			else {
				p = strstr(line, "null-body=");
				if (p) {
					p += 10;
					body_offset = (size_t)strtoull(p, NULL, 10);
				}
			}

			char *h = strstr(line, "req-hdr=");
			if (!h) h = strstr(line, "res-hdr=");
			if (h) {
				h += 8;
				header_offset = (size_t)strtoull(h, NULL, 10);
			}
		}
		free(line);
	}

	if (evbuffer_get_length(input) == 0) {
		log_finest("No content left in ICAP response after headers");
		return 0;
	}

	/* Set veto flag if detected */
	if (is_veto) {
		icap_ctx->is_veto = 1;
		
		/* If body exists, save it as the veto page to send to client */
		if (evbuffer_get_length(input) > 0 && !icap_ctx->veto_page) {
			icap_ctx->veto_page = evbuffer_new();
			if (icap_ctx->veto_page) {
				evbuffer_add_buffer(icap_ctx->veto_page, input);
			}
		}
	}

	size_t hdrlen = body_offset - header_offset;

	/* Check for HTTP 4xx/5xx in encapsulated HTTP status (for REQMOD) */
	if (hdrlen > 0 && ctx && ctx->spec && ctx->spec->http) {
		char *hdr_buf = malloc(hdrlen + 1);
		if (hdr_buf) {
			evbuffer_copyout(input, hdr_buf, hdrlen);
			hdr_buf[hdrlen] = '\0';
			
			/* Look for HTTP status line with 4xx or 5xx */
			char *status_line = strstr(hdr_buf, "HTTP/");
			if (status_line) {
				/* Check for 4xx or 5xx status codes */
				if (strstr(status_line, "HTTP/1.0 4") || strstr(status_line, "HTTP/1.1 4") ||
				    strstr(status_line, "HTTP/1.0 5") || strstr(status_line, "HTTP/1.1 5")) {
					log_finest("ICAP Veto detected: Encapsulated HTTP error response");
					icap_ctx->is_veto = 1;
				}
			}
			free(hdr_buf);
		}
	}
	if (hdrlen > 0) {
		if (icap_ctx->current_service->type == ICAP_SERVICE_PARALLEL_INSPECT) {
			log_finest_va("Do not update headers in parallel mode, hdr=%zu", hdrlen);
			evbuffer_drain(input, hdrlen);
		}
		else {
			log_finest_va("Update headers in serial mode, hdr=%zu", hdrlen);
			// Copy any headers encapsulated before the body
			struct evbuffer *new_header = evbuffer_new();
			if (!new_header) return -1;

			evbuffer_remove_buffer(input, new_header, hdrlen);

			/* Swap into Golden hdr buffer */
			if (icap_ctx->hdr) {
				evbuffer_free(icap_ctx->hdr);
			}
			icap_ctx->hdr = new_header;
		}
	}
	else {
		log_finest("No encapsulated headers");
	}

	if (!is_body) {
		log_finest("No modified body");
		/* Drain the rest since we don't have a body to extract */
		evbuffer_drain(input, evbuffer_get_length(input));
		return 0;
	}

	if (icap_ctx->current_service->type == ICAP_SERVICE_PARALLEL_INSPECT) {
		log_finest_va("Do not update body in parallel mode, inbuf=%zu", evbuffer_get_length(input));
		evbuffer_drain(input, evbuffer_get_length(input));
	}
	else {
		/* Now input contains the body, chunked encoded by ICAP.
		* We need to unchunk it into a new buffer, then swap with icap_ctx->body.
		*/
		log_finest_va("Update body in serial mode, inbuf=%zu", evbuffer_get_length(input));

		struct evbuffer *new_body = evbuffer_new();
		if (!new_body) return -1;

		while (evbuffer_get_length(input) > 0) {
			line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
			if (!line) {
				log_finest("Incomplete chunk header or EOF");
				break;
			}

			size_t chunk_size = (size_t)strtoull(line, NULL, 16);
			free(line);

			if (chunk_size == 0) {
				/* End of chunks */
				/* Read trailing "\r\n" */
				line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
				if (line) free(line);
				log_finest("End of body chunks");
				break;
			}

			/* Read chunk data */
			while (chunk_size > 0 && evbuffer_get_length(input) > 0) {
				size_t avail = evbuffer_get_length(input);

				if (icap_preview_enabled(icap_ctx)) {
					struct evbuffer_ptr term_ptr = evbuffer_search(input, "\r\n0; ieof", 9, NULL);
					if (term_ptr.pos != -1 && (size_t)term_ptr.pos < chunk_size) {
						log_finest("Detected merged ieof terminator inside data chunk");
						chunk_size = term_ptr.pos; // Truncate the read to stop before the '0'
					}
				}

				size_t to_read = (avail < chunk_size) ? avail : chunk_size;
				
				/* Move data to new_body */
				unsigned char *data = evbuffer_pullup(input, to_read);
				evbuffer_add(new_body, data, to_read);
				evbuffer_drain(input, to_read);
				
				chunk_size -= to_read;
			}

			/* Read trailing "\r\n" after chunk data */
			line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
			if (line) free(line);
		}

		log_finest_va("Extracted %zu bytes of unchunked body", evbuffer_get_length(new_body));

		/* Swap into Golden body buffer */
		if (icap_ctx->body) {
			evbuffer_free(icap_ctx->body);
		}
		icap_ctx->body = new_body;
	}
	return 0;
}

static icap_response_state_t *
icap_get_read_state(struct bufferevent *bev, icap_ctx_t *icap_ctx)
{
	// TODO: Find a better way to associate the bev with the correct read state for parallel services
	icap_response_state_t *read_state = NULL;
	for (int i = 0; i < ICAP_MAX_PARALLEL; i++) {
		if (icap_ctx->parallel_bevs[i] == bev) {
			read_state = &icap_ctx->parallel_read_state[i];
			break;
		}
	}
	if (!read_state) {
		read_state = &icap_ctx->read_state;
	}
	return read_state;
}

/*
 * ICAP bufferevent read callback - handle RESPMOD response
 */
static void
icap_bev_readcb(struct bufferevent *bev, void *arg)
{
	icap_ctx_t *icap_ctx = (icap_ctx_t *)arg;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	icap_response_state_t *read_state = icap_get_read_state(bev, icap_ctx);

	struct evbuffer *input = bufferevent_get_input(bev);
	log_finest_va("ENTER for %s, read_state=%d, inbuf=%zu", icap_ctx->reqmod ? "REQMOD" : "RESPMOD", *read_state, evbuffer_get_length(input));

    /* 1. Header Phase */
    if (*read_state == ICAP_READ_STATE_WAIT_HEADERS || 
        *read_state == ICAP_READ_STATE_PREVIEW_RESPONSE) {
        
		/* Check for 100 Continue (Preview response) */
        if (*read_state == ICAP_READ_STATE_PREVIEW_RESPONSE) {
			log_finest_va("Check for 100 Continue in preview response for %s ", icap_ctx->reqmod ? "REQMOD" : "RESPMOD");

			/* Search for the status line specifically */
			struct evbuffer_ptr ptr = evbuffer_search(input, "ICAP/1.0 100", 12, NULL);
			
			if (ptr.pos != -1) {
				/* * Ensure the 100 Continue is fully received (ends in \r\n\r\n) 
				* before we drain it and move to the next state.
				*/
				struct evbuffer_ptr end_ptr = evbuffer_search(input, "\r\n\r\n", 4, &ptr);
				
				if (end_ptr.pos != -1) {
					log_finest("Found ICAP 100 Continue - Preview accepted, sending remainder");

					/* Drain the entire 100 Continue response (including trailing CRLFs) */
					evbuffer_drain(input, end_ptr.pos + 4);
					// evbuffer_drain(input, evbuffer_get_length(input));

					/* Send the remainder of the body */
					icap_send_remainder(icap_ctx, bev);
				}
				/* If end_ptr is -1, we found the '100' but are waiting on the end of headers */
				return; 
			}
        }
        
        /* Wait for full headers */
        struct evbuffer_ptr ptr = evbuffer_search(input, "\r\n\r\n", 4, NULL);
        if (ptr.pos == -1) {
			log_finest("Keep waiting for more data");
			return;
		}

        /* We found the end of headers. Parse the Encapsulated header. */
        char *headers = malloc(ptr.pos + 1);
        evbuffer_copyout(input, headers, ptr.pos);
        headers[ptr.pos] = '\0';

        /* Use a simple parser to find the body offset */
        char *enc_hdr = strcasestr(headers, "Encapsulated:");
        if (enc_hdr) {
            char *body_ptr = strcasestr(enc_hdr, "res-body=");
            if (!body_ptr) body_ptr = strcasestr(enc_hdr, "req-body=");

            if (body_ptr) {
                *read_state = ICAP_READ_STATE_WAIT_BODY;
            } else {
                /* null-body: no body expected, we are done */
                *read_state = ICAP_READ_STATE_PROCESSING;
            }
        }
        
        free(headers);
    }

    /* 2. Body Phase (Chunked Decoding) */
    if (*read_state == ICAP_READ_STATE_WAIT_BODY) {
		/* Search for the ICAP terminator 0\r\n\r\n */
        struct evbuffer_ptr term_ptr = evbuffer_search(input, "\r\n0\r\n\r\n", 7, NULL);
        // struct evbuffer_ptr term_ptr = evbuffer_search(input, "0\r\n\r\n", 5, NULL);

        /* If not found, we haven't received the end of the stream yet. */
        if (term_ptr.pos == -1) {
	        term_ptr = evbuffer_search(input, "\r\n0; ieof\r\n\r\n", 12, NULL);
	        // term_ptr = evbuffer_search(input, "0; ieof\r\n\r\n", 10, NULL);
	        if (term_ptr.pos == -1) return;
		}

		log_finest("Found ICAP terminator, full body received");
		/* Success! We have the full body. */
		*read_state = ICAP_READ_STATE_PROCESSING;
	}

    /* 3. Processing Phase */
    if (*read_state == ICAP_READ_STATE_PROCESSING) {
		/* Log first 200 bytes for debugging */
		size_t len = evbuffer_get_length(input);
		size_t log_len = len < 200 ? len : 200;
		char *log_buf = malloc(log_len + 1);
		if (log_buf) {
			evbuffer_copyout(input, log_buf, log_len);
			log_buf[log_len] = '\0';
			log_finest_va("ICAP response (first %zu bytes, orig %zu bytes): %s", log_len, len, log_buf);
			free(log_buf);
		}

		/* Look for ICAP response status line properly */
		char *status_line = evbuffer_readln(input, NULL, EVBUFFER_EOL_CRLF);
		if (!status_line) {
			log_finest("Incomplete headers");
			icap_disconnect(icap_ctx);
			return;
		}

		/* Check for response code */
		if (strstr(status_line, "ICAP/1.0 204")) {
			log_finest("ICAP 204 No Content - no modification needed, bypassing");
			icap_ctx->state = ICAP_STATE_DONE;
			icap_ctx->done = 1;
			icap_ctx->pending = 0;
			evbuffer_drain(input, evbuffer_get_length(input));
		} else if (strstr(status_line, "ICAP/1.0 200")) {
			log_finest("ICAP 200 OK - body modified, extracting...");
			if (icap_extract_200_ok(icap_ctx, input) < 0) {
				log_finest("ICAP failed to extract modified body");
				icap_ctx->state = ICAP_STATE_ERROR;
				evbuffer_drain(input, evbuffer_get_length(input));
			} else {
				icap_ctx->state = ICAP_STATE_DONE;
			}
		} else {
			log_finest_va("ICAP unexpected response: %s", status_line);
			icap_ctx->state = ICAP_STATE_ERROR;
			evbuffer_drain(input, evbuffer_get_length(input));
		}

		free(status_line);

		/* Move to the next service in the chain or resume connection */
		*read_state = ICAP_READ_STATE_WAIT_HEADERS;

		/* Chain Orchestration: End of Service Hand-off */
		if (!icap_ctx->current_service) {
			log_finest("ICAP complete, resuming flow");
			icap_disconnect(icap_ctx);
			return;
		}

		if (icap_ctx->state == ICAP_STATE_ERROR && icap_ctx->current_service->fail_mode == ICAP_FAIL_CLOSED) {
			log_finest_va("ICAP chain blocked by error on %s", icap_ctx->current_service->server);
			icap_disconnect(icap_ctx);
			return;
		}

		if (icap_ctx->current_service->type == ICAP_SERVICE_SERIAL_MODIFYING) {
			/* Apply changes if any (200 OK), then advance the chain */
			log_finest_va("Advance serial, parallel pending count=%d for %s", icap_ctx->parallel_pending_count, icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
			icap_ctx->current_service = icap_ctx->current_service->next;
			icap_process_chain(icap_ctx);
		} else if (icap_ctx->current_service->type == ICAP_SERVICE_PARALLEL_INSPECT) {
			icap_ctx->parallel_pending_count--;
			if (icap_ctx->parallel_pending_count <= 0) {
				log_finest_va("Advance parallel, parallel pending count=%d for %s", icap_ctx->parallel_pending_count, icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
				/* Skip to the first service AFTER the parallel block */
				icap_service_t *next_svc = icap_ctx->current_service;
				while (next_svc && next_svc->type == ICAP_SERVICE_PARALLEL_INSPECT) {
					next_svc = next_svc->next;
				}
				icap_ctx->current_service = next_svc;
				icap_process_chain(icap_ctx);
			}
			else {
				log_finest_va("Wait for pending parallel services, parallel pending count=%d for %s", icap_ctx->parallel_pending_count, icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
				icap_process_chain(icap_ctx);
			}
		}
	}
}

/*
 * ICAP bufferevent write callback - stub for now
 */
static void
icap_bev_writecb(UNUSED struct bufferevent *bev, UNUSED void *arg)
{
	icap_ctx_t *icap_ctx = (icap_ctx_t *)arg;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
	log_finest_va("ICAP write callback called for %s", icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
}

/*
 * Add standard X-headers to ICAP request
 */
static void
icap_add_standard_x_headers(pxy_conn_ctx_t *ctx, struct evbuffer *icap_buf)
{
	char x_hdr[256];
	
	/* X-Client-IP header */
	snprintf(x_hdr, sizeof(x_hdr), "X-Client-IP: %s\r\n", STRORNONE(ctx->srchost_str));
	evbuffer_add(icap_buf, x_hdr, strlen(x_hdr));
	
	/* X-Server-IP header */
	snprintf(x_hdr, sizeof(x_hdr), "X-Server-IP: %s\r\n", STRORNONE(ctx->dsthost_str));
	evbuffer_add(icap_buf, x_hdr, strlen(x_hdr));
	
#ifndef WITHOUT_USERAUTH
	/* X-Authenticated-User header if available */
	if (ctx->user) {
		snprintf(x_hdr, sizeof(x_hdr), "X-Authenticated-User: %s\r\n", ctx->user);
		evbuffer_add(icap_buf, x_hdr, strlen(x_hdr));
	}
#endif /* !WITHOUT_USERAUTH */
}

/*
 * Build and send ICAP request
 */
static int NONNULL(1,2,3)
icap_build_request(icap_ctx_t *icap_ctx, struct bufferevent *bev, icap_service_t *svc)
{
	pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	icap_response_state_t *read_state = icap_get_read_state(bev, icap_ctx);

	size_t body_len = evbuffer_get_length(icap_ctx->body);
	size_t hdr_len = evbuffer_get_length(icap_ctx->hdr);

	/* Calculate Encapsulated lengths */
	char *req_or_res = icap_ctx->reqmod ? "req" : "res";
	char encapsulated_hdr[128];

	if (ctx->spec->http) {
		snprintf(encapsulated_hdr, sizeof(encapsulated_hdr), "%s-hdr=0, %s-body=%zu",
			req_or_res, body_len > 0 ? req_or_res : "null", hdr_len);
	} else {
		/* Non-HTTP protocols: treat as pure body */
		snprintf(encapsulated_hdr, sizeof(encapsulated_hdr), "%s-body=0", req_or_res);
	}

	/* Use service-specific hostname, proxy hostname, or "localhost" if not set */
	const char *icap_host = svc->server ? svc->server : (icap_ctx->server ? icap_ctx->server : "localhost");

	/* 1. Send ICAP Header */
	char icap_hdr_str[2048];
	char preview_hdr[64] = "";
	
	/* Add Preview header if configured */
	if (icap_preview_enabled(icap_ctx) && body_len > icap_ctx->preview_size) {
		snprintf(preview_hdr, sizeof(preview_hdr), "Preview: %zu\r\n", icap_ctx->preview_size);
		log_finest_va("Adding Preview header: %zu bytes", icap_ctx->preview_size);
	}
	
	snprintf(icap_hdr_str, sizeof(icap_hdr_str),
		"%s icap://%s/echo ICAP/1.0\r\n"
		"Host: %s\r\n"
		"User-Agent: SSLproxy\r\n"
		"Allow: 204\r\n"
		"%s"
		"Encapsulated: %s\r\n",
		icap_ctx->reqmod ? "REQMOD" : "RESPMOD",
		icap_host, icap_host, preview_hdr, encapsulated_hdr
		);
	
	log_finest_va("Generated ICAP Header start: %s", icap_hdr_str);
	evbuffer_add(icap_ctx->icap_buf, icap_hdr_str, strlen(icap_hdr_str));

	/* Add standard X-headers */
	icap_add_standard_x_headers(ctx, icap_ctx->icap_buf);
	
	/* Add custom ICAP meta headers if any */
	if (ctx->icap_meta_header) {
		evbuffer_add(icap_ctx->icap_buf, ctx->icap_meta_header, strlen(ctx->icap_meta_header));
	}
	
	/* Final CRLF to end headers */
	evbuffer_add(icap_ctx->icap_buf, "\r\n", 2);

	if (bufferevent_write_buffer(bev, icap_ctx->icap_buf) < 0) {
		log_finest("Failed to send ICAP header");
		return -1;
	}

	/* 2. Send Headers (HTTP only) */
	if (ctx->spec->http && hdr_len > 0) {
		log_finest_va("Sending HTTP headers to ICAP server, hdr=%zu", hdr_len);
		// Copy from hdr buf without draining it
		// TODO: Avoid large contiguous allocation
		bufferevent_write(bev, evbuffer_pullup(icap_ctx->hdr, -1), hdr_len);
	}

	/* 3. Send Body (Chunked) */
	if (body_len > 0) {
		/* Format as chunked for ICAP */
		struct evbuffer *chunk_buf = evbuffer_new();
		if (chunk_buf) {
			size_t chunk_len = body_len;

			if (icap_preview_enabled(icap_ctx) && body_len > icap_ctx->preview_size) {
				*read_state = ICAP_READ_STATE_PREVIEW_RESPONSE;
				chunk_len = body_len < icap_ctx->preview_size ? body_len : icap_ctx->preview_size;
				log_finest_va("Sending body preview to ICAP server, body=%zu, preview=%zu", body_len, chunk_len);
			} else {
				log_finest_va("Sending body chunk to ICAP server, body=%zu", body_len);
			}

			evbuffer_add_printf(chunk_buf, "%zx\r\n", chunk_len);

			// TODO: Avoid large contiguous allocation
			evbuffer_add(chunk_buf, evbuffer_pullup(icap_ctx->body, chunk_len), chunk_len);

			evbuffer_add_printf(chunk_buf, "\r\n");
			evbuffer_add_printf(chunk_buf, "0\r\n\r\n");

			bufferevent_write_buffer(bev, chunk_buf);
			evbuffer_free(chunk_buf);
		}
	}

	return 0;
}

/*
 * ICAP bufferevent event callback
 */
static void
icap_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	icap_ctx_t *icap_ctx = (icap_ctx_t *)arg;
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
	icap_service_t *svc = NULL;

	if (bev == icap_ctx->bev) {
		svc = icap_ctx->current_service;
	} else {
		for (int i = 0; i < ICAP_MAX_PARALLEL; i++) {
			if (icap_ctx->parallel_bevs[i] == bev) {
				svc = icap_ctx->parallel_svcs[i];
				break;
			}
		}
	}

	if (!svc) {
		log_finest_va("ICAP event 0x%x on unknown bufferevent, svc=NULL", events);
		return;
	}

	log_finest_va("ICAP event 0x%x for %s on %s", events, icap_ctx->reqmod ? "REQMOD" : "RESPMOD", svc->server);

	if (events & BEV_EVENT_CONNECTED) {
		log_finest_va("ICAP connected to %s, sending %s request", svc->server, icap_ctx->reqmod ? "REQMOD" : "RESPMOD");

		if (icap_build_request(icap_ctx, bev, svc) < 0) {
			log_finest_va("ICAP failed to build and send %s request to %s", icap_ctx->reqmod ? "REQMOD" : "RESPMOD", svc->server);
			icap_disconnect(icap_ctx);
			icap_ctx->state = ICAP_STATE_ERROR;
			return;
		}

		icap_ctx->state = icap_ctx->reqmod ? ICAP_STATE_REQ_HDR : ICAP_STATE_RESPMOD_REQ; // Need standard states
		log_finest_va("ICAP %s request sent to %s", icap_ctx->reqmod ? "REQMOD" : "RESPMOD", svc->server);
		return;
	}

	if (events & BEV_EVENT_ERROR) {
		log_finest("ICAP connection error");
		icap_disconnect(icap_ctx);
		icap_ctx->state = ICAP_STATE_ERROR;
		return;
	}

	if (events & BEV_EVENT_EOF) {
		log_finest("ICAP connection closed");
		icap_disconnect(icap_ctx);
		icap_ctx->state = ICAP_STATE_ERROR;
		return;
	}

	if (events & BEV_EVENT_TIMEOUT) {
		log_finest("ICAP connection timeout");
		icap_disconnect(icap_ctx);
		icap_ctx->state = ICAP_STATE_ERROR;
		return;
	}
}

void 
icap_process_chain(icap_ctx_t *icap_ctx)
{
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;

	/* Check for Veto: abort chain immediately if a previous service blocked the content */
	if (icap_ctx->is_veto) {
		log_finest("ICAP Veto detected in chain, aborting remaining services");
		icap_disconnect(icap_ctx);
		return;
	}

	if (!icap_ctx->current_service) {
		log_finest("End of chain reached");

		if (icap_disconnect(icap_ctx) == 1) {
			struct evbuffer *inbuf = bufferevent_get_input(icap_ctx->conn_bev);
			log_finest_va("Process pending data in inbuf=%zu, do not advance chain", evbuffer_get_length(inbuf));
			struct evbuffer *outbuf = bufferevent_get_output(icap_ctx->conn_bev == ctx->src.bev  ? ctx->dst.bev : ctx->src.bev);
			icap_process_data(inbuf, outbuf, ctx, icap_ctx, icap_ctx->reqmod);
		}
		return;
	}

	icap_service_t *svc = icap_ctx->current_service;

	if (svc->type == ICAP_SERVICE_SERIAL_MODIFYING) {
		log_finest_va("Triggering SERIAL_MODIFYING on %s", svc->server);

		if (icap_service_connect(icap_ctx, svc, -1) < 0) {
			if (svc->fail_mode == ICAP_FAIL_CLOSED) {
				log_finest("Connection blocked by fail_mode setting.");
				icap_disconnect(icap_ctx);
			} else {
				log_finest("Connection failed, bypassing item");
				icap_ctx->current_service = svc->next;
				icap_process_chain(icap_ctx);
			}
		}
	}
	else if (svc->type == ICAP_SERVICE_PARALLEL_INSPECT) {
		log_finest("Starting PARALLEL_INSPECT block");
		icap_ctx->parallel_pending_count = 0;

		/* Scan forward and trigger all contiguous parallel services */
		while (svc && svc->type == ICAP_SERVICE_PARALLEL_INSPECT && icap_ctx->parallel_idx < ICAP_MAX_PARALLEL) {
			log_finest_va("Dispatching parallel request to %s", svc->server);
			if (icap_service_connect(icap_ctx, svc, icap_ctx->parallel_idx) == 0) {
				icap_ctx->parallel_pending_count++;
				icap_ctx->parallel_idx++;
			} else if (svc->fail_mode == ICAP_FAIL_CLOSED) {
				log_finest("Parallel connection failed, halting sequence");
				icap_disconnect(icap_ctx);
				return;
			}
			svc = svc->next;
		}

		/* If we successfully fired them off, wait. If none succeeded and were bypassed, move on. */
		log_finest_va("Dispatched parallel block, parallel_pending_count=%d, parallel_idx=%d", icap_ctx->parallel_pending_count, icap_ctx->parallel_idx);
		if (icap_ctx->parallel_pending_count == 0 && icap_ctx->parallel_idx < ICAP_MAX_PARALLEL) {
			icap_ctx->current_service = svc;
			icap_process_chain(icap_ctx);
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

/*
 * Trigger ICAP processing
 * ATTENTION: We have to pass reqmod too, because icap_ctx is initialized inside this function
 */
static void NONNULL(1,2)
icap_trigger(pxy_conn_ctx_t *ctx, icap_ctx_t *icap_ctx, int reqmod)
{
	icap_ctx->reqmod = reqmod;

	log_finest_va("ENTER, %s", icap_ctx->reqmod ? "REQMOD" : "RESPMOD");

	if (!icap_enabled(ctx)) {
		log_finest("ICAP not enabled");
		return;
	}

	/* Check if already pending ICAP processing */
	if (icap_ctx->pending) {
		log_finest("ICAP already pending");
		return;
	}

	/* Mark that we're waiting for ICAP response */
	icap_ctx->pending = 1;

	icap_ctx->conn_ctx = ctx;
	icap_ctx->conn_bev = icap_ctx->reqmod ? ctx->src.bev : ctx->dst.bev;

	/* Pause reading from src or dst: disable read callback temporarily */
	// TODO: Should we disable the current conn_bev only?
	bufferevent_disable(icap_ctx->conn_bev, EV_READ);
	// bufferevent_disable(ctx->src.bev, EV_READ);
	// bufferevent_disable(ctx->dst.bev, EV_READ);

	/* Connect to ICAP server if not connected */
	if (icap_connect(icap_ctx) == -1) {
		log_finest("ICAP connect failed, continuing without ICAP");
		/* On error, decide based on fail_open setting */
		if (!icap_ctx->fail_open) {
			ctx->term = 1;
		}
	}

	log_finest_va("ICAP %s triggered for response", icap_ctx->reqmod ? "REQMOD" : "RESPMOD");
}

/*
 * Send remaining body data after 100 Continue response
 */
static void
icap_send_remainder(icap_ctx_t *icap_ctx, struct bufferevent *bev)
{
	UNUSED pxy_conn_ctx_t *ctx = icap_ctx->conn_ctx;
	
	icap_response_state_t *read_state = icap_get_read_state(bev, icap_ctx);

	UNUSED struct evbuffer *input = bufferevent_get_input(bev);
	size_t body_len = evbuffer_get_length(icap_ctx->body);

	log_finest_va("ENTER for %s, body_len=%zu, inbuf=%zu", icap_ctx->reqmod ? "REQMOD" : "RESPMOD", body_len, evbuffer_get_length(input));

	if (body_len == 0) {
		log_finest("No remainder body to send");
		return;
	}
	
	log_finest_va("Sending remainder body to ICAP server, body=%zu", body_len);
	
	/* Send the rest of the body as chunked */
	struct evbuffer *chunk_buf = evbuffer_new();
	if (chunk_buf) {
		evbuffer_add_printf(chunk_buf, "%zx\r\n", body_len);
		
		struct evbuffer_ptr pos;
		size_t remainder_len = body_len - icap_ctx->preview_size;

		// 1. Initialize the pointer to the start
		// 2. Advance it to the preview_size offset
		if (evbuffer_ptr_set(icap_ctx->body, &pos, icap_ctx->preview_size, EVBUFFER_PTR_SET) < 0) {
			log_finest("Failed to set buffer pointer for ICAP remainder");
			return;
		}

		char *remainder_buf = malloc(remainder_len + 1);
		if (!remainder_buf) {
			log_finest("Failed to allocate memory for ICAP remainder buffer");
			return;
		}

		// 3. Copy out starting from that position
		evbuffer_copyout_from(icap_ctx->body, &pos, remainder_buf, remainder_len);
		evbuffer_add(chunk_buf, remainder_buf, remainder_len);
		free(remainder_buf);


		evbuffer_add_printf(chunk_buf, "\r\n");
		// evbuffer_add_printf(chunk_buf, "0\r\n\r\n");
		evbuffer_add_printf(chunk_buf, "0; ieof\r\n\r\n");
		
		bufferevent_write_buffer(bev, chunk_buf);
		evbuffer_free(chunk_buf);
	}
	
	*read_state = ICAP_READ_STATE_WAIT_BODY;
}

static void NONNULL(1,2,3,4)
icap_process_done(struct evbuffer *inbuf, struct evbuffer *outbuf, pxy_conn_ctx_t *ctx, icap_ctx_t *icap_ctx, UNUSED int reqmod)
{
	log_finest_va("%s data ICAP done=%d, inbuf=%zu, outbuf=%zu, hdr=%zu, body=%zu, is_veto=%d",
		reqmod ? "REQMOD" : "RESPMOD", icap_ctx->done,
		evbuffer_get_length(inbuf), evbuffer_get_length(outbuf),
		evbuffer_get_length(icap_ctx->hdr), evbuffer_get_length(icap_ctx->body),
		icap_ctx->is_veto);

	if (icap_ctx->is_veto) {
		log_finest("Content vetoed by ICAP service");

		// ATTENTION: Do NOT reset is_veto here - it must remain set until context is freed
		evbuffer_drain(inbuf, -1);
		evbuffer_drain(outbuf, -1);

		evbuffer_drain(icap_ctx->hdr, -1);
		icap_ctx->sent_hdr = 0;
		evbuffer_drain(icap_ctx->body, -1);

		if (icap_ctx->veto_page) {
			log_finest("Sending veto page to client");

			// Send block page to src (client), not dst (server)
			if (ctx->src.bev) {
				// TODO: Avoid large contiguous allocation
				evbuffer_add(bufferevent_get_output(ctx->src.bev), evbuffer_pullup(icap_ctx->veto_page, -1), evbuffer_get_length(icap_ctx->veto_page));
			}
			else {
				log_finest("Src connection already closed, cannot send veto page");
			}
		}
	}
	else {
		// Send the data in golden buffers to their destination
		if (ctx->spec->http && !icap_ctx->sent_hdr) {
			log_finest("Send hdr to destination, only once, not with subsequent body chunks");
			evbuffer_add_buffer(outbuf, icap_ctx->hdr);
			icap_ctx->sent_hdr = 1;
		}

		log_finest("Send body to destination, and reset ICAP state for next chunk");
		evbuffer_add_buffer(outbuf, icap_ctx->body);
	}

	icap_ctx->done = 0;
	icap_ctx->pending = 0;
	icap_ctx->state = ICAP_STATE_IDLE;
}

static int NONNULL(1)
icap_max_body_size_enabled(icap_ctx_t *icap_ctx)
{
	return icap_ctx->max_body_size > 0;
}

void NONNULL(1,2,3,4)
icap_process_data(struct evbuffer *inbuf, UNUSED struct evbuffer *outbuf, pxy_conn_ctx_t *ctx, icap_ctx_t *icap_ctx, int reqmod)
{
	log_finest_va("%s data ICAP done=%d, inbuf=%zu, outbuf=%zu, hdr=%zu, body=%zu, is_veto=%d",
		reqmod ? "REQMOD" : "RESPMOD", icap_ctx->done,
		evbuffer_get_length(inbuf), evbuffer_get_length(outbuf),
		evbuffer_get_length(icap_ctx->hdr), evbuffer_get_length(icap_ctx->body),
		icap_ctx->is_veto);

	if (evbuffer_get_length(inbuf) > 0 || evbuffer_get_length(icap_ctx->hdr) > 0) {
		log_finest("Trigger ICAP and read data from inbuf");
		icap_trigger(ctx, icap_ctx, reqmod);

		// Check body size limit before moving data into golden body buffer for ICAP processing
		size_t body_len = evbuffer_get_length(icap_ctx->body) + evbuffer_get_length(inbuf);

		if (icap_max_body_size_enabled(icap_ctx) && body_len > icap_ctx->max_body_size) {
			// Move max_body_size data from inbuf into golden body buffer for ICAP processing
			evbuffer_remove_buffer(inbuf, icap_ctx->body, icap_ctx->max_body_size);
			log_finest_va("Body size %zu exceeded max %zu, moved max bytes only, inbuf=%zu", body_len, icap_ctx->max_body_size, evbuffer_get_length(inbuf));
		}
		else if (evbuffer_get_length(inbuf) > 0 || evbuffer_get_length(icap_ctx->hdr) > 0) {
			// Move all data from inbuf into golden body buffer for ICAP processing
			// The hdr buffer is filled by protocol layer, if any (e.g. HTTP headers)
			evbuffer_add_buffer(icap_ctx->body, inbuf);
			log_finest_va("Body size %zu within max %zu, moved all bytes, inbuf=%zu", body_len, icap_ctx->max_body_size, evbuffer_get_length(inbuf));
		}
		else {
			log_finest("No new body data to move, but still trigger ICAP for header-only processing");
		}
	}
	else {
		log_finest("No data to trigger ICAP");
	}
}
#endif /* !WITHOUT_ICAP */

typedef int dummy_declaration_to_avoid_empty_translation_unit;

/* vim: set noet ft=c: */
