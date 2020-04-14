/*-
 * SSLproxy - transparent SSL/TLS proxy
 *
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

#include "protosmtp.h"
#include "prototcp.h"
#include "protossl.h"

#include <string.h>

typedef struct protosmtp_ctx protosmtp_ctx_t;

struct protosmtp_ctx {
	unsigned int not_valid : 1;
	unsigned int seen_command_count;
};

// Size = 25
static char *protosmtp_commands[] = { "EHLO", "HELO", "AUTH", "MAIL", "MAIL FROM", "RCPT", "RCPT TO", "DATA", "SEND", "RSET", "QUIT", "ATRN", "ETRN", "TURN",
	"SAML", "SOML", "EXPN", "NOOP", "HELP", "ONEX", "BDAT", "BURL", "SUBMITTER", "VERB", "VRFY" };

static int NONNULL(1)
protosmtp_validate_command(char *packet
#ifdef DEBUG_PROXY
	, size_t packet_size, pxy_conn_ctx_t *ctx
#endif /* DEBUG_PROXY */
	)
{
	char *c;
	unsigned int i;
	for (i = 0; i < sizeof(protosmtp_commands)/sizeof(char *); i++) {
		c = protosmtp_commands[i];
		if (!strncasecmp(packet, c, strlen(c))) {
			log_finest_va("Passed command validation: %.*s", (int)packet_size, packet);
			return 0;
		}
	}
	return -1;
}

static int NONNULL(1,2)
protosmtp_validate(pxy_conn_ctx_t *ctx, char *packet
#ifdef DEBUG_PROXY
	, size_t packet_size
#endif /* DEBUG_PROXY */
	)
{
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	if (smtp_ctx->not_valid) {
		log_finest("Not smtp, validation failed previously");
		return -1;
	}
	if (protosmtp_validate_command(packet
#ifdef DEBUG_PROXY
			, packet_size, ctx
#endif /* DEBUG_PROXY */
			) == -1) {
		smtp_ctx->not_valid = 1;
		log_finest_va("Failed command validation: %.*s", (int)packet_size, packet);
		return -1;
	} else {
		smtp_ctx->seen_command_count++;
	}
	if (smtp_ctx->seen_command_count > 2) {
		ctx->protoctx->is_valid = 1;
		log_finest("Passed validation");
	}
	return 0;
}

static int NONNULL(1,2)
protosmtp_validate_response(pxy_conn_ctx_t *ctx, char *packet
#ifdef DEBUG_PROXY
	, size_t packet_size
#endif /* DEBUG_PROXY */
	)
{
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	if (smtp_ctx->not_valid) {
		log_finest("Not smtp, validation failed previously");
		return -1;
	}

	char response[4];
	memcpy(response, packet, 3);
	response[3] = '\0';

	unsigned int i = atoi(response);
	if (i >= 200 && i < 600) {
		// Don't set is_valid flag here, it should be set on the client side
		//ctx->protoctx->is_valid = 1;
		log_finest_va("Passed response validation: %.*s", (int)packet_size, packet);
		return 0;
	}

	smtp_ctx->not_valid = 1;
	log_finest_va("Failed response validation: %.*s", (int)packet_size, packet);
	return -1;
}

static int NONNULL(1,2,3,4)
protosmtp_try_validate_response(struct bufferevent *bev, pxy_conn_ctx_t *ctx, struct evbuffer *inbuf, struct evbuffer *outbuf)
{
	if (ctx->spec->opts->validate_proto) {
		size_t packet_size = evbuffer_get_length(inbuf);
		char *packet = (char *)pxy_malloc_packet(packet_size, ctx);
		if (!packet) {
			return -1;
		}
		if (evbuffer_copyout(inbuf, packet, packet_size) == -1) {
			free(packet);
			return -1;
		}
		if (protosmtp_validate_response(ctx, packet
#ifdef DEBUG_PROXY
				, packet_size
#endif /* DEBUG_PROXY */
				) == -1) {
			// Send message to the client: outbuf of src
			evbuffer_add(outbuf, PROTOERROR_MSG, PROTOERROR_MSG_LEN);
			ctx->sent_protoerror_msg = 1;
			// Discard packets from the client: inbuf of src
			pxy_discard_inbuf(ctx->src.bev);
			// Discard packets to the server: outbuf of srvdst
			evbuffer_drain(bufferevent_get_output(bev), evbuffer_get_length(bufferevent_get_output(bev)));
			free(packet);
			return -1;
		}
		free(packet);
	}
	return 0;
}

static void NONNULL(1)
protosmtp_conn_connect_common(pxy_conn_ctx_t *ctx)
{
	// Conn setup is successful, so add the conn to the conn list of its thread now
	pxy_thrmgr_add_conn(ctx);

	// We enable readcb for srvdst to relay the 220 smtp greeting from the server to the client, otherwise the conn stalls
	bufferevent_setcb(ctx->srvdst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->srvdst.bev, EV_READ|EV_WRITE);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srvdst.bev, (struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "protosmtp_conn_connect: bufferevent_socket_connect for srvdst failed\n");
		log_fine("bufferevent_socket_connect for srvdst failed");
		// @attention Do not try to term/close conns or do anything else with conn ctx on the thrmgr thread after setting event callbacks and/or socket connect.
	}
}

static int NONNULL(1) WUNRES
protosmtp_conn_connect(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	/* create server-side socket and eventbuffer */
	if (prototcp_setup_srvdst(ctx) == -1) {
		return -1;
	}
	protosmtp_conn_connect_common(ctx);
	return 0;
}

static int NONNULL(1) WUNRES
protosmtps_conn_connect(pxy_conn_ctx_t *ctx)
{
	log_finest("ENTER");

	/* create server-side socket and eventbuffer */
	if (protossl_setup_srvdst(ctx) == -1) {
		return -1;
	}
	protosmtp_conn_connect_common(ctx);
	return 0;
}

static void NONNULL(1)
protosmtp_bev_readcb_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	log_finest_va("ENTER, size=%zu", evbuffer_get_length(bufferevent_get_input(bev)));

	// Make sure src.bev exists
	if (!ctx->src.bev) {
		log_finest("src.bev does not exist");
		return;
	}

	if (prototcp_try_send_userauth_msg(ctx->src.bev, ctx)) {
		return;
	}

	struct evbuffer *inbuf = bufferevent_get_input(bev);
	struct evbuffer *outbuf = bufferevent_get_output(ctx->src.bev);

	// We should validate the response from the smtp server to protect the client,
	// because here we directly relay the packets from the server to the client
	// until we receive the first packet from the client,
	// at which time we xfer srvdst to the first child conn and effectively disable this readcb,
	// hence start diverting packets to the listening program
	if (protosmtp_try_validate_response(bev, ctx, inbuf, outbuf) != 0) {
		return;
	}

	if (ctx->src.closed) {
		pxy_discard_inbuf(bev);
		return;
	}

	evbuffer_add_buffer(outbuf, inbuf);
	pxy_try_set_watermark(bev, ctx, ctx->src.bev);
}

static void NONNULL(1)
protosmtp_bev_readcb(struct bufferevent *bev, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (bev == ctx->src.bev) {
		prototcp_bev_readcb_src(bev, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_readcb_dst(bev, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protosmtp_bev_readcb_srvdst(bev, ctx);
	} else {
		log_err_printf("protosmtp_bev_readcb: UNKWN conn end\n");
	}
}

protocol_t
protosmtp_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_SMTP;

	ctx->protoctx->connectcb = protosmtp_conn_connect;

	ctx->protoctx->bev_readcb = protosmtp_bev_readcb;

	ctx->protoctx->validatecb = protosmtp_validate;

	ctx->protoctx->arg = malloc(sizeof(protosmtp_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protosmtp_ctx_t));

	return PROTO_SMTP;
}

protocol_t
protosmtps_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_SMTPS;

	ctx->protoctx->connectcb = protosmtps_conn_connect;
	ctx->protoctx->fd_readcb = protossl_fd_readcb;
	
	ctx->protoctx->bev_readcb = protosmtp_bev_readcb;
	ctx->protoctx->bev_eventcb = protossl_bev_eventcb;

	ctx->protoctx->proto_free = protossl_free;
	ctx->protoctx->validatecb = protosmtp_validate;

	ctx->protoctx->arg = malloc(sizeof(protosmtp_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protosmtp_ctx_t));

	ctx->sslctx = malloc(sizeof(ssl_ctx_t));
	if (!ctx->sslctx) {
		free(ctx->protoctx->arg);
		return PROTO_ERROR;
	}
	memset(ctx->sslctx, 0, sizeof(ssl_ctx_t));

	return PROTO_SMTPS;
}

/* vim: set noet ft=c: */
