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
		log_finest("Not smtp");
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

protocol_t
protosmtp_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_SMTP;

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

	ctx->protoctx->connectcb = protossl_conn_connect;
	ctx->protoctx->fd_readcb = protossl_fd_readcb;
	
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
