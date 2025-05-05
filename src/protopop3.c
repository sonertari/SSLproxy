/*-
 * SSLproxy - transparent SSL/TLS proxy
 *
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

#include "protopop3.h"
#include "protossl.h"
#include "util.h"

#include <string.h>

// Size = 14
static char *protopop3_commands[] = { "CAPA", "USER", "PASS", "AUTH", "APOP", "STLS", "LIST", "STAT", "UIDL", "RETR", "DELE", "RSET", "TOP", "QUIT", "NOOP" };

static int NONNULL(1)
protopop3_validate_command(char *packet, size_t packet_size
#ifdef DEBUG_PROXY
	, pxy_conn_ctx_t *ctx
#endif /* DEBUG_PROXY */
	)
{
	size_t command_len = util_get_first_word_len(packet, packet_size);

	unsigned int i;
	for (i = 0; i < sizeof(protopop3_commands)/sizeof(char *); i++) {
		char *c = protopop3_commands[i];
		// We need case-insensitive comparison, and here it is safe to call strncasecmp()
		// with a non-string param packet, as we call it only if the lengths are the same
		if (strlen(c) == command_len && !strncasecmp(packet, c, command_len)) {
			log_finest_va("Passed command validation: %.*s", (int)packet_size, packet);
			return 0;
		}
	}
	return -1;
}

int
protopop3_validate(pxy_conn_ctx_t *ctx, char *packet, size_t packet_size)
{
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;

	if (pop3_ctx->not_valid) {
		log_finest("Not pop3, validation failed previously");
		return -1;
	}
	if (protopop3_validate_command(packet, packet_size
#ifdef DEBUG_PROXY
			, ctx
#endif /* DEBUG_PROXY */
			) == -1) {
		pop3_ctx->not_valid = 1;
		log_finest_va("Failed command validation: %.*s", (int)packet_size, packet);
		return -1;
	} else {
		pop3_ctx->seen_command_count++;
	}
	if (pop3_ctx->seen_command_count > 2) {
		ctx->protoctx->is_valid = 1;
		log_finest("Passed validation");
	}
	return 0;
}

static void NONNULL(1)
protopop3_free(pxy_conn_ctx_t *ctx)
{
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;
	free(pop3_ctx);
}

// @attention Called by thrmgr thread
protocol_t
protopop3_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_POP3;

	ctx->protoctx->proto_free = protopop3_free;
	ctx->protoctx->validatecb = protopop3_validate;

	ctx->protoctx->arg = malloc(sizeof(protopop3_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protopop3_ctx_t));

	return PROTO_POP3;
}

static void NONNULL(1)
protopop3s_free(pxy_conn_ctx_t *ctx)
{
	protopop3_free(ctx);
	protossl_free(ctx);
}

// @attention Called by thrmgr thread
protocol_t
protopop3s_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_POP3S;

	ctx->protoctx->connectcb = protossl_conn_connect;
	ctx->protoctx->init_conn = protossl_init_conn;
	
	ctx->protoctx->bev_eventcb = protossl_bev_eventcb;

	ctx->protoctx->proto_free = protopop3s_free;
	ctx->protoctx->validatecb = protopop3_validate;

	ctx->protoctx->arg = malloc(sizeof(protopop3_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protopop3_ctx_t));

	ctx->sslctx = malloc(sizeof(ssl_ctx_t));
	if (!ctx->sslctx) {
		free(ctx->protoctx->arg);
		return PROTO_ERROR;
	}
	memset(ctx->sslctx, 0, sizeof(ssl_ctx_t));

	return PROTO_POP3S;
}

/* vim: set noet ft=c: */
