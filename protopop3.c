/*-
 * SSLproxy - transparent SSL/TLS proxy
 *
 * Copyright (c) 2018-2019, Soner Tari <sonertari@gmail.com>.
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

#include <string.h>

typedef struct protopop3_ctx protopop3_ctx_t;

struct protopop3_ctx {
	unsigned int not_valid : 1;
	unsigned int seen_command_count;
};

// Size = 14
static char *protopop3_commands[] = { "CAPA", "USER", "PASS", "AUTH", "APOP", "STLS", "LIST", "STAT", "UIDL", "RETR", "DELE", "RSET", "TOP", "QUIT", "NOOP" };

static int NONNULL(1)
protopop3_validate_command(char *packet, UNUSED size_t packet_size)
{
	char *c;
	unsigned int i;
	for (i = 0; i < sizeof(protopop3_commands)/sizeof(char *); i++) {
		c = protopop3_commands[i];
		if (!strncasecmp(packet, c, strlen(c))) {
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopop3_validate_command: Passed command validation: %.*s\n", (int)packet_size, packet);
#endif /* DEBUG_PROXY */
			return 0;
		}
	}
	return -1;
}

static int NONNULL(1,2)
protopop3_validate(pxy_conn_ctx_t *ctx, char *packet, size_t packet_size)
{
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;

	if (pop3_ctx->not_valid) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopop3_validate: Not pop3\n");
#endif /* DEBUG_PROXY */
		return -1;
	}
	if (protopop3_validate_command(packet, packet_size) == -1) {
		pop3_ctx->not_valid = 1;
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopop3_validate: Failed command validation: %.*s\n", (int)packet_size, packet);
#endif /* DEBUG_PROXY */
		return -1;
	} else {
		pop3_ctx->seen_command_count++;
	}
	if (pop3_ctx->seen_command_count > 2) {
		ctx->protoctx->is_valid = 1;
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protopop3_validate: Passed validation\n");
#endif /* DEBUG_PROXY */
	}
	return 0;
}

protocol_t
protopop3_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_POP3;

	ctx->protoctx->validatecb = protopop3_validate;

	ctx->protoctx->arg = malloc(sizeof(protopop3_ctx_t));
	if (!ctx->protoctx->arg) {
		return PROTO_ERROR;
	}
	memset(ctx->protoctx->arg, 0, sizeof(protopop3_ctx_t));

	return PROTO_POP3;
}

protocol_t
protopop3s_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_POP3S;

	ctx->protoctx->connectcb = protossl_conn_connect;
	ctx->protoctx->fd_readcb = protossl_fd_readcb;
	
	ctx->protoctx->bev_eventcb = protossl_bev_eventcb;

	ctx->protoctx->proto_free = protossl_free;
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
