/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2017-2022, Soner Tari <sonertari@gmail.com>.
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
#include "protopop3.h"
#include "protosmtp.h"

#include <check.h>

static void
proto_free(pxy_conn_ctx_t *ctx)
{
	global_t *global = ctx->global;
	pxy_thrmgr_ctx_t *thrmgr = ctx->thrmgr;
	proxyspec_t *spec = ctx->spec;

	pxy_conn_ctx_free(ctx, 1);
	proxyspec_free(spec);
	pxy_thrmgr_free(thrmgr);
	global_free(global);
}

/*
 * We need to initialize further than just calling the *_new() functions,
 * because the *_free() functions called in proto_free() depend on those extra
 * initialization.
 */
static pxy_conn_ctx_t *
proto_init(protocol_t proto)
{
	global_t *global = global_new();

	pxy_thrmgr_ctx_t *thrmgr = pxy_thrmgr_new(global);
	thrmgr->num_thr = 1;
	thrmgr->thr = malloc(thrmgr->num_thr * sizeof(pxy_thr_ctx_t*));
	memset(thrmgr->thr, 0, thrmgr->num_thr * sizeof(pxy_thr_ctx_t*));
	thrmgr->thr[0] = malloc(sizeof(pxy_thr_ctx_t));
	memset(thrmgr->thr[0], 0, sizeof(pxy_thr_ctx_t));

	proxyspec_t *spec = proxyspec_new(global, "sslproxy", NULL);
	if (proto == PROTO_HTTP) {
		spec->http = 1;
	} else if (proto == PROTO_POP3) {
		spec->pop3 = 1;
	} else if (proto == PROTO_SMTP) {
		spec->smtp = 1;
	}

	pxy_conn_ctx_t *ctx = proxy_conn_ctx_new(0, thrmgr, spec, global
#ifndef WITHOUT_USERAUTH
			, 0
#endif /* !WITHOUT_USERAUTH */
			);
	pxy_thrmgr_assign_thr(ctx);
	pxy_thr_attach(ctx);

	return ctx;
}

START_TEST(protohttp_validate_01)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->seen_keyword_count = 1;
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_02)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->seen_keyword_count = 1;
	http_ctx->http_method = strdup("GET");
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_03)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->http_method = strdup("GET");
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 0, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_04)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->http_method = strdup("GET1");
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 0, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_05)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->seen_keyword_count = 1;
	http_ctx->http_method = strdup("GET1");
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	rv = protohttp_validate(ctx);

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	free(http_ctx->http_method);
	http_ctx->http_method = strdup("GET");
	rv = protohttp_validate(ctx);

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_06)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->seen_keyword_count = 1;
	http_ctx->http_method = strdup("GET");
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	rv = protohttp_validate(ctx);

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	// Normally we don't call protohttp_validate() if ctx->protoctx->is_valid is set,
	// So both not_valid and is_valid are set.
	// This is for testing purposes only.
	free(http_ctx->http_method);
	http_ctx->http_method = strdup("GET1");
	rv = protohttp_validate(ctx);

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 0, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_07)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->seen_bytes = 8193;
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 0, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 8193, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_08)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->seen_bytes = 8193;
	http_ctx->seen_keyword_count = 1;
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 8193, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_09)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->seen_bytes = 8193;
	http_ctx->http_method = strdup("GET");
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 0, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 8193, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protohttp_validate_10)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_HTTP);
	protohttp_ctx_t *http_ctx = ctx->protoctx->arg;

	http_ctx->seen_bytes = 8193;
	http_ctx->seen_keyword_count = 1;
	http_ctx->http_method = strdup("GET");
	int rv = protohttp_validate(ctx);

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(http_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(http_ctx->seen_keyword_count == 1, "wrong seen_keyword_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");
	ck_assert_msg(http_ctx->seen_bytes == 8193, "wrong seen_bytes");

	proto_free(ctx);
}
END_TEST

START_TEST(protopop3_validate_01)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_POP3);
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;

	char array01[] = {'C', 'A', 'P', 'A'};
	int rv = protopop3_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array02[] = {'U', 'S', 'E', 'R', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protopop3_validate(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 2, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array03[] = {'P', 'A', 'S', 'S', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protopop3_validate(ctx, array03, sizeof(array03));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 3, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	// Normally we don't call protopop3_validate() if ctx->protoctx->is_valid is set,
	// so pop3_ctx->seen_command_count never goes above 3.
	// This is for testing purposes only.
	char array04[] = {'Q', 'U', 'I', 'T'};
	rv = protopop3_validate(ctx, array04, sizeof(array04));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 4, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protopop3_validate_02)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_POP3);
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;

	char array01[] = {'C', 'A', 'P'};
	int rv = protopop3_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protopop3_validate_03)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_POP3);
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;

	char array01[] = {'C', 'A', 'P', 'A'};
	int rv = protopop3_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array02[] = {'U', 'S', 'E', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protopop3_validate(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protopop3_validate_04)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_POP3);
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;

	char array01[] = {'C', 'A', 'P', 'A'};
	int rv = protopop3_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array02[] = {'U', 'S', 'E', 'R', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protopop3_validate(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 2, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array03[] = {'P', 'A', 'S', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protopop3_validate(ctx, array03, sizeof(array03));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 2, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protopop3_validate_05)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_POP3);
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;

	char array01[] = {'C', 'A', 'P', 'A'};
	int rv = protopop3_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array02[] = {'U', 'S', 'E', 'R', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protopop3_validate(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 2, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array03[] = {'P', 'A', 'S', 'S', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protopop3_validate(ctx, array03, sizeof(array03));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 3, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	// Normally we don't call protopop3_validate() if ctx->protoctx->is_valid is set,
	// So both not_valid and is_valid are set.
	// This is for testing purposes only.
	char array04[] = {'Q', 'U', 'I'};
	rv = protopop3_validate(ctx, array04, sizeof(array04));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 3, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	// Again, this is for testing purposes only.
	rv = protopop3_validate(ctx, array04, sizeof(array04));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 3, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protopop3_validate_06)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_POP3);
	protopop3_ctx_t *pop3_ctx = ctx->protoctx->arg;

	char array01[] = {'C', 'A', 'P'};
	int rv = protopop3_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	rv = protopop3_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(pop3_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(pop3_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_01)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'E', 'H', 'L', 'O'};
	int rv = protosmtp_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array02[] = {'A', 'U', 'T', 'H', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protosmtp_validate(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 2, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array03[] = {'M', 'A', 'I', 'L', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protosmtp_validate(ctx, array03, sizeof(array03));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 3, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	// Normally we don't call protosmtp_validate() if ctx->protoctx->is_valid is set,
	// so smtp_ctx->seen_command_count never goes above 3.
	// This is for testing purposes only.
	char array04[] = {'Q', 'U', 'I', 'T'};
	rv = protosmtp_validate(ctx, array04, sizeof(array04));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 4, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_02)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'E', 'H', 'L'};
	int rv = protosmtp_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_03)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'E', 'H', 'L', 'O'};
	int rv = protosmtp_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array02[] = {'A', 'U', 'T', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protosmtp_validate(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_04)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'E', 'H', 'L', 'O'};
	int rv = protosmtp_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array02[] = {'A', 'U', 'T', 'H', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protosmtp_validate(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 2, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array03[] = {'M', 'A', 'I', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protosmtp_validate(ctx, array03, sizeof(array03));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 2, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_05)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'E', 'H', 'L', 'O'};
	int rv = protosmtp_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 1, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array02[] = {'A', 'U', 'T', 'H', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protosmtp_validate(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 2, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	char array03[] = {'M', 'A', 'I', 'L', ' ', 's', 'o', 'n', 'e', 'r'};
	rv = protosmtp_validate(ctx, array03, sizeof(array03));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 3, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	// Normally we don't call protosmtp_validate() if ctx->protoctx->is_valid is set,
	// So both not_valid and is_valid are set.
	// This is for testing purposes only.
	char array04[] = {'Q', 'U', 'I'};
	rv = protosmtp_validate(ctx, array04, sizeof(array04));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 3, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	// Again, this is for testing purposes only.
	rv = protosmtp_validate(ctx, array04, sizeof(array04));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 3, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 1, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_06)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'E', 'H', 'L'};
	int rv = protosmtp_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	rv = protosmtp_validate(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_response_01)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'2', '2', '0', ' ', 's', 'm', 't', 'p'};
	int rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_response_02)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'1', '9', '9', ' ', 's', 'm', 't', 'p'};
	int rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_response_03)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'6', '0', '0', ' ', 's', 'm', 't', 'p'};
	int rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_response_04)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'2', '2', '0', ' ', 's', 'm', 't', 'p'};
	int rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	// Normally we don't call protosmtp_validate_response() more than once.
	// This is for testing purposes only.
	ck_assert_msg(rv == 0, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 0, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	// Normally we don't call protosmtp_validate_response() more than once,
	// but smtp_ctx->not_valid should be set to 1.
	// This is for testing purposes only.
	char array02[] = {'1', '9', '9', ' ', 's', 'm', 't', 'p'};
	rv = protosmtp_validate_response(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_response_05)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'1', '9', '9', ' ', 's', 'm', 't', 'p'};
	int rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	// Normally we don't call protosmtp_validate_response() more than once.
	// This is for testing purposes only.
	rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	// Normally we don't call protosmtp_validate_response() more than once,
	// but smtp_ctx->not_valid should remain 1.
	// This is for testing purposes only.
	char array02[] = {'2', '2', '0', ' ', 's', 'm', 't', 'p'};
	rv = protosmtp_validate_response(ctx, array02, sizeof(array02));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_response_06)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'2', '2', '0', '0', ' ', 's', 'm', 't', 'p'};
	int rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_response_07)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'1', '9', '9', '9', ' ', 's', 'm', 't', 'p'};
	int rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

START_TEST(protosmtp_validate_response_08)
{
	pxy_conn_ctx_t *ctx = proto_init(PROTO_SMTP);
	protosmtp_ctx_t *smtp_ctx = ctx->protoctx->arg;

	char array01[] = {'6', '0', '0', '0', ' ', 's', 'm', 't', 'p'};
	int rv = protosmtp_validate_response(ctx, array01, sizeof(array01));

	ck_assert_msg(rv == -1, "wrong return value");
	ck_assert_msg(smtp_ctx->not_valid == 1, "wrong not_valid");
	ck_assert_msg(smtp_ctx->seen_command_count == 0, "wrong seen_command_count");
	ck_assert_msg(ctx->protoctx->is_valid == 0, "wrong is_valid");

	proto_free(ctx);
}
END_TEST

Suite *
proto_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("proto");

	tc = tcase_create("protohttp_validate");
	tcase_add_test(tc, protohttp_validate_01);
	tcase_add_test(tc, protohttp_validate_02);
	tcase_add_test(tc, protohttp_validate_03);
	tcase_add_test(tc, protohttp_validate_04);
	tcase_add_test(tc, protohttp_validate_05);
	tcase_add_test(tc, protohttp_validate_06);
	tcase_add_test(tc, protohttp_validate_07);
	tcase_add_test(tc, protohttp_validate_08);
	tcase_add_test(tc, protohttp_validate_09);
	tcase_add_test(tc, protohttp_validate_10);
	suite_add_tcase(s, tc);

	tc = tcase_create("protopop3_validate");
	tcase_add_test(tc, protopop3_validate_01);
	tcase_add_test(tc, protopop3_validate_02);
	tcase_add_test(tc, protopop3_validate_03);
	tcase_add_test(tc, protopop3_validate_04);
	tcase_add_test(tc, protopop3_validate_05);
	tcase_add_test(tc, protopop3_validate_06);
	suite_add_tcase(s, tc);

	tc = tcase_create("protosmtp_validate");
	tcase_add_test(tc, protosmtp_validate_01);
	tcase_add_test(tc, protosmtp_validate_02);
	tcase_add_test(tc, protosmtp_validate_03);
	tcase_add_test(tc, protosmtp_validate_04);
	tcase_add_test(tc, protosmtp_validate_05);
	tcase_add_test(tc, protosmtp_validate_06);
	suite_add_tcase(s, tc);

	tc = tcase_create("protosmtp_validate_response");
	tcase_add_test(tc, protosmtp_validate_response_01);
	tcase_add_test(tc, protosmtp_validate_response_02);
	tcase_add_test(tc, protosmtp_validate_response_03);
	tcase_add_test(tc, protosmtp_validate_response_04);
	tcase_add_test(tc, protosmtp_validate_response_05);
	tcase_add_test(tc, protosmtp_validate_response_06);
	tcase_add_test(tc, protosmtp_validate_response_07);
	tcase_add_test(tc, protosmtp_validate_response_08);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
