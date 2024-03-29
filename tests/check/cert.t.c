/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
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

#include "ssl.h"
#include "cert.h"

#include <stdlib.h>
#include <unistd.h>

#include <check.h>

#define TESTCERT "pki/targets/daniel.roe.ch.pem"

START_TEST(cert_new_load_01)
{
	cert_t *c;

	c = cert_new_load(TESTCERT);
	ck_assert_msg(!!c, "loading PEM failed");
	ck_assert_msg(!!c->crt, "loading crt failed");
	ck_assert_msg(!!c->key, "loading key failed");
	ck_assert_msg(!!c->chain, "initializing chain stack failed");
	ck_assert_msg(sk_X509_num(c->chain) == 1, "loading chain failed");
	cert_free(c);
}
END_TEST

START_TEST(cert_refcount_inc_01)
{
	cert_t *c;

	c = cert_new_load(TESTCERT);
	ck_assert_msg(!!c, "loading PEM failed");
	ck_assert_msg(c->references == 1, "refcount mismatch");
	cert_refcount_inc(c);
	ck_assert_msg(c->references == 2, "refcount mismatch");
	cert_free(c);
	ck_assert_msg(c->references == 1, "refcount mismatch");
	cert_free(c);
#if 0
	/* deliberate access after last free() */
	ck_assert_msg(c->references == 0, "refcount mismatch");
#endif
}
END_TEST

Suite *
cert_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("cert");

	tc = tcase_create("cert_new_load");
	tcase_add_test(tc, cert_new_load_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("cert_refcount_inc");
	tcase_add_test(tc, cert_refcount_inc_01);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
