/*-
 * SSLproxy
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

#include "attrib.h"
#include "opts.h"
#include "filter.h"

#include <check.h>
#include <unistd.h>

START_TEST(set_filter_rule_01)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	// ATTENTION: We cannot use const string like 's = "*"' here, because we modify s in filter_rule_set(), which gives signal 11
	s = strdup("*");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST

START_TEST(set_filter_rule_02)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("from ip *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip 192.168.0.1*");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip 192.168.0.1*");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip 192.168.0.1*");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip 192.168.0.1*");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from ip 192.168.0.1*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("$macro 192.168.0.1 192.168.0.2 192.168.0.1* 192.168.0.2*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	// macro expansion returns 1, not 0
	s = strdup("from ip $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from ip $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from ip $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from ip $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from ip $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST

#ifndef WITHOUT_USERAUTH
START_TEST(set_filter_rule_03)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("$macro root daemon admin*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	close(2);

	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);

	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);

	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);

	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);

	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == -1, "failed to parse rule");
	free(s);

	conn_opts->user_auth = 1;

	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc desc");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("from user $macro desc $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST
#endif /* !WITHOUT_USERAUTH */

START_TEST(set_filter_rule_04)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("to ip *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to ip * port *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip * port *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip * port *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip * port *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip * port *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to ip 192.168.0.1 port *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1 port *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1 port *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1 port *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1 port *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to ip * port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip * port 443");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip * port 443");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip * port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip * port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to ip 192.168.0.1 port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1 port 443");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1 port 443");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1 port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to ip 192.168.0.1 port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("$macro1 192.168.0.1 192.168.0.2 192.168.0.1*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$macro2 443 444 80*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("to ip $macro1 port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to ip $macro1 port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to ip $macro1 port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to ip $macro1 port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to ip $macro1 port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST

START_TEST(set_filter_rule_05)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("$macro example.com example*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$macro2 443 444 80*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("to sni *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to sni example.com");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to sni example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to sni $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to sni example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to sni $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to sni $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to cn *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to cn example.com");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to cn example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to cn $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to cn example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to cn $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to cn $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to host *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to host example.com");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host example.com");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host example.com");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host example.com");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host example.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to host example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to host example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to host $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to host example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to host $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to host $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to uri *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to uri example.com");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to uri example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to uri $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to uri example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri example.com port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to uri $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to uri $macro port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("to port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to port 443");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to port 443");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("to port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("to port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("to port $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST

START_TEST(set_filter_rule_06)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log connect");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log connect");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log connect");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log connect");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log connect");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log master");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log master");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log master");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log master");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log master");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log cert");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log cert");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log cert");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log cert");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log cert");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log content");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log content");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log content");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log content");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log content");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log pcap");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log pcap");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log pcap");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log pcap");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log pcap");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log mirror");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log mirror");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log mirror");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log mirror");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log mirror");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log !*");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !*");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !*");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !*");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log !connect");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !connect");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !connect");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !connect");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !connect");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log !master");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !master");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !master");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !master");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !master");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log !cert");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !cert");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !cert");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !cert");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !cert");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log !content");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !content");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !content");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !content");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !content");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log !pcap");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !pcap");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !pcap");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !pcap");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !pcap");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("log !mirror");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !mirror");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !mirror");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !mirror");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);
	s = strdup("log !mirror");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("$macro connect master cert content pcap mirror");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("log $macro");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("$macro2 !connect !master !cert !content !pcap !mirror");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("log $macro2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro2");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro2");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro2");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("$macro3 connect !master cert !content pcap !mirror");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("log $macro3");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro3");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro3");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro3");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro3");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("$macro4 !connect master !cert content !pcap mirror");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("log $macro4");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro4");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro4");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro4");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro4");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("$macro5 connect master cert !content !pcap !mirror");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("log $macro5");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro5");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro5");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro5");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro5");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = strdup("$macro6 !connect !master !cert content pcap mirror");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("log $macro6");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro6");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro6");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro6");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);
	s = strdup("log $macro6");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST

#ifndef WITHOUT_USERAUTH
START_TEST(set_filter_rule_07)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("*");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from *");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip * to ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	conn_opts->user_auth = 1;

	s = strdup("from user *");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from desc *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user * desc desc");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user root desc *");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user * desc *");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from * to * log *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
	ck_assert_msg(!strcmp(strstr(s, "filter rule 5: "),
		"filter rule 5: dstip=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=||||match, log=|||||, precedence=1\n"
		"filter rule 5: sni=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=||||match, log=|||||, precedence=1\n"
		"filter rule 5: cn=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=||||match, log=|||||, precedence=1\n"
		"filter rule 5: host=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=||||match, log=|||||, precedence=1\n"
		"filter rule 5: uri=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=||||match, log=|||||, precedence=1\n"
		"filter rule 6: dstip=, dstport=, srcip=, user=, desc=desc, exact=||||desc, all=|users|sites|, action=|split|||, log=|||||, precedence=2\n"
		"filter rule 6: sni=, dstport=, srcip=, user=, desc=desc, exact=||||desc, all=|users|sites|, action=|split|||, log=|||||, precedence=2\n"
		"filter rule 6: cn=, dstport=, srcip=, user=, desc=desc, exact=||||desc, all=|users|sites|, action=|split|||, log=|||||, precedence=2\n"
		"filter rule 6: host=, dstport=, srcip=, user=, desc=desc, exact=||||desc, all=|users|sites|, action=|split|||, log=|||||, precedence=2\n"
		"filter rule 6: uri=, dstport=, srcip=, user=, desc=desc, exact=||||desc, all=|users|sites|, action=|split|||, log=|||||, precedence=2\n"
		"filter rule 7: dstip=, dstport=, srcip=, user=root, desc=, exact=|||user|, all=||sites|, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 7: sni=, dstport=, srcip=, user=root, desc=, exact=|||user|, all=||sites|, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 7: cn=, dstport=, srcip=, user=root, desc=, exact=|||user|, all=||sites|, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 7: host=, dstport=, srcip=, user=root, desc=, exact=|||user|, all=||sites|, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 7: uri=, dstport=, srcip=, user=root, desc=, exact=|||user|, all=||sites|, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 8: dstip=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=divert||||, log=|||||, precedence=1\n"
		"filter rule 8: sni=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=divert||||, log=|||||, precedence=1\n"
		"filter rule 8: cn=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=divert||||, log=|||||, precedence=1\n"
		"filter rule 8: host=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=divert||||, log=|||||, precedence=1\n"
		"filter rule 8: uri=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=divert||||, log=|||||, precedence=1\n"
		"filter rule 9: dstip=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||||match, log=connect|master|cert|content|pcap|mirror, precedence=1\n"
		"filter rule 9: sni=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||||match, log=connect|master|cert|content|pcap|mirror, precedence=1\n"
		"filter rule 9: cn=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||||match, log=connect|master|cert|content|pcap|mirror, precedence=1\n"
		"filter rule 9: host=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||||match, log=connect|master|cert|content|pcap|mirror, precedence=1\n"
		"filter rule 9: uri=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||||match, log=connect|master|cert|content|pcap|mirror, precedence=1\n"),
		"failed to parse rule: %s", strstr(s, "filter rule 5: "));

	// Trim the tail
	char *p = strstr(s, "filter rule 5: ");
	*p = '\0';

	ck_assert_msg(!strcmp(s,
		"filter rule 0: dstip=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=divert||||, log=|||||, precedence=0\n"
		"filter rule 0: sni=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=divert||||, log=|||||, precedence=0\n"
		"filter rule 0: cn=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=divert||||, log=|||||, precedence=0\n"
		"filter rule 0: host=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=divert||||, log=|||||, precedence=0\n"
		"filter rule 0: uri=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=divert||||, log=|||||, precedence=0\n"
		"filter rule 1: dstip=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=|split|||, log=|||||, precedence=0\n"
		"filter rule 1: sni=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=|split|||, log=|||||, precedence=0\n"
		"filter rule 1: cn=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=|split|||, log=|||||, precedence=0\n"
		"filter rule 1: host=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=|split|||, log=|||||, precedence=0\n"
		"filter rule 1: uri=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=|split|||, log=|||||, precedence=0\n"
		"filter rule 2: dstip=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||pass||, log=|||||, precedence=0\n"
		"filter rule 2: sni=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||pass||, log=|||||, precedence=0\n"
		"filter rule 2: cn=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||pass||, log=|||||, precedence=0\n"
		"filter rule 2: host=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||pass||, log=|||||, precedence=0\n"
		"filter rule 2: uri=, dstport=, srcip=, user=, desc=, exact=||||, all=conns||sites|, action=||pass||, log=|||||, precedence=0\n"
		"filter rule 3: dstip=192.168.0.1, dstport=, srcip=, user=, desc=, exact=site||||, all=conns|||, action=|||block|, log=|||||, precedence=1\n"
		"filter rule 4: dstip=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=|||block|, log=|||||, precedence=1\n"
		"filter rule 4: sni=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=|||block|, log=|||||, precedence=1\n"
		"filter rule 4: cn=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=|||block|, log=|||||, precedence=1\n"
		"filter rule 4: host=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=|||block|, log=|||||, precedence=1\n"
		"filter rule 4: uri=, dstport=, srcip=, user=, desc=, exact=||||, all=|users|sites|, action=|||block|, log=|||||, precedence=1\n"),
		"failed to parse rule: %s", s);
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
"userdesc_filter_substring->\n"
"user_filter_exact->\n"
"  user 0 root (exact)=\n"
"    ip all:\n"
"      0:  (all_sites, substring, action=||pass||, log=|||||, precedence=2)\n"
"    sni all:\n"
"      0:  (all_sites, substring, action=||pass||, log=|||||, precedence=2)\n"
"    cn all:\n"
"      0:  (all_sites, substring, action=||pass||, log=|||||, precedence=2)\n"
"    host all:\n"
"      0:  (all_sites, substring, action=||pass||, log=|||||, precedence=2)\n"
"    uri all:\n"
"      0:  (all_sites, substring, action=||pass||, log=|||||, precedence=2)\n"
"user_filter_substring->\n"
"desc_filter_exact->\n"
"   desc 0 desc (exact)=\n"
"    ip all:\n"
"      0:  (all_sites, substring, action=|split|||, log=|||||, precedence=2)\n"
"    sni all:\n"
"      0:  (all_sites, substring, action=|split|||, log=|||||, precedence=2)\n"
"    cn all:\n"
"      0:  (all_sites, substring, action=|split|||, log=|||||, precedence=2)\n"
"    host all:\n"
"      0:  (all_sites, substring, action=|split|||, log=|||||, precedence=2)\n"
"    uri all:\n"
"      0:  (all_sites, substring, action=|split|||, log=|||||, precedence=2)\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"    ip all:\n"
"      0:  (all_sites, substring, action=divert|||block|match, log=|||||, precedence=1)\n"
"    sni all:\n"
"      0:  (all_sites, substring, action=divert|||block|match, log=|||||, precedence=1)\n"
"    cn all:\n"
"      0:  (all_sites, substring, action=divert|||block|match, log=|||||, precedence=1)\n"
"    host all:\n"
"      0:  (all_sites, substring, action=divert|||block|match, log=|||||, precedence=1)\n"
"    uri all:\n"
"      0:  (all_sites, substring, action=divert|||block|match, log=|||||, precedence=1)\n"
"ip_filter_exact->\n"
"ip_filter_substring->\n"
"filter_all->\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=|||block|, log=|||||, precedence=1)\n"
"    ip all:\n"
"      0:  (all_sites, substring, action=divert|split|pass||match, log=connect|master|cert|content|pcap|mirror, precedence=1)\n"
"    sni all:\n"
"      0:  (all_sites, substring, action=divert|split|pass||match, log=connect|master|cert|content|pcap|mirror, precedence=1)\n"
"    cn all:\n"
"      0:  (all_sites, substring, action=divert|split|pass||match, log=connect|master|cert|content|pcap|mirror, precedence=1)\n"
"    host all:\n"
"      0:  (all_sites, substring, action=divert|split|pass||match, log=connect|master|cert|content|pcap|mirror, precedence=1)\n"
"    uri all:\n"
"      0:  (all_sites, substring, action=divert|split|pass||match, log=connect|master|cert|content|pcap|mirror, precedence=1)\n"), "failed to translate rule: %s", s);
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST
#endif /* !WITHOUT_USERAUTH */

START_TEST(set_filter_rule_08)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("from ip 192.168.0.1 to ip 192.168.0.2");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip 192.168.0.1 to ip 192.168.0.2 log connect master cert content pcap mirror");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip 192.168.0.1 to ip 192.168.0.2 log !connect !cert !pcap");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Block action at precedence 1 is not applied to a site of the same rule at precedence 2 now
	s = strdup("from ip 192.168.0.1 to ip 192.168.0.2");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target
	s = strdup("from ip 192.168.0.1 to ip 192.168.0.3");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another source
	s = strdup("from ip 192.168.0.2 to ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip 192.168.0.2 to ip *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Search substring (subnet?)
	s = strdup("from ip 192.168.0.2 to ip 192.168.0.*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target
	s = strdup("from ip 192.168.0.2 to ip 192.168.0.3");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add substring src
	s = strdup("from ip 192.168.1.* to ip 192.168.0.1");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add substring src and target
	s = strdup("from ip 192.168.2.* to ip 192.168.3.*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
#ifndef WITHOUT_USERAUTH
	ck_assert_msg(!strcmp(s,
		"filter rule 0: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=divert||||, log=|||||, precedence=2\n"
		"filter rule 1: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=|split|||, log=connect|master|cert|content|pcap|mirror, precedence=3\n"
		"filter rule 2: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=||pass||, log=!connect||!cert||!pcap|, precedence=3\n"
		"filter rule 3: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=|||block|, log=|||||, precedence=2\n"
		"filter rule 4: dstip=192.168.0.3, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 5: dstip=192.168.0.1, dstport=, srcip=192.168.0.2, user=, desc=, exact=site||ip||, all=|||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 6: dstip=, dstport=, srcip=192.168.0.2, user=, desc=, exact=||ip||, all=||sites|, action=||||match, log=|||||, precedence=2\n"
		"filter rule 7: dstip=192.168.0., dstport=, srcip=192.168.0.2, user=, desc=, exact=||ip||, all=|||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 8: dstip=192.168.0.3, dstport=, srcip=192.168.0.2, user=, desc=, exact=site||ip||, all=|||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 9: dstip=192.168.0.1, dstport=, srcip=192.168.1., user=, desc=, exact=site||||, all=|||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 10: dstip=192.168.3., dstport=, srcip=192.168.2., user=, desc=, exact=||||, all=|||, action=||||match, log=|||||, precedence=2\n"),
		"failed to parse rule: %s", s);
#else /* WITHOUT_USERAUTH */
	ck_assert_msg(!strcmp(s,
		"filter rule 0: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, exact=site||ip, all=||, action=divert||||, log=|||||, precedence=2\n"
		"filter rule 1: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, exact=site||ip, all=||, action=|split|||, log=connect|master|cert|content|pcap|mirror, precedence=3\n"
		"filter rule 2: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, exact=site||ip, all=||, action=||pass||, log=!connect||!cert||!pcap|, precedence=3\n"
		"filter rule 3: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, exact=site||ip, all=||, action=|||block|, log=|||||, precedence=2\n"
		"filter rule 4: dstip=192.168.0.3, dstport=, srcip=192.168.0.1, exact=site||ip, all=||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 5: dstip=192.168.0.1, dstport=, srcip=192.168.0.2, exact=site||ip, all=||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 6: dstip=, dstport=, srcip=192.168.0.2, exact=||ip, all=|sites|, action=||||match, log=|||||, precedence=2\n"
		"filter rule 7: dstip=192.168.0., dstport=, srcip=192.168.0.2, exact=||ip, all=||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 8: dstip=192.168.0.3, dstport=, srcip=192.168.0.2, exact=site||ip, all=||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 9: dstip=192.168.0.1, dstport=, srcip=192.168.1., exact=site||, all=||, action=||||match, log=|||||, precedence=2\n"
		"filter rule 10: dstip=192.168.3., dstport=, srcip=192.168.2., exact=||, all=||, action=||||match, log=|||||, precedence=2\n"),
		"failed to parse rule: %s", s);
#endif /* WITHOUT_USERAUTH */
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
#ifndef WITHOUT_USERAUTH
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
"userdesc_filter_substring->\n"
"user_filter_exact->\n"
"user_filter_substring->\n"
"desc_filter_exact->\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"  ip 0 192.168.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.2 (exact, action=divert|split|pass||, log=!connect|master|!cert|content|!pcap|mirror, precedence=3)\n"
"      1: 192.168.0.3 (exact, action=||||match, log=|||||, precedence=2)\n"
"  ip 1 192.168.0.2 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=||||match, log=|||||, precedence=2)\n"
"      1: 192.168.0.3 (exact, action=||||match, log=|||||, precedence=2)\n"
"    ip substring:\n"
"      0: 192.168.0. (substring, action=||||match, log=|||||, precedence=2)\n"
"    ip all:\n"
"      0:  (all_sites, substring, action=||||match, log=|||||, precedence=2)\n"
"ip_filter_substring->\n"
"  ip 0 192.168.1. (substring)=\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=||||match, log=|||||, precedence=2)\n"
"  ip 1 192.168.2. (substring)=\n"
"    ip substring:\n"
"      0: 192.168.3. (substring, action=||||match, log=|||||, precedence=2)\n"
"filter_all->\n"), "failed to translate rule: %s", s);
#else /* WITHOUT_USERAUTH */
	ck_assert_msg(!strcmp(s, "filter=>\n"
"ip_filter_exact->\n"
"  ip 0 192.168.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.2 (exact, action=divert|split|pass||, log=!connect|master|!cert|content|!pcap|mirror, precedence=3)\n"
"      1: 192.168.0.3 (exact, action=||||match, log=|||||, precedence=2)\n"
"  ip 1 192.168.0.2 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=||||match, log=|||||, precedence=2)\n"
"      1: 192.168.0.3 (exact, action=||||match, log=|||||, precedence=2)\n"
"    ip substring:\n"
"      0: 192.168.0. (substring, action=||||match, log=|||||, precedence=2)\n"
"    ip all:\n"
"      0:  (all_sites, substring, action=||||match, log=|||||, precedence=2)\n"
"ip_filter_substring->\n"
"  ip 0 192.168.1. (substring)=\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=||||match, log=|||||, precedence=2)\n"
"  ip 1 192.168.2. (substring)=\n"
"    ip substring:\n"
"      0: 192.168.3. (substring, action=||||match, log=|||||, precedence=2)\n"
"filter_all->\n"), "failed to translate rule: %s", s);
#endif /* WITHOUT_USERAUTH */
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(set_filter_rule_09)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("from ip 192.168.0.1 to ip 192.168.0.2 port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip 192.168.0.1 to ip 192.168.0.2 port 443 log connect master cert content pcap mirror");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip 192.168.0.1 to ip 192.168.0.2 port 443 log !connect !cert !pcap");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Block action at precedence 2 is not applied to a port of the same rule at precedence 3 now
	s = strdup("from ip 192.168.0.1 to ip 192.168.0.2 port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target, the following port rules should not change this site rule
	s = strdup("from ip 192.168.0.1 to ip 192.168.0.3 log !mirror");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target port
	s = strdup("from ip 192.168.0.1 to ip 192.168.0.3 port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target port
	s = strdup("from ip 192.168.0.1 to ip 192.168.0.3 port 80");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another source
	s = strdup("from ip 192.168.0.2 to ip 192.168.0.1 port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add substring source
	s = strdup("from ip 192.168.1.* to ip 192.168.0.1 port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add substring source and target
	s = strdup("from ip 192.168.2.* to ip 192.168.3.* port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from ip 192.168.0.2 to ip 192.168.0.1 port *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Search substring
	s = strdup("from ip 192.168.0.2 to ip 192.168.0.1 port 80*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add substring source, target, and port
	s = strdup("from ip 192.168.4.* to ip 192.168.5.* port 80*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
#ifndef WITHOUT_USERAUTH
	ck_assert_msg(!strcmp(s,
		"filter rule 0: dstip=192.168.0.2, dstport=443, srcip=192.168.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=divert||||, log=|||||, precedence=3\n"
		"filter rule 1: dstip=192.168.0.2, dstport=443, srcip=192.168.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=|split|||, log=connect|master|cert|content|pcap|mirror, precedence=4\n"
		"filter rule 2: dstip=192.168.0.2, dstport=443, srcip=192.168.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=||pass||, log=!connect||!cert||!pcap|, precedence=4\n"
		"filter rule 3: dstip=192.168.0.2, dstport=443, srcip=192.168.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=|||block|, log=|||||, precedence=3\n"
		"filter rule 4: dstip=192.168.0.3, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=||||match, log=|||||!mirror, precedence=3\n"
		"filter rule 5: dstip=192.168.0.3, dstport=443, srcip=192.168.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 6: dstip=192.168.0.3, dstport=80, srcip=192.168.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 7: dstip=192.168.0.1, dstport=443, srcip=192.168.0.2, user=, desc=, exact=site|port|ip||, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 8: dstip=192.168.0.1, dstport=443, srcip=192.168.1., user=, desc=, exact=site|port|||, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 9: dstip=192.168.3., dstport=443, srcip=192.168.2., user=, desc=, exact=|port|||, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 10: dstip=192.168.0.1, dstport=, srcip=192.168.0.2, user=, desc=, exact=site||ip||, all=|||ports, action=||||match, log=|||||, precedence=3\n"
		"filter rule 11: dstip=192.168.0.1, dstport=80, srcip=192.168.0.2, user=, desc=, exact=site||ip||, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 12: dstip=192.168.5., dstport=80, srcip=192.168.4., user=, desc=, exact=||||, all=|||, action=||||match, log=|||||, precedence=3\n"),
		"failed to parse rule: %s", s);
#else /* WITHOUT_USERAUTH */
	ck_assert_msg(!strcmp(s,
		"filter rule 0: dstip=192.168.0.2, dstport=443, srcip=192.168.0.1, exact=site|port|ip, all=||, action=divert||||, log=|||||, precedence=3\n"
		"filter rule 1: dstip=192.168.0.2, dstport=443, srcip=192.168.0.1, exact=site|port|ip, all=||, action=|split|||, log=connect|master|cert|content|pcap|mirror, precedence=4\n"
		"filter rule 2: dstip=192.168.0.2, dstport=443, srcip=192.168.0.1, exact=site|port|ip, all=||, action=||pass||, log=!connect||!cert||!pcap|, precedence=4\n"
		"filter rule 3: dstip=192.168.0.2, dstport=443, srcip=192.168.0.1, exact=site|port|ip, all=||, action=|||block|, log=|||||, precedence=3\n"
		"filter rule 4: dstip=192.168.0.3, dstport=, srcip=192.168.0.1, exact=site||ip, all=||, action=||||match, log=|||||!mirror, precedence=3\n"
		"filter rule 5: dstip=192.168.0.3, dstport=443, srcip=192.168.0.1, exact=site|port|ip, all=||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 6: dstip=192.168.0.3, dstport=80, srcip=192.168.0.1, exact=site|port|ip, all=||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 7: dstip=192.168.0.1, dstport=443, srcip=192.168.0.2, exact=site|port|ip, all=||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 8: dstip=192.168.0.1, dstport=443, srcip=192.168.1., exact=site|port|, all=||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 9: dstip=192.168.3., dstport=443, srcip=192.168.2., exact=|port|, all=||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 10: dstip=192.168.0.1, dstport=, srcip=192.168.0.2, exact=site||ip, all=||ports, action=||||match, log=|||||, precedence=3\n"
		"filter rule 11: dstip=192.168.0.1, dstport=80, srcip=192.168.0.2, exact=site||ip, all=||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 12: dstip=192.168.5., dstport=80, srcip=192.168.4., exact=||, all=||, action=||||match, log=|||||, precedence=3\n"),
		"failed to parse rule: %s", s);
#endif /* WITHOUT_USERAUTH */
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
#ifndef WITHOUT_USERAUTH
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
"userdesc_filter_substring->\n"
"user_filter_exact->\n"
"user_filter_substring->\n"
"desc_filter_exact->\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"  ip 0 192.168.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.2 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=divert|split|pass||, log=!connect|master|!cert|content|!pcap|mirror, precedence=4)\n"
"      1: 192.168.0.3 (exact, action=||||match, log=|||||!mirror, precedence=3)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=3)\n"
"          1: 80 (exact, action=||||match, log=|||||, precedence=3)\n"
"  ip 1 192.168.0.2 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=3)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|||||, precedence=3)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=|||||, precedence=3)\n"
"ip_filter_substring->\n"
"  ip 0 192.168.1. (substring)=\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=3)\n"
"  ip 1 192.168.2. (substring)=\n"
"    ip substring:\n"
"      0: 192.168.3. (substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=3)\n"
"  ip 2 192.168.4. (substring)=\n"
"    ip substring:\n"
"      0: 192.168.5. (substring, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|||||, precedence=3)\n"
"filter_all->\n"), "failed to translate rule: %s", s);
#else /* WITHOUT_USERAUTH */
	ck_assert_msg(!strcmp(s, "filter=>\n"
"ip_filter_exact->\n"
"  ip 0 192.168.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.2 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=divert|split|pass||, log=!connect|master|!cert|content|!pcap|mirror, precedence=4)\n"
"      1: 192.168.0.3 (exact, action=||||match, log=|||||!mirror, precedence=3)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=3)\n"
"          1: 80 (exact, action=||||match, log=|||||, precedence=3)\n"
"  ip 1 192.168.0.2 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=3)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|||||, precedence=3)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=|||||, precedence=3)\n"
"ip_filter_substring->\n"
"  ip 0 192.168.1. (substring)=\n"
"    ip exact:\n"
"      0: 192.168.0.1 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=3)\n"
"  ip 1 192.168.2. (substring)=\n"
"    ip substring:\n"
"      0: 192.168.3. (substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=3)\n"
"  ip 2 192.168.4. (substring)=\n"
"    ip substring:\n"
"      0: 192.168.5. (substring, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|||||, precedence=3)\n"
"filter_all->\n"), "failed to translate rule: %s", s);
#endif /* WITHOUT_USERAUTH */
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST

#ifndef WITHOUT_USERAUTH
START_TEST(set_filter_rule_10)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	conn_opts->user_auth = 1;

	s = strdup("from user root to sni example.com");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user root to sni example.com log connect master cert content pcap mirror");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user root to sni example.com log !connect !cert !pcap");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Block action at precedence 2 is not applied to a site of the same rule at precedence 4 now
	s = strdup("from user root to sni example.com");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target
	s = strdup("from user root to sni example2.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another source
	s = strdup("from user daemon to sni example.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user daemon to sni *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Search substring (subdomain?)
	s = strdup("from user daemon to sni .example.com*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target
	s = strdup("from user daemon to sni example3.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add substring source
	s = strdup("from user admin1* to sni example4.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user admin2* to sni example5.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
	ck_assert_msg(!strcmp(s,
		"filter rule 0: sni=example.com, dstport=, srcip=, user=root, desc=, exact=site|||user|, all=|||, action=divert||||, log=|||||, precedence=3\n"
		"filter rule 1: sni=example.com, dstport=, srcip=, user=root, desc=, exact=site|||user|, all=|||, action=|split|||, log=connect|master|cert|content|pcap|mirror, precedence=4\n"
		"filter rule 2: sni=example.com, dstport=, srcip=, user=root, desc=, exact=site|||user|, all=|||, action=||pass||, log=!connect||!cert||!pcap|, precedence=4\n"
		"filter rule 3: sni=example.com, dstport=, srcip=, user=root, desc=, exact=site|||user|, all=|||, action=|||block|, log=|||||, precedence=3\n"
		"filter rule 4: sni=example2.com, dstport=, srcip=, user=root, desc=, exact=site|||user|, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 5: sni=example.com, dstport=, srcip=, user=daemon, desc=, exact=site|||user|, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 6: sni=, dstport=, srcip=, user=daemon, desc=, exact=|||user|, all=||sites|, action=||||match, log=|||||, precedence=3\n"
		"filter rule 7: sni=.example.com, dstport=, srcip=, user=daemon, desc=, exact=|||user|, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 8: sni=example3.com, dstport=, srcip=, user=daemon, desc=, exact=site|||user|, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 9: sni=example4.com, dstport=, srcip=, user=admin1, desc=, exact=site||||, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 10: sni=example5.com, dstport=, srcip=, user=admin2, desc=, exact=site||||, all=|||, action=||||match, log=|||||, precedence=3\n"),
		"failed to parse rule: %s", s);
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
"userdesc_filter_substring->\n"
"user_filter_exact->\n"
"  user 0 daemon (exact)=\n"
"    sni exact:\n"
"      0: example.com (exact, action=||||match, log=|||||, precedence=3)\n"
"      1: example3.com (exact, action=||||match, log=|||||, precedence=3)\n"
"    sni substring:\n"
"      0: .example.com (substring, action=||||match, log=|||||, precedence=3)\n"
"    sni all:\n"
"      0:  (all_sites, substring, action=||||match, log=|||||, precedence=3)\n"
"  user 1 root (exact)=\n"
"    sni exact:\n"
"      0: example.com (exact, action=divert|split|pass||, log=!connect|master|!cert|content|!pcap|mirror, precedence=4)\n"
"      1: example2.com (exact, action=||||match, log=|||||, precedence=3)\n"
"user_filter_substring->\n"
"  user 0 admin1 (substring)=\n"
"    sni exact:\n"
"      0: example4.com (exact, action=||||match, log=|||||, precedence=3)\n"
"  user 1 admin2 (substring)=\n"
"    sni exact:\n"
"      0: example5.com (exact, action=||||match, log=|||||, precedence=3)\n"
"desc_filter_exact->\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"ip_filter_substring->\n"
"filter_all->\n"), "failed to translate rule: %s", s);
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(set_filter_rule_11)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	conn_opts->user_auth = 1;

	s = strdup("from user root to cn example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user root to cn example.com port 443 log connect master cert content pcap mirror");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user root to cn example.com port 443 log !connect !cert !pcap");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Block action at precedence 3 is not applied to a site of the same rule at precedence 5 now
	s = strdup("from user root to cn example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target
	s = strdup("from user root to cn example2.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another source
	s = strdup("from user daemon to cn example.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user daemon to cn * port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user daemon to cn example.com port *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user daemon to cn * port *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Search substring (subdomain?)
	s = strdup("from user daemon to cn .example.com* port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user daemon to cn .example.com* port 443*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target
	s = strdup("from user daemon to cn example3.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add substring source
	s = strdup("from user admin1* to cn example4.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user admin2* to cn example5.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
	ck_assert_msg(!strcmp(s,
		"filter rule 0: cn=example.com, dstport=443, srcip=, user=root, desc=, exact=site|port||user|, all=|||, action=divert||||, log=|||||, precedence=4\n"
		"filter rule 1: cn=example.com, dstport=443, srcip=, user=root, desc=, exact=site|port||user|, all=|||, action=|split|||, log=connect|master|cert|content|pcap|mirror, precedence=5\n"
		"filter rule 2: cn=example.com, dstport=443, srcip=, user=root, desc=, exact=site|port||user|, all=|||, action=||pass||, log=!connect||!cert||!pcap|, precedence=5\n"
		"filter rule 3: cn=example.com, dstport=443, srcip=, user=root, desc=, exact=site|port||user|, all=|||, action=|||block|, log=|||||, precedence=4\n"
		"filter rule 4: cn=example2.com, dstport=443, srcip=, user=root, desc=, exact=site|port||user|, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 5: cn=example.com, dstport=443, srcip=, user=daemon, desc=, exact=site|port||user|, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 6: cn=, dstport=443, srcip=, user=daemon, desc=, exact=|port||user|, all=||sites|, action=||||match, log=|||||, precedence=4\n"
		"filter rule 7: cn=example.com, dstport=, srcip=, user=daemon, desc=, exact=site|||user|, all=|||ports, action=||||match, log=|||||, precedence=4\n"
		"filter rule 8: cn=, dstport=, srcip=, user=daemon, desc=, exact=|||user|, all=||sites|ports, action=||||match, log=|||||, precedence=4\n"
		"filter rule 9: cn=.example.com, dstport=443, srcip=, user=daemon, desc=, exact=|port||user|, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 10: cn=.example.com, dstport=443, srcip=, user=daemon, desc=, exact=|||user|, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 11: cn=example3.com, dstport=443, srcip=, user=daemon, desc=, exact=site|port||user|, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 12: cn=example4.com, dstport=443, srcip=, user=admin1, desc=, exact=site|port|||, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 13: cn=example5.com, dstport=443, srcip=, user=admin2, desc=, exact=site|port|||, all=|||, action=||||match, log=|||||, precedence=4\n"),
		"failed to parse rule: %s", s);
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
"userdesc_filter_substring->\n"
"user_filter_exact->\n"
"  user 0 daemon (exact)=\n"
"    cn exact:\n"
"      0: example.com (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=4)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=|||||, precedence=4)\n"
"      1: example3.com (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=4)\n"
"    cn substring:\n"
"      0: .example.com (substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=4)\n"
"        port substring:\n"
"          0: 443 (substring, action=||||match, log=|||||, precedence=4)\n"
"    cn all:\n"
"      0:  (all_sites, substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=4)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=|||||, precedence=4)\n"
"  user 1 root (exact)=\n"
"    cn exact:\n"
"      0: example.com (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=divert|split|pass||, log=!connect|master|!cert|content|!pcap|mirror, precedence=5)\n"
"      1: example2.com (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=4)\n"
"user_filter_substring->\n"
"  user 0 admin1 (substring)=\n"
"    cn exact:\n"
"      0: example4.com (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=4)\n"
"  user 1 admin2 (substring)=\n"
"    cn exact:\n"
"      0: example5.com (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=4)\n"
"desc_filter_exact->\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"ip_filter_substring->\n"
"filter_all->\n"), "failed to translate rule: %s", s);
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(set_filter_rule_12)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	conn_opts->user_auth = 1;

	s = strdup("from user root desc desc to host example.com");
	rv = filter_rule_set(opts, conn_opts, "Divert", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user root desc desc to host example.com port 443 log connect master cert content pcap mirror");
	rv = filter_rule_set(opts, conn_opts, "Split", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user root desc desc to host example.com log !connect !cert !pcap");
	rv = filter_rule_set(opts, conn_opts, "Pass", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Block action at precedence 2 is not applied to a site of the same rule at precedence 5 now
	s = strdup("from user root desc desc to host example.com");
	rv = filter_rule_set(opts, conn_opts, "Block", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target
	s = strdup("from user root desc desc to host example2.com port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another source
	s = strdup("from user daemon desc desc to host example.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user daemon desc desc to host * port 443");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Search substring (subdomain?)
	s = strdup("from user daemon desc desc to host .example.com*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another target
	s = strdup("from user daemon desc desc to host example3.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add substring source
	s = strdup("from user admin1* desc desc1* to host example4.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user admin2* desc desc2* to host example5.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another desc
	s = strdup("from user daemon desc desc2 to host example6.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add all users
	s = strdup("from user * desc desc to host example7.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add all users all sni sites
	s = strdup("from user * desc desc to sni *");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	// Add another desc
	s = strdup("from desc desc3 to uri example8.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user * desc desc4* to host example9.com");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = strdup("from user admin* desc desc5* to host example10.com* port 443*");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 0, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
	ck_assert_msg(!strcmp(s,
		"filter rule 0: host=example.com, dstport=, srcip=, user=root, desc=desc, exact=site|||user|desc, all=|||, action=divert||||, log=|||||, precedence=4\n"
		"filter rule 1: host=example.com, dstport=443, srcip=, user=root, desc=desc, exact=site|port||user|desc, all=|||, action=|split|||, log=connect|master|cert|content|pcap|mirror, precedence=6\n"
		"filter rule 2: host=example.com, dstport=, srcip=, user=root, desc=desc, exact=site|||user|desc, all=|||, action=||pass||, log=!connect||!cert||!pcap|, precedence=5\n"
		"filter rule 3: host=example.com, dstport=, srcip=, user=root, desc=desc, exact=site|||user|desc, all=|||, action=|||block|, log=|||||, precedence=4\n"
		"filter rule 4: host=example2.com, dstport=443, srcip=, user=root, desc=desc, exact=site|port||user|desc, all=|||, action=||||match, log=|||||, precedence=5\n"
		"filter rule 5: host=example.com, dstport=, srcip=, user=daemon, desc=desc, exact=site|||user|desc, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 6: host=, dstport=443, srcip=, user=daemon, desc=desc, exact=|port||user|desc, all=||sites|, action=||||match, log=|||||, precedence=5\n"
		"filter rule 7: host=.example.com, dstport=, srcip=, user=daemon, desc=desc, exact=|||user|desc, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 8: host=example3.com, dstport=, srcip=, user=daemon, desc=desc, exact=site|||user|desc, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 9: host=example4.com, dstport=, srcip=, user=admin1, desc=desc1, exact=site||||, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 10: host=example5.com, dstport=, srcip=, user=admin2, desc=desc2, exact=site||||, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 11: host=example6.com, dstport=, srcip=, user=daemon, desc=desc2, exact=site|||user|desc, all=|||, action=||||match, log=|||||, precedence=4\n"
		"filter rule 12: host=example7.com, dstport=, srcip=, user=, desc=desc, exact=site||||desc, all=|users||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 13: sni=, dstport=, srcip=, user=, desc=desc, exact=||||desc, all=|users|sites|, action=||||match, log=|||||, precedence=3\n"
		"filter rule 14: uri=example8.com, dstport=, srcip=, user=, desc=desc3, exact=site||||desc, all=|||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 15: host=example9.com, dstport=, srcip=, user=, desc=desc4, exact=site||||, all=|users||, action=||||match, log=|||||, precedence=3\n"
		"filter rule 16: host=example10.com, dstport=443, srcip=, user=admin, desc=desc5, exact=||||, all=|||, action=||||match, log=|||||, precedence=5\n"),
		"failed to parse rule: %s", s);
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
" user 0 daemon (exact)=\n"
"  desc exact:\n"
"   desc 0 desc (exact)=\n"
"    host exact:\n"
"      0: example.com (exact, action=||||match, log=|||||, precedence=4)\n"
"      1: example3.com (exact, action=||||match, log=|||||, precedence=4)\n"
"    host substring:\n"
"      0: .example.com (substring, action=||||match, log=|||||, precedence=4)\n"
"    host all:\n"
"      0:  (all_sites, substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=5)\n"
"   desc 1 desc2 (exact)=\n"
"    host exact:\n"
"      0: example6.com (exact, action=||||match, log=|||||, precedence=4)\n"
" user 1 root (exact)=\n"
"  desc exact:\n"
"   desc 0 desc (exact)=\n"
"    host exact:\n"
"      0: example.com (exact, action=divert||pass||, log=!connect||!cert||!pcap|, precedence=5)\n"
"        port exact:\n"
"          0: 443 (exact, action=|split|||, log=connect|master|cert|content|pcap|mirror, precedence=6)\n"
"      1: example2.com (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|||||, precedence=5)\n"
"userdesc_filter_substring->\n"
" user 0 admin (substring)=\n"
"  desc substring:\n"
"   desc 0 desc5 (substring)=\n"
"    host substring:\n"
"      0: example10.com (substring, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 443 (substring, action=||||match, log=|||||, precedence=5)\n"
" user 1 admin1 (substring)=\n"
"  desc substring:\n"
"   desc 0 desc1 (substring)=\n"
"    host exact:\n"
"      0: example4.com (exact, action=||||match, log=|||||, precedence=4)\n"
" user 2 admin2 (substring)=\n"
"  desc substring:\n"
"   desc 0 desc2 (substring)=\n"
"    host exact:\n"
"      0: example5.com (exact, action=||||match, log=|||||, precedence=4)\n"
"user_filter_exact->\n"
"user_filter_substring->\n"
"desc_filter_exact->\n"
"   desc 0 desc (exact)=\n"
"    sni all:\n"
"      0:  (all_sites, substring, action=||||match, log=|||||, precedence=3)\n"
"    host exact:\n"
"      0: example7.com (exact, action=||||match, log=|||||, precedence=3)\n"
"   desc 1 desc3 (exact)=\n"
"    uri exact:\n"
"      0: example8.com (exact, action=||||match, log=|||||, precedence=3)\n"
"desc_filter_substring->\n"
"   desc 0 desc4 (substring)=\n"
"    host exact:\n"
"      0: example9.com (exact, action=||||match, log=|||||, precedence=3)\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"ip_filter_substring->\n"
"filter_all->\n"), "failed to translate rule: %s", s);
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST
#endif /* !WITHOUT_USERAUTH */

START_TEST(set_filter_rule_13)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("$ips 192.168.0.1 192.168.0.2*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$dstips 192.168.0.3 192.168.0.4*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$ports 80* 443");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$logs !master !pcap");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("from ip $ips to ip $dstips port $ports log $logs");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
#ifndef WITHOUT_USERAUTH
	ck_assert_msg(!strcmp(s,
		"filter rule 0: dstip=192.168.0.3, dstport=80, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 1: dstip=192.168.0.3, dstport=80, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 2: dstip=192.168.0.3, dstport=443, srcip=192.168.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 3: dstip=192.168.0.3, dstport=443, srcip=192.168.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 4: dstip=192.168.0.4, dstport=80, srcip=192.168.0.1, user=, desc=, exact=||ip||, all=|||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 5: dstip=192.168.0.4, dstport=80, srcip=192.168.0.1, user=, desc=, exact=||ip||, all=|||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 6: dstip=192.168.0.4, dstport=443, srcip=192.168.0.1, user=, desc=, exact=|port|ip||, all=|||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 7: dstip=192.168.0.4, dstport=443, srcip=192.168.0.1, user=, desc=, exact=|port|ip||, all=|||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 8: dstip=192.168.0.3, dstport=80, srcip=192.168.0.2, user=, desc=, exact=site||||, all=|||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 9: dstip=192.168.0.3, dstport=80, srcip=192.168.0.2, user=, desc=, exact=site||||, all=|||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 10: dstip=192.168.0.3, dstport=443, srcip=192.168.0.2, user=, desc=, exact=site|port|||, all=|||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 11: dstip=192.168.0.3, dstport=443, srcip=192.168.0.2, user=, desc=, exact=site|port|||, all=|||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 12: dstip=192.168.0.4, dstport=80, srcip=192.168.0.2, user=, desc=, exact=||||, all=|||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 13: dstip=192.168.0.4, dstport=80, srcip=192.168.0.2, user=, desc=, exact=||||, all=|||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 14: dstip=192.168.0.4, dstport=443, srcip=192.168.0.2, user=, desc=, exact=|port|||, all=|||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 15: dstip=192.168.0.4, dstport=443, srcip=192.168.0.2, user=, desc=, exact=|port|||, all=|||, action=||||match, log=||||!pcap|, precedence=4\n"),
		"failed to parse rule: %s", s);
#else /* WITHOUT_USERAUTH */
	ck_assert_msg(!strcmp(s,
		"filter rule 0: dstip=192.168.0.3, dstport=80, srcip=192.168.0.1, exact=site||ip, all=||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 1: dstip=192.168.0.3, dstport=80, srcip=192.168.0.1, exact=site||ip, all=||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 2: dstip=192.168.0.3, dstport=443, srcip=192.168.0.1, exact=site|port|ip, all=||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 3: dstip=192.168.0.3, dstport=443, srcip=192.168.0.1, exact=site|port|ip, all=||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 4: dstip=192.168.0.4, dstport=80, srcip=192.168.0.1, exact=||ip, all=||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 5: dstip=192.168.0.4, dstport=80, srcip=192.168.0.1, exact=||ip, all=||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 6: dstip=192.168.0.4, dstport=443, srcip=192.168.0.1, exact=|port|ip, all=||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 7: dstip=192.168.0.4, dstport=443, srcip=192.168.0.1, exact=|port|ip, all=||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 8: dstip=192.168.0.3, dstport=80, srcip=192.168.0.2, exact=site||, all=||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 9: dstip=192.168.0.3, dstport=80, srcip=192.168.0.2, exact=site||, all=||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 10: dstip=192.168.0.3, dstport=443, srcip=192.168.0.2, exact=site|port|, all=||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 11: dstip=192.168.0.3, dstport=443, srcip=192.168.0.2, exact=site|port|, all=||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 12: dstip=192.168.0.4, dstport=80, srcip=192.168.0.2, exact=||, all=||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 13: dstip=192.168.0.4, dstport=80, srcip=192.168.0.2, exact=||, all=||, action=||||match, log=||||!pcap|, precedence=4\n"
		"filter rule 14: dstip=192.168.0.4, dstport=443, srcip=192.168.0.2, exact=|port|, all=||, action=||||match, log=|!master||||, precedence=4\n"
		"filter rule 15: dstip=192.168.0.4, dstport=443, srcip=192.168.0.2, exact=|port|, all=||, action=||||match, log=||||!pcap|, precedence=4\n"),
		"failed to parse rule: %s", s);
#endif /* WITHOUT_USERAUTH */
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
#ifndef WITHOUT_USERAUTH
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
"userdesc_filter_substring->\n"
"user_filter_exact->\n"
"user_filter_substring->\n"
"desc_filter_exact->\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"  ip 0 192.168.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.3 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"    ip substring:\n"
"      0: 192.168.0.4 (substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"ip_filter_substring->\n"
"  ip 0 192.168.0.2 (substring)=\n"
"    ip exact:\n"
"      0: 192.168.0.3 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"    ip substring:\n"
"      0: 192.168.0.4 (substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"filter_all->\n"), "failed to translate rule: %s", s);
#else /* WITHOUT_USERAUTH */
	ck_assert_msg(!strcmp(s, "filter=>\n"
"ip_filter_exact->\n"
"  ip 0 192.168.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.3 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"    ip substring:\n"
"      0: 192.168.0.4 (substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"ip_filter_substring->\n"
"  ip 0 192.168.0.2 (substring)=\n"
"    ip exact:\n"
"      0: 192.168.0.3 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"    ip substring:\n"
"      0: 192.168.0.4 (substring, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 443 (exact, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=|!master|||!pcap|, precedence=4)\n"
"filter_all->\n"), "failed to translate rule: %s", s);
#endif /* WITHOUT_USERAUTH */
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST

#ifndef WITHOUT_USERAUTH
START_TEST(set_filter_rule_14)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("$users root admin*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$descs desc1 desc2*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$sites site1 site2*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	// check errors out if we add all log actions to the macro:
	// "../../src/check_pack.c:306: Message string too long"
	// Also, the compiler gives:
	// warning: string length ‘4186’ is greater than the length ‘4095’ ISO C99 compilers are required to support [-Woverlength-strings]
	// so use 2 log actions only
	s = strdup("$logs connect content");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	conn_opts->user_auth = 1;

	s = strdup("from user $users desc $descs to sni $sites log $logs");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
	ck_assert_msg(!strcmp(s,
		"filter rule 0: sni=site1, dstport=, srcip=, user=root, desc=desc1, exact=site|||user|desc, all=|||, action=||||match, log=connect|||||, precedence=5\n"
		"filter rule 1: sni=site1, dstport=, srcip=, user=root, desc=desc1, exact=site|||user|desc, all=|||, action=||||match, log=|||content||, precedence=5\n"
		"filter rule 2: sni=site2, dstport=, srcip=, user=root, desc=desc1, exact=|||user|desc, all=|||, action=||||match, log=connect|||||, precedence=5\n"
		"filter rule 3: sni=site2, dstport=, srcip=, user=root, desc=desc1, exact=|||user|desc, all=|||, action=||||match, log=|||content||, precedence=5\n"
		"filter rule 4: sni=site1, dstport=, srcip=, user=root, desc=desc2, exact=site|||user|, all=|||, action=||||match, log=connect|||||, precedence=5\n"
		"filter rule 5: sni=site1, dstport=, srcip=, user=root, desc=desc2, exact=site|||user|, all=|||, action=||||match, log=|||content||, precedence=5\n"
		"filter rule 6: sni=site2, dstport=, srcip=, user=root, desc=desc2, exact=|||user|, all=|||, action=||||match, log=connect|||||, precedence=5\n"
		"filter rule 7: sni=site2, dstport=, srcip=, user=root, desc=desc2, exact=|||user|, all=|||, action=||||match, log=|||content||, precedence=5\n"
		"filter rule 8: sni=site1, dstport=, srcip=, user=admin, desc=desc1, exact=site||||desc, all=|||, action=||||match, log=connect|||||, precedence=5\n"
		"filter rule 9: sni=site1, dstport=, srcip=, user=admin, desc=desc1, exact=site||||desc, all=|||, action=||||match, log=|||content||, precedence=5\n"
		"filter rule 10: sni=site2, dstport=, srcip=, user=admin, desc=desc1, exact=||||desc, all=|||, action=||||match, log=connect|||||, precedence=5\n"
		"filter rule 11: sni=site2, dstport=, srcip=, user=admin, desc=desc1, exact=||||desc, all=|||, action=||||match, log=|||content||, precedence=5\n"
		"filter rule 12: sni=site1, dstport=, srcip=, user=admin, desc=desc2, exact=site||||, all=|||, action=||||match, log=connect|||||, precedence=5\n"
		"filter rule 13: sni=site1, dstport=, srcip=, user=admin, desc=desc2, exact=site||||, all=|||, action=||||match, log=|||content||, precedence=5\n"
		"filter rule 14: sni=site2, dstport=, srcip=, user=admin, desc=desc2, exact=||||, all=|||, action=||||match, log=connect|||||, precedence=5\n"
		"filter rule 15: sni=site2, dstport=, srcip=, user=admin, desc=desc2, exact=||||, all=|||, action=||||match, log=|||content||, precedence=5\n"),
		"failed to parse rule: %s", s);
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
" user 0 root (exact)=\n"
"  desc exact:\n"
"   desc 0 desc1 (exact)=\n"
"    sni exact:\n"
"      0: site1 (exact, action=||||match, log=connect|||content||, precedence=5)\n"
"    sni substring:\n"
"      0: site2 (substring, action=||||match, log=connect|||content||, precedence=5)\n"
"  desc substring:\n"
"   desc 0 desc2 (substring)=\n"
"    sni exact:\n"
"      0: site1 (exact, action=||||match, log=connect|||content||, precedence=5)\n"
"    sni substring:\n"
"      0: site2 (substring, action=||||match, log=connect|||content||, precedence=5)\n"
"userdesc_filter_substring->\n"
" user 0 admin (substring)=\n"
"  desc exact:\n"
"   desc 0 desc1 (exact)=\n"
"    sni exact:\n"
"      0: site1 (exact, action=||||match, log=connect|||content||, precedence=5)\n"
"    sni substring:\n"
"      0: site2 (substring, action=||||match, log=connect|||content||, precedence=5)\n"
"  desc substring:\n"
"   desc 0 desc2 (substring)=\n"
"    sni exact:\n"
"      0: site1 (exact, action=||||match, log=connect|||content||, precedence=5)\n"
"    sni substring:\n"
"      0: site2 (substring, action=||||match, log=connect|||content||, precedence=5)\n"
"user_filter_exact->\n"
"user_filter_substring->\n"
"desc_filter_exact->\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"ip_filter_substring->\n"
"filter_all->\n"), "failed to translate rule: %s", s);
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(set_filter_rule_15)
{
	char *s;
	int rv;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	s = strdup("$users root admin*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$descs desc1 desc2*");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	s = strdup("$sites site1* site2");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	// Syntactically right, but semantically redundant/useless
	s = strdup("$ports 80* *");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	// check errors out if we add all log actions to the macro:
	// "../../src/check_pack.c:306: Message string too long"
	// Also, the compiler gives:
	// warning: string length ‘4186’ is greater than the length ‘4095’ ISO C99 compilers are required to support [-Woverlength-strings]
	// so use 1 log action only
	s = strdup("$logs pcap");
	rv = filter_macro_set(opts, s, 0);
	ck_assert_msg(rv == 0, "failed to set macro");
	free(s);

	conn_opts->user_auth = 1;

	s = strdup("from user $users desc $descs to cn $sites port $ports log $logs");
	rv = filter_rule_set(opts, conn_opts, "Match", s, 0);
	ck_assert_msg(rv == 1, "failed to parse rule");
	free(s);

	s = filter_rule_str(opts->filter_rules);
	ck_assert_msg(!strcmp(s,
		"filter rule 0: cn=site1, dstport=80, srcip=, user=root, desc=desc1, exact=|||user|desc, all=|||, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 1: cn=site1, dstport=, srcip=, user=root, desc=desc1, exact=|||user|desc, all=|||ports, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 2: cn=site2, dstport=80, srcip=, user=root, desc=desc1, exact=site|||user|desc, all=|||, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 3: cn=site2, dstport=, srcip=, user=root, desc=desc1, exact=site|||user|desc, all=|||ports, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 4: cn=site1, dstport=80, srcip=, user=root, desc=desc2, exact=|||user|, all=|||, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 5: cn=site1, dstport=, srcip=, user=root, desc=desc2, exact=|||user|, all=|||ports, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 6: cn=site2, dstport=80, srcip=, user=root, desc=desc2, exact=site|||user|, all=|||, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 7: cn=site2, dstport=, srcip=, user=root, desc=desc2, exact=site|||user|, all=|||ports, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 8: cn=site1, dstport=80, srcip=, user=admin, desc=desc1, exact=||||desc, all=|||, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 9: cn=site1, dstport=, srcip=, user=admin, desc=desc1, exact=||||desc, all=|||ports, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 10: cn=site2, dstport=80, srcip=, user=admin, desc=desc1, exact=site||||desc, all=|||, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 11: cn=site2, dstport=, srcip=, user=admin, desc=desc1, exact=site||||desc, all=|||ports, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 12: cn=site1, dstport=80, srcip=, user=admin, desc=desc2, exact=||||, all=|||, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 13: cn=site1, dstport=, srcip=, user=admin, desc=desc2, exact=||||, all=|||ports, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 14: cn=site2, dstport=80, srcip=, user=admin, desc=desc2, exact=site||||, all=|||, action=||||match, log=||||pcap|, precedence=6\n"
		"filter rule 15: cn=site2, dstport=, srcip=, user=admin, desc=desc2, exact=site||||, all=|||ports, action=||||match, log=||||pcap|, precedence=6\n"),
		"failed to parse rule: %s", s);
	free(s);

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	close(2);
	opts->filter = filter_set(opts->filter_rules, "sslproxy", tmp_opts);

	s = filter_str(opts->filter);
	ck_assert_msg(!strcmp(s, "filter=>\n"
"userdesc_filter_exact->\n"
" user 0 root (exact)=\n"
"  desc exact:\n"
"   desc 0 desc1 (exact)=\n"
"    cn exact:\n"
"      0: site2 (exact, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=||||pcap|, precedence=6)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=||||pcap|, precedence=6)\n"
"    cn substring:\n"
"      0: site1 (substring, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=||||pcap|, precedence=6)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=||||pcap|, precedence=6)\n"
"  desc substring:\n"
"   desc 0 desc2 (substring)=\n"
"    cn exact:\n"
"      0: site2 (exact, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=||||pcap|, precedence=6)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=||||pcap|, precedence=6)\n"
"    cn substring:\n"
"      0: site1 (substring, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=||||pcap|, precedence=6)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=||||pcap|, precedence=6)\n"
"userdesc_filter_substring->\n"
" user 0 admin (substring)=\n"
"  desc exact:\n"
"   desc 0 desc1 (exact)=\n"
"    cn exact:\n"
"      0: site2 (exact, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=||||pcap|, precedence=6)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=||||pcap|, precedence=6)\n"
"    cn substring:\n"
"      0: site1 (substring, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=||||pcap|, precedence=6)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=||||pcap|, precedence=6)\n"
"  desc substring:\n"
"   desc 0 desc2 (substring)=\n"
"    cn exact:\n"
"      0: site2 (exact, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=||||pcap|, precedence=6)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=||||pcap|, precedence=6)\n"
"    cn substring:\n"
"      0: site1 (substring, action=||||, log=|||||, precedence=0)\n"
"        port substring:\n"
"          0: 80 (substring, action=||||match, log=||||pcap|, precedence=6)\n"
"        port all:\n"
"          0:  (all_ports, substring, action=||||match, log=||||pcap|, precedence=6)\n"
"user_filter_exact->\n"
"user_filter_substring->\n"
"desc_filter_exact->\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"ip_filter_substring->\n"
"filter_all->\n"), "failed to translate rule: %s", s);
	free(s);

	opts_free(opts);
	conn_opts_free(conn_opts);
	tmp_opts_free(tmp_opts);
}
END_TEST
#endif /* !WITHOUT_USERAUTH */

Suite *
filter_suite(void)
{
	Suite *s;
	TCase *tc;
	s = suite_create("filter");

	tc = tcase_create("set_filter_rule");
	tcase_add_test(tc, set_filter_rule_01);
	tcase_add_test(tc, set_filter_rule_02);
#ifndef WITHOUT_USERAUTH
	tcase_add_test(tc, set_filter_rule_03);
#endif /* !WITHOUT_USERAUTH */
	tcase_add_test(tc, set_filter_rule_04);
	tcase_add_test(tc, set_filter_rule_05);
	tcase_add_test(tc, set_filter_rule_06);
#ifndef WITHOUT_USERAUTH
	tcase_add_test(tc, set_filter_rule_07);
#endif /* !WITHOUT_USERAUTH */
	tcase_add_test(tc, set_filter_rule_08);
	tcase_add_test(tc, set_filter_rule_09);
#ifndef WITHOUT_USERAUTH
	tcase_add_test(tc, set_filter_rule_10);
	tcase_add_test(tc, set_filter_rule_11);
	tcase_add_test(tc, set_filter_rule_12);
#endif /* !WITHOUT_USERAUTH */
	tcase_add_test(tc, set_filter_rule_13);
#ifndef WITHOUT_USERAUTH
	tcase_add_test(tc, set_filter_rule_14);
	tcase_add_test(tc, set_filter_rule_15);
#endif /* !WITHOUT_USERAUTH */
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
