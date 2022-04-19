/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
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

#include "util.h"

#include <string.h>

#include <check.h>

static const char *string01 = "test";
static const char *string02 = "    test";
static const char *string03 = "\t\t\t\ttest";
static const char *string04 = "\t \t test";
static const char *string05 = "    \r\ntest";

START_TEST(util_skipws_01)
{
	char *p;

	p = util_skipws(string01);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "test"), "wrong data");
}
END_TEST

START_TEST(util_skipws_02)
{
	char *p;

	p = util_skipws(string02);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "test"), "wrong data");
}
END_TEST

START_TEST(util_skipws_03)
{
	char *p;

	p = util_skipws(string03);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "test"), "wrong data");
}
END_TEST

START_TEST(util_skipws_04)
{
	char *p;

	p = util_skipws(string04);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "test"), "wrong data");
}
END_TEST

START_TEST(util_skipws_05)
{
	char *p;

	p = util_skipws(string05);
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, "\r\ntest"), "wrong data");
}
END_TEST

START_TEST(util_skipws_06)
{
	char *p;

	p = util_skipws("");
	fail_unless(!!p, "no pointer returned");
	fail_unless(!strcmp(p, ""), "wrong data");
}
END_TEST

START_TEST(util_get_first_word_len_01)
{
	size_t l;

	char array01[] = {'\0'};
	l = util_get_first_word_len(array01, sizeof(array01));
	fail_unless(l == 0, "wrong len for null = %zu", l);

	char array02[] = {' '};
	l = util_get_first_word_len(array02, sizeof(array02));
	fail_unless(l == 0, "wrong len for space = %zu", l);

	char array03[] = {'\t'};
	l = util_get_first_word_len(array03, sizeof(array03));
	fail_unless(l == 0, "wrong len for tab = %zu", l);

	char array04[] = {'\r'};
	l = util_get_first_word_len(array04, sizeof(array04));
	fail_unless(l == 0, "wrong len for cr = %zu", l);

	char array05[] = {'\n'};
	l = util_get_first_word_len(array05, sizeof(array05));
	fail_unless(l == 0, "wrong len for nl = %zu", l);

	char array06[] = {'\t', '\r', '\n'};
	l = util_get_first_word_len(array06, sizeof(array06));
	fail_unless(l == 0, "wrong len for space, tab, cr, nl = %zu", l);

	char array07[] = {'1'};
	l = util_get_first_word_len(array07, sizeof(array07));
	fail_unless(l == 1, "wrong len for 1 = %zu", l);

	char array08[] = {'1', ' '};
	l = util_get_first_word_len(array08, sizeof(array08));
	fail_unless(l == 1, "wrong len for 1, space = %zu", l);

	char array09[] = {'1', '\t'};
	l = util_get_first_word_len(array09, sizeof(array09));
	fail_unless(l == 1, "wrong len for 1, tab = %zu", l);

	char array10[] = {'1', '\r'};
	l = util_get_first_word_len(array10, sizeof(array10));
	fail_unless(l == 1, "wrong len for 1, cr = %zu", l);

	char array11[] = {'1', '\n'};
	l = util_get_first_word_len(array11, sizeof(array11));
	fail_unless(l == 1, "wrong len for 1, nl = %zu", l);

	char array12[] = {'1', ' ', '\t', '\r', '\n'};
	l = util_get_first_word_len(array12, sizeof(array12));
	fail_unless(l == 1, "wrong len for 1, space, tab, cr, nl = %zu", l);

	char array13[] = {'1', '\t', '\r', '\n'};
	l = util_get_first_word_len(array13, sizeof(array13));
	fail_unless(l == 1, "wrong len for 1, tab, cr, nl = %zu", l);

	char array14[] = {'1', '\r', '\n'};
	l = util_get_first_word_len(array14, sizeof(array14));
	fail_unless(l == 1, "wrong len for 1, cr, nl = %zu", l);

	char array15[] = {'1', '2', '\r', '\n'};
	l = util_get_first_word_len(array15, sizeof(array15));
	fail_unless(l == 2, "wrong len for 12, cr, nl = %zu", l);

	char array16[] = {'1', '2'};
	l = util_get_first_word_len(array16, sizeof(array16));
	fail_unless(l == 2, "wrong len for 12 = %zu", l);

	char array17[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
	l = util_get_first_word_len(array17, sizeof(array17));
	fail_unless(l == 10, "wrong len for 1234567890 = %zu", l);

	char array18[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '\r', '\n'};
	l = util_get_first_word_len(array18, sizeof(array18));
	fail_unless(l == 10, "wrong len for 1234567890, cr, nl = %zu", l);

	l = util_get_first_word_len(array18, 1);
	fail_unless(l == 1, "wrong len for size 1 in 1234567890, cr, nl = %zu", l);

	l = util_get_first_word_len(array18, 0);
	fail_unless(l == 0, "wrong len for size 0 in 1234567890, cr, nl = %zu", l);

	char array19[] = {'1', ' ', '2', '\r', '\n'};
	l = util_get_first_word_len(array19, sizeof(array19));
	fail_unless(l == 1, "wrong len for 1 2, cr, nl = %zu", l);

	char array20[] = {' ', '1'};
	l = util_get_first_word_len(array20, sizeof(array20));
	fail_unless(l == 0, "wrong len for space, 1 = %zu", l);
}
END_TEST

Suite *
util_suite(void)
{
	Suite *s;
	TCase *tc;

	s = suite_create("util");

	tc = tcase_create("util_skipws");
	tcase_add_test(tc, util_skipws_01);
	tcase_add_test(tc, util_skipws_02);
	tcase_add_test(tc, util_skipws_03);
	tcase_add_test(tc, util_skipws_04);
	tcase_add_test(tc, util_skipws_05);
	tcase_add_test(tc, util_skipws_06);
	suite_add_tcase(s, tc);

	tc = tcase_create("util_get_first_word_len");
	tcase_add_test(tc, util_get_first_word_len_01);
	suite_add_tcase(s, tc);

	return s;
}

/* vim: set noet ft=c: */
