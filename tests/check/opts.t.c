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

#include "attrib.h"
#include "opts.h"

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

static char *argv01[] = {
	"https", "127.0.0.1", "10443", "up:8080", "127.0.0.2", "443"
};
#ifndef TRAVIS
static char *argv02[] = {
	"https", "::1", "10443", "up:8080", "::2", "443"
};
#endif /* !TRAVIS */
static char *argv03[] = {
	"http", "127.0.0.1", "10443", "up:8080", "127.0.0.2", "443"
};
static char *argv04[] = {
	"ssl", "127.0.0.1", "10443", "up:8080", "127.0.0.2", "443"
};
static char *argv05[] = {
	"tcp", "127.0.0.1", "10443", "up:8080", "127.0.0.2", "443"
};
static char *argv06[] = {
	"https", "127.0.0.1", "10443", "up:8080", "sni", "443"
};
static char *argv07[] = {
	"http", "127.0.0.1", "10443", "up:8080", "sni", "443"
};
static char *argv08[] = {
	"https", "127.0.0.1", "10443", "up:8080", "no_such_engine"
};
#ifndef TRAVIS
static char *argv09[] = {
	"https", "127.0.0.1", "10443", "up:8080", "127.0.0.2", "443",
	"https", "::1", "10443", "up:8080", "::2", "443"
};
static char *argv10[] = {
	"https", "127.0.0.1", "10443", "up:8080",
	"https", "::1", "10443", "up:8080"
};
#endif /* !TRAVIS */
static char *argv11[] = {
	"autossl", "127.0.0.1", "10025", "up:8080"
};
static char *argv12[] = {
	"autossl", "127.0.0.1", "10025", "up:9199", "127.0.0.2", "25",
	"https", "127.0.0.1", "10443", "up:8080", "127.0.0.2", "443"
};
static char *argv13[] = {
	"autossl", "127.0.0.1", "10025", "up:9199", "sni", "25"
};
static char *argv14[] = {
	"https", "127.0.0.1", "10443", "up:8080",
	"autossl", "127.0.0.1", "10025", "up:9199", "127.0.0.2", "25"
};

#ifdef __linux__
#define NATENGINE "netfilter"
#else
#define NATENGINE "pf"
#endif

START_TEST(proxyspec_parse_01)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv01;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

#ifndef TRAVIS
START_TEST(proxyspec_parse_02)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv02;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST
#endif /* !TRAVIS */

START_TEST(proxyspec_parse_03)
{
	global_t *global = global_new();
	int argc = 2;
	char **argv = argv01;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_04)
{
	global_t *global = global_new();
	int argc = 5;
	char **argv = argv01;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_05)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv03;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(!spec->ssl, "SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_06)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv04;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(!spec->http, "HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_07)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv05;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(!spec->ssl, "SSL");
	fail_unless(!spec->http, "HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_08)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv06;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(!spec->connect_addrlen, "connect addr set");
	fail_unless(spec->sni_port == 443, "SNI port is not set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_09)
{
	global_t *global = global_new();
	int argc = 5;
	char **argv = argv07;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_10)
{
	global_t *global = global_new();
	int argc = 5;
	char **argv = argv06;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_11)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 4;
	char **argv = argv08;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(!spec->connect_addrlen, "connect addr set");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!!spec->natengine, "natengine not set");
	fail_unless(!strcmp(spec->natengine, NATENGINE), "natengine mismatch");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_12)
{
	global_t *global = global_new();
	int argc = 5;
	char **argv = argv08;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

#ifndef TRAVIS
START_TEST(proxyspec_parse_13)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 12;
	char **argv = argv09;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!!spec->next, "next is not set");
	fail_unless(spec->next->ssl, "not SSL");
	fail_unless(spec->next->http, "not HTTP");
	fail_unless(!spec->next->upgrade, "Upgrade");
	fail_unless(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->next->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->next->sni_port, "SNI port is set");
	fail_unless(!spec->next->natengine, "natengine is set");
	fail_unless(!spec->next->natlookup, "natlookup() is set");
	fail_unless(!spec->next->natsocket, "natsocket() is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_14)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 8;
	char **argv = argv10;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in6),
	            "not IPv6 listen addr");
	fail_unless(!spec->connect_addrlen, "connect addr set");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!!spec->natengine, "natengine not set");
	fail_unless(!strcmp(spec->natengine, NATENGINE), "natengine mismatch");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!!spec->next, "next is not set");
	fail_unless(spec->next->ssl, "not SSL");
	fail_unless(spec->next->http, "not HTTP");
	fail_unless(!spec->next->upgrade, "Upgrade");
	fail_unless(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(!spec->next->connect_addrlen, "connect addr set");
	fail_unless(!spec->next->sni_port, "SNI port is set");
	fail_unless(!!spec->next->natengine, "natengine not set");
	fail_unless(!strcmp(spec->next->natengine, NATENGINE),
	            "natengine mismatch");
	fail_unless(!spec->next->natlookup, "natlookup() is set");
	fail_unless(!spec->next->natsocket, "natsocket() is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST
#endif /* !TRAVIS */

START_TEST(proxyspec_parse_15)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 4;
	char **argv = argv11;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(!spec->ssl, "SSL");
	fail_unless(!spec->http, "HTTP");
	fail_unless(spec->upgrade, "not Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(!spec->connect_addrlen, "connect addr set");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!!spec->natengine, "natengine is not set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!spec->next, "next is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_16)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 12;
	char **argv = argv12;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(spec->ssl, "not SSL");
	fail_unless(spec->http, "not HTTP");
	fail_unless(!spec->upgrade, "Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!!spec->next, "next is not set");
	fail_unless(!spec->next->ssl, "SSL");
	fail_unless(!spec->next->http, "HTTP");
	fail_unless(spec->next->upgrade, "not Upgrade");
	fail_unless(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->next->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->next->sni_port, "SNI port is set");
	fail_unless(!spec->next->natengine, "natengine is set");
	fail_unless(!spec->next->natlookup, "natlookup() is set");
	fail_unless(!spec->next->natsocket, "natsocket() is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_17)
{
	global_t *global = global_new();
	int argc = 6;
	char **argv = argv13;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	close(2);
	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_parse_18)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 10;
	char **argv = argv14;

	tmp_global_opts_t *tmp_global_opts = malloc(sizeof(tmp_global_opts_t));
	memset(tmp_global_opts, 0, sizeof(tmp_global_opts_t));

	proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_global_opts);
	spec = global->spec;
	fail_unless(!!spec, "failed to parse spec");
	fail_unless(!spec->ssl, "SSL");
	fail_unless(!spec->http, "HTTP");
	fail_unless(spec->upgrade, "not Upgrade");
	fail_unless(spec->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(spec->connect_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 connect addr");
	fail_unless(!spec->sni_port, "SNI port is set");
	fail_unless(!spec->natengine, "natengine is set");
	fail_unless(!spec->natlookup, "natlookup() is set");
	fail_unless(!spec->natsocket, "natsocket() is set");
	fail_unless(!!spec->next, "next is not set");
	fail_unless(spec->next->ssl, "not SSL");
	fail_unless(spec->next->http, "not HTTP");
	fail_unless(!spec->next->upgrade, "Upgrade");
	fail_unless(spec->next->listen_addrlen == sizeof(struct sockaddr_in),
	            "not IPv4 listen addr");
	fail_unless(!spec->next->connect_addrlen, "connect addr set");
	fail_unless(!spec->next->sni_port, "SNI port is set");
	fail_unless(!!spec->next->natengine, "natengine is not set");
	fail_unless(!spec->next->natlookup, "natlookup() is set");
	fail_unless(!spec->next->natsocket, "natsocket() is set");
	global_free(global);
	tmp_global_opts_free(tmp_global_opts);
}
END_TEST

START_TEST(proxyspec_set_proto_01)
{
	global_t *global = global_new();
	proxyspec_t *spec  = proxyspec_new(global, "sslproxy", NULL);

	proxyspec_set_proto(spec, "tcp");
	fail_unless(!spec->ssl, "ssl set in tcp spec");
	fail_unless(!spec->http, "http set in tcp spec");
	fail_unless(!spec->upgrade, "upgrade set in tcp spec");
	fail_unless(!spec->pop3, "pop3 set in tcp spec");
	fail_unless(!spec->smtp, "smtp set in tcp spec");

	proxyspec_set_proto(spec, "ssl");
	fail_unless(spec->ssl, "ssl not set in ssl spec");
	fail_unless(!spec->http, "http set in ssl spec");
	fail_unless(!spec->upgrade, "upgrade set in ssl spec");
	fail_unless(!spec->pop3, "pop3 set in ssl spec");
	fail_unless(!spec->smtp, "smtp set in ssl spec");

	proxyspec_set_proto(spec, "http");
	fail_unless(!spec->ssl, "ssl set in http spec");
	fail_unless(spec->http, "http not set in http spec");
	fail_unless(!spec->upgrade, "upgrade set in http spec");
	fail_unless(!spec->pop3, "pop3 set in http spec");
	fail_unless(!spec->smtp, "smtp set in http spec");

	proxyspec_set_proto(spec, "https");
	fail_unless(spec->ssl, "ssl not set in https spec");
	fail_unless(spec->http, "http not set in https spec");
	fail_unless(!spec->upgrade, "upgrade set in https spec");
	fail_unless(!spec->pop3, "pop3 set in https spec");
	fail_unless(!spec->smtp, "smtp set in https spec");

	proxyspec_set_proto(spec, "autossl");
	fail_unless(!spec->ssl, "ssl set in autossl spec");
	fail_unless(!spec->http, "http set in autossl spec");
	fail_unless(spec->upgrade, "upgrade not set in autossl spec");
	fail_unless(!spec->pop3, "pop3 set in autossl spec");
	fail_unless(!spec->smtp, "smtp set in autossl spec");

	proxyspec_set_proto(spec, "pop3");
	fail_unless(!spec->ssl, "ssl set in pop3 spec");
	fail_unless(!spec->http, "http set in pop3 spec");
	fail_unless(!spec->upgrade, "upgrade set in pop3 spec");
	fail_unless(spec->pop3, "pop3 not set in pop3 spec");
	fail_unless(!spec->smtp, "smtp set in pop3 spec");

	proxyspec_set_proto(spec, "pop3s");
	fail_unless(spec->ssl, "ssl not set in pop3s spec");
	fail_unless(!spec->http, "http set in pop3s spec");
	fail_unless(!spec->upgrade, "upgrade set in pop3s spec");
	fail_unless(spec->pop3, "pop3 not set in pop3s spec");
	fail_unless(!spec->smtp, "smtp set in pop3s spec");

	proxyspec_set_proto(spec, "smtp");
	fail_unless(!spec->ssl, "ssl set in smtp spec");
	fail_unless(!spec->http, "http set in smtp spec");
	fail_unless(!spec->upgrade, "upgrade set in smtp spec");
	fail_unless(!spec->pop3, "pop3 set in smtp spec");
	fail_unless(spec->smtp, "smtp not set in smtp spec");

	proxyspec_set_proto(spec, "smtps");
	fail_unless(spec->ssl, "ssl not set in smtps spec");
	fail_unless(!spec->http, "http set in smtps spec");
	fail_unless(!spec->upgrade, "upgrade set in smtps spec");
	fail_unless(!spec->pop3, "pop3 set in smtps spec");
	fail_unless(spec->smtp, "smtp not set in smtps spec");

	proxyspec_free(spec);
}
END_TEST

START_TEST(opts_debug_01)
{
	global_t *global = global_new();

	global->debug = 0;
	fail_unless(!global->debug, "plain 0");
	fail_unless(!OPTS_DEBUG(global), "macro 0");
	global->debug = 1;
	fail_unless(!!global->debug, "plain 1");
	fail_unless(!!OPTS_DEBUG(global), "macro 1");
	global_free(global);
}
END_TEST

START_TEST(opts_set_passsite_01)
{
	char *ps;
	opts_t *opts = opts_new();

	char *s = strdup("example.com");
	opts_set_passsite(opts, s, 0);
	free(s);

	fail_unless(!strcmp(opts->filter_rules->site, "example.com"), "site not example.com");
	fail_unless(!opts->filter_rules->ip, "ip set");
#ifndef WITHOUT_USERAUTH
	fail_unless(!opts->filter_rules->user, "user set");
	fail_unless(opts->filter_rules->all_conns, "all_conns not 1");
	fail_unless(!opts->filter_rules->keyword, "keyword set");
#endif /* !WITHOUT_USERAUTH */
	fail_unless(!opts->filter_rules->next, "next set");

	ps = filter_rule_str(opts->filter_rules);
#ifndef WITHOUT_USERAUTH
	fail_unless(!strcmp(ps, "filter rule 0: site=example.com, exact, ip=, user=, keyword=, all=conns||, action=||pass||, log=|||||, apply to=|sni|cn||"), "failed parsing passite example.com: %s", ps);
#else /* WITHOUT_USERAUTH */
	fail_unless(!strcmp(ps, "filter rule 0: site=example.com, exact, ip=, all=conns|, action=||pass||, log=|||||, apply to=|sni|cn||"), "failed parsing passite example.com: %s", ps);
#endif /* WITHOUT_USERAUTH */
	free(ps);

	opts_free(opts);
}
END_TEST

START_TEST(opts_set_passsite_02)
{
	char *ps;
	opts_t *opts = opts_new();

	char *s = strdup("example.com 192.168.0.1");
	opts_set_passsite(opts, s, 0);
	free(s);

	fail_unless(!strcmp(opts->filter_rules->site, "example.com"), "site not example.com");
	fail_unless(!strcmp(opts->filter_rules->ip, "192.168.0.1"), "ip not 192.168.0.1");
#ifndef WITHOUT_USERAUTH
	fail_unless(!opts->filter_rules->user, "user set");
	fail_unless(!opts->filter_rules->all_conns, "all_conns not 0");
	fail_unless(!opts->filter_rules->keyword, "keyword set");
#endif /* !WITHOUT_USERAUTH */
	fail_unless(!opts->filter_rules->next, "next set");

	ps = filter_rule_str(opts->filter_rules);
#ifndef WITHOUT_USERAUTH
	fail_unless(!strcmp(ps, "filter rule 0: site=example.com, exact, ip=192.168.0.1, user=, keyword=, all=||, action=||pass||, log=|||||, apply to=|sni|cn||"), "failed parsing passite example.com 192.168.0.1: %s", ps);
#else /* WITHOUT_USERAUTH */
	fail_unless(!strcmp(ps, "filter rule 0: site=example.com, exact, ip=192.168.0.1, all=|, action=||pass||, log=|||||, apply to=|sni|cn||"), "failed parsing passite example.com 192.168.0.1: %s", ps);
#endif /* !WITHOUT_USERAUTH */
	free(ps);

	opts_free(opts);
}
END_TEST

#ifndef WITHOUT_USERAUTH
START_TEST(opts_set_passsite_03)
{
	char *ps;
	opts_t *opts = opts_new();

	opts->user_auth = 1;

	char *s = strdup("example.com root");
	opts_set_passsite(opts, s, 0);
	free(s);

	fail_unless(!strcmp(opts->filter_rules->site, "example.com"), "site not example.com");
	fail_unless(!opts->filter_rules->ip, "ip set");
	fail_unless(!strcmp(opts->filter_rules->user, "root"), "user not root");
	fail_unless(!opts->filter_rules->all_conns, "all_conns not 0");
	fail_unless(!opts->filter_rules->keyword, "keyword set");
	fail_unless(!opts->filter_rules->next, "next set");

	ps = filter_rule_str(opts->filter_rules);
	fail_unless(!strcmp(ps, "filter rule 0: site=example.com, exact, ip=, user=root, keyword=, all=||, action=||pass||, log=|||||, apply to=|sni|cn||"), "failed parsing passite example.com root: %s", ps);
	free(ps);

	opts_free(opts);
}
END_TEST

START_TEST(opts_set_passsite_04)
{
	char *ps;
	opts_t *opts = opts_new();

	opts->user_auth = 1;

	char *s = strdup("*.google.com * android");
	opts_set_passsite(opts, s, 0);
	free(s);

	fail_unless(!strcmp(opts->filter_rules->site, "*.google.com"), "site not *.google.com");
	fail_unless(!opts->filter_rules->ip, "ip set");
	fail_unless(!opts->filter_rules->user, "user set");
	fail_unless(!opts->filter_rules->all_conns, "all_conns not 0");
	fail_unless(opts->filter_rules->all_users, "all_users not 1");
	fail_unless(!strcmp(opts->filter_rules->keyword, "android"), "keyword not android");
	fail_unless(!opts->filter_rules->next, "next set");

	ps = filter_rule_str(opts->filter_rules);
	fail_unless(!strcmp(ps, "filter rule 0: site=*.google.com, exact, ip=, user=, keyword=android, all=|users|, action=||pass||, log=|||||, apply to=|sni|cn||"), "failed parsing passite *.google.com * android: %s", ps);
	free(ps);

	opts_free(opts);
}
END_TEST
#endif /* !WITHOUT_USERAUTH */

START_TEST(opts_set_passsite_05)
{
	char *ps;
	char *s;
	opts_t *opts = opts_new();

	// Dup string using strdup(), otherwise strtok_r() in opts_set_passsite() will cause segmentation fault
	s = strdup("example.com");
	opts_set_passsite(opts, s, 0);
	free(s);
	fail_unless(!opts->filter_rules->next, "next set");

	s = strdup("example.com *");
	opts_set_passsite(opts, s, 1);
	free(s);
	fail_unless(opts->filter_rules->next, "next not set");
	fail_unless(!opts->filter_rules->next->next, "next->next set");

	s = strdup("example.com 192.168.0.1");
	opts_set_passsite(opts, s, 2);
	free(s);
	fail_unless(opts->filter_rules->next, "next not set");
	fail_unless(opts->filter_rules->next->next, "next->next not set");
	fail_unless(!opts->filter_rules->next->next->next, "next->next->next set");

#ifndef WITHOUT_USERAUTH
	opts->user_auth = 1;
	// Use root user, opts_set_passsite() calls sys_isuser() to validate the user
	s = strdup("example.com root");
	opts_set_passsite(opts, s, 3);
	free(s);
	fail_unless(opts->filter_rules->next, "next not set");
	fail_unless(opts->filter_rules->next->next, "next->next not set");
	fail_unless(opts->filter_rules->next->next->next, "next->next->next not set");
	fail_unless(!opts->filter_rules->next->next->next->next, "next->next->next->next set");

	s = strdup("*.google.com * android");
	opts_set_passsite(opts, s, 4);
	free(s);
#endif /* !WITHOUT_USERAUTH */
	ps = filter_rule_str(opts->filter_rules);
	fail_unless(opts->filter_rules->next, "next not set");
	fail_unless(opts->filter_rules->next->next, "next->next not set");
#ifndef WITHOUT_USERAUTH
	fail_unless(opts->filter_rules->next->next->next, "next->next->next not set");
	fail_unless(opts->filter_rules->next->next->next->next, "next->next->next->next not set");
	fail_unless(!opts->filter_rules->next->next->next->next->next, "next->next->next->next->next set");
	fail_unless(!strcmp(ps, "filter rule 0: site=*.google.com, exact, ip=, user=, keyword=android, all=|users|, action=||pass||, log=|||||, apply to=|sni|cn||\n"
		"filter rule 1: site=example.com, exact, ip=, user=root, keyword=, all=||, action=||pass||, log=|||||, apply to=|sni|cn||\n"
		"filter rule 2: site=example.com, exact, ip=192.168.0.1, user=, keyword=, all=||, action=||pass||, log=|||||, apply to=|sni|cn||\n"
		"filter rule 3: site=example.com, exact, ip=, user=, keyword=, all=|users|, action=||pass||, log=|||||, apply to=|sni|cn||\n"
		"filter rule 4: site=example.com, exact, ip=, user=, keyword=, all=conns||, action=||pass||, log=|||||, apply to=|sni|cn||"),
		"failed parsing multiple passites: %s", ps);
#else /* WITHOUT_USERAUTH */
	fail_unless(!opts->filter_rules->next->next->next, "next->next->next set");
	fail_unless(!strcmp(ps, "filter rule 0: site=example.com, exact, ip=192.168.0.1, all=|, action=||pass||, log=|||||, apply to=|sni|cn||\n"
		"filter rule 1: site=example.com, exact, ip=, all=conns|, action=||pass||, log=|||||, apply to=|sni|cn||\n"
		"filter rule 2: site=example.com, exact, ip=, all=conns|, action=||pass||, log=|||||, apply to=|sni|cn||"),
		"failed parsing multiple passites: %s", ps);
#endif /* WITHOUT_USERAUTH */
	free(ps);

	opts_free(opts);
}
END_TEST

START_TEST(opts_is_yesno_01)
{
	int yes;

	yes = is_yesno("yes");
	fail_unless(yes == 1, "failed yes");

	yes = is_yesno("ye");
	fail_unless(yes == -1, "failed ye");

	yes = is_yesno("yes1");
	fail_unless(yes == -1, "failed yes1");

	yes = is_yesno("");
	fail_unless(yes == -1, "failed empty string");
}
END_TEST

START_TEST(opts_is_yesno_02)
{
	int yes;

	yes = is_yesno("no");
	fail_unless(yes == 0, "failed no");

	yes = is_yesno("n");
	fail_unless(yes == -1, "failed n");

	yes = is_yesno("no1");
	fail_unless(yes == -1, "failed no1");
}
END_TEST

START_TEST(opts_get_name_value_01)
{
	int retval;
	char *name;
	char *value;
	
	name = strdup("Name Value");
	retval = get_name_value(&name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);
	
	name = strdup("Name  Value");
	retval = get_name_value(&name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);

	// Leading white space must be handled by the caller,
	// so we don't have a test for " Name Value", or similar
	
	name = strdup("Name Value ");
	retval = get_name_value(&name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);
	
	name = strdup("Name=Value");
	retval = get_name_value(&name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);
	
	name = strdup("Name=Value ");
	retval = get_name_value(&name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);
	
	name = strdup("Name = Value");
	retval = get_name_value(&name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);
	
	name = strdup("Name = Value ");
	retval = get_name_value(&name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);
	
	name = strdup("Name");
	retval = get_name_value(&name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(retval == -1, "failed rejecting just name");
	free(name);

	name = strdup("Name ");
	retval = get_name_value(&name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name  ");
	retval = get_name_value(&name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name=");
	retval = get_name_value(&name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name= ");
	retval = get_name_value(&name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name =");
	retval = get_name_value(&name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name = ");
	retval = get_name_value(&name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);
}
END_TEST

Suite *
opts_suite(void)
{
	Suite *s;
	TCase *tc;
	s = suite_create("opts");

	tc = tcase_create("proxyspec_parse");
	tcase_add_test(tc, proxyspec_parse_01);
#ifndef TRAVIS
	tcase_add_test(tc, proxyspec_parse_02); /* IPv6 */
#endif /* !TRAVIS */
	tcase_add_exit_test(tc, proxyspec_parse_03, EXIT_FAILURE);
	tcase_add_exit_test(tc, proxyspec_parse_04, EXIT_FAILURE);
	tcase_add_test(tc, proxyspec_parse_05);
	tcase_add_test(tc, proxyspec_parse_06);
	tcase_add_test(tc, proxyspec_parse_07);
	tcase_add_test(tc, proxyspec_parse_08);
	tcase_add_exit_test(tc, proxyspec_parse_09, EXIT_FAILURE);
	tcase_add_exit_test(tc, proxyspec_parse_10, EXIT_FAILURE);
	tcase_add_test(tc, proxyspec_parse_11);
	tcase_add_exit_test(tc, proxyspec_parse_12, EXIT_FAILURE);
#ifndef TRAVIS
	tcase_add_test(tc, proxyspec_parse_13); /* IPv6 */
	tcase_add_test(tc, proxyspec_parse_14); /* IPv6 */
#endif /* !TRAVIS */
	tcase_add_test(tc, proxyspec_parse_15);
	tcase_add_test(tc, proxyspec_parse_16);
	tcase_add_exit_test(tc, proxyspec_parse_17, EXIT_FAILURE);
	tcase_add_test(tc, proxyspec_parse_18);
	tcase_add_test(tc, proxyspec_set_proto_01);
	suite_add_tcase(s, tc);

	tc = tcase_create("opts_config");
	tcase_add_test(tc, opts_debug_01);
	tcase_add_test(tc, opts_set_passsite_01);
	tcase_add_test(tc, opts_set_passsite_02);
#ifndef WITHOUT_USERAUTH
	tcase_add_test(tc, opts_set_passsite_03);
	tcase_add_test(tc, opts_set_passsite_04);
#endif /* !WITHOUT_USERAUTH */
	tcase_add_test(tc, opts_set_passsite_05);
	tcase_add_test(tc, opts_is_yesno_01);
	tcase_add_test(tc, opts_is_yesno_02);
	tcase_add_test(tc, opts_get_name_value_01);
	suite_add_tcase(s, tc);

#ifdef TRAVIS
	fprintf(stderr, "opts: 3 tests omitted because building in travis\n");
#endif

	return s;
}

/* vim: set noet ft=c: */
