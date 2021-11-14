/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2021, Soner Tari <sonertari@gmail.com>.
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER))
#ifdef HAVE_TLSV13
#define SSL_PROTO_CONFIG_PROXYSPEC "tls13 -tls13>=tls11<=tls12|no sslcomp|no_tls13"
#define SSL_PROTO_CONFIG_FILTERRULE "tls13 -tls13>=tls10<=tls11|no_tls13"
#else
#define SSL_PROTO_CONFIG_PROXYSPEC "tls12 -tls10>=tls11<=tls12|no sslcomp|no_tls10"
#define SSL_PROTO_CONFIG_FILTERRULE "tls12>=tls10<=tls11"
#endif /* HAVE_TLSV13 */
#elif (OPENSSL_VERSION_NUMBER < 0x10000000L)
#define SSL_PROTO_CONFIG_PROXYSPEC "tls10 -tls10|no_tls10"
#define SSL_PROTO_CONFIG_FILTERRULE "tls10"
#elif (OPENSSL_VERSION_NUMBER <= 0x1000013fL)
#define SSL_PROTO_CONFIG_PROXYSPEC "tls10 -tls10|no sslcomp|no_tls10"
#define SSL_PROTO_CONFIG_FILTERRULE "tls10"
#elif (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x20702000L)
#define SSL_PROTO_CONFIG_PROXYSPEC "tls12 -tls10>=tls11<=tls12|no sslcomp|no_tls10"
#define SSL_PROTO_CONFIG_FILTERRULE "tls12>=tls10<=tls11"
#else
#define SSL_PROTO_CONFIG_PROXYSPEC "tls12 -tls10|no sslcomp|no_tls10"
#define SSL_PROTO_CONFIG_FILTERRULE "tls12"
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

#ifdef HAVE_TLSV13
#define	FORCE_SSL_PROTO	"tls13"
#elif defined(HAVE_TLSV12)
#define	FORCE_SSL_PROTO	"tls12"
#elif defined(HAVE_TLSV11)
#define	FORCE_SSL_PROTO	"tls11"
#else
#define	FORCE_SSL_PROTO	"tls10"
#endif

#ifndef OPENSSL_NO_ECDH
#define	ECDH_PRIME1 "prime256v1|"
#define	ECDH_PRIME2 "prime192v1|"
#else
#define	ECDH_PRIME1 ""
#define	ECDH_PRIME2 ""
#endif /* !OPENSSL_NO_ECDH */

START_TEST(proxyspec_parse_01)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv01;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

#ifndef TRAVIS
START_TEST(proxyspec_parse_02)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv02;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST
#endif /* !TRAVIS */

START_TEST(proxyspec_parse_03)
{
	global_t *global = global_new();
	int argc = 2;
	char **argv = argv01;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	// Disable error messages
	close(2);

	int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
	fail_unless(rv == -1, "failed to reject spec");

	argc = 5;
	rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
	fail_unless(rv == -1, "failed to reject spec");

	argc = 5;
	argv = argv07;
	rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
	fail_unless(rv == -1, "failed to reject spec");

	argc = 5;
	argv = argv06;
	rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
	fail_unless(rv == -1, "failed to reject spec");

	argc = 5;
	argv = argv08;
	rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
	fail_unless(rv == -1, "failed to reject spec");

	argc = 6;
	argv = argv13;
	rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
	fail_unless(rv == -1, "failed to reject spec");

	global_free(global);
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_parse_04)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv03;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_parse_05)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv04;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_parse_06)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv05;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_parse_07)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 6;
	char **argv = argv06;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_parse_08)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 4;
	char **argv = argv08;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

#ifndef TRAVIS
START_TEST(proxyspec_parse_09)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 12;
	char **argv = argv09;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_parse_10)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 8;
	char **argv = argv10;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST
#endif /* !TRAVIS */

START_TEST(proxyspec_parse_11)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 4;
	char **argv = argv11;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_parse_12)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 12;
	char **argv = argv12;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_parse_13)
{
	global_t *global = global_new();
	proxyspec_t *spec = NULL;
	int argc = 10;
	char **argv = argv14;

	tmp_opts_t *tmp_opts = malloc(sizeof(tmp_opts_t));
	memset(tmp_opts, 0, sizeof(tmp_opts_t));

	UNUSED int rv = proxyspec_parse(&argc, &argv, NATENGINE, global, "sslproxy", tmp_opts);
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
	tmp_opts_free(tmp_opts);
}
END_TEST

START_TEST(proxyspec_set_proto_01)
{
	global_t *global = global_new();
	proxyspec_t *spec  = proxyspec_new(global, "sslproxy", NULL);

	UNUSED int rv = proxyspec_set_proto(spec, "tcp");
	fail_unless(!spec->ssl, "ssl set in tcp spec");
	fail_unless(!spec->http, "http set in tcp spec");
	fail_unless(!spec->upgrade, "upgrade set in tcp spec");
	fail_unless(!spec->pop3, "pop3 set in tcp spec");
	fail_unless(!spec->smtp, "smtp set in tcp spec");

	rv = proxyspec_set_proto(spec, "ssl");
	fail_unless(spec->ssl, "ssl not set in ssl spec");
	fail_unless(!spec->http, "http set in ssl spec");
	fail_unless(!spec->upgrade, "upgrade set in ssl spec");
	fail_unless(!spec->pop3, "pop3 set in ssl spec");
	fail_unless(!spec->smtp, "smtp set in ssl spec");

	rv = proxyspec_set_proto(spec, "http");
	fail_unless(!spec->ssl, "ssl set in http spec");
	fail_unless(spec->http, "http not set in http spec");
	fail_unless(!spec->upgrade, "upgrade set in http spec");
	fail_unless(!spec->pop3, "pop3 set in http spec");
	fail_unless(!spec->smtp, "smtp set in http spec");

	rv = proxyspec_set_proto(spec, "https");
	fail_unless(spec->ssl, "ssl not set in https spec");
	fail_unless(spec->http, "http not set in https spec");
	fail_unless(!spec->upgrade, "upgrade set in https spec");
	fail_unless(!spec->pop3, "pop3 set in https spec");
	fail_unless(!spec->smtp, "smtp set in https spec");

	rv = proxyspec_set_proto(spec, "autossl");
	fail_unless(!spec->ssl, "ssl set in autossl spec");
	fail_unless(!spec->http, "http set in autossl spec");
	fail_unless(spec->upgrade, "upgrade not set in autossl spec");
	fail_unless(!spec->pop3, "pop3 set in autossl spec");
	fail_unless(!spec->smtp, "smtp set in autossl spec");

	rv = proxyspec_set_proto(spec, "pop3");
	fail_unless(!spec->ssl, "ssl set in pop3 spec");
	fail_unless(!spec->http, "http set in pop3 spec");
	fail_unless(!spec->upgrade, "upgrade set in pop3 spec");
	fail_unless(spec->pop3, "pop3 not set in pop3 spec");
	fail_unless(!spec->smtp, "smtp set in pop3 spec");

	rv = proxyspec_set_proto(spec, "pop3s");
	fail_unless(spec->ssl, "ssl not set in pop3s spec");
	fail_unless(!spec->http, "http set in pop3s spec");
	fail_unless(!spec->upgrade, "upgrade set in pop3s spec");
	fail_unless(spec->pop3, "pop3 not set in pop3s spec");
	fail_unless(!spec->smtp, "smtp set in pop3s spec");

	rv = proxyspec_set_proto(spec, "smtp");
	fail_unless(!spec->ssl, "ssl set in smtp spec");
	fail_unless(!spec->http, "http set in smtp spec");
	fail_unless(!spec->upgrade, "upgrade set in smtp spec");
	fail_unless(!spec->pop3, "pop3 set in smtp spec");
	fail_unless(spec->smtp, "smtp not set in smtp spec");

	rv = proxyspec_set_proto(spec, "smtps");
	fail_unless(spec->ssl, "ssl not set in smtps spec");
	fail_unless(!spec->http, "http set in smtps spec");
	fail_unless(!spec->upgrade, "upgrade set in smtps spec");
	fail_unless(!spec->pop3, "pop3 set in smtps spec");
	fail_unless(spec->smtp, "smtp not set in smtps spec");

	proxyspec_free(spec);
	global_free(global);
}
END_TEST

START_TEST(proxyspec_struct_parse_01)
{
	char *s;
	int rv;
	global_t *global = global_new();

	tmp_opts_t *tmp_opts = malloc(sizeof (tmp_opts_t));
	memset(tmp_opts, 0, sizeof (tmp_opts_t));

	FILE *f;
	unsigned int line_num = 0;

	s =
		"Proto https     # inline\n"
		"Addr 127.0.0.1  # comments\n"
		"Port 8213       # supported\n"
		"DivertPort 8080\n"
		"DivertAddr 192.168.1.1\n"
		"ReturnAddr 192.168.2.1\n"
		"TargetAddr 127.0.0.1\n"
		"TargetPort 9213\n"
		"Divert yes\n"
		"NatEngine "NATENGINE"\n"
		"SNIPort 4444\n"
		"\n"
		"# FilterRule below should override these options\n"
		"DenyOCSP yes\n"
		"Passthrough no\n"
		"CACert ../testproxy/ca2.crt\n"
		"CAKey ../testproxy/ca2.key\n"
		"ClientCert ../testproxy/ca.crt\n"
		"ClientKey ../testproxy/ca.key\n"
		"CAChain ../testproxy/server2.crt\n"
		"LeafCRLURL http://example2.com/example2.crl\n"
		"#DHGroupParams /etc/sslproxy/dh.pem\n"
#ifndef OPENSSL_NO_ECDH
		"ECDHCurve prime256v1\n"
#endif /* !OPENSSL_NO_ECDH */
#ifdef SSL_OP_NO_COMPRESSION
		"SSLCompression no\n"
#endif /* SSL_OP_NO_COMPRESSION */
		"ForceSSLProto "FORCE_SSL_PROTO"\n"
#ifdef HAVE_TLSV13
		"DisableSSLProto tls13\n"
#else
		"DisableSSLProto tls1\n"
#endif /* HAVE_TLSV13 */
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x20702000L)
		"MinSSLProto tls11\n"
		"MaxSSLProto tls12\n"
#endif
		"Ciphers MEDIUM:HIGH\n"
		"CipherSuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256\n"
		"RemoveHTTPAcceptEncoding yes\n"
		"RemoveHTTPReferer yes\n"
		"VerifyPeer yes\n"
		"AllowWrongHost no\n"
#ifndef WITHOUT_USERAUTH
		"UserAuth yes\n"
		"UserTimeout 300\n"
		"UserAuthURL https://192.168.0.13/userdblogin3.php\n"
		"\n"
		"DivertUsers root daemon\n"
		"PassUsers root daemon\n"
#endif /* !WITHOUT_USERAUTH */
		"ValidateProto yes\n"
		"MaxHTTPHeaderSize 2048\n"
		"\n"
		"PassSite example4.com\n"
		"\n"
		"Define $ip 127.0.0.1\n"
		"Match from ip $ip to ip 127.0.0.1 port 9191 log content\n"
		"Block from ip $ip to ip 127.0.0.1 port 9191 log content\n"
		"Pass from ip $ip to ip 127.0.0.1 port 9191 log content\n"
		"Split from ip $ip to ip 127.0.0.1 port 9191 log content\n"
		"Divert from ip $ip to ip 127.0.0.1 port 9191 log content\n"
		"\n"
		"FilterRule {\n"
			"Action Match       # inline\n"
			"SrcIp 192.168.0.1  # comments\n"
			"DstIp 192.168.0.2  # supported\n"
			"Log connect\n"
			"ReconnectSSL yes\n"
			"DenyOCSP no\n"
			"Passthrough yes\n"
			"CACert ../testproxy/ca.crt\n"
			"CAKey ../testproxy/ca.key\n"
			"ClientCert ../testproxy/ca2.crt\n"
			"ClientKey ../testproxy/ca2.key\n"
			"CAChain ../testproxy/server.crt\n"
			"LeafCRLURL http://example1.com/example1.crl\n"
			"#DHGroupParams /etc/sslproxy/dh.pem\n"
#ifndef OPENSSL_NO_ECDH
			"ECDHCurve prime192v1\n"
#endif /* !OPENSSL_NO_ECDH */
#ifdef SSL_OP_NO_COMPRESSION
			"SSLCompression yes\n"
#endif /* SSL_OP_NO_COMPRESSION */
			"ForceSSLProto "FORCE_SSL_PROTO"\n"
#ifdef HAVE_TLSV13
			"DisableSSLProto tls13\n"
#else
			"DisableSSLProto tls1\n"
#endif /* HAVE_TLSV13 */
			"EnableSSLProto tls1\n"
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x20702000L)
			"MinSSLProto tls10\n"
			"MaxSSLProto tls11\n"
#endif
			"Ciphers LOW\n"
			"CipherSuites TLS_AES_128_CCM_SHA256\n"
			"RemoveHTTPAcceptEncoding no\n"
			"RemoveHTTPReferer no\n"
			"VerifyPeer no\n"
			"AllowWrongHost yes\n"
#ifndef WITHOUT_USERAUTH
			"UserAuth no\n"
			"UserTimeout 1200\n"
			"UserAuthURL https://192.168.0.12/userdblogin1.php\n"
#endif /* !WITHOUT_USERAUTH */
			"ValidateProto no\n"
			"MaxHTTPHeaderSize 2048\n"
			"}\n"
		"}";
	f = fmemopen(s, strlen(s), "r");

//	close(2);

	char *natengine = "pf";
	rv = load_proxyspec_struct(global, "sslproxy", &natengine, &line_num, f, tmp_opts);

	fclose(f);
	fail_unless(rv == 0, "failed to parse proxyspec");

	global->spec->opts->filter = filter_set(global->spec->opts->filter_rules, "sslproxy", tmp_opts);

	s = proxyspec_str(global->spec);

#ifndef WITHOUT_USERAUTH
	fail_unless(!strcmp(s,
"listen=[127.0.0.1]:8213 ssl|http \n"
"sni 4444\n"
"divert addr= [127.0.0.1]:8080\n"
"return addr= [192.168.2.1]:0\n"
"opts= conn opts: "SSL_PROTO_CONFIG_PROXYSPEC"|deny_ocsp|MEDIUM:HIGH|TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256|"ECDH_PRIME1"http://example2.com/example2.crl|remove_http_accept_encoding|remove_http_referer|verify_peer|user_auth|https://192.168.0.13/userdblogin3.php|300|validate_proto|2048\n"
"divert|daemon,root|daemon,root\n"
"macro $ip = 127.0.0.1\n"
"filter rule 0: sni=example4.com, dstport=, srcip=, user=, desc=, exact=site||||, all=conns|||, action=||pass||, log=|||||, precedence=1\n"
"filter rule 0: cn=example4.com, dstport=, srcip=, user=, desc=, exact=site||||, all=conns|||, action=||pass||, log=|||||, precedence=1\n"
"filter rule 1: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=||||match, log=|||content||, precedence=4\n"
"filter rule 2: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=|||block|, log=|||content||, precedence=4\n"
"filter rule 3: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=||pass||, log=|||content||, precedence=4\n"
"filter rule 4: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=|split|||, log=|||content||, precedence=4\n"
"filter rule 5: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, user=, desc=, exact=site|port|ip||, all=|||, action=divert||||, log=|||content||, precedence=4\n"
"filter rule 6: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||ip||, all=|||, action=||||match, log=connect|||||, precedence=3\n"
"  conn opts: "SSL_PROTO_CONFIG_FILTERRULE"|passthrough|LOW|TLS_AES_128_CCM_SHA256|"ECDH_PRIME2"http://example1.com/example1.crl|allow_wrong_host|https://192.168.0.12/userdblogin1.php|1200|reconnect_ssl|2048\n"
"filter=>\n"
"userdesc_filter_exact->\n"
"userdesc_filter_substring->\n"
"user_filter_exact->\n"
"user_filter_substring->\n"
"desc_filter_exact->\n"
"desc_filter_substring->\n"
"user_filter_all->\n"
"ip_filter_exact->\n"
"  ip 0 127.0.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 127.0.0.1 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 9191 (exact, action=divert|split|pass|block|match, log=|||content||, precedence=4)\n"
"  ip 1 192.168.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.2 (exact, action=||||match, log=connect|||||, precedence=3\n"
"        conn opts: "SSL_PROTO_CONFIG_FILTERRULE"|passthrough|LOW|TLS_AES_128_CCM_SHA256|"ECDH_PRIME2"no leafcrlurl|allow_wrong_host|https://192.168.0.12/userdblogin1.php|1200|reconnect_ssl|2048)\n"
"ip_filter_substring->\n"
"filter_all->\n"
"    sni exact:\n"
"      0: example4.com (exact, action=||pass||, log=|||||, precedence=1)\n"
"    cn exact:\n"
"      0: example4.com (exact, action=||pass||, log=|||||, precedence=1)\n"),
		"failed to parse proxyspec: %s", s);
#else /* WITHOUT_USERAUTH */
	fail_unless(!strcmp(s,
"listen=[127.0.0.1]:8213 ssl|http \n"
"sni 4444\n"
"divert addr= [127.0.0.1]:8080\n"
"return addr= [192.168.2.1]:0\n"
"opts= conn opts: "SSL_PROTO_CONFIG_PROXYSPEC"|no sslcomp|no_tls13|deny_ocsp|MEDIUM:HIGH|TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256|"ECDH_PRIME1"http://example2.com/example2.crl|remove_http_accept_encoding|remove_http_referer|verify_peer|validate_proto|2048\n"
"divert\n"
"macro $ip = 127.0.0.1\n"
"filter rule 0: sni=example4.com, dstport=, srcip=, exact=site||, all=conns||, action=||pass||, log=|||||, precedence=1\n"
"filter rule 0: cn=example4.com, dstport=, srcip=, exact=site||, all=conns||, action=||pass||, log=|||||, precedence=1\n"
"filter rule 1: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, exact=site|port|ip, all=||, action=||||match, log=|||content||, precedence=4\n"
"filter rule 2: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, exact=site|port|ip, all=||, action=|||block|, log=|||content||, precedence=4\n"
"filter rule 3: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, exact=site|port|ip, all=||, action=||pass||, log=|||content||, precedence=4\n"
"filter rule 4: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, exact=site|port|ip, all=||, action=|split|||, log=|||content||, precedence=4\n"
"filter rule 5: dstip=127.0.0.1, dstport=9191, srcip=127.0.0.1, exact=site|port|ip, all=||, action=divert||||, log=|||content||, precedence=4\n"
"filter rule 6: dstip=192.168.0.2, dstport=, srcip=192.168.0.1, exact=site||ip, all=||, action=||||match, log=connect|||||, precedence=3\n"
"  conn opts: "SSL_PROTO_CONFIG_FILTERRULE"|passthrough|LOW|TLS_AES_128_CCM_SHA256|"ECDH_PRIME2"http://example1.com/example1.crl|allow_wrong_host|reconnect_ssl|2048\n"
"filter=>\n"
"ip_filter_exact->\n"
"  ip 0 127.0.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 127.0.0.1 (exact, action=||||, log=|||||, precedence=0)\n"
"        port exact:\n"
"          0: 9191 (exact, action=divert|split|pass|block|match, log=|||content||, precedence=4)\n"
"  ip 1 192.168.0.1 (exact)=\n"
"    ip exact:\n"
"      0: 192.168.0.2 (exact, action=||||match, log=connect|||||, precedence=3\n"
"        conn opts: "SSL_PROTO_CONFIG_FILTERRULE"|passthrough|LOW|TLS_AES_128_CCM_SHA256|"ECDH_PRIME2"no leafcrlurl|allow_wrong_host|reconnect_ssl|2048)\n"
"ip_filter_substring->\n"
"filter_all->\n"
"    sni exact:\n"
"      0: example4.com (exact, action=||pass||, log=|||||, precedence=1)\n"
"    cn exact:\n"
"      0: example4.com (exact, action=||pass||, log=|||||, precedence=1)\n"),
		"failed to parse proxyspec: %s", s);
#endif /* WITHOUT_USERAUTH */
	free(s);

	tmp_opts_free(tmp_opts);
	global_free(global);
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
	conn_opts_t *conn_opts = conn_opts_new();

	char *s = strdup("example.com");
	UNUSED int rv = filter_passsite_set(opts, conn_opts, s, 0);
	free(s);

	fail_unless(!strcmp(opts->filter_rules->sni, "example.com"), "site not example.com");
	fail_unless(!strcmp(opts->filter_rules->cn, "example.com"), "site not example.com");
	fail_unless(!opts->filter_rules->ip, "ip set");
#ifndef WITHOUT_USERAUTH
	fail_unless(!opts->filter_rules->user, "user set");
	fail_unless(opts->filter_rules->all_conns, "all_conns not 1");
	fail_unless(!opts->filter_rules->desc, "desc set");
#endif /* !WITHOUT_USERAUTH */
	fail_unless(!opts->filter_rules->next, "next set");

	ps = filter_rule_str(opts->filter_rules);
#ifndef WITHOUT_USERAUTH
	fail_unless(!strcmp(ps, "filter rule 0: sni=example.com, dstport=, srcip=, user=, desc=, exact=site||||, all=conns|||, action=||pass||, log=|||||, precedence=1\n"
		"filter rule 0: cn=example.com, dstport=, srcip=, user=, desc=, exact=site||||, all=conns|||, action=||pass||, log=|||||, precedence=1\n"),
		"failed parsing passite example.com: %s", ps);
#else /* WITHOUT_USERAUTH */
	fail_unless(!strcmp(ps, "filter rule 0: sni=example.com, dstport=, srcip=, exact=site||, all=conns||, action=||pass||, log=|||||, precedence=1\n"
		"filter rule 0: cn=example.com, dstport=, srcip=, exact=site||, all=conns||, action=||pass||, log=|||||, precedence=1\n"),
		"failed parsing passite example.com: %s", ps);
#endif /* WITHOUT_USERAUTH */
	free(ps);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST

START_TEST(opts_set_passsite_02)
{
	char *ps;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	char *s = strdup("example.com 192.168.0.1");
	UNUSED int rv = filter_passsite_set(opts, conn_opts, s, 0);
	free(s);

	fail_unless(!strcmp(opts->filter_rules->sni, "example.com"), "site not example.com");
	fail_unless(!strcmp(opts->filter_rules->cn, "example.com"), "site not example.com");
	fail_unless(!strcmp(opts->filter_rules->ip, "192.168.0.1"), "ip not 192.168.0.1");
#ifndef WITHOUT_USERAUTH
	fail_unless(!opts->filter_rules->user, "user set");
	fail_unless(!opts->filter_rules->all_conns, "all_conns not 0");
	fail_unless(!opts->filter_rules->desc, "desc set");
#endif /* !WITHOUT_USERAUTH */
	fail_unless(!opts->filter_rules->next, "next set");

	ps = filter_rule_str(opts->filter_rules);
#ifndef WITHOUT_USERAUTH
	fail_unless(!strcmp(ps, "filter rule 0: sni=example.com, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||||, all=|||, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 0: cn=example.com, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||||, all=|||, action=||pass||, log=|||||, precedence=2\n"),
		"failed parsing passite example.com 192.168.0.1: %s", ps);
#else /* WITHOUT_USERAUTH */
	fail_unless(!strcmp(ps, "filter rule 0: sni=example.com, dstport=, srcip=192.168.0.1, exact=site||, all=||, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 0: cn=example.com, dstport=, srcip=192.168.0.1, exact=site||, all=||, action=||pass||, log=|||||, precedence=2\n"),
		"failed parsing passite example.com 192.168.0.1: %s", ps);
#endif /* !WITHOUT_USERAUTH */
	free(ps);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST

#ifndef WITHOUT_USERAUTH
START_TEST(opts_set_passsite_03)
{
	char *ps;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	conn_opts->user_auth = 1;

	char *s = strdup("example.com root");
	UNUSED int rv = filter_passsite_set(opts, conn_opts, s, 0);
	free(s);

	fail_unless(!strcmp(opts->filter_rules->sni, "example.com"), "site not example.com");
	fail_unless(!strcmp(opts->filter_rules->cn, "example.com"), "site not example.com");
	fail_unless(!opts->filter_rules->ip, "ip set");
	fail_unless(!strcmp(opts->filter_rules->user, "root"), "user not root");
	fail_unless(!opts->filter_rules->all_conns, "all_conns not 0");
	fail_unless(!opts->filter_rules->desc, "desc set");
	fail_unless(!opts->filter_rules->next, "next set");

	ps = filter_rule_str(opts->filter_rules);
	fail_unless(!strcmp(ps, "filter rule 0: sni=example.com, dstport=, srcip=, user=root, desc=, exact=site||||, all=|||, action=||pass||, log=|||||, precedence=3\n"
		"filter rule 0: cn=example.com, dstport=, srcip=, user=root, desc=, exact=site||||, all=|||, action=||pass||, log=|||||, precedence=3\n"),
		"failed parsing passite example.com root: %s", ps);
	free(ps);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST

START_TEST(opts_set_passsite_04)
{
	char *ps;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	conn_opts->user_auth = 1;

	char *s = strdup("*.google.com * android");
	UNUSED int rv = filter_passsite_set(opts, conn_opts, s, 0);
	free(s);

	fail_unless(!strcmp(opts->filter_rules->sni, "*.google.com"), "site not *.google.com");
	fail_unless(!strcmp(opts->filter_rules->cn, "*.google.com"), "site not *.google.com");
	fail_unless(!opts->filter_rules->ip, "ip set");
	fail_unless(!opts->filter_rules->user, "user set");
	fail_unless(!opts->filter_rules->all_conns, "all_conns not 0");
	fail_unless(opts->filter_rules->all_users, "all_users not 1");
	fail_unless(!strcmp(opts->filter_rules->desc, "android"), "desc not android");
	fail_unless(!opts->filter_rules->next, "next set");

	ps = filter_rule_str(opts->filter_rules);
	fail_unless(!strcmp(ps, "filter rule 0: sni=*.google.com, dstport=, srcip=, user=, desc=android, exact=site||||, all=|users||, action=||pass||, log=|||||, precedence=3\n"
		"filter rule 0: cn=*.google.com, dstport=, srcip=, user=, desc=android, exact=site||||, all=|users||, action=||pass||, log=|||||, precedence=3\n"),
		"failed parsing passite *.google.com * android: %s", ps);
	free(ps);

	opts_free(opts);
	conn_opts_free(conn_opts);
}
END_TEST
#endif /* !WITHOUT_USERAUTH */

START_TEST(opts_set_passsite_05)
{
	char *ps;
	char *s;
	opts_t *opts = opts_new();
	conn_opts_t *conn_opts = conn_opts_new();

	// Dup string using strdup(), otherwise strtok_r() in opts_set_passsite() will cause segmentation fault
	s = strdup("example.com");
	UNUSED int rv = filter_passsite_set(opts, conn_opts, s, 0);
	free(s);
	fail_unless(!opts->filter_rules->next, "next set");

	s = strdup("example.com *");
	rv = filter_passsite_set(opts, conn_opts, s, 1);
	free(s);
	fail_unless(opts->filter_rules->next, "next not set");
	fail_unless(!opts->filter_rules->next->next, "next->next set");

	s = strdup("example.com 192.168.0.1");
	rv = filter_passsite_set(opts, conn_opts, s, 2);
	free(s);
	fail_unless(opts->filter_rules->next, "next not set");
	fail_unless(opts->filter_rules->next->next, "next->next not set");
	fail_unless(!opts->filter_rules->next->next->next, "next->next->next set");

#ifndef WITHOUT_USERAUTH
	conn_opts->user_auth = 1;

	// Use root user, opts_set_passsite() calls sys_isuser() to validate the user
	s = strdup("example.com root");
	rv = filter_passsite_set(opts, conn_opts, s, 3);
	free(s);
	fail_unless(opts->filter_rules->next, "next not set");
	fail_unless(opts->filter_rules->next->next, "next->next not set");
	fail_unless(opts->filter_rules->next->next->next, "next->next->next not set");
	fail_unless(!opts->filter_rules->next->next->next->next, "next->next->next->next set");

	s = strdup("*.google.com * android");
	rv = filter_passsite_set(opts, conn_opts, s, 4);
	free(s);
#endif /* !WITHOUT_USERAUTH */
	ps = filter_rule_str(opts->filter_rules);
	fail_unless(opts->filter_rules->next, "next not set");
	fail_unless(opts->filter_rules->next->next, "next->next not set");
#ifndef WITHOUT_USERAUTH
	fail_unless(opts->filter_rules->next->next->next, "next->next->next not set");
	fail_unless(opts->filter_rules->next->next->next->next, "next->next->next->next not set");
	fail_unless(!opts->filter_rules->next->next->next->next->next, "next->next->next->next->next set");
	fail_unless(!strcmp(ps, "filter rule 0: sni=example.com, dstport=, srcip=, user=, desc=, exact=site||||, all=conns|||, action=||pass||, log=|||||, precedence=1\n"
		"filter rule 0: cn=example.com, dstport=, srcip=, user=, desc=, exact=site||||, all=conns|||, action=||pass||, log=|||||, precedence=1\n"
		"filter rule 1: sni=example.com, dstport=, srcip=, user=, desc=, exact=site||||, all=|users||, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 1: cn=example.com, dstport=, srcip=, user=, desc=, exact=site||||, all=|users||, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 2: sni=example.com, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||||, all=|||, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 2: cn=example.com, dstport=, srcip=192.168.0.1, user=, desc=, exact=site||||, all=|||, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 3: sni=example.com, dstport=, srcip=, user=root, desc=, exact=site||||, all=|||, action=||pass||, log=|||||, precedence=3\n"
		"filter rule 3: cn=example.com, dstport=, srcip=, user=root, desc=, exact=site||||, all=|||, action=||pass||, log=|||||, precedence=3\n"
		"filter rule 4: sni=*.google.com, dstport=, srcip=, user=, desc=android, exact=site||||, all=|users||, action=||pass||, log=|||||, precedence=3\n"
		"filter rule 4: cn=*.google.com, dstport=, srcip=, user=, desc=android, exact=site||||, all=|users||, action=||pass||, log=|||||, precedence=3\n"),
		"failed parsing multiple passites: %s", ps);
#else /* WITHOUT_USERAUTH */
	fail_unless(!opts->filter_rules->next->next->next, "next->next->next set");
	fail_unless(!strcmp(ps, "filter rule 0: sni=example.com, dstport=, srcip=, exact=site||, all=conns||, action=||pass||, log=|||||, precedence=1\n"
		"filter rule 0: cn=example.com, dstport=, srcip=, exact=site||, all=conns||, action=||pass||, log=|||||, precedence=1\n"
		"filter rule 1: sni=example.com, dstport=, srcip=, exact=site||, all=conns||, action=||pass||, log=|||||, precedence=1\n"
		"filter rule 1: cn=example.com, dstport=, srcip=, exact=site||, all=conns||, action=||pass||, log=|||||, precedence=1\n"
		"filter rule 2: sni=example.com, dstport=, srcip=192.168.0.1, exact=site||, all=||, action=||pass||, log=|||||, precedence=2\n"
		"filter rule 2: cn=example.com, dstport=, srcip=192.168.0.1, exact=site||, all=||, action=||pass||, log=|||||, precedence=2\n"),
		"failed parsing multiple passites: %s", ps);
#endif /* WITHOUT_USERAUTH */
	free(ps);

	opts_free(opts);
	conn_opts_free(conn_opts);
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
	retval = get_name_value(name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);

	name = strdup("Name  Value");
	retval = get_name_value(name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);

	close(2);

	// Leading white space must be handled by the caller
	// We cannot modify the name pointer, so we return -1
	// So we don't actually need a test for " Name Value", or similar
	name = strdup(" Name Value");
	retval = get_name_value(name, &value, ' ', 0);
	fail_unless(!strcmp(name, ""), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == -1, "failed rejecting leading white space, empty name");
	free(name);

	name = strdup("Name Value ");
	retval = get_name_value(name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);

	name = strdup("Name=Value");
	retval = get_name_value(name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);

	// Leading white space must be handled by the caller
	// We cannot modify the name pointer, so we return -1
	// So we don't actually need a test for " Name Value", or similar
	name = strdup(" Name=Value");
	retval = get_name_value(name, &value, ' ', 0);
	fail_unless(!strcmp(name, ""), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == -1, "failed rejecting leading white space, empty name");
	free(name);

	name = strdup("Name=Value ");
	retval = get_name_value(name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);

	name = strdup("Name = Value");
	retval = get_name_value(name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);

	name = strdup("Name = Value ");
	retval = get_name_value(name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, "Value"), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name value");
	free(name);

	// Name without value, e.g. '}' char is used for marking the end of structured proxyspecs
	// so do not reject any form of just name, return success
	name = strdup("Name");
	retval = get_name_value(name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing just name");
	free(name);

	name = strdup("Name ");
	retval = get_name_value(name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name  ");
	retval = get_name_value(name, &value, ' ', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name");
	retval = get_name_value(name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name=");
	retval = get_name_value(name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name= ");
	retval = get_name_value(name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name =");
	retval = get_name_value(name, &value, '=', 0);
	fail_unless(!strcmp(name, "Name"), "failed parsing name");
	fail_unless(!strcmp(value, ""), "failed parsing value");
	fail_unless(retval == 0, "failed parsing name empty value");
	free(name);

	name = strdup("Name = ");
	retval = get_name_value(name, &value, '=', 0);
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
	tcase_add_test(tc, proxyspec_parse_03);
	tcase_add_test(tc, proxyspec_parse_04);
	tcase_add_test(tc, proxyspec_parse_05);
	tcase_add_test(tc, proxyspec_parse_06);
	tcase_add_test(tc, proxyspec_parse_07);
	tcase_add_test(tc, proxyspec_parse_08);
#ifndef TRAVIS
	tcase_add_test(tc, proxyspec_parse_09); /* IPv6 */
	tcase_add_test(tc, proxyspec_parse_10); /* IPv6 */
#endif /* !TRAVIS */
	tcase_add_test(tc, proxyspec_parse_11);
	tcase_add_test(tc, proxyspec_parse_12);
	tcase_add_test(tc, proxyspec_parse_13);
	tcase_add_test(tc, proxyspec_set_proto_01);
	tcase_add_test(tc, proxyspec_struct_parse_01);
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
