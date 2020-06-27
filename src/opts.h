/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2019, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2020, Soner Tari <sonertari@gmail.com>.
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

#ifndef OPTS_H
#define OPTS_H

#include "proc.h"
#include "nat.h"
#include "ssl.h"
#include "cert.h"
#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sqlite3.h>

/*
 * Print helper for logging code.
 */
#define STRORDASH(x)	(((x)&&*(x))?(x):"-")
#define STRORNONE(x)	(((x)&&*(x))?(x):"")

typedef struct global global_t;

typedef struct opts {
	unsigned int sslcomp : 1;
#ifdef HAVE_SSLV2
	unsigned int no_ssl2 : 1;
#endif /* HAVE_SSLV2 */
#ifdef HAVE_SSLV3
	unsigned int no_ssl3 : 1;
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	unsigned int no_tls10 : 1;
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	unsigned int no_tls11 : 1;
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	unsigned int no_tls12 : 1;
#endif /* HAVE_TLSV12 */
#ifdef HAVE_TLSV13
	unsigned int no_tls13 : 1;
#endif /* HAVE_TLSV13 */
	unsigned int passthrough : 1;
	unsigned int deny_ocsp : 1;
	char *ciphers;
	char *ciphersuites;
	CONST_SSL_METHOD *(*sslmethod)(void);
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x20702000L)
	int sslversion;
	int minsslversion;
	int maxsslversion;
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
	X509 *cacrt;
	EVP_PKEY *cakey;
	STACK_OF(X509) *chain;
	X509 *clientcrt;
	EVP_PKEY *clientkey;
#ifndef OPENSSL_NO_DH
	DH *dh;
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	char *ecdhcurve;
#endif /* !OPENSSL_NO_ECDH */
	char *leafcrlurl;
	unsigned int remove_http_accept_encoding: 1;
	unsigned int remove_http_referer: 1;
	unsigned int verify_peer: 1;
	unsigned int allow_wrong_host: 1;
	unsigned int user_auth: 1;
	char *user_auth_url;
	unsigned int user_timeout;
	unsigned int validate_proto : 1;
	unsigned int max_http_header_size;
	struct passsite *passsites;
	global_t *global;
} opts_t;

typedef struct proxyspec {
	unsigned int ssl : 1;
	unsigned int http : 1;
	unsigned int upgrade: 1;
	unsigned int pop3 : 1;
	unsigned int smtp : 1;
	unsigned int dns : 1;		/* set if spec needs DNS lookups */
	struct sockaddr_storage listen_addr;
	socklen_t listen_addrlen;
	/* connect_addr and connect_addrlen are set: static mode;
	 * natlookup is set: NAT mode; natsocket /may/ be set too;
	 * sni_port is set, in which case we use SNI lookups */
	struct sockaddr_storage connect_addr;
	socklen_t connect_addrlen;
	unsigned short sni_port;
	char *natengine;
	nat_lookup_cb_t natlookup;
	nat_socket_cb_t natsocket;
	struct proxyspec *next;

	struct sockaddr_storage conn_dst_addr;
	socklen_t conn_dst_addrlen;

	struct sockaddr_storage child_src_addr;
	socklen_t child_src_addrlen;

	// Each proxyspec has its own opts
	opts_t *opts;
} proxyspec_t;

typedef struct passsite {
	char *site;
	// Filter definition fields
	char *ip;
	char *user;
	unsigned int all : 1; /* 1 for all users */
	char *keyword;
	struct passsite *next;
} passsite_t;

// global opts strings used while cloning into proxyspec opts
// A var of this type is passed around as a flag to indicate if these opts are
// global (if non-NULL), so should be stored here and used as such, or
// proxyspec specific (if NULL), so should not be used as global.
typedef struct global_opts_str {
	char *cacrt_str;
	char *cakey_str;
	char *chain_str;
	char *clientcrt_str;
	char *clientkey_str;
	char *leafcrlurl_str;
	char *dh_str;
} global_opts_str_t;

struct global {
	unsigned int debug : 1;
	unsigned int detach : 1;
	unsigned int contentlog_isdir : 1;
	unsigned int contentlog_isspec : 1;
	unsigned int pcaplog_isdir : 1;
	unsigned int pcaplog_isspec : 1;
#ifdef HAVE_LOCAL_PROCINFO
	unsigned int lprocinfo : 1;
#endif /* HAVE_LOCAL_PROCINFO */
	unsigned int certgen_writeall : 1;
	char *certgendir;
	char *leafcertdir;
	char *dropuser;
	char *dropgroup;
	char *jaildir;
	char *pidfile;
	char *conffile;
	char *connectlog;
	char *contentlog;
	char *contentlog_basedir; /* static part of logspec for privsep srv */
	char *masterkeylog;
	char *pcaplog;
	char *pcaplog_basedir; /* static part of pcap logspec for privsep srv */
#ifndef WITHOUT_MIRROR
	char *mirrorif;
	char *mirrortarget;
#endif /* !WITHOUT_MIRROR */
	unsigned int conn_idle_timeout;
	unsigned int expired_conn_check_period;
	unsigned int stats_period;
	unsigned int statslog: 1;
	unsigned int log_stats: 1;
	char *userdb_path;
	sqlite3 *userdb;
	struct sqlite3_stmt *update_user_atime;
	proxyspec_t *spec;
	opts_t *opts;

	// @todo Modify cert cache to move the key field to opts struct
	// Otherwise, cache HIT fetches certs forged using different leaf cert keys,
	// which fails loading src server keys
	// We must use the same key while forging and reusing certs
	EVP_PKEY *leafkey;
	cert_t *defaultleafcert;
	int leafkey_rsabits;

#ifndef OPENSSL_NO_ENGINE
	// @todo Use different openssl engines for each proxyspec, so move to opts?
	char *openssl_engine;
#endif /* !OPENSSL_NO_ENGINE */
};

typedef struct userdbkeys {
	char ip[46];
	char user[32];
	char ether[18];
} userdbkeys_t;

void NORET oom_die(const char *) NONNULL(1);
cert_t *opts_load_cert_chain_key(const char *) NONNULL(1);

void proxyspec_free(proxyspec_t *);
proxyspec_t *proxyspec_new(global_t *, const char *, global_opts_str_t *);
void proxyspec_set_proto(proxyspec_t *, const char *);
void proxyspec_parse(int *, char **[], const char *, global_t *, const char *, global_opts_str_t *);
char *proxyspec_str(proxyspec_t *) NONNULL(1) MALLOC;

opts_t *opts_new(void) MALLOC;
void opts_free(opts_t *) NONNULL(1);
char *passsite_str(passsite_t *);
char *opts_proto_dbg_dump(opts_t *) NONNULL(1);
void opts_set_cacrt(opts_t *, const char *, const char *, global_opts_str_t *) NONNULL(1,2,3);
void opts_set_cakey(opts_t *, const char *, const char *, global_opts_str_t *) NONNULL(1,2,3);
void opts_set_chain(opts_t *, const char *, const char *, global_opts_str_t *) NONNULL(1,2,3);
void opts_set_leafcrlurl(opts_t *, const char *, global_opts_str_t *) NONNULL(1,2);
void opts_set_deny_ocsp(opts_t *) NONNULL(1);
void opts_set_passthrough(opts_t *) NONNULL(1);
void opts_set_clientcrt(opts_t *, const char *, const char *, global_opts_str_t *) NONNULL(1,2,3);
void opts_set_clientkey(opts_t *, const char *, const char *, global_opts_str_t *) NONNULL(1,2,3);
#ifndef OPENSSL_NO_DH
void opts_set_dh(opts_t *, const char *, const char *, global_opts_str_t *) NONNULL(1,2,3);
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
void opts_set_ecdhcurve(opts_t *, const char *, const char *) NONNULL(1,2,3);
#endif /* !OPENSSL_NO_ECDH */
void opts_unset_sslcomp(opts_t *) NONNULL(1);
void opts_force_proto(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_disable_proto(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_ciphers(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_ciphersuites(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_pass_site(opts_t *, char *, int);
#define OPTS_DEBUG(global) unlikely((global)->debug)

global_t * global_new(void) MALLOC;
void global_opts_str_free(global_opts_str_t *) NONNULL(1);
void global_free(global_t *) NONNULL(1);
int global_has_ssl_spec(global_t *) NONNULL(1) WUNRES;
int global_has_dns_spec(global_t *) NONNULL(1) WUNRES;
int global_has_userauth_spec(global_t *) NONNULL(1) WUNRES;
int global_has_cakey_spec(global_t *) NONNULL(1) WUNRES;
void global_set_user(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_group(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_jaildir(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_pidfile(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_connectlog(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_contentlog(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_contentlogdir(global_t *, const char *, const char *)
     NONNULL(1,2,3);
void global_set_contentlogpathspec(global_t *, const char *, const char *)
     NONNULL(1,2,3);
#ifdef HAVE_LOCAL_PROCINFO
void global_set_lprocinfo(global_t *) NONNULL(1);
#endif /* HAVE_LOCAL_PROCINFO */
void global_set_masterkeylog(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_pcaplog(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_pcaplogdir(global_t *, const char *, const char *)
     NONNULL(1,2,3);
void global_set_pcaplogpathspec(global_t *, const char *, const char *)
     NONNULL(1,2,3);
#ifndef WITHOUT_MIRROR
void global_set_mirrorif(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_mirrortarget(global_t *, const char *, const char *) NONNULL(1,2,3);
#endif /* !WITHOUT_MIRROR */
void global_set_daemon(global_t *) NONNULL(1);
void global_set_debug(global_t *) NONNULL(1);
void global_set_debug_level(const char *) NONNULL(1);
void global_set_statslog(global_t *) NONNULL(1);

int check_value_yesno(const char *, const char *, int);
int get_name_value(char **, char **, const char, int);
int global_set_option(global_t *, const char *, const char *, char **, global_opts_str_t *) NONNULL(1,2,3,5);
void global_set_leafkey(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_leafcertdir(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_defaultleafcert(global_t *, const char *, const char *) NONNULL(1,2,3);
void global_set_certgendir_writeall(global_t *, const char *, const char *)
     NONNULL(1,2,3);
void global_set_certgendir_writegencerts(global_t *, const char *, const char *)
     NONNULL(1,2,3);
void global_set_openssl_engine(global_t *, const char *, const char *)
     NONNULL(1,2,3);
int global_load_conffile(global_t *, const char *, char **, global_opts_str_t *) NONNULL(1,2,4);
#endif /* !OPTS_H */

/* vim: set noet ft=c: */
