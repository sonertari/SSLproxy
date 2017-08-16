/*
 * SSLsplit - transparent SSL/TLS interception
 * Copyright (c) 2009-2016, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "opts.h"

#include "sys.h"
#include "log.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif /* !OPENSSL_NO_DH */
#include <openssl/x509.h>

opts_t *
opts_new(void)
{
	opts_t *opts;

	opts = malloc(sizeof(opts_t));
	memset(opts, 0, sizeof(opts_t));

	opts->sslcomp = 1;
	opts->chain = sk_X509_new_null();
	opts->sslmethod = SSLv23_method;

	return opts;
}

void
opts_free(opts_t *opts)
{
	sk_X509_pop_free(opts->chain, X509_free);
	if (opts->cacrt) {
		X509_free(opts->cacrt);
	}
	if (opts->cakey) {
		EVP_PKEY_free(opts->cakey);
	}
	if (opts->key) {
		EVP_PKEY_free(opts->key);
	}
#ifndef OPENSSL_NO_DH
	if (opts->dh) {
		DH_free(opts->dh);
	}
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	if (opts->ecdhcurve) {
		free(opts->ecdhcurve);
	}
#endif /* !OPENSSL_NO_ECDH */
	if (opts->spec) {
		proxyspec_free(opts->spec);
	}
	if (opts->ciphers) {
		free(opts->ciphers);
	}
	if (opts->tgcrtdir) {
		free(opts->tgcrtdir);
	}
	if (opts->dropuser) {
		free(opts->dropuser);
	}
	if (opts->dropgroup) {
		free(opts->dropgroup);
	}
	if (opts->jaildir) {
		free(opts->jaildir);
	}
	if (opts->pidfile) {
		free(opts->pidfile);
	}
	if (opts->connectlog) {
		free(opts->connectlog);
	}
	if (opts->contentlog) {
		free(opts->contentlog);
	}
	if (opts->certgendir) {
		free(opts->certgendir);
	}
	if (opts->contentlog_basedir) {
		free(opts->contentlog_basedir);
	}
	memset(opts, 0, sizeof(opts_t));
	free(opts);
}

/*
 * Return 1 if opts_t contains a proxyspec that (eventually) uses SSL/TLS,
 * 0 otherwise.  When 0, it is safe to assume that no SSL/TLS operations
 * will take place with this configuration.
 */
int
opts_has_ssl_spec(opts_t *opts)
{
	proxyspec_t *p = opts->spec;

	while (p) {
		if (p->ssl || p->upgrade)
			return 1;
		p = p->next;
	}

	return 0;
}

/*
 * Return 1 if opts_t contains a proxyspec with dns, 0 otherwise.
 */
int
opts_has_dns_spec(opts_t *opts)
{
	proxyspec_t *p = opts->spec;

	while (p) {
		if (p->dns)
			return 1;
		p = p->next;
	}

	return 0;
}

/*
 * Parse SSL proto string in optarg and look up the corresponding SSL method.
 * Calls exit() on failure.
 */
void
opts_proto_force(opts_t *opts, const char *optarg, const char *argv0)
{
	if (opts->sslmethod != SSLv23_method) {
		fprintf(stderr, "%s: cannot use -r multiple times\n", argv0);
		exit(EXIT_FAILURE);
	}

#ifdef HAVE_SSLV2
	if (!strcmp(optarg, "ssl2")) {
		opts->sslmethod = SSLv2_method;
	} else
#endif /* HAVE_SSLV2 */
#ifdef HAVE_SSLV3
	if (!strcmp(optarg, "ssl3")) {
		opts->sslmethod = SSLv3_method;
	} else
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	if (!strcmp(optarg, "tls10") || !strcmp(optarg, "tls1")) {
		opts->sslmethod = TLSv1_method;
	} else
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	if (!strcmp(optarg, "tls11")) {
		opts->sslmethod = TLSv1_1_method;
	} else
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	if (!strcmp(optarg, "tls12")) {
		opts->sslmethod = TLSv1_2_method;
	} else
#endif /* HAVE_TLSV12 */
	{
		fprintf(stderr, "%s: Unsupported SSL/TLS protocol '%s'\n",
		                argv0, optarg);
		exit(EXIT_FAILURE);
	}
}

/*
 * Parse SSL proto string in optarg and set the corresponding no_foo bit.
 * Calls exit() on failure.
 */
void
opts_proto_disable(opts_t *opts, const char *optarg, const char *argv0)
{
#ifdef HAVE_SSLV2
	if (!strcmp(optarg, "ssl2")) {
		opts->no_ssl2 = 1;
	} else
#endif /* HAVE_SSLV2 */
#ifdef HAVE_SSLV3
	if (!strcmp(optarg, "ssl3")) {
		opts->no_ssl3 = 1;
	} else
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	if (!strcmp(optarg, "tls10") || !strcmp(optarg, "tls1")) {
		opts->no_tls10 = 1;
	} else
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	if (!strcmp(optarg, "tls11")) {
		opts->no_tls11 = 1;
	} else
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	if (!strcmp(optarg, "tls12")) {
		opts->no_tls12 = 1;
	} else
#endif /* HAVE_TLSV12 */
	{
		fprintf(stderr, "%s: Unsupported SSL/TLS protocol '%s'\n",
		                argv0, optarg);
		exit(EXIT_FAILURE);
	}
}

/*
 * Dump the SSL/TLS protocol related configuration to the debug log.
 */
void
opts_proto_dbg_dump(opts_t *opts)
{
	log_dbg_printf("SSL/TLS protocol: %s%s%s%s%s%s\n",
#ifdef HAVE_SSLV2
	               (opts->sslmethod == SSLv2_method) ? "nossl2" :
#endif /* HAVE_SSLV2 */
#ifdef HAVE_SSLV3
	               (opts->sslmethod == SSLv3_method) ? "ssl3" :
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	               (opts->sslmethod == TLSv1_method) ? "tls10" :
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	               (opts->sslmethod == TLSv1_1_method) ? "tls11" :
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	               (opts->sslmethod == TLSv1_2_method) ? "tls12" :
#endif /* HAVE_TLSV12 */
	               "negotiate",
#ifdef HAVE_SSLV2
	               opts->no_ssl2 ? " -ssl2" :
#endif /* HAVE_SSLV2 */
	               "",
#ifdef HAVE_SSLV3
	               opts->no_ssl3 ? " -ssl3" :
#endif /* HAVE_SSLV3 */
	               "",
#ifdef HAVE_TLSV10
	               opts->no_tls10 ? " -tls10" :
#endif /* HAVE_TLSV10 */
	               "",
#ifdef HAVE_TLSV11
	               opts->no_tls11 ? " -tls11" :
#endif /* HAVE_TLSV11 */
	               "",
#ifdef HAVE_TLSV12
	               opts->no_tls12 ? " -tls12" :
#endif /* HAVE_TLSV12 */
	               "");
}

/*
 * Parse proxyspecs using a simple state machine.
 */
void
proxyspec_parse(int *argc, char **argv[], const char *natengine, opts_t *opts)
{
	proxyspec_t *curspec;
	char *addr = NULL;
	int af = AF_UNSPEC;
	int state = 0;

	while ((*argc)--) {
		switch (state) {
			default:
			case 0:
				/* tcp | ssl | http | https | autossl | mail | mails */
				curspec = malloc(sizeof(proxyspec_t));
				memset(curspec, 0, sizeof(proxyspec_t));

				curspec->next = opts->spec;
				opts->spec = curspec;

				// Defaults
				curspec->ssl = 0;
				curspec->http = 0;
				curspec->upgrade = 0;
				curspec->mail = 0;
				if (!strcmp(**argv, "tcp")) {
					// use defaults
				} else
				if (!strcmp(**argv, "ssl")) {
					curspec->ssl = 1;
				} else
				if (!strcmp(**argv, "http")) {
					curspec->http = 1;
				} else
				if (!strcmp(**argv, "https")) {
					curspec->ssl = 1;
					curspec->http = 1;
				} else
				if (!strcmp(**argv, "autossl")) {
					curspec->upgrade = 1;
				} else
				if (!strcmp(**argv, "mail")) {
					curspec->mail = 1;
				} else
				if (!strcmp(**argv, "mails")) {
					curspec->ssl = 1;
					curspec->mail = 1;
				} else {
					fprintf(stderr, "Unknown connection "
					                "type '%s'\n", **argv);
					exit(EXIT_FAILURE);
				}
				state++;
				break;
			case 1:
				/* listenaddr */
				addr = **argv;
				state++;
				break;
			case 2:
				/* listenport */
				if (strstr(addr, ":"))
					af = AF_INET6;
				else if (!strpbrk(addr, "abcdefghijklmnopqrstu"
				                        "vwxyzABCDEFGHIJKLMNOP"
				                        "QRSTUVWXYZ-"))
					af = AF_INET;
				else
					af = AF_UNSPEC;
				af = sys_sockaddr_parse(&curspec->listen_addr,
				                        &curspec->listen_addrlen,
				                        addr, **argv, af,
				                        EVUTIL_AI_PASSIVE);
				if (af == -1) {
					exit(EXIT_FAILURE);
				}
				if (natengine) {
					curspec->natengine = strdup(natengine);
					if (!curspec->natengine) {
						fprintf(stderr,
						        "Out of memory"
						        "\n");
						exit(EXIT_FAILURE);
					}
				} else {
					curspec->natengine = NULL;
				}
				state++;
				break;
			case 3:
				/* UTM service port is mandatory */
				// The UTM port is set/used in pf and UTM service config.
				// @todo Make this a conf file option?
				// @todo Need IPv6?
				if (strstr(**argv, "up:")) {
					af = sys_sockaddr_parse(&curspec->parent_dst_addr,
										&curspec->parent_dst_addrlen,
										"127.0.0.1", **argv + 3, AF_INET, EVUTIL_AI_PASSIVE);
					if (af == -1) {
						exit(EXIT_FAILURE);
					}
					af = sys_sockaddr_parse(&curspec->child_src_addr,
										&curspec->child_src_addrlen,
										"127.0.0.1", "0", AF_INET, EVUTIL_AI_PASSIVE);
					if (af == -1) {
						exit(EXIT_FAILURE);
					}
					state++;
				}
				break;
			case 4:
				/* [ natengine | dstaddr ] */
				if (!strcmp(**argv, "tcp") ||
				    !strcmp(**argv, "ssl") ||
				    !strcmp(**argv, "http") ||
				    !strcmp(**argv, "https") ||
				    !strcmp(**argv, "autossl") ||
				    !strcmp(**argv, "mail") ||
				    !strcmp(**argv, "mails")) {
					/* implicit default natengine */
					(*argv)--; (*argc)++; /* rewind */
					state = 0;
				} else
				if (!strcmp(**argv, "sni")) {
					free(curspec->natengine);
					curspec->natengine = NULL;
					if (!curspec->ssl) {
						fprintf(stderr,
						        "SNI hostname lookup "
						        "only works for ssl "
						        "and https proxyspecs"
						        "\n");
						exit(EXIT_FAILURE);
					}
					state = 6;
				} else
				if (nat_exist(**argv)) {
					/* natengine */
					free(curspec->natengine);
					curspec->natengine = strdup(**argv);
					if (!curspec->natengine) {
						fprintf(stderr,
						        "Out of memory"
						        "\n");
						exit(EXIT_FAILURE);
					}
					state = 0;
				} else {
					/* explicit target address */
					free(curspec->natengine);
					curspec->natengine = NULL;
					addr = **argv;
					state++;
				}
				break;
			case 5:
				/* dstport */
				af = sys_sockaddr_parse(&curspec->connect_addr,
				                        &curspec->connect_addrlen,
				                        addr, **argv, af, 0);
				if (af == -1) {
					exit(EXIT_FAILURE);
				}
				state = 0;
				break;
			case 6:
				/* SNI dstport */
				curspec->sni_port = atoi(**argv);
				if (!curspec->sni_port) {
					fprintf(stderr, "Invalid port '%s'\n",
					                **argv);
					exit(EXIT_FAILURE);
				}
				curspec->dns = 1;
				state = 0;
				break;
		}
		(*argv)++;
	}
	if (state != 0 && state != 4) {
		fprintf(stderr, "Incomplete proxyspec!\n");
		exit(EXIT_FAILURE);
	}
}

/*
 * Clear and free a proxy spec.
 */
void
proxyspec_free(proxyspec_t *spec)
{
	do {
		proxyspec_t *next = spec->next;
		if (spec->natengine)
			free(spec->natengine);
		memset(spec, 0, sizeof(proxyspec_t));
		free(spec);
		spec = next;
	} while (spec);
}

/*
 * Return text representation of proxy spec for display to the user.
 * Returned string must be freed by caller.
 */
char *
proxyspec_str(proxyspec_t *spec)
{
	char *s;
	char *lhbuf, *lpbuf;
	char *cbuf = NULL;
	char *pdstbuf = NULL;
	char *csrcbuf = NULL;
	if (sys_sockaddr_str((struct sockaddr *)&spec->listen_addr,
	                     spec->listen_addrlen, &lhbuf, &lpbuf) != 0) {
		return NULL;
	}
	if (spec->connect_addrlen) {
		char *chbuf, *cpbuf;
		if (sys_sockaddr_str((struct sockaddr *)&spec->connect_addr,
		                     spec->connect_addrlen,
		                     &chbuf, &cpbuf) != 0) {
			return NULL;
		}
		if (asprintf(&cbuf, "\nconnect= [%s]:%s", chbuf, cpbuf) < 0) {
			return NULL;
		}
		free(chbuf);
		free(cpbuf);
	}
	if (spec->parent_dst_addrlen) {
		char *chbuf, *cpbuf;
		if (sys_sockaddr_str((struct sockaddr *)&spec->parent_dst_addr,
		                     spec->parent_dst_addrlen,
		                     &chbuf, &cpbuf) != 0) {
			return NULL;
		}
		if (asprintf(&pdstbuf, "\nparent dst addr= [%s]:%s", chbuf, cpbuf) < 0) {
			return NULL;
		}
		free(chbuf);
		free(cpbuf);
	}
	if (spec->child_src_addrlen) {
		char *chbuf, *cpbuf;
		if (sys_sockaddr_str((struct sockaddr *)&spec->child_src_addr,
		                     spec->child_src_addrlen,
		                     &chbuf, &cpbuf) != 0) {
			return NULL;
		}
		if (asprintf(&csrcbuf, "\nchild src addr= [%s]:%s", chbuf, cpbuf) < 0) {
			return NULL;
		}
		free(chbuf);
		free(cpbuf);
	}
	if (spec->sni_port) {
		if (asprintf(&cbuf, "\nsni %i", spec->sni_port) < 0) {
			return NULL;
		}
	}
	if (asprintf(&s, "listen=[%s]:%s %s%s%s%s %s%s%s", lhbuf, lpbuf,
	             (spec->ssl ? "ssl" : "tcp"),
	             (spec->upgrade ? "|upgrade" : ""),
	             (spec->http ? "|http" : ""),
	             (spec->mail ? "|mail" : ""),
	             (spec->natengine ? spec->natengine : cbuf),
	             (pdstbuf),
	             (csrcbuf)) < 0) {
		s = NULL;
	}
	free(lhbuf);
	free(lpbuf);
	if (cbuf)
		free(cbuf);
	if (pdstbuf)
		free(pdstbuf);
	if (csrcbuf)
		free(csrcbuf);
	return s;
}

/* vim: set noet ft=c: */
