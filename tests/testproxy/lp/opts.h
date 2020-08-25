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

#ifndef OPTS_H
#define OPTS_H

#include "attrib.h"

#include <sys/types.h>
#include <sys/socket.h>

/*
 * Print helper for logging code.
 */
#define STRORDASH(x)	(((x)&&*(x))?(x):"-")
#define STRORNONE(x)	(((x)&&*(x))?(x):"")

typedef struct proxyspec {
	struct sockaddr_storage listen_addr;
	socklen_t listen_addrlen;
	/* connect_addr and connect_addrlen are set: static mode;
	 * natlookup is set: NAT mode; natsocket /may/ be set too;
	 * sni_port is set, in which case we use SNI lookups */
	struct sockaddr_storage connect_addr;
	socklen_t connect_addrlen;
	struct proxyspec *next;
} proxyspec_t;

typedef struct opts {
	unsigned int debug : 1;
	unsigned int detach : 1;
	unsigned int contentlog_isdir : 1;
	unsigned int contentlog_isspec : 1;
	char *dropuser;
	char *dropgroup;
	char *jaildir;
	char *pidfile;
	char *conffile;
	char *connectlog;
	char *contentlog;
	char *contentlog_basedir; /* static part of logspec for privsep srv */
	proxyspec_t *spec;
	unsigned int stats_period;
	unsigned int statslog: 1;
	unsigned int log_stats: 1;
} opts_t;

void NORET oom_die(const char *) NONNULL(1);

opts_t *opts_new(void) MALLOC;
void opts_free(opts_t *) NONNULL(1);
void opts_proto_dbg_dump(opts_t *) NONNULL(1);
#define OPTS_DEBUG(opts) unlikely((opts)->debug)

void proxyspec_parse(int *, char **[], proxyspec_t **);
void proxyspec_free(proxyspec_t *) NONNULL(1);
char *proxyspec_str(proxyspec_t *) NONNULL(1) MALLOC;

void opts_set_user(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_group(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_jaildir(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_pidfile(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_connectlog(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_contentlog(opts_t *, const char *, const char *) NONNULL(1,2,3);
void opts_set_contentlogdir(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
void opts_set_contentlogpathspec(opts_t *, const char *, const char *)
     NONNULL(1,2,3);
void opts_set_daemon(opts_t *) NONNULL(1);
void opts_set_debug(opts_t *) NONNULL(1);
void opts_set_debug_level(const char *) NONNULL(1);
void opts_set_statslog(opts_t *) NONNULL(1);
int opts_set_option(opts_t *, const char *, const char *)
    NONNULL(1,2,3);

int opts_load_conffile(opts_t *, const char *) NONNULL(1,2);
#endif /* !OPTS_H */

/* vim: set noet ft=c: */
