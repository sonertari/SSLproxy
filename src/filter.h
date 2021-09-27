/*-
 * SSLproxy
 *
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

#ifndef FILTER_H
#define FILTER_H

#include "opts.h"

#define FILTER_ACTION_NONE   0x00000000U
#define FILTER_ACTION_MATCH  0x00000200U
#define FILTER_ACTION_DIVERT 0x00000400U
#define FILTER_ACTION_SPLIT  0x00000800U
#define FILTER_ACTION_PASS   0x00001000U
#define FILTER_ACTION_BLOCK  0x00002000U

#define FILTER_LOG_CONNECT   0x00004000U
#define FILTER_LOG_MASTER    0x00008000U
#define FILTER_LOG_CERT      0x00010000U
#define FILTER_LOG_CONTENT   0x00020000U
#define FILTER_LOG_PCAP      0x00040000U
#define FILTER_LOG_MIRROR    0x00080000U

#define FILTER_LOG_NOCONNECT 0x00100000U
#define FILTER_LOG_NOMASTER  0x00200000U
#define FILTER_LOG_NOCERT    0x00400000U
#define FILTER_LOG_NOCONTENT 0x00800000U
#define FILTER_LOG_NOPCAP    0x01000000U
#define FILTER_LOG_NOMIRROR  0x02000000U

#define FILTER_PRECEDENCE    0x000000FFU

typedef struct value {
	char *value;
	struct value *next;
} value_t;

typedef struct macro {
	char *name;
	struct value *value;
	struct macro *next;
} macro_t;

typedef struct filter_action {
	// Filter action
	unsigned int divert : 1;
	unsigned int split : 1;
	unsigned int pass : 1;
	unsigned int block : 1;
	unsigned int match : 1;

	// Log action, two bits
	// 0: don't change, 1: disable, 2: enable
	unsigned int log_connect : 2;
	unsigned int log_master : 2;
	unsigned int log_cert : 2;
	unsigned int log_content : 2;
	unsigned int log_pcap : 2;
#ifndef WITHOUT_MIRROR
	unsigned int log_mirror : 2;
#endif /* !WITHOUT_MIRROR */

	// Precedence is used in rule application
	// More specific rules have higher precedence
	unsigned int precedence;
} filter_action_t;

typedef struct filter_rule {
	// from: source filter
	unsigned int all_conns : 1;   /* 1 to apply to all src ips and users */

#ifndef WITHOUT_USERAUTH
	unsigned int all_users : 1;   /* 1 to apply to all users */

	char *user;
	char *keyword;
#endif /* !WITHOUT_USERAUTH */
	char *ip;
	
	// to: target filter
	char *site;
	unsigned int all_sites : 1;   /* 1 to match all sites == '*' */
	unsigned int exact : 1;       /* 1 for exact, 0 for substring match */

	// Used with dstip filters only, i.e. if the site is an ip address
	// This is not for the src ip in the 'from' part of rules
	char *port;
	unsigned int all_ports : 1;   /* 1 to match all ports == '*' */
	unsigned int exact_port : 1;  /* 1 for exact, 0 for substring match */

	// Conn field to apply filter to
	unsigned int dstip : 1;       /* 1 to apply to dst ip */
	unsigned int host : 1;        /* 1 to apply to http host */
	unsigned int uri : 1;         /* 1 to apply to http uri */
	unsigned int sni : 1;         /* 1 to apply to sni */
	unsigned int cn : 1;          /* 1 to apply to common names */

	struct filter_action action;

	struct filter_rule *next;
} filter_rule_t;

typedef struct filter_port {
	char *port;
	unsigned int all_ports : 1;
	unsigned int exact : 1;

	struct filter_action action;

	struct filter_port *next;
} filter_port_t;

typedef struct filter_site {
	char *site;
	unsigned int all_sites : 1;
	unsigned int exact : 1;

	// Used with dstip filters only, i.e. if the site is an ip address
	struct filter_port *port;

	struct filter_action action;

	struct filter_site *next;
} filter_site_t;

typedef struct filter_list {
	struct filter_site *ip;
	struct filter_site *sni;
	struct filter_site *cn;
	struct filter_site *host;
	struct filter_site *uri;
} filter_list_t;

typedef struct filter_ip {
	char *ip;
	struct filter_list *list;
	struct filter_ip *next;
} filter_ip_t;

#ifndef WITHOUT_USERAUTH
typedef struct filter_keyword {
	char *keyword;
	struct filter_list *list;
	struct filter_keyword *next;
} filter_keyword_t;

typedef struct filter_user {
	char *user;
	struct filter_list *list;
	struct filter_keyword *keyword;
	struct filter_user *next;
} filter_user_t;
#endif /* !WITHOUT_USERAUTH */

typedef struct filter {
#ifndef WITHOUT_USERAUTH
	struct filter_user *user;
	struct filter_keyword *keyword;
	struct filter_list *all_user;
#endif /* !WITHOUT_USERAUTH */
	struct filter_ip *ip;
	struct filter_list *all;
} filter_t;

void filter_macro_free(opts_t *);
void filter_rules_free(opts_t *) NONNULL(1);
void filter_free(opts_t *);

int filter_macro_copy(macro_t *, const char *, opts_t *) NONNULL(2,3) WUNRES;
int filter_rules_copy(filter_rule_t *, const char *, opts_t *) NONNULL(2,3) WUNRES;

char *filter_macro_str(macro_t *);
char *filter_rule_str(filter_rule_t *);
char *filter_str(filter_t *);

int filter_passsite_set(opts_t *, char *, int) WUNRES;
int filter_macro_set(opts_t *, char *, int) WUNRES;

filter_ip_t *filter_ip_find(filter_ip_t *, char *) NONNULL(2);
#ifndef WITHOUT_USERAUTH
filter_keyword_t *filter_keyword_find(filter_keyword_t *, char *) NONNULL(2);
filter_user_t *filter_user_find(filter_user_t *, char *) NONNULL(2);
#endif /* !WITHOUT_USERAUTH */
int filter_rule_set(opts_t *, const char *, char *, int) NONNULL(1,2,3) WUNRES;
filter_t *filter_set(filter_rule_t *);

#endif /* !FILTER_H */

/* vim: set noet ft=c: */