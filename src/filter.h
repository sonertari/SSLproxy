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
#include "kbtree.h"

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
	unsigned int exact_user : 1;  /* 1 for exact, 0 for substring match */

	char *keyword;
	unsigned int exact_keyword : 1; /* 1 for exact, 0 for substring match */
#endif /* !WITHOUT_USERAUTH */

	char *ip;
	unsigned int exact_ip : 1;    /* 1 for exact, 0 for substring match */
	
	// to: target filter
	char *site;
	unsigned int all_sites : 1;   /* 1 to match all sites == '*' */
	unsigned int exact_site : 1;  /* 1 for exact, 0 for substring match */

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
	unsigned int exact : 1;       /* used in debug logging only */

	struct filter_action action;
} filter_port_t;

typedef const char *str_t;

#define getk_port(a) (a)->port
typedef filter_port_t *filter_port_p_t;
KBTREE_INIT(port, filter_port_p_t, kb_str_cmp, str_t, getk_port)

typedef struct filter_port_list {
	struct filter_port *port;
	struct filter_port_list *next;
} filter_port_list_t;

typedef struct filter_site {
	char *site;
	unsigned int all_sites : 1;
	unsigned int exact : 1;       /* used in debug logging only */

	// Used with dstip filters only, i.e. if the site is an ip address
	kbtree_t(port) *port_btree;
	struct filter_port_list *port_list;

	struct filter_action action;
} filter_site_t;

#define getk_site(a) (a)->site
typedef filter_site_t *filter_site_p_t;
KBTREE_INIT(site, filter_site_p_t, kb_str_cmp, str_t, getk_site)

typedef struct filter_site_list {
	struct filter_site *site;
	struct filter_site_list *next;
} filter_site_list_t;

typedef struct filter_list {
	kbtree_t(site) *ip_btree;
	struct filter_site_list *ip_list;

	kbtree_t(site) *sni_btree;
	struct filter_site_list *sni_list;

	kbtree_t(site) *cn_btree;
	struct filter_site_list *cn_list;

	kbtree_t(site) *host_btree;
	struct filter_site_list *host_list;

	kbtree_t(site) *uri_btree;
	struct filter_site_list *uri_list;
} filter_list_t;

typedef struct filter_ip {
	char *ip;
	unsigned int exact : 1;       /* used in debug logging only */
	struct filter_list *list;
} filter_ip_t;

typedef struct filter_ip_list {
	struct filter_ip *ip;
	struct filter_ip_list *next;
} filter_ip_list_t;

#ifndef WITHOUT_USERAUTH
typedef struct filter_keyword {
	char *keyword;
	unsigned int exact : 1;       /* used in debug logging only */
	struct filter_list *list;
} filter_keyword_t;

#define getk_keyword(a) (a)->keyword
typedef filter_keyword_t *filter_keyword_p_t;
KBTREE_INIT(keyword, filter_keyword_p_t, kb_str_cmp, str_t, getk_keyword)

typedef struct filter_keyword_list {
	struct filter_keyword *keyword;
	struct filter_keyword_list *next;
} filter_keyword_list_t;

typedef struct filter_user {
	char *user;
	unsigned int exact : 1;       /* used in debug logging only */
	struct filter_list *list;
	kbtree_t(keyword) *keyword_btree;
	struct filter_keyword_list *keyword_list;
} filter_user_t;

#define getk_user(a) (a)->user
typedef filter_user_t *filter_user_p_t;
KBTREE_INIT(user, filter_user_p_t, kb_str_cmp, str_t, getk_user)

typedef struct filter_user_list {
	struct filter_user *user;
	struct filter_user_list *next;
} filter_user_list_t;
#endif /* !WITHOUT_USERAUTH */

#define getk_ip(a) (a)->ip
typedef filter_ip_t *filter_ip_p_t;
KBTREE_INIT(ip, filter_ip_p_t, kb_str_cmp, str_t, getk_ip)

typedef struct filter {
#ifndef WITHOUT_USERAUTH
	kbtree_t(user) *user_btree;               /* exact */
	struct filter_user_list *user_list;       /* substring */

	kbtree_t(keyword) *keyword_btree;         /* exact */
	struct filter_keyword_list *keyword_list; /* substring */

	struct filter_list *all_user;
#endif /* !WITHOUT_USERAUTH */

	kbtree_t(ip) *ip_btree;                   /* exact */
	struct filter_ip_list *ip_list;           /* substring */

	struct filter_list *all;
} filter_t;

#ifndef WITHOUT_USERAUTH
void filter_userlist_free(userlist_t *);
int filter_userlist_copy(userlist_t *, const char *, userlist_t **) NONNULL(2) WUNRES;
char *filter_userlist_str(userlist_t *);
int filter_userlist_set(char *, int, userlist_t **, const char *) NONNULL(1,4) WUNRES;
#endif /* !WITHOUT_USERAUTH */

void filter_macro_free(opts_t *) NONNULL(1);
void filter_rules_free(opts_t *) NONNULL(1);
void filter_free(opts_t *) NONNULL(1);

int filter_macro_copy(macro_t *, const char *, opts_t *) NONNULL(2,3) WUNRES;
int filter_rules_copy(filter_rule_t *, const char *, opts_t *) NONNULL(2,3) WUNRES;

char *filter_macro_str(macro_t *);
char *filter_rule_str(filter_rule_t *);
char *filter_str(filter_t *);

int filter_passsite_set(opts_t *, char *, int) NONNULL(1,2) WUNRES;
int filter_macro_set(opts_t *, char *, int) NONNULL(1,2) WUNRES;

filter_port_t *filter_port_find(filter_site_t *, char *) NONNULL(1,2);

filter_site_t *filter_site_btree_exact_match(kbtree_t(site) *, char *) NONNULL(2) WUNRES;
filter_site_t *filter_site_list_substring_match(filter_site_list_t *, char *) NONNULL(2) WUNRES;
filter_site_t *filter_site_find(kbtree_t(site) *, filter_site_list_t *, char *) NONNULL(3) WUNRES;

filter_ip_t *filter_ip_find(filter_t *, char *) NONNULL(1,2);
#ifndef WITHOUT_USERAUTH
filter_keyword_t *filter_keyword_find(filter_t *, filter_user_t *, char *) NONNULL(1,3);
filter_user_t *filter_user_find(filter_t *, char *) NONNULL(1,2);
#endif /* !WITHOUT_USERAUTH */
int filter_rule_set(opts_t *, const char *, char *, int) NONNULL(1,2,3) WUNRES;
filter_t *filter_set(filter_rule_t *) NONNULL(1) WUNRES;

#endif /* !FILTER_H */

/* vim: set noet ft=c: */
