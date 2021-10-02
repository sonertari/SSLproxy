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

#include "opts.h"
#include "filter.h"

#include "sys.h"
#include "log.h"
#include "util.h"

#define free_list(list, type) { \
	while (list) { \
		type *next = (list)->next; \
		free(list); \
		list = next; \
	}}

#define append_list(list, value, type) { \
	type *l = *list; \
	while (l) { \
		if (!l->next) \
			break; \
		l = l->next; \
	} \
	if (l) \
		l->next = value; \
	else \
		*list = value; \
	}

#ifndef WITHOUT_USERAUTH
void
filter_userlist_free(userlist_t *ul)
{
	while (ul) {
		userlist_t *next = ul->next;
		free(ul->user);
		free(ul);
		ul = next;
	}
}

int
filter_userlist_copy(userlist_t *userlist, const char *argv0, userlist_t **ul)
{
	while (userlist) {
		userlist_t *du = malloc(sizeof(userlist_t));
		if (!du)
			return oom_return(argv0);
		memset(du, 0, sizeof(userlist_t));

		du->user = strdup(userlist->user);
		if (!du->user)
			return oom_return(argv0);

		append_list(ul, du, userlist_t)

		userlist = userlist->next;
	}
	return 0;
}

char *
filter_userlist_str(userlist_t *u)
{
	char *us = NULL;

	if (!u) {
		us = strdup("");
		if (!us)
			return oom_return_na_null();
		goto out;
	}

	while (u) {
		char *nus;
		if (asprintf(&nus, "%s%s%s", STRORNONE(us), us ? "," : "", u->user) < 0) {
			goto err;
		}

		if (us)
			free(us);
		us = nus;
		u = u->next;
	}
	goto out;
err:
	if (us) {
		free(us);
		us = NULL;
	}
out:
	return us;
}

// Limit the number of users to max 50
#define MAX_USERS 50

int
filter_userlist_set(char *value, int line_num, userlist_t **list, const char *listname)
{
	// Delimiter can be either or all of ",", " ", and "\t"
	// Using space as a delimiter disables spaces in user names too
	// user1[,user2[,user3]]
	char *argv[sizeof(char *) * MAX_USERS];
	int argc = 0;
	char *p, *last = NULL;

	// strtok_r() removes all delimiters around user names, and does not return empty tokens
	for ((p = strtok_r(value, ", \t", &last));
		 p;
		 (p = strtok_r(NULL, ", \t", &last))) {
		if (argc < MAX_USERS) {
			argv[argc++] = p;
		} else {
			fprintf(stderr, "Too many arguments in user list, max users allowed %d, on line %d\n", MAX_USERS, line_num);
			return -1;
		}
	}

	if (!argc) {
		fprintf(stderr, "%s requires at least one parameter on line %d\n", listname, line_num);
		return -1;
	}

	// Override the copied global list, if any
	if (*list) {
		filter_userlist_free(*list);
		*list = NULL;
	}

	while (argc--) {
		userlist_t *ul = malloc(sizeof(userlist_t));
		if (!ul)
			return oom_return_na();
		memset(ul, 0, sizeof(userlist_t));

		ul->user = strdup(argv[argc]);
		if (!ul->user)
			return oom_return_na();

		append_list(list, ul, userlist_t)
	}
	return 0;
}
#endif /* !WITHOUT_USERAUTH */

static void
filter_value_free(value_t *value)
{
	while (value) {
		value_t *next = value->next;
		free(value->value);
		free(value);
		value = next;
	}
}

void
filter_macro_free(opts_t *opts)
{
	macro_t *macro = opts->macro;
	while (macro) {
		macro_t *next = macro->next;
		free(macro->name);
		filter_value_free(macro->value);
		free(macro);
		macro = next;
	}
	opts->macro = NULL;
}

void
filter_rules_free(opts_t *opts)
{
	filter_rule_t *rule = opts->filter_rules;
	while (rule) {
		filter_rule_t *next = rule->next;
		free(rule->site);
		if (rule->port)
			free(rule->port);
		if (rule->ip)
			free(rule->ip);
#ifndef WITHOUT_USERAUTH
		if (rule->user)
			free(rule->user);
		if (rule->keyword)
			free(rule->keyword);
#endif /* !WITHOUT_USERAUTH */
		free(rule);
		rule = next;
	}
	opts->filter_rules = NULL;
}

#define free_port(p) { \
	free(*p->port); \
	free(*p); }

static void
filter_port_btree_free(kbtree_t(port) *port_btree)
{
	if (port_btree) {
		__kb_traverse(filter_port_p_t, port_btree, free_port);
		__kb_destroy(port_btree);
	}
}

static void
filter_port_list_free(filter_port_list_t *port)
{
	while (port) {
		filter_port_list_t *p = port->next;
		free_port(&port)
		port = p;
	}
}

#define free_site(p) { \
	free(*p->site); \
	filter_port_btree_free(*p->port_btree); \
	filter_port_list_free(*p->port_list); \
	free(*p); }

static filter_site_list_t *
filter_site_free(filter_site_list_t *site_list)
{
	filter_site_list_t *s = site_list->next;
	free_site(&site_list->site)
	free(site_list);
	return s;
}

static void
filter_list_free(filter_list_t *list)
{
	if (list->ip_btree) {
		__kb_traverse(filter_site_p_t, list->ip_btree, free_site);
		__kb_destroy(list->ip_btree);
	}
	while (list->ip_list)
		list->ip_list = filter_site_free(list->ip_list);

	if (list->sni_btree) {
		__kb_traverse(filter_site_p_t, list->sni_btree, free_site);
		__kb_destroy(list->sni_btree);
	}
	while (list->sni_list)
		list->sni_list = filter_site_free(list->sni_list);

	if (list->cn_btree) {
		__kb_traverse(filter_site_p_t, list->cn_btree, free_site);
		__kb_destroy(list->cn_btree);
	}
	while (list->cn_list)
		list->cn_list = filter_site_free(list->cn_list);

	if (list->host_btree) {
		__kb_traverse(filter_site_p_t, list->host_btree, free_site);
		__kb_destroy(list->host_btree);
	}
	while (list->host_list)
		list->host_list = filter_site_free(list->host_list);

	if (list->uri_btree) {
		__kb_traverse(filter_site_p_t, list->uri_btree, free_site);
		__kb_destroy(list->uri_btree);
	}
	while (list->uri_list)
		list->uri_list = filter_site_free(list->uri_list);

	free(list);
}

#ifndef WITHOUT_USERAUTH
#define free_keyword(p) { \
	free(*p->keyword); \
	filter_list_free(*p->list); \
	free(*p); }

static void
filter_keyword_list_free(filter_keyword_list_t *list)
{
	while (list) {
		filter_keyword_list_t *keyword = list->next;
		free_keyword(&list->keyword)
		free(list);
		list = keyword;
	}
}

static void
filter_user_free(filter_user_t *user)
{
	free(user->user);
	filter_list_free(user->list);

	if (user->keyword_btree) {
		__kb_traverse(filter_keyword_p_t, user->keyword_btree, free_keyword);
		__kb_destroy(user->keyword_btree);
	}

	filter_keyword_list_free(user->keyword_list);
}

#define free_user(p) { \
	filter_user_free(*p); \
	free(*p); }
#endif /* !WITHOUT_USERAUTH */

void
filter_free(opts_t *opts)
{
	if (!opts->filter)
		return;

	filter_t *pf = opts->filter;
#ifndef WITHOUT_USERAUTH
	if (pf->user_btree) {
		__kb_traverse(filter_user_p_t, pf->user_btree, free_user);
		__kb_destroy(pf->user_btree);
	}

	while (pf->user_list) {
		filter_user_free(pf->user_list->user);

		filter_user_list_t *user = pf->user_list->next;
		free(pf->user_list);
		pf->user_list = user;
	}

	if (pf->keyword_btree) {
		__kb_traverse(filter_keyword_p_t, pf->keyword_btree, free_keyword);
		__kb_destroy(pf->keyword_btree);
	}

	filter_keyword_list_free(pf->keyword_list);

	filter_list_free(pf->all_user);
#endif /* !WITHOUT_USERAUTH */

#define free_ip(p) { \
	free(*p->ip); \
	filter_list_free(*p->list); \
	free(*p); }

	if (pf->ip_btree) {
		__kb_traverse(filter_ip_p_t, pf->ip_btree, free_ip);
		__kb_destroy(pf->ip_btree);
	}

	while (pf->ip_list) {
		free(pf->ip_list->ip->ip);
		filter_list_free(pf->ip_list->ip->list);
		free(pf->ip_list->ip);

		filter_ip_list_t *ip = pf->ip_list->next;
		free(pf->ip_list);
		pf->ip_list = ip;
	}

	filter_list_free(pf->all);

	free(opts->filter);
	opts->filter = NULL;
}

int
filter_macro_copy(macro_t *macro, const char *argv0, opts_t *opts)
{
	while (macro) {
		macro_t *m = malloc(sizeof(macro_t));
		if (!m)
			return oom_return(argv0);
		memset(m, 0, sizeof(macro_t));

		m->name = strdup(macro->name);
		if (!m->name)
			return oom_return(argv0);

		value_t *value = macro->value;
		while (value) {
			value_t *v = malloc(sizeof(value_t));
			if (!v)
				return oom_return(argv0);
			memset(v, 0, sizeof(value_t));

			v->value = strdup(value->value);
			if (!v->value)
				return oom_return(argv0);

			append_list(&m->value, v, value_t)

			value = value->next;
		}

		append_list(&opts->macro, m, macro_t)

		macro = macro->next;
	}
	return 0;
}

int
filter_rules_copy(filter_rule_t *rule, const char *argv0, opts_t *opts)
{
	while (rule) {
		filter_rule_t *r = malloc(sizeof(filter_rule_t));
		if (!r)
			return oom_return(argv0);
		memset(r, 0, sizeof(filter_rule_t));

		r->all_conns = rule->all_conns;

#ifndef WITHOUT_USERAUTH
		r->all_users = rule->all_users;

		if (rule->user) {
			r->user = strdup(rule->user);
			if (!r->user)
				return oom_return(argv0);
		}
		r->exact_user = rule->exact_user;

		if (rule->keyword) {
			r->keyword = strdup(rule->keyword);
			if (!r->keyword)
				return oom_return(argv0);
		}
		r->exact_keyword = rule->exact_keyword;
#endif /* !WITHOUT_USERAUTH */

		if (rule->ip) {
			r->ip = strdup(rule->ip);
			if (!r->ip)
				return oom_return(argv0);
		}
		r->exact_ip = rule->exact_ip;

		if (rule->site) {
			r->site = strdup(rule->site);
			if (!r->site)
				return oom_return(argv0);
		}
		r->all_sites = rule->all_sites;
		r->exact_site = rule->exact_site;

		if (rule->port) {
			r->port = strdup(rule->port);
			if (!r->port)
				return oom_return(argv0);
		}
		r->all_ports = rule->all_ports;
		r->exact_port = rule->exact_port;

		r->dstip = rule->dstip;
		r->sni = rule->sni;
		r->cn = rule->cn;
		r->host = rule->host;
		r->uri = rule->uri;

		// The action field is not a pointer, hence the direct assignment (copy)
		r->action = rule->action;

		append_list(&opts->filter_rules, r, filter_rule_t)

		rule = rule->next;
	}
	return 0;
}

static char *
filter_value_str(value_t *value)
{
	char *s = NULL;

	while (value) {
		char *p;
		if (asprintf(&p, "%s%s%s", STRORNONE(s), s ? ", " : "", value->value) < 0) {
			goto err;
		}
		if (s)
			free(s);
		s = p;
		value = value->next;
	}
	goto out;
err:
	if (s) {
		free(s);
		s = NULL;
	}
out:
	return s;
}

char *
filter_macro_str(macro_t *macro)
{
	char *s = NULL;

	if (!macro) {
		s = strdup("");
		if (!s)
			return oom_return_na_null();
		goto out;
	}

	while (macro) {
		char *v = filter_value_str(macro->value);

		char *p;
		if (asprintf(&p, "%s%smacro %s = %s", STRORNONE(s), s ? "\n" : "", macro->name, STRORNONE(v)) < 0) {
			if (v)
				free(v);
			goto err;
		}
		if (v)
			free(v);
		if (s)
			free(s);
		s = p;
		macro = macro->next;
	}
	goto out;
err:
	if (s) {
		free(s);
		s = NULL;
	}
out:
	return s;
}

char *
filter_rule_str(filter_rule_t *rule)
{
	char *frs = NULL;

	if (!rule) {
		frs = strdup("");
		if (!frs)
			return oom_return_na_null();
		goto out;
	}

	int count = 0;
	while (rule) {
		char *p;
		if (asprintf(&p, "site=%s, port=%s, ip=%s"
#ifndef WITHOUT_USERAUTH
				", user=%s, keyword=%s"
#endif /* !WITHOUT_USERAUTH */
				", exact=%s|%s|%s"
#ifndef WITHOUT_USERAUTH
				"|%s|%s"
#endif /* !WITHOUT_USERAUTH */
				", all=%s"
#ifndef WITHOUT_USERAUTH
				"|%s"
#endif /* !WITHOUT_USERAUTH */
				"|%s|%s, action=%s|%s|%s|%s|%s, log=%s|%s|%s|%s|%s"
#ifndef WITHOUT_MIRROR
				"|%s"
#endif /* !WITHOUT_MIRROR */
				", apply to=%s|%s|%s|%s|%s, precedence=%d",
				rule->site, STRORNONE(rule->port), STRORNONE(rule->ip),
#ifndef WITHOUT_USERAUTH
				STRORNONE(rule->user), STRORNONE(rule->keyword),
#endif /* !WITHOUT_USERAUTH */
				rule->exact_site ? "site" : "", rule->exact_port ? "port" : "", rule->exact_ip ? "ip" : "",
#ifndef WITHOUT_USERAUTH
				rule->exact_user ? "user" : "", rule->exact_keyword ? "keyword" : "",
#endif /* !WITHOUT_USERAUTH */
				rule->all_conns ? "conns" : "",
#ifndef WITHOUT_USERAUTH
				rule->all_users ? "users" : "",
#endif /* !WITHOUT_USERAUTH */
				rule->all_sites ? "sites" : "", rule->all_ports ? "ports" : "",
				rule->action.divert ? "divert" : "", rule->action.split ? "split" : "", rule->action.pass ? "pass" : "", rule->action.block ? "block" : "", rule->action.match ? "match" : "",
				rule->action.log_connect ? (rule->action.log_connect == 1 ? "!connect" : "connect") : "", rule->action.log_master ? (rule->action.log_master == 1 ? "!master" : "master") : "",
				rule->action.log_cert ? (rule->action.log_cert == 1 ? "!cert" : "cert") : "", rule->action.log_content ? (rule->action.log_content == 1 ? "!content" : "content") : "",
				rule->action.log_pcap ? (rule->action.log_pcap == 1 ? "!pcap" : "pcap") : "",
#ifndef WITHOUT_MIRROR
				rule->action.log_mirror ? (rule->action.log_mirror == 1 ? "!mirror" : "mirror") : "",
#endif /* !WITHOUT_MIRROR */
				rule->dstip ? "dstip" : "", rule->sni ? "sni" : "", rule->cn ? "cn" : "", rule->host ? "host" : "", rule->uri ? "uri" : "",
				rule->action.precedence) < 0) {
			goto err;
		}
		char *nfrs;
		if (asprintf(&nfrs, "%s%sfilter rule %d: %s", 
					STRORNONE(frs), frs ? "\n" : "", count, p) < 0) {
			free(p);
			goto err;
		}
		free(p);
		if (frs)
			free(frs);
		frs = nfrs;
		rule = rule->next;
		count++;
	}
	goto out;
err:
	if (frs) {
		free(frs);
		frs = NULL;
	}
out:
	return frs;
}

static char *
filter_port_str(filter_port_list_t *port_list)
{
	char *s = NULL;

	int count = 0;
	while (port_list) {
		char *p;
		if (asprintf(&p, "%s\n          %d: %s (%s%s, action=%s|%s|%s|%s|%s, log=%s|%s|%s|%s|%s"
#ifndef WITHOUT_MIRROR
				"|%s"
#endif /* !WITHOUT_MIRROR */
				", precedence=%d)", STRORNONE(s), count,
				port_list->port->port, port_list->port->all_ports ? "all_ports, " : "", port_list->port->exact ? "exact" : "substring",
				port_list->port->action.divert ? "divert" : "", port_list->port->action.split ? "split" : "", port_list->port->action.pass ? "pass" : "", port_list->port->action.block ? "block" : "", port_list->port->action.match ? "match" : "",
				port_list->port->action.log_connect ? (port_list->port->action.log_connect == 1 ? "!connect" : "connect") : "", port_list->port->action.log_master ? (port_list->port->action.log_master == 1 ? "!master" : "master") : "",
				port_list->port->action.log_cert ? (port_list->port->action.log_cert == 1 ? "!cert" : "cert") : "", port_list->port->action.log_content ? (port_list->port->action.log_content == 1 ? "!content" : "content") : "",
				port_list->port->action.log_pcap ? (port_list->port->action.log_pcap == 1 ? "!pcap" : "pcap") : "",
#ifndef WITHOUT_MIRROR
				port_list->port->action.log_mirror ? (port_list->port->action.log_mirror == 1 ? "!mirror" : "mirror") : "",
#endif /* !WITHOUT_MIRROR */
				port_list->port->action.precedence) < 0) {
			goto err;
		}
		if (s)
			free(s);
		s = p;
		port_list = port_list->next;
		count++;
	}
	goto out;
err:
	if (s) {
		free(s);
		s = NULL;
	}
out:
	return s;
}

#define build_port_list(p) { \
	filter_port_list_t *s = malloc(sizeof(filter_port_list_t)); \
	memset(s, 0, sizeof(filter_port_list_t)); \
	s->port = *p; \
	append_list(&port, s, filter_port_list_t) }

static char *
filter_sites_str(filter_site_list_t *site_list)
{
	char *s = NULL;

	int count = 0;
	while (site_list) {
		filter_port_list_t *port = NULL;

		if (site_list->site->port_btree)
			__kb_traverse(filter_port_p_t, site_list->site->port_btree, build_port_list);

		char *ports_exact = filter_port_str(port);
		char *ports_substring = filter_port_str(site_list->site->port_list);

		char *p;
		if (asprintf(&p, "%s\n      %d: %s (%s%s, action=%s|%s|%s|%s|%s, log=%s|%s|%s|%s|%s"
#ifndef WITHOUT_MIRROR
				"|%s"
#endif /* !WITHOUT_MIRROR */
				", precedence=%d)%s%s%s%s",
				STRORNONE(s), count,
				site_list->site->site, site_list->site->all_sites ? "all_sites, " : "", site_list->site->exact ? "exact" : "substring",
				site_list->site->action.divert ? "divert" : "", site_list->site->action.split ? "split" : "", site_list->site->action.pass ? "pass" : "", site_list->site->action.block ? "block" : "", site_list->site->action.match ? "match" : "",
				site_list->site->action.log_connect ? (site_list->site->action.log_connect == 1 ? "!connect" : "connect") : "", site_list->site->action.log_master ? (site_list->site->action.log_master == 1 ? "!master" : "master") : "",
				site_list->site->action.log_cert ? (site_list->site->action.log_cert == 1 ? "!cert" : "cert") : "", site_list->site->action.log_content ? (site_list->site->action.log_content == 1 ? "!content" : "content") : "",
				site_list->site->action.log_pcap ? (site_list->site->action.log_pcap == 1 ? "!pcap" : "pcap") : "",
#ifndef WITHOUT_MIRROR
				site_list->site->action.log_mirror ? (site_list->site->action.log_mirror == 1 ? "!mirror" : "mirror") : "",
#endif /* !WITHOUT_MIRROR */
				site_list->site->action.precedence,
				ports_exact ? "\n        port exact:" : "", STRORNONE(ports_exact),
				ports_substring ? "\n        port substring:" : "", STRORNONE(ports_substring)) < 0) {
			if (ports_exact) {
				free(ports_exact);
				free_list(port, filter_port_list_t)
			}
			if (ports_substring)
				free(ports_substring);
			goto err;
		}
		if (ports_exact) {
			free(ports_exact);
			free_list(port, filter_port_list_t)
		}
		if (ports_substring)
			free(ports_substring);
		if (s)
			free(s);
		s = p;
		site_list = site_list->next;
		count++;
	}
	goto out;
err:
	if (s) {
		free(s);
		s = NULL;
	}
out:
	return s;
}

static char *
filter_list_sub_str(filter_site_list_t *list, char *old_s, const char *name)
{
	char *new_s = NULL;
	char *s = filter_sites_str(list);
	if (asprintf(&new_s, "%s%s    %s: %s", STRORNONE(old_s), old_s ? "\n" : "", name, STRORNONE(s)) < 0) {
		// @todo Handle oom, and don't just use STRORNONE()
		new_s = NULL;
	}
	if (s)
		free(s);
	if (old_s)
		free(old_s);
	return new_s;
}

static void
filter_tmp_site_list_free(filter_site_list_t **list)
{
	free_list(*list, filter_site_list_t)
	*list = NULL;
}

static char *
filter_list_str(filter_list_t *list)
{
	char *s = NULL;
	filter_site_list_t *site = NULL;

#define build_site_list(p) { \
	filter_site_list_t *s = malloc(sizeof(filter_site_list_t)); \
	memset(s, 0, sizeof(filter_site_list_t)); \
	s->site = *p; \
	append_list(&site, s, filter_site_list_t) }

	if (list->ip_btree) {
		__kb_traverse(filter_site_p_t, list->ip_btree, build_site_list);
		s = filter_list_sub_str(site, s, "ip exact");
		filter_tmp_site_list_free(&site);
	}

	if (list->ip_list) {
		s = filter_list_sub_str(list->ip_list, s, "ip substring");
	}

	if (list->sni_btree) {
		__kb_traverse(filter_site_p_t, list->sni_btree, build_site_list);
		s = filter_list_sub_str(site, s, "sni exact");
		filter_tmp_site_list_free(&site);
	}

	if (list->sni_list) {
		s = filter_list_sub_str(list->sni_list, s, "sni substring");
	}

	if (list->cn_btree) {
		__kb_traverse(filter_site_p_t, list->cn_btree, build_site_list);
		s = filter_list_sub_str(site, s, "cn exact");
		filter_tmp_site_list_free(&site);
	}

	if (list->cn_list) {
		s = filter_list_sub_str(list->cn_list, s, "cn substring");
	}

	if (list->host_btree) {
		__kb_traverse(filter_site_p_t, list->host_btree, build_site_list);
		s = filter_list_sub_str(site, s, "host exact");
		filter_tmp_site_list_free(&site);
	}

	if (list->host_list) {
		s = filter_list_sub_str(list->host_list, s, "host substring");
	}

	if (list->uri_btree) {
		__kb_traverse(filter_site_p_t, list->uri_btree, build_site_list);
		s = filter_list_sub_str(site, s, "uri exact");
		filter_tmp_site_list_free(&site);
	}

	if (list->uri_list) {
		s = filter_list_sub_str(list->uri_list, s, "uri substring");
	}
	return s;
}

static char *
filter_ip_list_str(filter_ip_list_t *ip_list)
{
	char *s = NULL;

	int count = 0;
	while (ip_list) {
		char *list = filter_list_str(ip_list->ip->list);

		char *p;
		if (asprintf(&p, "%s%s  ip %d %s (%s)= \n%s", STRORNONE(s), s ? "\n" : "",
				count, ip_list->ip->ip, ip_list->ip->exact ? "exact" : "substring", STRORNONE(list)) < 0) {
			if (list)
				free(list);
			goto err;
		}
		if (list)
			free(list);
		if (s)
			free(s);
		s = p;
		ip_list = ip_list->next;
		count++;
	}
	goto out;
err:
	if (s) {
		free(s);
		s = NULL;
	}
out:
	return s;
}

static char *
filter_ip_btree_str(kbtree_t(ip) *ip_btree)
{
	if (!ip_btree)
		return NULL;

#define build_ip_list(p) { \
	filter_ip_list_t *i = malloc(sizeof(filter_ip_list_t)); \
	memset(i, 0, sizeof(filter_ip_list_t)); \
	i->ip = *p; \
	append_list(&ip, i, filter_ip_list_t) }
	
	filter_ip_list_t *ip = NULL;
	__kb_traverse(filter_ip_p_t, ip_btree, build_ip_list);

	char *s = filter_ip_list_str(ip);
	
	free_list(ip, filter_ip_list_t)
	return s;
}

#ifndef WITHOUT_USERAUTH
static char *
filter_user_list_str(filter_user_list_t *user)
{
	char *s = NULL;

	int count = 0;
	while (user) {
		// Make sure the current user does not have any keyword
		if (user->user->keyword_btree || user->user->keyword_list)
			goto skip;

		char *list = filter_list_str(user->user->list);

		char *p = NULL;

		// Make sure the user has a filter rule
		// It is possible to have users without any filter rule,
		// but the user exists because it has keyword filters
		if (list) {
			if (asprintf(&p, "%s%s  user %d %s (%s)= \n%s", STRORNONE(s), s ? "\n" : "",
					count, user->user->user, user->user->exact ? "exact" : "substring", list) < 0) {
				free(list);
				goto err;
			}
			free(list);
		}
		if (s)
			free(s);
		s = p;
		count++;
skip:
		user = user->next;
	}
	goto out;
err:
	if (s) {
		free(s);
		s = NULL;
	}
out:
	return s;
}

#define build_user_list(p) { \
	filter_user_list_t *u = malloc(sizeof(filter_user_list_t)); \
	memset(u, 0, sizeof(filter_user_list_t)); \
	u->user = *p; \
	append_list(&user, u, filter_user_list_t) }

static char *
filter_user_btree_str(kbtree_t(user) *user_btree)
{
	if (!user_btree)
		return NULL;

	filter_user_list_t *user = NULL;
	__kb_traverse(filter_user_p_t, user_btree, build_user_list);

	char *s = filter_user_list_str(user);

	free_list(user, filter_user_list_t)
	return s;
}

static char *
filter_keyword_list_str(filter_keyword_list_t *keyword)
{
	char *s = NULL;

	int count = 0;
	while (keyword) {
		char *list = filter_list_str(keyword->keyword->list);

		char *p;
		if (asprintf(&p, "%s%s   keyword %d %s (%s)= \n%s", STRORNONE(s), s ? "\n" : "",
				count, keyword->keyword->keyword, keyword->keyword->exact ? "exact" : "substring", STRORNONE(list)) < 0) {
			if (list)
				free(list);
			goto err;
		}
		if (list)
			free(list);
		if (s)
			free(s);
		s = p;
		keyword = keyword->next;
		count++;
	}
	goto out;
err:
	if (s) {
		free(s);
		s = NULL;
	}
out:
	return s;
}

static char *
filter_keyword_btree_str(kbtree_t(keyword) *keyword_btree)
{
	if (!keyword_btree)
		return NULL;

#define build_keyword_list(p) { \
	filter_keyword_list_t *k = malloc(sizeof(filter_keyword_list_t)); \
	memset(k, 0, sizeof(filter_keyword_list_t)); \
	k->keyword = *p; \
	append_list(&keyword, k, filter_keyword_list_t) }
	
	filter_keyword_list_t *keyword = NULL;
	__kb_traverse(filter_keyword_p_t, keyword_btree, build_keyword_list);

	char *s = filter_keyword_list_str(keyword);
	
	free_list(keyword, filter_keyword_list_t)
	return s;
}

static char *
filter_userkeyword_list_str(filter_user_list_t *user)
{
	char *s = NULL;

	int count = 0;
	while (user) {
		// Make sure the current user has a keyword
		if (!user->user->keyword_btree && !user->user->keyword_list)
			goto skip;

		char *list_exact = filter_keyword_btree_str(user->user->keyword_btree);
		char *list_substr = filter_keyword_list_str(user->user->keyword_list);

		char *p = NULL;
		if (asprintf(&p, "%s%s user %d %s (%s)=%s%s%s%s", STRORNONE(s), s ? "\n" : "",
				count, user->user->user, user->user->exact ? "exact" : "substring",
				list_exact ? "\n  keyword exact:\n" : "", STRORNONE(list_exact),
				list_substr ? "\n  keyword substring:\n" : "", STRORNONE(list_substr)
				) < 0) {
			if (list_exact)
				free(list_exact);
			if (list_substr)
				free(list_substr);
			goto err;
		}
		if (list_exact)
			free(list_exact);
		if (list_substr)
			free(list_substr);
		if (s)
			free(s);
		s = p;
		count++;
skip:
		user = user->next;
	}
	goto out;
err:
	if (s) {
		free(s);
		s = NULL;
	}
out:
	return s;
}

static char *
filter_userkeyword_btree_str(kbtree_t(user) *user_btree)
{
	if (!user_btree)
		return NULL;

	filter_user_list_t *user = NULL;
	__kb_traverse(filter_user_p_t, user_btree, build_user_list);

	char *s = filter_userkeyword_list_str(user);

	free_list(user, filter_user_list_t)
	return s;
}
#endif /* !WITHOUT_USERAUTH */

char *
filter_str(filter_t *filter)
{
	char *fs = NULL;
#ifndef WITHOUT_USERAUTH
	char *userkeyword_filter_exact = NULL;
	char *userkeyword_filter_substr = NULL;
	char *user_filter_exact = NULL;
	char *user_filter_substr = NULL;
	char *keyword_filter_exact = NULL;
	char *keyword_filter_substr = NULL;
	char *all_user_filter = NULL;
#endif /* !WITHOUT_USERAUTH */
	char *ip_filter_exact = NULL;
	char *ip_filter_substr = NULL;
	char *all_filter = NULL;

	if (!filter) {
		fs = strdup("");
		if (!fs)
			return oom_return_na_null();
		goto out;
	}

#ifndef WITHOUT_USERAUTH
	userkeyword_filter_exact = filter_userkeyword_btree_str(filter->user_btree);
	userkeyword_filter_substr = filter_userkeyword_list_str(filter->user_list);
	user_filter_exact = filter_user_btree_str(filter->user_btree);
	user_filter_substr = filter_user_list_str(filter->user_list);
	keyword_filter_exact = filter_keyword_btree_str(filter->keyword_btree);
	keyword_filter_substr = filter_keyword_list_str(filter->keyword_list);
	all_user_filter = filter_list_str(filter->all_user);
#endif /* !WITHOUT_USERAUTH */
	ip_filter_exact = filter_ip_btree_str(filter->ip_btree);
	ip_filter_substr = filter_ip_list_str(filter->ip_list);
	all_filter = filter_list_str(filter->all);

	if (asprintf(&fs, "filter=>\n"
#ifndef WITHOUT_USERAUTH
			"userkeyword_filter_exact->%s%s\n"
			"userkeyword_filter_substr->%s%s\n"
			"user_filter_exact->%s%s\n"
			"user_filter_substr->%s%s\n"
			"keyword_filter_exact->%s%s\n"
			"keyword_filter_substr->%s%s\n"
			"all_user_filter->%s%s\n"
#endif /* !WITHOUT_USERAUTH */
			"ip_filter_exact->%s%s\n"
			"ip_filter_substr->%s%s\n"
			"all_filter->%s%s\n",
#ifndef WITHOUT_USERAUTH
			userkeyword_filter_exact ? "\n" : "", STRORNONE(userkeyword_filter_exact),
			userkeyword_filter_substr ? "\n" : "", STRORNONE(userkeyword_filter_substr),
			user_filter_exact ? "\n" : "", STRORNONE(user_filter_exact),
			user_filter_substr ? "\n" : "", STRORNONE(user_filter_substr),
			keyword_filter_exact ? "\n" : "", STRORNONE(keyword_filter_exact),
			keyword_filter_substr ? "\n" : "", STRORNONE(keyword_filter_substr),
			all_user_filter ? "\n" : "", STRORNONE(all_user_filter),
#endif /* !WITHOUT_USERAUTH */
			ip_filter_exact ? "\n" : "", STRORNONE(ip_filter_exact),
			ip_filter_substr ? "\n" : "", STRORNONE(ip_filter_substr),
			all_filter ? "\n" : "", STRORNONE(all_filter)) < 0) {
		// fs is undefined
		goto err;
	}
	goto out;
err:
	if (fs) {
		free(fs);
		fs = NULL;
	}
out:
#ifndef WITHOUT_USERAUTH
	if (userkeyword_filter_exact)
		free(userkeyword_filter_exact);
	if (userkeyword_filter_substr)
		free(userkeyword_filter_substr);
	if (user_filter_exact)
		free(user_filter_exact);
	if (user_filter_substr)
		free(user_filter_substr);
	if (keyword_filter_exact)
		free(keyword_filter_exact);
	if (keyword_filter_substr)
		free(keyword_filter_substr);
	if (all_user_filter)
		free(all_user_filter);
#endif /* !WITHOUT_USERAUTH */
	if (ip_filter_exact)
		free(ip_filter_exact);
	if (ip_filter_substr)
		free(ip_filter_substr);
	if (all_filter)
		free(all_filter);
	return fs;
}

#ifdef DEBUG_OPTS
static void
filter_rule_dbg_print(filter_rule_t *rule)
{
	log_dbg_printf("Filter rule: site=%s, port=%s, ip=%s"
#ifndef WITHOUT_USERAUTH
		", user=%s, keyword=%s"
#endif /* !WITHOUT_USERAUTH */
		", exact=%s|%s|%s"
#ifndef WITHOUT_USERAUTH
		"|%s|%s"
#endif /* !WITHOUT_USERAUTH */
		", all=%s|"
#ifndef WITHOUT_USERAUTH
		"%s|"
#endif /* !WITHOUT_USERAUTH */
		"%s|%s, action=%s|%s|%s|%s|%s, log=%s|%s|%s|%s|%s"
#ifndef WITHOUT_MIRROR
		"|%s"
#endif /* !WITHOUT_MIRROR */
		", apply to=%s|%s|%s|%s|%s, precedence=%d\n",
		rule->site, STRORNONE(rule->port), STRORNONE(rule->ip),
#ifndef WITHOUT_USERAUTH
		STRORNONE(rule->user), STRORNONE(rule->keyword),
#endif /* !WITHOUT_USERAUTH */
		rule->exact_site ? "site" : "", rule->exact_port ? "port" : "", rule->exact_ip ? "ip" : "",
#ifndef WITHOUT_USERAUTH
		rule->exact_user ? "user" : "", rule->exact_keyword ? "keyword" : "",
#endif /* !WITHOUT_USERAUTH */
		rule->all_conns ? "conns" : "",
#ifndef WITHOUT_USERAUTH
		rule->all_users ? "users" : "",
#endif /* !WITHOUT_USERAUTH */
		rule->all_sites ? "sites" : "", rule->all_ports ? "ports" : "",
		rule->action.divert ? "divert" : "", rule->action.split ? "split" : "", rule->action.pass ? "pass" : "", rule->action.block ? "block" : "", rule->action.match ? "match" : "",
		rule->action.log_connect ? (rule->action.log_connect == 1 ? "!connect" : "connect") : "", rule->action.log_master ? (rule->action.log_master == 1 ? "!master" : "master") : "",
		rule->action.log_cert ? (rule->action.log_cert == 1 ? "!cert" : "cert") : "", rule->action.log_content ? (rule->action.log_content == 1 ? "!content" : "content") : "",
		rule->action.log_pcap ? (rule->action.log_pcap == 1 ? "!pcap" : "pcap") : "",
#ifndef WITHOUT_MIRROR
		rule->action.log_mirror ? (rule->action.log_mirror == 1 ? "!mirror" : "mirror") : "",
#endif /* !WITHOUT_MIRROR */
		rule->dstip ? "dstip" : "", rule->sni ? "sni" : "", rule->cn ? "cn" : "", rule->host ? "host" : "", rule->uri ? "uri" : "",
		rule->action.precedence);
}
#endif /* DEBUG_OPTS */

#define MAX_SITE_LEN 200

int
filter_passsite_set(opts_t *opts, char *value, int line_num)
{
#define MAX_PASSSITE_TOKENS 3

	// site[*] [(clientaddr|user|*) [keyword]]
	char *argv[sizeof(char *) * MAX_PASSSITE_TOKENS];
	int argc = 0;
	char *p, *last = NULL;

	for ((p = strtok_r(value, " ", &last));
		 p;
		 (p = strtok_r(NULL, " ", &last))) {
		if (argc < MAX_PASSSITE_TOKENS) {
			argv[argc++] = p;
		} else {
			fprintf(stderr, "Too many arguments in passsite option on line %d\n", line_num);
			return -1;
		}
	}

	if (!argc) {
		fprintf(stderr, "Filter rule requires at least one parameter on line %d\n", line_num);
		return -1;
	}

	filter_rule_t *rule = malloc(sizeof(filter_rule_t));
	if (!rule)
		return oom_return_na();
	memset(rule, 0, sizeof(filter_rule_t));

	// The for loop with strtok_r() above does not output empty strings
	// So, no need to check if the length of argv[0] > 0
	size_t len = strlen(argv[0]);

	if (len > MAX_SITE_LEN) {
		fprintf(stderr, "Filter site too long %zu > %d on line %d\n", len, MAX_SITE_LEN, line_num);
		return -1;
	}

	if (argv[0][len - 1] == '*') {
		rule->exact_site = 0;
		len--;
		argv[0][len] = '\0';
		// site == "*" ?
		if (len == 0)
			rule->all_sites = 1;
	} else {
		rule->exact_site = 1;
	}

	rule->site = strdup(argv[0]);
	if (!rule->site)
		return oom_return_na();

	// precedence can only go up not down
	rule->action.precedence = 0;

	if (argc == 1) {
		// Apply filter rule to all conns
		// Equivalent to "site *" without user auth
		rule->all_conns = 1;
	}

	if (argc > 1) {
		if (!strcmp(argv[1], "*")) {
#ifndef WITHOUT_USERAUTH
			// Apply filter rule to all users perhaps with keyword
			rule->action.precedence++;
			rule->all_users = 1;
		} else if (sys_isuser(argv[1])) {
			if (!opts->user_auth) {
				fprintf(stderr, "User filter requires user auth on line %d\n", line_num);
				return -1;
			}
			rule->action.precedence += 2;
			rule->user = strdup(argv[1]);
			if (!rule->user)
				return oom_return_na();
#else /* !WITHOUT_USERAUTH */
			// Apply filter rule to all conns, if USERAUTH is disabled, ip == '*'
			rule->all_conns = 1;
#endif /* WITHOUT_USERAUTH */
		} else {
			rule->action.precedence++;
			rule->ip = strdup(argv[1]);
			if (!rule->ip)
				return oom_return_na();
		}
	}

	if (argc > 2) {
		if (rule->ip) {
			fprintf(stderr, "Ip filter cannot define keyword filter"
#ifndef WITHOUT_USERAUTH
					", or user '%s' does not exist"
#endif /* !WITHOUT_USERAUTH */
					" on line %d\n",
#ifndef WITHOUT_USERAUTH
					rule->ip,
#endif /* !WITHOUT_USERAUTH */
					line_num);
			return -1;
		}
#ifndef WITHOUT_USERAUTH
		if (!opts->user_auth) {
			fprintf(stderr, "Keyword filter requires user auth on line %d\n", line_num);
			return -1;
		}
		rule->action.precedence++;
		rule->keyword = strdup(argv[2]);
		if (!rule->keyword)
			return oom_return_na();
#endif /* !WITHOUT_USERAUTH */
	}

	rule->action.precedence++;
	rule->sni = 1;
	rule->cn = 1;
	rule->action.pass = 1;

	append_list(&opts->filter_rules, rule, filter_rule_t)

#ifdef DEBUG_OPTS
	filter_rule_dbg_print(rule);
#endif /* DEBUG_OPTS */
	return 0;
}

static macro_t *
filter_macro_find(macro_t *macro, char *name)
{
	while (macro) {
		if (equal(macro->name, name)) {
			return macro;
		}
		macro = macro->next;
	}
	return NULL;
}

int
filter_macro_set(opts_t *opts, char *value, int line_num)
{
#define MAX_MACRO_TOKENS 50

	// $name value1 [value2 [value3] ...]
	char *argv[sizeof(char *) * MAX_MACRO_TOKENS];
	int argc = 0;
	char *p, *last = NULL;

	for ((p = strtok_r(value, " ", &last));
		 p;
		 (p = strtok_r(NULL, " ", &last))) {
		if (argc < MAX_MACRO_TOKENS) {
			argv[argc++] = p;
		} else {
			fprintf(stderr, "Too many arguments in macro definition on line %d\n", line_num);
			return -1;
		}
	}

	if (argc < 2) {
		fprintf(stderr, "Macro definition requires at least two arguments on line %d\n", line_num);
		return -1;
	}

	if (argv[0][0] != '$') {
		fprintf(stderr, "Macro name should start with '$' on line %d\n", line_num);
		return -1;
	}

	if (filter_macro_find(opts->macro, argv[0])) {
		fprintf(stderr, "Macro name '%s' already exists on line %d\n", argv[0], line_num);
		return -1;
	}

	macro_t *macro = malloc(sizeof(macro_t));
	if (!macro)
		return oom_return_na();
	memset(macro, 0, sizeof(macro_t));

	macro->name = strdup(argv[0]);
	if (!macro->name)
		return oom_return_na();

	int i = 1;
	while (i < argc) {
		// Do not allow macro within macro, no recursive macro definitions
		if (argv[i][0] == '$') {
			fprintf(stderr, "Invalid macro value '%s' on line %d\n", argv[i], line_num);
			return -1;
		}

		value_t *v = malloc(sizeof(value_t));
		if (!v)
			return oom_return_na();
		memset(v, 0, sizeof(value_t));

		v->value = strdup(argv[i++]);
		if (!v->value)
			return oom_return_na();

		append_list(&macro->value, v, value_t)
	}

	append_list(&opts->macro, macro, macro_t)

#ifdef DEBUG_OPTS
	log_dbg_printf("Macro: %s = %s\n", macro->name, filter_value_str(macro->value));
#endif /* DEBUG_OPTS */
	return 0;
}

static int WUNRES
filter_site_set(filter_rule_t *rule, const char *site, int line_num)
{
	// The for loop with strtok_r() does not output empty strings
	// So, no need to check if the length of site > 0
	size_t len = strlen(site);

	if (len > MAX_SITE_LEN) {
		fprintf(stderr, "Filter site too long %zu > %d on line %d\n", len, MAX_SITE_LEN, line_num);
		return -1;
	}

	// Don't modify site, site is reused in macro expansion
	rule->site = strdup(site);
	if (!rule->site)
		return oom_return_na();

	if (rule->site[len - 1] == '*') {
		rule->exact_site = 0;
		len--;
		rule->site[len] = '\0';
		// site == "*" ?
		if (len == 0)
			rule->all_sites = 1;
	} else {
		rule->exact_site = 1;
	}

	// redundant?
	if (equal(rule->site, "*"))
		rule->all_sites = 1;
	return 0;
}

static int WUNRES
filter_port_set(filter_rule_t *rule, const char *port, int line_num)
{
#define MAX_PORT_LEN 6

	size_t len = strlen(port);

	if (len > MAX_PORT_LEN) {
		fprintf(stderr, "Filter port too long %zu > %d on line %d\n", len, MAX_PORT_LEN, line_num);
		return -1;
	}

	rule->port = strdup(port);
	if (!rule->port)
		return oom_return_na();

	if (rule->port[len - 1] == '*') {
		rule->exact_port = 0;
		len--;
		rule->port[len] = '\0';
		// site == "*" ?
		if (len == 0)
			rule->all_ports = 1;
	} else {
		rule->exact_port = 1;
	}

	// redundant?
	if (equal(rule->port, "*"))
		rule->all_ports = 1;

	if (!rule->site) {
		rule->site = strdup("");
		if (!rule->site)
			return oom_return_na();
	}
	return 0;
}

static int WUNRES
filter_is_exact(const char *arg)
{
	return arg[strlen(arg) - 1] != '*';
}

static int WUNRES
filter_is_all(const char *arg)
{
	return equal(arg, "*");
}

static int WUNRES
filter_field_set(char **field, const char *arg, int line_num)
{
	// The for loop with strtok_r() does not output empty strings
	// So, no need to check if the length of field > 0
	size_t len = strlen(arg);

	if (len > MAX_SITE_LEN) {
		fprintf(stderr, "Filter field too long %zu > %d on line %d\n", len, MAX_SITE_LEN, line_num);
		return -1;
	}

	*field = strdup(arg);
	if (!*field)
		return oom_return_na();

	if ((*field)[len - 1] == '*')
		(*field)[len - 1] = '\0';
	return 0;
}

static int WUNRES
filter_arg_index_inc(int i, int argc, char *last, int line_num)
{
	if (i + 1 < argc) {
		return i + 1;
	} else {
		fprintf(stderr, "Not enough arguments in filter rule after '%s' on line %d\n", last, line_num);
		return -1;
	}
}

static int WUNRES
filter_rule_translate(opts_t *opts, const char *name, int argc, char **argv, int line_num)
{
	//(Divert|Split|Pass|Block|Match)
	// ([from (
	//     user (username[*]|$macro|*) [desc (keyword[*]|$macro|*)]|
	//     desc (keyword[*]|$macro|*)|
	//     ip (clientip[*]|$macro|*)|
	//     *)]
	//  [to (
	//     sni (servername[*]|$macro|*)|
	//     cn (commonname[*]|$macro|*)|
	//     host (host[*]|$macro|*)|
	//     uri (uri[*]|$macro|*)|
	//     ip (serverip[*]|$macro|*) [port (serverport[*]|$macro|*)]|
	//     port (serverport[*]|$macro|*)|
	//     *)]
	//  [log ([[!]connect] [[!]master] [[!]cert]
	//        [[!]content] [[!]pcap] [[!]mirror] [$macro]|*|!*)]
	//  |*)

	filter_rule_t *rule = malloc(sizeof(filter_rule_t));
	if (!rule)
		return oom_return_na();
	memset(rule, 0, sizeof(filter_rule_t));

	if (equal(name, "Divert"))
		rule->action.divert = 1;
	else if (equal(name, "Split"))
		rule->action.split = 1;
	else if (equal(name, "Pass"))
		rule->action.pass = 1;
	else if (equal(name, "Block"))
		rule->action.block = 1;
	else if (equal(name, "Match"))
		rule->action.match = 1;

	// precedence can only go up not down
	rule->action.precedence = 0;

	int done_from = 0;
	int done_to = 0;
	int i = 0;
	while (i < argc) {
		if (equal(argv[i], "*")) {
			i++;
		}
		else if (equal(argv[i], "from")) {
			if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
				return -1;
#ifndef WITHOUT_USERAUTH
			if (equal(argv[i], "user") || equal(argv[i], "desc")) {
				if (equal(argv[i], "user")) {
					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;

					rule->action.precedence++;
					rule->all_users = filter_is_all(argv[i]);

					if (!rule->all_users) {
						rule->exact_user = filter_is_exact(argv[i]);
						if (filter_field_set(&rule->user, argv[i], line_num) == -1)
							return -1;
						rule->action.precedence++;
					}
					i++;
				}

				if (i < argc && equal(argv[i], "desc")) {
					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;

					if (!filter_is_all(argv[i])) {
						rule->exact_keyword = filter_is_exact(argv[i]);
						if (filter_field_set(&rule->keyword, argv[i], line_num) == -1)
							return -1;
						rule->action.precedence++;
					}
					i++;
				}

				done_from = 1;
			}
			else
#endif /* !WITHOUT_USERAUTH */
			if (equal(argv[i], "ip")) {
				if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
					return -1;

				rule->all_conns = filter_is_all(argv[i]);

				if (!rule->all_conns) {
					rule->exact_ip = filter_is_exact(argv[i]);
					if (filter_field_set(&rule->ip, argv[i], line_num) == -1)
						return -1;
					rule->action.precedence++;
				}
				i++;
				done_from = 1;
			}
			else if (equal(argv[i], "*")) {
				i++;
			}
		}
		else if (equal(argv[i], "to")) {
			if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
				return -1;

			if (equal(argv[i], "sni") || equal(argv[i], "cn") || equal(argv[i], "host") || equal(argv[i], "uri")) {
				rule->action.precedence++;
				if (equal(argv[i], "sni"))
					rule->sni = 1;
				else if (equal(argv[i], "cn"))
					rule->cn = 1;
				else if (equal(argv[i], "host"))
					rule->host = 1;
				else if (equal(argv[i], "uri"))
					rule->uri = 1;

				if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
					return -1;

				if (filter_site_set(rule, argv[i++], line_num) == -1)
					return -1;

				done_to = 1;
			}
			else if (equal(argv[i], "ip") || equal(argv[i], "port")) {
				rule->dstip = 1;

				if (equal(argv[i], "ip")) {
					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;

					// Just ip spec should not increase rule precedence

					if (filter_site_set(rule, argv[i++], line_num) == -1)
						return -1;
				}

				if (i < argc && equal(argv[i], "port")) {
					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;

					rule->action.precedence++;

					if (filter_port_set(rule, argv[i++], line_num) == -1)
						return -1;
				}

				done_to = 1;
			}
			else if (equal(argv[i], "*")) {
				i++;
			}
		}
		else if (equal(argv[i], "log")) {
			if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
				return -1;

			rule->action.precedence++;

			if (equal(argv[i], "connect") || equal(argv[i], "master") || equal(argv[i], "cert") || equal(argv[i], "content") || equal(argv[i], "pcap") ||
				equal(argv[i], "!connect") || equal(argv[i], "!master") || equal(argv[i], "!cert") || equal(argv[i], "!content") || equal(argv[i], "!pcap")
#ifndef WITHOUT_MIRROR
				|| equal(argv[i], "mirror") || equal(argv[i], "!mirror")
#endif /* !WITHOUT_MIRROR */
				) {
				do {
					if (equal(argv[i], "connect"))
						rule->action.log_connect = 2;
					else if (equal(argv[i], "master"))
						rule->action.log_master = 2;
					else if (equal(argv[i], "cert"))
						rule->action.log_cert = 2;
					else if (equal(argv[i], "content"))
						rule->action.log_content = 2;
					else if (equal(argv[i], "pcap"))
						rule->action.log_pcap = 2;
					else if (equal(argv[i], "!connect"))
						rule->action.log_connect = 1;
					else if (equal(argv[i], "!master"))
						rule->action.log_master = 1;
					else if (equal(argv[i], "!cert"))
						rule->action.log_cert = 1;
					else if (equal(argv[i], "!content"))
						rule->action.log_content = 1;
					else if (equal(argv[i], "!pcap"))
						rule->action.log_pcap = 1;
#ifndef WITHOUT_MIRROR
					else if (equal(argv[i], "mirror"))
						rule->action.log_mirror = 2;
					else if (equal(argv[i], "!mirror"))
						rule->action.log_mirror = 1;
#endif /* !WITHOUT_MIRROR */

					if (++i == argc)
						break;
				} while (equal(argv[i], "connect") || equal(argv[i], "master") || equal(argv[i], "cert") || equal(argv[i], "content") || equal(argv[i], "pcap") ||
						 equal(argv[i], "!connect") || equal(argv[i], "!master") || equal(argv[i], "!cert") || equal(argv[i], "!content") || equal(argv[i], "!pcap")
#ifndef WITHOUT_MIRROR
					|| equal(argv[i], "mirror") || equal(argv[i], "!mirror")
#endif /* !WITHOUT_MIRROR */
					);
			}
			else if (equal(argv[i], "*")) {
				rule->action.log_connect = 2;
				rule->action.log_master = 2;
				rule->action.log_cert = 2;
				rule->action.log_content = 2;
				rule->action.log_pcap = 2;
#ifndef WITHOUT_MIRROR
				rule->action.log_mirror = 2;
#endif /* !WITHOUT_MIRROR */
				i++;
			}
			else if (equal(argv[i], "!*")) {
				rule->action.log_connect = 1;
				rule->action.log_master = 1;
				rule->action.log_cert = 1;
				rule->action.log_content = 1;
				rule->action.log_pcap = 1;
#ifndef WITHOUT_MIRROR
				rule->action.log_mirror = 1;
#endif /* !WITHOUT_MIRROR */
				i++;
			}
		}
	}

	if (!done_from) {
		rule->all_conns = 1;
	}
	if (!done_to) {
		rule->site = strdup("");
		if (!rule->site)
			return oom_return_na();
		rule->all_sites = 1;
		rule->sni = 1;
		rule->cn = 1;
		rule->host = 1;
		rule->uri = 1;
		rule->dstip = 1;
	}

	append_list(&opts->filter_rules, rule, filter_rule_t)

#ifdef DEBUG_OPTS
	filter_rule_dbg_print(rule);
#endif /* DEBUG_OPTS */
	return 0;
}

static int WUNRES
filter_rule_parse(opts_t *opts, const char *name, int argc, char **argv, int line_num);

#define MAX_FILTER_RULE_TOKENS 17

static int WUNRES
filter_rule_macro_expand(opts_t *opts, const char *name, int argc, char **argv, int i, int line_num)
{
	if (argv[i][0] == '$') {
		macro_t *macro;
		if ((macro = filter_macro_find(opts->macro, argv[i]))) {
			value_t *value = macro->value;
			while (value) {
				// Prevent infinite macro expansion, macros do not allow it, but macro expansion should detect it too
				if (value->value[0] == '$') {
					fprintf(stderr, "Invalid macro value '%s' on line %d\n", value->value, line_num);
					return -1;
				}

				char *expanded_argv[sizeof(char *) * MAX_FILTER_RULE_TOKENS];
				memcpy(expanded_argv, argv, sizeof expanded_argv);

				expanded_argv[i] = value->value;

				if (filter_rule_parse(opts, name, argc, expanded_argv, line_num) == -1)
					return -1;

				value = value->next;
			}
			// End of macro expansion, the caller must stop processing the rule
			return 1;
		}
		else {
			fprintf(stderr, "No such macro '%s' on line %d\n", argv[i], line_num);
			return -1;
		}
	}
	return 0;
}

static int WUNRES
filter_rule_parse(opts_t *opts, const char *name, int argc, char **argv, int line_num)
{
	int done_all = 0;
	int done_from = 0;
	int done_to = 0;
	int done_log = 0;
	int rv = 0;
	int i = 0;
	while (i < argc) {
		if (equal(argv[i], "*")) {
			if (done_all) {
				fprintf(stderr, "Only one '*' statement allowed on line %d\n", line_num);
				return -1;
			}
			if (++i > argc) {
				fprintf(stderr, "Too many arguments for '*' on line %d\n", line_num);
				return -1;
			}
			done_all = 1;
		}
		else if (equal(argv[i], "from")) {
			if (done_from) {
				fprintf(stderr, "Only one 'from' statement allowed on line %d\n", line_num);
				return -1;
			}

			if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
				return -1;
#ifndef WITHOUT_USERAUTH
			if (equal(argv[i], "user") || equal(argv[i], "desc")) {
				if (equal(argv[i], "user")) {
					if (!opts->user_auth) {
						fprintf(stderr, "User filter requires user auth on line %d\n", line_num);
						return -1;
					}

					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;

					if (argv[i][strlen(argv[i]) - 1] == '*') {
						// Nothing to do for '*' or substring search for 'user*'
					}
					else if ((rv = filter_rule_macro_expand(opts, name, argc, argv, i, line_num)) != 0) {
						return rv;
					}
					else if (!sys_isuser(argv[i])) {
						fprintf(stderr, "No such user '%s' on line %d\n", argv[i], line_num);
						return -1;
					}
					i++;
				}

				// It is possible to define desc without user (i.e. * or all_users), hence no 'else' here
				if (i < argc && equal(argv[i], "desc")) {
					if (!opts->user_auth) {
						fprintf(stderr, "Desc filter requires user auth on line %d\n", line_num);
						return -1;
					}

					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;

					if (argv[i][strlen(argv[i]) - 1] == '*') {
						// Nothing to do for '*' or substring search for 'keyword*'
					}
					else if ((rv = filter_rule_macro_expand(opts, name, argc, argv, i, line_num)) != 0) {
						return rv;
					}
					i++;
				}

				done_from = 1;
			}
			else
#endif /* !WITHOUT_USERAUTH */
			if (equal(argv[i], "ip")) {
				if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
					return -1;

				if (argv[i][strlen(argv[i]) - 1] == '*') {
					// Nothing to do for '*' or substring search for 'ip*'
					}
				else if ((rv = filter_rule_macro_expand(opts, name, argc, argv, i, line_num)) != 0) {
					return rv;
				}
				i++;
				done_from = 1;
			}
			else if (equal(argv[i], "*")) {
				i++;
			}
			else {
				fprintf(stderr, "Unknown argument in filter rule at '%s' on line %d\n", argv[i], line_num);
				return -1;
			}
		}
		else if (equal(argv[i], "to")) {
			if (done_to) {
				fprintf(stderr, "Only one 'to' statement allowed on line %d\n", line_num);
				return -1;
			}

			if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
				return -1;

			if (equal(argv[i], "sni") || equal(argv[i], "cn") || equal(argv[i], "host") || equal(argv[i], "uri")) {
				if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
					return -1;

				if ((rv = filter_rule_macro_expand(opts, name, argc, argv, i, line_num)) != 0) {
					return rv;
				}
				i++;

				done_to = 1;
			}
			else if (equal(argv[i], "ip") || equal(argv[i], "port")) {
				if (equal(argv[i], "ip")) {
					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;

					if ((rv = filter_rule_macro_expand(opts, name, argc, argv, i, line_num)) != 0) {
						return rv;
					}
					i++;
				}

				// It is possible to define port without ip (i.e. * or all_sites), hence no 'else' here
				if (i < argc && equal(argv[i], "port")) {
					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;

					if ((rv = filter_rule_macro_expand(opts, name, argc, argv, i, line_num)) != 0) {
						return rv;
					}
					i++;
				}

				done_to = 1;
			}
			else if (equal(argv[i], "*")) {
				i++;
			}
			else {
				fprintf(stderr, "Unknown argument in filter rule at '%s' on line %d\n", argv[i], line_num);
				return -1;
			}
		}
		else if (equal(argv[i], "log")) {
			if (done_log) {
				fprintf(stderr, "Only one 'log' statement allowed on line %d\n", line_num);
				return -1;
			}

			if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
				return -1;

			if (equal(argv[i], "connect") || equal(argv[i], "master") || equal(argv[i], "cert") || equal(argv[i], "content") || equal(argv[i], "pcap") ||
				equal(argv[i], "!connect") || equal(argv[i], "!master") || equal(argv[i], "!cert") || equal(argv[i], "!content") || equal(argv[i], "!pcap")
#ifndef WITHOUT_MIRROR
				|| equal(argv[i], "mirror") || equal(argv[i], "!mirror")
#endif /* !WITHOUT_MIRROR */
				|| argv[i][0] == '$') {
				do {
					if ((rv = filter_rule_macro_expand(opts, name, argc, argv, i, line_num)) != 0) {
						return rv;
					}
					if (++i == argc)
						break;
				} while (equal(argv[i], "connect") || equal(argv[i], "master") || equal(argv[i], "cert") || equal(argv[i], "content") || equal(argv[i], "pcap") ||
						 equal(argv[i], "!connect") || equal(argv[i], "!master") || equal(argv[i], "!cert") || equal(argv[i], "!content") || equal(argv[i], "!pcap")
#ifndef WITHOUT_MIRROR
					|| equal(argv[i], "mirror") || equal(argv[i], "!mirror")
#endif /* !WITHOUT_MIRROR */
					|| argv[i][0] == '$');

				done_log = 1;
			}
			else if (equal(argv[i], "*")) {
				i++;
				done_log = 1;
			}
			else if (equal(argv[i], "!*")) {
				i++;
				done_log = 1;
			}
			else {
				fprintf(stderr, "Unknown argument in filter rule at '%s' on line %d\n", argv[i], line_num);
				return -1;
			}
		}
		else {
			fprintf(stderr, "Unknown argument in filter rule at '%s' on line %d\n", argv[i], line_num);
				return -1;
		}
	}

	// All checks passed and all macros expanded, if any
	return filter_rule_translate(opts, name, argc, argv, line_num);
}

int
filter_rule_set(opts_t *opts, const char *name, char *value, int line_num)
{
	char *argv[sizeof(char *) * MAX_FILTER_RULE_TOKENS];
	int argc = 0;
	char *p, *last = NULL;

	for ((p = strtok_r(value, " ", &last));
		 p;
		 (p = strtok_r(NULL, " ", &last))) {
		if (argc < MAX_FILTER_RULE_TOKENS) {
			argv[argc++] = p;
		} else {
			fprintf(stderr, "Too many arguments in filter rule on line %d\n", line_num);
			return -1;
		}
	}

	return filter_rule_parse(opts, name, argc, argv, line_num);
}

static filter_port_t *
filter_port_btree_exact_match(kbtree_t(port) *port_btree, char *p)
{
	if (!port_btree)
		return NULL;
	filter_port_t **port = kb_get(port, port_btree, p);
	return port ? *port : NULL;
}

static filter_port_t *
filter_port_list_substring_match(filter_port_list_t *list, char *p)
{
	while (list) {
		if (strstr(p, list->port->port))
			break;
		list = list->next;
	}
	return list ? list->port : NULL;
}

filter_port_t *
filter_port_find(filter_site_t *site, char *p)
{
	filter_port_t *port = filter_port_btree_exact_match(site->port_btree, p);
	if (port)
		return port;
	return filter_port_list_substring_match(site->port_list, p);
}

static filter_port_t *
filter_port_list_exact_match(filter_port_list_t *list, char *p)
{
	while (list) {
		if (!strcmp(list->port->port, p))
			break;
		list = list->next;
	}
	return list ? list->port : NULL;
}

static filter_port_t *
filter_rule_port_find(filter_site_t *site, filter_rule_t *rule)
{
	if (rule->exact_port)
		return filter_port_btree_exact_match(site->port_btree, rule->port);
	else
		return filter_port_list_exact_match(site->port_list, rule->port);
}

static int NONNULL(1,2) WUNRES
filter_port_add(filter_site_t *site, filter_rule_t *rule)
{
	filter_port_t *port = filter_rule_port_find(site, rule);
	if (!port) {
		port = malloc(sizeof(filter_port_t));
		if (!port)
			return oom_return_na();
		memset(port, 0, sizeof(filter_port_t));

		port->port = strdup(rule->port);
		if (!port->port)
			return oom_return_na();

		if (rule->exact_port) {
			if (!site->port_btree)
				if (!(site->port_btree = kb_init(port, KB_DEFAULT_SIZE)))
					return oom_return_na();

			kb_put(port, site->port_btree, port);
		}
		else {
			filter_port_list_t *port_list = malloc(sizeof(filter_port_list_t));
			if (!port_list)
				return oom_return_na();
			memset(port_list, 0, sizeof(filter_port_list_t));

			port_list->port = port;

			// all_ports should be at the end of the port list, it has the lowest precedence
			filter_port_list_t *prev = NULL;
			filter_port_list_t *l = site->port_list;
			while (l) {
				if (l->port->all_ports)
					break;
				prev = l;
				l = l->next;
			}

			if (prev) {
				port_list->next = prev->next;
				prev->next = port_list;
			}
			else {
				if (site->port_list)
					port_list->next = site->port_list;
				site->port_list = port_list;
			}
		}
	}

	port->all_ports = rule->all_ports;
	port->exact = rule->exact_port;

	// Do not override the specs of port rules at higher precedence
	// precedence can only go up not down
	if (rule->action.precedence >= port->action.precedence) {
		// Multiple rules can set an action for the same port, hence the bit-wise OR
		port->action.divert |= rule->action.divert;
		port->action.split |= rule->action.split;
		port->action.pass |= rule->action.pass;
		port->action.block |= rule->action.block;
		port->action.match |= rule->action.match;

		// Multiple log actions can be set for the same port
		// Multiple rules can enable/disable or don't change a log action for the same port
		// 0: don't change, 1: disable, 2: enable
		if (rule->action.log_connect)
			port->action.log_connect = rule->action.log_connect;
		if (rule->action.log_master)
			port->action.log_master = rule->action.log_master;
		if (rule->action.log_cert)
			port->action.log_cert = rule->action.log_cert;
		if (rule->action.log_content)
			port->action.log_content = rule->action.log_content;
		if (rule->action.log_pcap)
			port->action.log_pcap = rule->action.log_pcap;
#ifndef WITHOUT_MIRROR
		if (rule->action.log_mirror)
			port->action.log_mirror = rule->action.log_mirror;
#endif /* !WITHOUT_MIRROR */

		port->action.precedence = rule->action.precedence;
	}
	return 0;
}

filter_site_t *
filter_site_btree_exact_match(kbtree_t(site) *site_btree, char *s)
{
	if (!site_btree)
		return NULL;
	filter_site_t **site = kb_get(site, site_btree, s);
	return site ? *site : NULL;
}

filter_site_t *
filter_site_list_substring_match(filter_site_list_t *list, char *s)
{
	while (list) {
		if (strstr(s, list->site->site))
			break;
		list = list->next;
	}
	return list ? list->site : NULL;
}

filter_site_t *
filter_site_find(kbtree_t(site) *site_btree, filter_site_list_t *list, char *s)
{
	filter_site_t *site = filter_site_btree_exact_match(site_btree, s);
	if (site)
		return site;
	return filter_site_list_substring_match(list, s);
}

static filter_site_t *
filter_site_list_exact_match(filter_site_list_t *list, char *s)
{
	while (list) {
		if (!strcmp(list->site->site, s))
			break;
		list = list->next;
	}
	return list ? list->site : NULL;
}

static filter_site_t *
filter_rule_site_find(kbtree_t(site) *site_btree, filter_site_list_t *list, filter_rule_t *rule)
{
	if (rule->exact_site)
		return filter_site_btree_exact_match(site_btree, rule->site);
	else
		return filter_site_list_exact_match(list, rule->site);
}

static int NONNULL(3) WUNRES
filter_site_add(kbtree_t(site) **site_btree, filter_site_list_t **site_list, filter_rule_t *rule)
{
	filter_site_t *site = filter_rule_site_find(*site_btree, *site_list, rule);
	if (!site) {
		site = malloc(sizeof(filter_site_t));
		if (!site)
			return oom_return_na();
		memset(site, 0, sizeof(filter_site_t));

		site->site = strdup(rule->site);
		if (!site->site)
			return oom_return_na();

		if (rule->exact_site) {
			if (!*site_btree)
				if (!(*site_btree = kb_init(site, KB_DEFAULT_SIZE)))
					return oom_return_na();

			kb_put(site, *site_btree, site);
		}
		else {
			filter_site_list_t *list = malloc(sizeof(filter_site_list_t));
			if (!list)
				return oom_return_na();
			memset(list, 0, sizeof(filter_site_list_t));

			list->site = site;

			// all_sites should be at the end of the site list, it has the lowest precedence
			filter_site_list_t *prev = NULL;
			filter_site_list_t *l = *site_list;
			while (l) {
				if (l->site->all_sites)
					break;
				prev = l;
				l = l->next;
			}

			if (prev) {
				list->next = prev->next;
				prev->next = list;
			}
			else {
				if (*site_list)
					list->next = *site_list;
				*site_list = list;
			}
		}
	}

	site->all_sites = rule->all_sites;
	site->exact = rule->exact_site;

	// Do not override the specs of a site with a port rule
	// Port rule is added as a new port under the same site
	// hence 'if else', not just 'if'
	if (rule->port) {
		if (filter_port_add(site, rule) == -1)
			return -1;
	}
	// Do not override the specs of site rules at higher precedence
	// precedence can only go up not down
	else if (rule->action.precedence >= site->action.precedence) {
		// Multiple rules can set an action for the same site, hence the bit-wise OR
		site->action.divert |= rule->action.divert;
		site->action.split |= rule->action.split;
		site->action.pass |= rule->action.pass;
		site->action.block |= rule->action.block;
		site->action.match |= rule->action.match;

		// Multiple log actions can be set for the same site
		// Multiple rules can enable/disable or don't change a log action for the same site
		// 0: don't change, 1: disable, 2: enable
		if (rule->action.log_connect)
			site->action.log_connect = rule->action.log_connect;
		if (rule->action.log_master)
			site->action.log_master = rule->action.log_master;
		if (rule->action.log_cert)
			site->action.log_cert = rule->action.log_cert;
		if (rule->action.log_content)
			site->action.log_content = rule->action.log_content;
		if (rule->action.log_pcap)
			site->action.log_pcap = rule->action.log_pcap;
#ifndef WITHOUT_MIRROR
		if (rule->action.log_mirror)
			site->action.log_mirror = rule->action.log_mirror;
#endif /* !WITHOUT_MIRROR */

		site->action.precedence = rule->action.precedence;
	}
	return 0;
}

static int
filter_sitelist_add(filter_list_t *list, filter_rule_t *rule)
{
	if (rule->dstip) {
		if (filter_site_add(&list->ip_btree, &list->ip_list, rule) == -1)
			return -1;
	}
	if (rule->sni) {
		if (filter_site_add(&list->sni_btree, &list->sni_list, rule) == -1)
			return -1;
	}
	if (rule->cn) {
		if (filter_site_add(&list->cn_btree, &list->cn_list, rule) == -1)
			return -1;
	}
	if (rule->host) {
		if (filter_site_add(&list->host_btree, &list->host_list, rule) == -1)
			return -1;
	}
	if (rule->uri) {
		if (filter_site_add(&list->uri_btree, &list->uri_list, rule) == -1)
			return -1;
	}
	return 0;
}

static filter_ip_t *
filter_ip_btree_exact_match(kbtree_t(ip) *ip_btree, char *i)
{
	if (!ip_btree)
		return NULL;
	filter_ip_t **ip = kb_get(ip, ip_btree, i);
	return ip ? *ip : NULL;
}

static filter_ip_t *
filter_ip_list_substring_match(filter_ip_list_t *list, char *i)
{
	while (list) {
		if (strstr(i, list->ip->ip))
			break;
		list = list->next;
	}
	return list ? list->ip : NULL;
}

filter_ip_t *
filter_ip_find(filter_t *filter, char *i)
{
	filter_ip_t *ip = filter_ip_btree_exact_match(filter->ip_btree, i);
	if (ip)
		return ip;
	return filter_ip_list_substring_match(filter->ip_list, i);
}

static filter_ip_t *
filter_ip_list_exact_match(filter_ip_list_t *list, char *i)
{
	while (list) {
		if (!strcmp(list->ip->ip, i))
			break;
		list = list->next;
	}
	return list ? list->ip : NULL;
}

static filter_ip_t *
filter_rule_ip_find(filter_t *filter, filter_rule_t *rule)
{
	if (rule->exact_ip)
		return filter_ip_btree_exact_match(filter->ip_btree, rule->ip);
	else
		return filter_ip_list_exact_match(filter->ip_list, rule->ip);
}

static filter_ip_t *
filter_ip_get(filter_t *filter, filter_rule_t *rule)
{
	filter_ip_t *ip = filter_rule_ip_find(filter, rule);
	if (!ip) {
		ip = malloc(sizeof(filter_ip_t));
		if (!ip)
			return oom_return_na_null();
		memset(ip, 0, sizeof(filter_ip_t));

		ip->list = malloc(sizeof(filter_list_t));
		if (!ip->list)
			return oom_return_na_null();
		memset(ip->list, 0, sizeof(filter_list_t));

		ip->ip = strdup(rule->ip);
		if (!ip->ip)
			return oom_return_na_null();

		ip->exact = rule->exact_ip;

		if (rule->exact_ip) {
			if (!filter->ip_btree)
				if (!(filter->ip_btree = kb_init(ip, KB_DEFAULT_SIZE)))
					return oom_return_na_null();

			kb_put(ip, filter->ip_btree, ip);
		}
		else {
			filter_ip_list_t *ip_list = malloc(sizeof(filter_ip_list_t));
			if (!ip_list)
				return oom_return_na_null();
			memset(ip_list, 0, sizeof(filter_ip_list_t));

			ip_list->ip = ip;

			append_list(&filter->ip_list, ip_list, filter_ip_list_t)
		}
	}
	return ip;
}

#ifndef WITHOUT_USERAUTH
static filter_keyword_t *
filter_keyword_btree_exact_match(kbtree_t(keyword) *keyword_btree, char *k)
{
	if (!keyword_btree)
		return NULL;
	filter_keyword_t **keyword = kb_get(keyword, keyword_btree, k);
	return keyword ? *keyword : NULL;
}

static filter_keyword_t *
filter_keyword_list_substring_match(filter_keyword_list_t *list, char *k)
{
	while (list) {
		if (strstr(k, list->keyword->keyword))
			break;
		list = list->next;
	}
	return list ? list->keyword : NULL;
}

filter_keyword_t *
filter_keyword_find(filter_t *filter, filter_user_t *user, char *k)
{
	filter_keyword_t *keyword = filter_keyword_btree_exact_match(user ? user->keyword_btree : filter->keyword_btree, k);
	if (keyword)
		return keyword;
	return filter_keyword_list_substring_match(user ? user->keyword_list : filter->keyword_list, k);
}

static filter_keyword_t *
filter_keyword_list_exact_match(filter_keyword_list_t *list, char *k)
{
	while (list) {
		if (!strcmp(list->keyword->keyword, k))
			break;
		list = list->next;
	}
	return list ? list->keyword : NULL;
}

static filter_keyword_t *
filter_rule_keyword_find(filter_t *filter, filter_user_t *user, filter_rule_t *rule)
{
	if (rule->exact_keyword)
		return filter_keyword_btree_exact_match(user ? user->keyword_btree : filter->keyword_btree, rule->keyword);
	else
		return filter_keyword_list_exact_match(user ? user->keyword_list : filter->keyword_list, rule->keyword);
}

static filter_keyword_t *
filter_keyword_get(filter_t *filter, filter_user_t *user, filter_rule_t *rule)
{
	filter_keyword_t *keyword = filter_rule_keyword_find(filter, user, rule);
	if (!keyword) {
		keyword = malloc(sizeof(filter_keyword_t));
		if (!keyword)
			return oom_return_na_null();
		memset(keyword, 0, sizeof(filter_keyword_t));

		keyword->list = malloc(sizeof(filter_list_t));
		if (!keyword->list)
			return oom_return_na_null();
		memset(keyword->list, 0, sizeof(filter_list_t));

		keyword->keyword = strdup(rule->keyword);
		if (!keyword->keyword)
			return oom_return_na_null();

		keyword->exact = rule->exact_keyword;

		if (rule->exact_keyword) {
			if (user) {
				if (!user->keyword_btree)
					if (!(user->keyword_btree = kb_init(keyword, KB_DEFAULT_SIZE)))
						return oom_return_na_null();
				kb_put(keyword, user->keyword_btree, keyword);
			}
			else {
				if (!filter->keyword_btree)
					if (!(filter->keyword_btree = kb_init(keyword, KB_DEFAULT_SIZE)))
						return oom_return_na_null();
				kb_put(keyword, filter->keyword_btree, keyword);
			}
		}
		else {
			filter_keyword_list_t *keyword_list = malloc(sizeof(filter_keyword_list_t));
			if (!keyword_list)
				return oom_return_na_null();
			memset(keyword_list, 0, sizeof(filter_keyword_list_t));

			keyword_list->keyword = keyword;

			filter_keyword_list_t **list = user ? &user->keyword_list : &filter->keyword_list;
			append_list(list, keyword_list, filter_keyword_list_t)
		}
	}
	return keyword;
}

static filter_user_t *
filter_user_btree_exact_match(kbtree_t(user) *user_btree, char *u)
{
	if (!user_btree)
		return NULL;
	filter_user_t **_user = kb_get(user, user_btree, u);
	return _user ? *_user : NULL;
}

static filter_user_t *
filter_user_list_substring_match(filter_user_list_t *list, char *u)
{
	while (list) {
		if (strstr(u, list->user->user))
			break;
		list = list->next;
	}
	return list ? list->user : NULL;
}

filter_user_t *
filter_user_find(filter_t *filter, char *u)
{
	filter_user_t *user = filter_user_btree_exact_match(filter->user_btree, u);
	if (user)
		return user;
	return filter_user_list_substring_match(filter->user_list, u);
}

static filter_user_t *
filter_user_list_exact_match(filter_user_list_t *list, char *u)
{
	while (list) {
		if (!strcmp(list->user->user, u))
			break;
		list = list->next;
	}
	return list ? list->user : NULL;
}

static filter_user_t *
filter_rule_user_find(filter_t *filter, filter_rule_t *rule)
{
	if (rule->exact_user)
		return filter_user_btree_exact_match(filter->user_btree, rule->user);
	else
		return filter_user_list_exact_match(filter->user_list, rule->user);
}

static filter_user_t *
filter_user_get(filter_t *filter, filter_rule_t *rule)
{
	filter_user_t *user = filter_rule_user_find(filter, rule);
	if (!user) {
		user = malloc(sizeof(filter_user_t));
		if (!user)
			return oom_return_na_null();
		memset(user, 0, sizeof(filter_user_t));

		user->list = malloc(sizeof(filter_list_t));
		if (!user->list)
			return oom_return_na_null();
		memset(user->list, 0, sizeof(filter_list_t));

		user->user = strdup(rule->user);
		if (!user->user)
			return oom_return_na_null();

		user->exact = rule->exact_user;

		if (rule->exact_user) {
			if (!filter->user_btree)
				if (!(filter->user_btree = kb_init(user, KB_DEFAULT_SIZE)))
					return oom_return_na_null();

			kb_put(user, filter->user_btree, user);
		}
		else {
			filter_user_list_t *user_list = malloc(sizeof(filter_user_list_t));
			if (!user_list)
				return oom_return_na_null();
			memset(user_list, 0, sizeof(filter_user_list_t));

			user_list->user = user;

			append_list(&filter->user_list, user_list, filter_user_list_t)
		}
	}
	return user;
}
#endif /* WITHOUT_USERAUTH */

filter_t *
filter_set(filter_rule_t *rule)
{
	filter_t *filter = malloc(sizeof(filter_t));
	if (!filter)
		return oom_return_na_null();
	memset(filter, 0, sizeof(filter_t));

#ifndef WITHOUT_USERAUTH
	filter->all_user = malloc(sizeof(filter_list_t));
	if (!filter->all_user)
		return oom_return_na_null();
	memset(filter->all_user, 0, sizeof(filter_list_t));
#endif /* WITHOUT_USERAUTH */

	filter->all = malloc(sizeof(filter_list_t));
	if (!filter->all)
		return oom_return_na_null();
	memset(filter->all, 0, sizeof(filter_list_t));

	while (rule) {
#ifndef WITHOUT_USERAUTH
		if (rule->user) {
			filter_user_t *user = filter_user_get(filter, rule);
			if (!user)
				return NULL;
			if (rule->keyword) {
				filter_keyword_t *keyword = filter_keyword_get(filter, user, rule);
				if (!keyword)
					return NULL;
				if (filter_sitelist_add(keyword->list, rule) == -1)
					return NULL;
			}
			else {
				if (filter_sitelist_add(user->list, rule) == -1)
					return NULL;
			}
		}
		else if (rule->keyword) {
			filter_keyword_t *keyword = filter_keyword_get(filter, NULL, rule);
			if (!keyword)
				return NULL;
			if (filter_sitelist_add(keyword->list, rule) == -1)
				return NULL;
		}
		else if (rule->all_users) {
			if (filter_sitelist_add(filter->all_user, rule) == -1)
				return NULL;
		}
		else
#endif /* WITHOUT_USERAUTH */
		if (rule->ip) {
			 filter_ip_t *ip = filter_ip_get(filter, rule);
			if (!ip)
				return NULL;
			if (filter_sitelist_add(ip->list, rule) == -1)
				return NULL;
		}
		else if (rule->all_conns) {
			if (filter_sitelist_add(filter->all, rule) == -1)
				return NULL;
		}
		rule = rule->next;
	}

#ifdef DEBUG_OPTS
#ifndef WITHOUT_USERAUTH
#define traverse_user(p) { if (cnt == 0) y = *p; ++cnt; }
	int cnt = 0;
	if (filter->user_btree) {
		filter_user_p_t x, y = NULL;
		__kb_traverse(filter_user_p_t, filter->user_btree, traverse_user);
		__kb_get_first(filter_user_p_t, filter->user_btree, x);
		fprintf(stderr, "user_exact # of elements from traversal: %d\n", cnt);
		if (cnt)
			fprintf(stderr, "user_exact first element: %s == %s\n", x->user, y->user);
	}
#define traverse_keyword(p) { if (cnt == 0) y2 = *p; ++cnt; }
	if (filter->keyword_btree) {
		cnt = 0;
		filter_keyword_p_t x2, y2 = NULL;
		__kb_traverse(filter_keyword_p_t, filter->keyword_btree, traverse_keyword);
		__kb_get_first(filter_keyword_p_t, filter->keyword_btree, x2);
		fprintf(stderr, "keyword_exact # of elements from traversal: %d\n", cnt);
		if (cnt)
			fprintf(stderr, "keyword_exact first element: %s == %s\n", x2->keyword, y2->keyword);
	}
#endif /* !WITHOUT_USERAUTH */
#define traverse_ip(p) { if (cnt2 == 0) y3 = *p; ++cnt2; }
	if (filter->ip_btree) {
		int cnt2 = 0;
		filter_ip_p_t x3, y3 = NULL;
		__kb_traverse(filter_ip_p_t, filter->ip_btree, traverse_ip);
		__kb_get_first(filter_ip_p_t, filter->ip_btree, x3);
		fprintf(stderr, "ip_exact # of elements from traversal: %d\n", cnt2);
		if (cnt2)
			fprintf(stderr, "ip_exact first element: %s == %s\n", x3->ip, y3->ip);
	}
#endif /* DEBUG_OPTS */
	return filter;
}

/* vim: set noet ft=c: */
