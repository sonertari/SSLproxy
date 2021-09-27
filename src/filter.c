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

static void
filter_port_free(filter_port_t *port)
{
	while (port) {
		filter_port_t *p = port->next;
		free(port->port);
		free(port);
		port = p;
	}
}

static filter_site_t *
filter_site_free(filter_site_t *site)
{
	filter_site_t *s = site->next;
	free(site->site);
	filter_port_free(site->port);
	free(site);
	return s;
}

static void
filter_list_free(filter_list_t *list)
{
	while (list->ip)
		list->ip = filter_site_free(list->ip);
	while (list->sni)
		list->sni = filter_site_free(list->sni);
	while (list->cn)
		list->cn = filter_site_free(list->cn);
	while (list->host)
		list->host = filter_site_free(list->host);
	while (list->uri)
		list->uri = filter_site_free(list->uri);
	free(list);
}

void
filter_free(opts_t *opts)
{
	if (!opts->filter)
		return;

	filter_t *pf = opts->filter;
#ifndef WITHOUT_USERAUTH
	while (pf->user) {
		while (pf->user->keyword) {
			filter_list_free(pf->user->keyword->list);
			filter_keyword_t *keyword = pf->user->keyword->next;
			free(pf->user->keyword);
			pf->user->keyword = keyword;
		}
		filter_list_free(pf->user->list);
		filter_user_t *user = pf->user->next;
		free(pf->user);
		pf->user = user;
	}
	while (pf->keyword) {
		filter_list_free(pf->keyword->list);
		filter_keyword_t *keyword = pf->keyword->next;
		free(pf->keyword);
		pf->keyword = keyword;
	}
	filter_list_free(pf->all_user);
#endif /* !WITHOUT_USERAUTH */
	while (pf->ip) {
		filter_list_free(pf->ip->list);
		filter_ip_t *ip = pf->ip->next;
		free(pf->ip);
		pf->ip = ip;
	}
	filter_list_free(pf->all);
	free(opts->filter);
	opts->filter = NULL;
}

static void
filter_macro_value_append(value_t **list, value_t *value)
{
	value_t *l = *list;
	while (l) {
		if (!l->next)
			break;
		l = l->next;
	}

	if (l)
		l->next = value;
	else
		*list = value;
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

			filter_macro_value_append(&m->value, v);

			value = value->next;
		}

		m->next = opts->macro;
		opts->macro = m;

		macro = macro->next;
	}
	return 0;
}

static void
filter_rule_append(filter_rule_t **list, filter_rule_t *rule)
{
	filter_rule_t *l = *list;
	while (l) {
		if (!l->next)
			break;
		l = l->next;
	}

	if (l)
		l->next = rule;
	else
		*list = rule;
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

		if (rule->keyword) {
			r->keyword = strdup(rule->keyword);
			if (!r->keyword)
				return oom_return(argv0);
		}
#endif /* !WITHOUT_USERAUTH */

		if (rule->ip) {
			r->ip = strdup(rule->ip);
			if (!r->ip)
				return oom_return(argv0);
		}

		if (rule->site) {
			r->site = strdup(rule->site);
			if (!r->site)
				return oom_return(argv0);
		}
		r->all_sites = rule->all_sites;
		r->exact = rule->exact;

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

		filter_rule_append(&opts->filter_rules, r);

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
		if (asprintf(&p, "site=%s, %s, port=%s, %s, ip=%s"
#ifndef WITHOUT_USERAUTH
				", user=%s, keyword=%s"
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
				rule->site, rule->exact ? "exact" : "substring",
				STRORNONE(rule->port), rule->port ? (rule->exact_port ? "exact_port" : "substring_port") : "",
				STRORNONE(rule->ip),
#ifndef WITHOUT_USERAUTH
				STRORNONE(rule->user), STRORNONE(rule->keyword),
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
filter_port_str(filter_port_t *port)
{
	char *s = NULL;

	int count = 0;
	while (port) {
		char *p;
		if (asprintf(&p, "%s\n          %d: %s (%s%s, action=%s|%s|%s|%s|%s, log=%s|%s|%s|%s|%s"
#ifndef WITHOUT_MIRROR
				"|%s"
#endif /* !WITHOUT_MIRROR */
				", precedence=%d)", STRORNONE(s), count,
				port->port, port->all_ports ? "all_ports, " : "", port->exact ? "exact" : "substring",
				port->action.divert ? "divert" : "", port->action.split ? "split" : "", port->action.pass ? "pass" : "", port->action.block ? "block" : "", port->action.match ? "match" : "",
				port->action.log_connect ? (port->action.log_connect == 1 ? "!connect" : "connect") : "", port->action.log_master ? (port->action.log_master == 1 ? "!master" : "master") : "",
				port->action.log_cert ? (port->action.log_cert == 1 ? "!cert" : "cert") : "", port->action.log_content ? (port->action.log_content == 1 ? "!content" : "content") : "",
				port->action.log_pcap ? (port->action.log_pcap == 1 ? "!pcap" : "pcap") : "",
#ifndef WITHOUT_MIRROR
				port->action.log_mirror ? (port->action.log_mirror == 1 ? "!mirror" : "mirror") : "",
#endif /* !WITHOUT_MIRROR */
				port->action.precedence) < 0) {
			goto err;
		}
		if (s)
			free(s);
		s = p;
		port = port->next;
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
filter_sites_str(filter_site_t *site)
{
	char *s = NULL;

	int count = 0;
	while (site) {
		char *ports = filter_port_str(site->port);

		char *p;
		if (asprintf(&p, "%s\n      %d: %s (%s%s, action=%s|%s|%s|%s|%s, log=%s|%s|%s|%s|%s"
#ifndef WITHOUT_MIRROR
				"|%s"
#endif /* !WITHOUT_MIRROR */
				", precedence=%d)%s%s", STRORNONE(s), count,
				site->site, site->all_sites ? "all_sites, " : "", site->exact ? "exact" : "substring",
				site->action.divert ? "divert" : "", site->action.split ? "split" : "", site->action.pass ? "pass" : "", site->action.block ? "block" : "", site->action.match ? "match" : "",
				site->action.log_connect ? (site->action.log_connect == 1 ? "!connect" : "connect") : "", site->action.log_master ? (site->action.log_master == 1 ? "!master" : "master") : "",
				site->action.log_cert ? (site->action.log_cert == 1 ? "!cert" : "cert") : "", site->action.log_content ? (site->action.log_content == 1 ? "!content" : "content") : "",
				site->action.log_pcap ? (site->action.log_pcap == 1 ? "!pcap" : "pcap") : "",
#ifndef WITHOUT_MIRROR
				site->action.log_mirror ? (site->action.log_mirror == 1 ? "!mirror" : "mirror") : "",
#endif /* !WITHOUT_MIRROR */
				site->action.precedence,
				ports ? "\n        port:" : "", STRORNONE(ports)) < 0) {
			if (ports)
				free(ports);
			goto err;
		}
		if (ports)
			free(ports);
		if (s)
			free(s);
		s = p;
		site = site->next;
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
filter_list_str(filter_list_t *list)
{
	char *p = NULL;
	char *op = NULL;

	// @todo Handle oom, don't use STRORNONE()
	char *s = filter_sites_str(list->ip);
	if (asprintf(&p, "    ip: %s", STRORNONE(s)) < 0) {
		goto err;
	}
	if (s)
		free(s);
	op = p;

	s = filter_sites_str(list->sni);
	if (asprintf(&p, "%s\n    sni: %s", op, STRORNONE(s)) < 0) {
		goto err;
	}
	if (s)
		free(s);
	free(op);
	op = p;

	s = filter_sites_str(list->cn);
	if (asprintf(&p, "%s\n    cn: %s", op, STRORNONE(s)) < 0) {
		goto err;
	}
	if (s)
		free(s);
	free(op);
	op = p;

	s = filter_sites_str(list->host);
	if (asprintf(&p, "%s\n    host: %s", op, STRORNONE(s)) < 0) {
		goto err;
	}
	if (s)
		free(s);
	free(op);
	op = p;

	s = filter_sites_str(list->uri);
	if (asprintf(&p, "%s\n    uri: %s", op, STRORNONE(s)) < 0) {
		goto err;
	}
	goto out;
err:
	if (p) {
		free(p);
		p = NULL;
	}
out:
	if (s)
		free(s);
	if (op)
		free(op);
	return p;
}

static char *
filter_ips_str(filter_ip_t *ip)
{
	char *s = NULL;

	int count = 0;
	while (ip) {
		char *list = filter_list_str(ip->list);

		char *p;
		if (asprintf(&p, "%s%s  ip %d %s= \n%s", STRORNONE(s), s ? "\n" : "", count, ip->ip, STRORNONE(list)) < 0) {
			if (list)
				free(list);
			goto err;
		}
		if (list)
			free(list);
		if (s)
			free(s);
		s = p;
		ip = ip->next;
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

#ifndef WITHOUT_USERAUTH
static char *
filter_users_str(filter_user_t *user)
{
	char *s = NULL;

	int count = 0;
	while (user) {
		// Make sure the current user does not have any keyword
		if (user->keyword)
			goto skip;

		char *list = filter_list_str(user->list);

		char *p = NULL;

		// Make sure the user has a filter rule
		// It is possible to have users without any filter rule,
		// but the user exists because it has keyword filters
		if (list) {
			if (asprintf(&p, "%s%s  user %d %s= \n%s", STRORNONE(s), s ? "\n" : "", count, user->user, list) < 0) {
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

static char *
filter_keywords_str(filter_keyword_t *keyword)
{
	char *s = NULL;

	int count = 0;
	while (keyword) {
		char *list = filter_list_str(keyword->list);

		char *p;
		if (asprintf(&p, "%s%s  keyword %d %s= \n%s", STRORNONE(s), s ? "\n" : "", count, keyword->keyword, STRORNONE(list)) < 0) {
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
filter_userkeywords_str(filter_user_t *user)
{
	char *s = NULL;

	int count = 0;
	while (user) {
		// Make sure the current user has a keyword
		if (!user->keyword)
			goto skip;

		char *list = filter_keywords_str(user->keyword);

		char *p = NULL;
		if (list) {
			if (asprintf(&p, "%s%s user %d %s=\n%s", STRORNONE(s), s ? "\n" : "", count, user->user, STRORNONE(list)) < 0) {
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
#endif /* !WITHOUT_USERAUTH */

char *
filter_str(filter_t *filter)
{
	char *fs = NULL;
#ifndef WITHOUT_USERAUTH
	char *userkeyword_filter = NULL;
	char *user_filter = NULL;
	char *keyword_filter = NULL;
	char *all_user_filter = NULL;
#endif /* !WITHOUT_USERAUTH */
	char *ip_filter = NULL;
	char *all_filter = NULL;

	if (!filter) {
		fs = strdup("");
		if (!fs)
			return oom_return_na_null();
		goto out;
	}

#ifndef WITHOUT_USERAUTH
	userkeyword_filter = filter_userkeywords_str(filter->user);
	user_filter = filter_users_str(filter->user);
	keyword_filter = filter_keywords_str(filter->keyword);
	all_user_filter = filter_list_str(filter->all_user);
#endif /* !WITHOUT_USERAUTH */
	ip_filter = filter_ips_str(filter->ip);
	all_filter = filter_list_str(filter->all);

	if (asprintf(&fs, "filter=>\n"
#ifndef WITHOUT_USERAUTH
			"userkeyword_filter->%s%s\nuser_filter->%s%s\nkeyword_filter->%s%s\nall_user_filter->%s%s\n"
#endif /* !WITHOUT_USERAUTH */
			"ip_filter->%s%s\nall_filter->%s%s\n",
#ifndef WITHOUT_USERAUTH
			userkeyword_filter ? "\n" : "", STRORNONE(userkeyword_filter),
			user_filter ? "\n" : "", STRORNONE(user_filter),
			keyword_filter ? "\n" : "", STRORNONE(keyword_filter),
			all_user_filter ? "\n" : "", STRORNONE(all_user_filter),
#endif /* !WITHOUT_USERAUTH */
			ip_filter ? "\n" : "", STRORNONE(ip_filter),
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
	if (userkeyword_filter)
		free(userkeyword_filter);
	if (user_filter)
		free(user_filter);
	if (keyword_filter)
		free(keyword_filter);
	if (all_user_filter)
		free(all_user_filter);
#endif /* !WITHOUT_USERAUTH */
	if (ip_filter)
		free(ip_filter);
	if (all_filter)
		free(all_filter);
	return fs;
}

#ifdef DEBUG_OPTS
static void
filter_rule_dbg_print(filter_rule_t *rule)
{
	log_dbg_printf("Filter rule: %s, %s, %s, %s, %s"
#ifndef WITHOUT_USERAUTH
		", %s, %s"
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
		rule->site, rule->exact ? "exact" : "substring",
		STRORNONE(rule->port), rule->port ? (rule->exact_port ? "exact_port" : "substring_port") : "",
		STRORNONE(rule->ip),
#ifndef WITHOUT_USERAUTH
		STRORNONE(rule->user), STRORNONE(rule->keyword),
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
		rule->exact = 0;
		len--;
		argv[0][len] = '\0';
		// site == "*" ?
		if (len == 0)
			rule->all_sites = 1;
	} else {
		rule->exact = 1;
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

	filter_rule_append(&opts->filter_rules, rule);

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

		filter_macro_value_append(&macro->value, v);
	}

	macro->next = opts->macro;
	opts->macro = macro;

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
		rule->exact = 0;
		len--;
		rule->site[len] = '\0';
		// site == "*" ?
		if (len == 0)
			rule->all_sites = 1;
	} else {
		rule->exact = 1;
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
	//     user (username|$macro|*) [desc (keyword|$macro|*)]|
	//     desc (keyword|$macro|*)|
	//     ip (clientip|$macro|*)|
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

					if (equal(argv[i], "*")) {
						rule->all_users = 1;
					} else {
						rule->action.precedence++;
						rule->user = strdup(argv[i]);
						if (!rule->user)
							return oom_return_na();
					}
					i++;
				}

				if (i < argc && equal(argv[i], "desc")) {
					if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
						return -1;
					rule->action.precedence++;
					rule->keyword = strdup(argv[i++]);
					if (!rule->keyword)
						return oom_return_na();
				}

				done_from = 1;
			}
			else
#endif /* !WITHOUT_USERAUTH */
			if (equal(argv[i], "ip")) {
				if ((i = filter_arg_index_inc(i, argc, argv[i], line_num)) == -1)
					return -1;

				if (equal(argv[i], "*")) {
					rule->all_conns = 1;
				} else {
					rule->action.precedence++;
					rule->ip = strdup(argv[i]);
					if (!rule->ip)
						return oom_return_na();
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

	filter_rule_append(&opts->filter_rules, rule);

#ifdef DEBUG_OPTS
	filter_rule_dbg_print(rule);
#endif /* DEBUG_OPTS */
	return 0;
}

static int WUNRES
filter_rule_parse(opts_t *opts, const char *name, int argc, char **argv, int line_num);

#define MAX_FILTER_RULE_TOKENS 15

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

					if (equal(argv[i], "*")) {
						// Nothing to do
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

					if ((rv = filter_rule_macro_expand(opts, name, argc, argv, i, line_num)) != 0) {
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

				if (equal(argv[i], "*")) {
					// Nothing to do
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
filter_port_find(filter_port_t *port, filter_rule_t *rule)
{
	while (port) {
		if ((port->exact == rule->exact_port) && !strcmp(port->port, rule->port))
			break;
		port = port->next;
	}
	return port;
}

static int NONNULL(1,2) WUNRES
filter_port_add(filter_port_t **port, filter_rule_t *rule)
{
	filter_port_t *p = filter_port_find(*port, rule);
	if (!p) {
		p = malloc(sizeof(filter_port_t));
		if (!p)
			return oom_return_na();
		memset(p, 0, sizeof(filter_port_t));
		p->port = strdup(rule->port);
		if (!p->port)
			return oom_return_na();

		// all_ports should be at the end of the port list, it has the lowest precedence
		filter_port_t *prev = NULL;
		filter_port_t *l = *port;
		while (l) {
			if (l->all_ports)
				break;
			prev = l;
			l = l->next;
		}

		if (prev) {
			p->next = prev->next;
			prev->next = p;
		}
		else {
			if (*port)
				p->next = *port;
			*port = p;
		}
	}

	// Do not override the specs of port rules at higher precedence
	// precedence can only go up not down
	if (rule->action.precedence >= p->action.precedence) {
		p->all_ports = rule->all_ports;
		p->exact = rule->exact_port;

		// Multiple rules can set an action for the same port, hence the bit-wise OR
		p->action.divert |= rule->action.divert;
		p->action.split |= rule->action.split;
		p->action.pass |= rule->action.pass;
		p->action.block |= rule->action.block;
		p->action.match |= rule->action.match;

		// Multiple log actions can be set for the same port
		// Multiple rules can enable/disable or don't change a log action for the same port
		// 0: don't change, 1: disable, 2: enable
		if (rule->action.log_connect)
			p->action.log_connect = rule->action.log_connect;
		if (rule->action.log_master)
			p->action.log_master = rule->action.log_master;
		if (rule->action.log_cert)
			p->action.log_cert = rule->action.log_cert;
		if (rule->action.log_content)
			p->action.log_content = rule->action.log_content;
		if (rule->action.log_pcap)
			p->action.log_pcap = rule->action.log_pcap;
#ifndef WITHOUT_MIRROR
		if (rule->action.log_mirror)
			p->action.log_mirror = rule->action.log_mirror;
#endif /* !WITHOUT_MIRROR */

		p->action.precedence = rule->action.precedence;
	}
	return 0;
}

static filter_site_t *
filter_site_find(filter_site_t *site, filter_rule_t *rule)
{
	while (site) {
		if ((site->exact == rule->exact) && !strcmp(site->site, rule->site))
			break;
		site = site->next;
	}
	return site;
}

static int NONNULL(1,2) WUNRES
filter_site_add(filter_site_t **site, filter_rule_t *rule)
{
	filter_site_t *s = filter_site_find(*site, rule);
	if (!s) {
		s = malloc(sizeof(filter_site_t));
		if (!s)
			return oom_return_na();
		memset(s, 0, sizeof(filter_site_t));
		s->site = strdup(rule->site);
		if (!s->site)
			return oom_return_na();

		// all_sites should be at the end of the site list, it has the lowest precedence
		filter_site_t *prev = NULL;
		filter_site_t *l = *site;
		while (l) {
			if (l->all_sites)
				break;
			prev = l;
			l = l->next;
		}

		if (prev) {
			s->next = prev->next;
			prev->next = s;
		}
		else {
			if (*site)
				s->next = *site;
			*site = s;
		}
	}

	s->all_sites = rule->all_sites;
	s->exact = rule->exact;

	// Do not override the specs of a site with a port rule
	// Port rule is added as a new port under the same site
	// hence 'if else', not just 'if'
	if (rule->port) {
		if (filter_port_add(&s->port, rule) == -1)
			return -1;
	}
	// Do not override the specs of site rules at higher precedence
	// precedence can only go up not down
	else if (rule->action.precedence >= s->action.precedence) {
		// Multiple rules can set an action for the same site, hence the bit-wise OR
		s->action.divert |= rule->action.divert;
		s->action.split |= rule->action.split;
		s->action.pass |= rule->action.pass;
		s->action.block |= rule->action.block;
		s->action.match |= rule->action.match;

		// Multiple log actions can be set for the same site
		// Multiple rules can enable/disable or don't change a log action for the same site
		// 0: don't change, 1: disable, 2: enable
		if (rule->action.log_connect)
			s->action.log_connect = rule->action.log_connect;
		if (rule->action.log_master)
			s->action.log_master = rule->action.log_master;
		if (rule->action.log_cert)
			s->action.log_cert = rule->action.log_cert;
		if (rule->action.log_content)
			s->action.log_content = rule->action.log_content;
		if (rule->action.log_pcap)
			s->action.log_pcap = rule->action.log_pcap;
#ifndef WITHOUT_MIRROR
		if (rule->action.log_mirror)
			s->action.log_mirror = rule->action.log_mirror;
#endif /* !WITHOUT_MIRROR */

		s->action.precedence = rule->action.precedence;
	}
	return 0;
}

static int
filter_sitelist_add(filter_list_t *list, filter_rule_t *rule)
{
	if (rule->dstip) {
		if (filter_site_add(&list->ip, rule) == -1)
			return -1;
	}
	if (rule->sni) {
		if (filter_site_add(&list->sni, rule) == -1)
			return -1;
	}
	if (rule->cn) {
		if (filter_site_add(&list->cn, rule) == -1)
			return -1;
	}
	if (rule->host) {
		if (filter_site_add(&list->host, rule) == -1)
			return -1;
	}
	if (rule->uri) {
		if (filter_site_add(&list->uri, rule) == -1)
			return -1;
	}
	return 0;
}

filter_ip_t *
filter_ip_find(filter_ip_t *list, char *i)
{
	while (list) {
		if (!strcmp(list->ip, i))
			break;
		list = list->next;
	}
	return list;
}

static filter_ip_t *
filter_ip_get(filter_ip_t **list, char *i)
{
	filter_ip_t *ip = filter_ip_find(*list, i);
	if (!ip) {
		ip = malloc(sizeof(filter_ip_t));
		if (!ip)
			return oom_return_na_null();
		memset(ip, 0, sizeof(filter_ip_t));

		ip->list = malloc(sizeof(filter_list_t));
		if (!ip->list)
			return oom_return_na_null();
		memset(ip->list, 0, sizeof(filter_list_t));

		ip->ip = strdup(i);
		if (!ip->ip)
			return oom_return_na_null();
		ip->next = *list;
		*list = ip;
	}
	return ip;
}

#ifndef WITHOUT_USERAUTH
filter_keyword_t *
filter_keyword_find(filter_keyword_t *list, char *k)
{
	while (list) {
		if (!strcmp(list->keyword, k))
			break;
		list = list->next;
	}
	return list;
}

static filter_keyword_t *
filter_keyword_get(filter_keyword_t **list, char *k)
{
	filter_keyword_t *keyword = filter_keyword_find(*list, k);
	if (!keyword) {
		keyword = malloc(sizeof(filter_keyword_t));
		if (!keyword)
			return oom_return_na_null();
		memset(keyword, 0, sizeof(filter_keyword_t));

		keyword->list = malloc(sizeof(filter_list_t));
		if (!keyword->list)
			return oom_return_na_null();
		memset(keyword->list, 0, sizeof(filter_list_t));

		keyword->keyword = strdup(k);
		if (!keyword->keyword)
			return oom_return_na_null();
		keyword->next = *list;
		*list = keyword;
	}
	return keyword;
}

filter_user_t *
filter_user_find(filter_user_t *list, char *u)
{
	while (list) {
		if (!strcmp(list->user, u))
			break;
		list = list->next;
	}
	return list;
}

static filter_user_t *
filter_user_get(filter_user_t **list, char *u)
{
	filter_user_t *user = filter_user_find(*list, u);
	if (!user) {
		user = malloc(sizeof(filter_user_t));
		if (!user)
			return oom_return_na_null();
		memset(user, 0, sizeof(filter_user_t));

		user->list = malloc(sizeof(filter_list_t));
		if (!user->list)
			return oom_return_na_null();
		memset(user->list, 0, sizeof(filter_list_t));

		user->user = strdup(u);
		if (!user->user)
			return oom_return_na_null();
		user->next = *list;
		*list = user;
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
			filter_user_t *user = filter_user_get(&filter->user, rule->user);
			if (!user)
				return NULL;
			if (rule->keyword) {
				filter_keyword_t *keyword = filter_keyword_get(&user->keyword, rule->keyword);
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
			filter_keyword_t *keyword = filter_keyword_get(&filter->keyword, rule->keyword);
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
			filter_ip_t *ip = filter_ip_get(&filter->ip, rule->ip);
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
	return filter;
}

/* vim: set noet ft=c: */