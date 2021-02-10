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

#include "opts.h"

#include "sys.h"
#include "log.h"
#include "defaults.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <errno.h>

#define equal(s1, s2) strlen((s1)) == strlen((s2)) && !strcmp((s1), (s2))

/*
 * Handle out of memory conditions in early stages of main().
 * Print error message and exit with failure status code.
 * Does not return.
 */
void NORET
oom_die(const char *argv0)
{
	fprintf(stderr, "%s: out of memory\n", argv0);
	exit(EXIT_FAILURE);
}

opts_t *
opts_new(void)
{
	opts_t *opts;

	opts = malloc(sizeof(opts_t));
	memset(opts, 0, sizeof(opts_t));

	opts->stats_period = 1;
	return opts;
}

void
opts_free(opts_t *opts)
{
	if (opts->spec) {
		proxyspec_free(opts->spec);
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
	if (opts->conffile) {
		free(opts->conffile);
	}
	if (opts->connectlog) {
		free(opts->connectlog);
	}
	if (opts->contentlog) {
		free(opts->contentlog);
	}
	if (opts->contentlog_basedir) {
		free(opts->contentlog_basedir);
	}
	memset(opts, 0, sizeof(opts_t));
	free(opts);
}

/*
 * Parse proxyspecs using a simple state machine.
 */
void
proxyspec_parse(int *argc, char **argv[], proxyspec_t **opts_spec)
{
	proxyspec_t *spec = NULL;
	int af = AF_UNSPEC;
	int state = 0;
	char *la, *lp;

	while ((*argc)--) {
		switch (state) {
			default:
			case 0:
				spec = malloc(sizeof(proxyspec_t));
				memset(spec, 0, sizeof(proxyspec_t));
				spec->next = *opts_spec;
				*opts_spec = spec;

				// @todo IPv6?
				la = **argv;
				state++;
				break;
			case 1:
				lp = **argv;
				af = sys_sockaddr_parse(&spec->listen_addr,
										&spec->listen_addrlen,
										la, lp,
										sys_get_af(la),
										EVUTIL_AI_PASSIVE);
				if (af == -1) {
					exit(EXIT_FAILURE);
				}
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
	if (asprintf(&s, "listen=[%s]:%s %s", lhbuf, lpbuf, "tcp") < 0) {
		s = NULL;
	}
	free(lhbuf);
	free(lpbuf);
	if (cbuf)
		free(cbuf);
	return s;
}

void
opts_set_user(opts_t *opts, const char *argv0, const char *optarg)
{
	if (!sys_isuser(optarg)) {
		fprintf(stderr, "%s: '%s' is not an existing user\n",
		        argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->dropuser)
		free(opts->dropuser);
	opts->dropuser = strdup(optarg);
	if (!opts->dropuser)
		oom_die(argv0);
#ifdef DEBUG_OPTS
	log_dbg_printf("User: %s\n", opts->dropuser);
#endif /* DEBUG_OPTS */
}

void
opts_set_group(opts_t *opts, const char *argv0, const char *optarg)
{

	if (!sys_isgroup(optarg)) {
		fprintf(stderr, "%s: '%s' is not an existing group\n",
		        argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->dropgroup)
		free(opts->dropgroup);
	opts->dropgroup = strdup(optarg);
	if (!opts->dropgroup)
		oom_die(argv0);
#ifdef DEBUG_OPTS
	log_dbg_printf("Group: %s\n", opts->dropgroup);
#endif /* DEBUG_OPTS */
}

void
opts_set_jaildir(opts_t *opts, const char *argv0, const char *optarg)
{
	if (!sys_isdir(optarg)) {
		fprintf(stderr, "%s: '%s' is not a directory\n", argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->jaildir)
		free(opts->jaildir);
	opts->jaildir = realpath(optarg, NULL);
	if (!opts->jaildir) {
		fprintf(stderr, "%s: Failed to realpath '%s': %s (%i)\n",
		        argv0, optarg, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG_OPTS
	log_dbg_printf("Chroot: %s\n", opts->jaildir);
#endif /* DEBUG_OPTS */
}

void
opts_set_pidfile(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->pidfile)
		free(opts->pidfile);
	opts->pidfile = strdup(optarg);
	if (!opts->pidfile)
		oom_die(argv0);
#ifdef DEBUG_OPTS
	log_dbg_printf("PidFile: %s\n", opts->pidfile);
#endif /* DEBUG_OPTS */
}

void
opts_set_connectlog(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->connectlog)
		free(opts->connectlog);
	if (!(opts->connectlog = sys_realdir(optarg))) {
		if (errno == ENOENT) {
			fprintf(stderr, "Directory part of '%s' does not "
			                "exist\n", optarg);
			exit(EXIT_FAILURE);
		} else {
			fprintf(stderr, "Failed to realpath '%s': %s (%i)\n",
			              optarg, strerror(errno), errno);
			oom_die(argv0);
		}
	}
#ifdef DEBUG_OPTS
	log_dbg_printf("ConnectLog: %s\n", opts->connectlog);
#endif /* DEBUG_OPTS */
}

void
opts_set_contentlog(opts_t *opts, const char *argv0, const char *optarg)
{
	if (opts->contentlog)
		free(opts->contentlog);
	if (!(opts->contentlog = sys_realdir(optarg))) {
		if (errno == ENOENT) {
			fprintf(stderr, "Directory part of '%s' does not "
			                "exist\n", optarg);
			exit(EXIT_FAILURE);
		} else {
			fprintf(stderr, "Failed to realpath '%s': %s (%i)\n",
			              optarg, strerror(errno), errno);
			oom_die(argv0);
		}
	}
	opts->contentlog_isdir = 0;
	opts->contentlog_isspec = 0;
#ifdef DEBUG_OPTS
	log_dbg_printf("ContentLog: %s\n", opts->contentlog);
#endif /* DEBUG_OPTS */
}

void
opts_set_contentlogdir(opts_t *opts, const char *argv0, const char *optarg)
{
	if (!sys_isdir(optarg)) {
		fprintf(stderr, "%s: '%s' is not a directory\n", argv0, optarg);
		exit(EXIT_FAILURE);
	}
	if (opts->contentlog)
		free(opts->contentlog);
	opts->contentlog = realpath(optarg, NULL);
	if (!opts->contentlog) {
		fprintf(stderr, "%s: Failed to realpath '%s': %s (%i)\n",
		        argv0, optarg, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	opts->contentlog_isdir = 1;
	opts->contentlog_isspec = 0;
#ifdef DEBUG_OPTS
	log_dbg_printf("ContentLogDir: %s\n", opts->contentlog);
#endif /* DEBUG_OPTS */
}

static void
opts_set_logbasedir(const char *argv0, const char *optarg,
                    char **basedir, char **log)
{
	char *lhs, *rhs, *p, *q;
	size_t n;
	if (*basedir)
		free(*basedir);
	if (*log)
		free(*log);
	if (log_content_split_pathspec(optarg, &lhs, &rhs) == -1) {
		fprintf(stderr, "%s: Failed to split '%s' in lhs/rhs:"
		                " %s (%i)\n", argv0, optarg,
		                strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	/* eliminate %% from lhs */
	for (p = q = lhs; *p; p++, q++) {
		if (q < p)
			*q = *p;
		if (*p == '%' && *(p+1) == '%')
			p++;
	}
	*q = '\0';
	/* all %% in lhs resolved to % */
	if (sys_mkpath(lhs, 0777) == -1) {
		fprintf(stderr, "%s: Failed to create '%s': %s (%i)\n",
		        argv0, lhs, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	*basedir = realpath(lhs, NULL);
	if (!*basedir) {
		fprintf(stderr, "%s: Failed to realpath '%s': %s (%i)\n",
		        argv0, lhs, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	/* count '%' in basedir */
	for (n = 0, p = *basedir;
		 *p;
		 p++) {
		if (*p == '%')
			n++;
	}
	free(lhs);
	n += strlen(*basedir);
	if (!(lhs = malloc(n + 1)))
		oom_die(argv0);
	/* re-encoding % to %%, copying basedir to lhs */
	for (p = *basedir, q = lhs;
		 *p;
		 p++, q++) {
		*q = *p;
		if (*q == '%')
			*(++q) = '%';
	}
	*q = '\0';
	/* lhs contains encoded realpathed basedir */
	if (asprintf(log, "%s/%s", lhs, rhs) < 0)
		oom_die(argv0);
	free(lhs);
	free(rhs);
}

void
opts_set_contentlogpathspec(opts_t *opts, const char *argv0, const char *optarg)
{
	opts_set_logbasedir(argv0, optarg, &opts->contentlog_basedir,
	                    &opts->contentlog);
	opts->contentlog_isdir = 0;
	opts->contentlog_isspec = 1;
#ifdef DEBUG_OPTS
	log_dbg_printf("ContentLogPathSpec: basedir=%s, %s\n",
	               opts->contentlog_basedir, opts->contentlog);
#endif /* DEBUG_OPTS */
}

void
opts_set_daemon(opts_t *opts)
{
	opts->detach = 1;
}

void
opts_unset_daemon(opts_t *opts)
{
	opts->detach = 0;
}

void
opts_set_debug(opts_t *opts)
{
	log_dbg_mode(LOG_DBG_MODE_ERRLOG);
	opts->debug = 1;
}

void
opts_unset_debug(opts_t *opts)
{
	log_dbg_mode(LOG_DBG_MODE_NONE);
	opts->debug = 0;
}

void
opts_set_debug_level(const char *optarg)
{
	if (equal(optarg, "2")) {
		log_dbg_mode(LOG_DBG_MODE_FINE);
	} else if (equal(optarg, "3")) {
		log_dbg_mode(LOG_DBG_MODE_FINER);
	} else if (equal(optarg, "4")) {
		log_dbg_mode(LOG_DBG_MODE_FINEST);
	} else {
		fprintf(stderr, "Invalid DebugLevel '%s', use 2-4\n", optarg);
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG_OPTS
	log_dbg_printf("DebugLevel: %s\n", optarg);
#endif /* DEBUG_OPTS */
}

void
opts_set_statslog(opts_t *opts)
{
	opts->statslog = 1;
}

void
opts_unset_statslog(opts_t *opts)
{
	opts->statslog = 0;
}

static void
opts_set_open_files_limit(const char *value, int line_num)
{
	unsigned int i = atoi(value);
	if (i >= 50 && i <= 10000) {
		struct rlimit rl;
		rl.rlim_cur = i;
		rl.rlim_max = i;
		if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
			fprintf(stderr, "Failed setting OpenFilesLimit\n");
			if (errno) {
				fprintf(stderr, "%s\n", strerror(errno));
			}
			exit(EXIT_FAILURE);
		}
	} else {
		fprintf(stderr, "Invalid OpenFilesLimit %s on line %d, use 50-10000\n", value, line_num);
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG_OPTS
	log_dbg_printf("OpenFilesLimit: %u\n", i);
#endif /* DEBUG_OPTS */
}

static int
check_value_yesno(const char *value, const char *name, int line_num)
{
	if (equal(value, "yes")) {
		return 1;
	} else if (equal(value, "no")) {
		return 0;
	}
	fprintf(stderr, "Error in conf: Invalid '%s' value '%s' on line %d, use yes|no\n", name, value, line_num);
	return -1;
}

#define MAX_TOKEN 10

static int
set_option(opts_t *opts, const char *argv0,
           const char *name, char *value, int line_num)
{
	int yes;
	int retval = -1;

	if (equal(name, "User")) {
		opts_set_user(opts, argv0, value);
	} else if (equal(name, "Group")) {
		opts_set_group(opts, argv0, value);
	} else if (equal(name, "Chroot")) {
		opts_set_jaildir(opts, argv0, value);
	} else if (equal(name, "PidFile")) {
		opts_set_pidfile(opts, argv0, value);
	} else if (equal(name, "ConnectLog")) {
		opts_set_connectlog(opts, argv0, value);
	} else if (equal(name, "ContentLog")) {
		opts_set_contentlog(opts, argv0, value);
	} else if (equal(name, "ContentLogDir")) {
		opts_set_contentlogdir(opts, argv0, value);
	} else if (equal(name, "ContentLogPathSpec")) {
		opts_set_contentlogpathspec(opts, argv0, value);
	} else if (equal(name, "Daemon")) {
		yes = check_value_yesno(value, "Daemon", line_num);
		if (yes == -1) {
			goto leave;
		}
		yes ? opts_set_daemon(opts) : opts_unset_daemon(opts);
#ifdef DEBUG_OPTS
		log_dbg_printf("Daemon: %u\n", opts->detach);
#endif /* DEBUG_OPTS */
	} else if (equal(name, "Debug")) {
		yes = check_value_yesno(value, "Debug", line_num);
		if (yes == -1) {
			goto leave;
		}
		yes ? opts_set_debug(opts) : opts_unset_debug(opts);
#ifdef DEBUG_OPTS
		log_dbg_printf("Debug: %u\n", opts->debug);
#endif /* DEBUG_OPTS */
	} else if (equal(name, "DebugLevel")) {
		opts_set_debug_level(value);
	} else if (equal(name, "ProxySpec")) {
		/* Use MAX_TOKEN instead of computing the actual number of tokens in value */
		char **argv = malloc(sizeof(char *) * MAX_TOKEN);
		char **save_argv = argv;
		int argc = 0;
		char *p, *last = NULL;

		for ((p = strtok_r(value, " ", &last));
		     p;
		     (p = strtok_r(NULL, " ", &last))) {
			/* Limit max # token */
			if (argc < MAX_TOKEN) {
				argv[argc++] = p;
			} else {
				break;
			}
		}

		proxyspec_parse(&argc, &argv, &opts->spec);
		free(save_argv);
	} else if (!strncasecmp(name, "LogStats", 9)) {
		yes = check_value_yesno(value, "LogStats", line_num);
		if (yes == -1) {
			goto leave;
		}
		yes ? opts_set_statslog(opts) : opts_unset_statslog(opts);
#ifdef DEBUG_OPTS
		log_dbg_printf("LogStats: %u\n", opts->statslog);
#endif /* DEBUG_OPTS */
	} else if (!strncasecmp(name, "StatsPeriod", 12)) {
		unsigned int i = atoi(value);
		if (i >= 1 && i <= 10) {
			opts->stats_period = i;
		} else {
			fprintf(stderr, "Invalid StatsPeriod %s on line %d, use 1-10\n", value, line_num);
			goto leave;
		}
#ifdef DEBUG_OPTS
		log_dbg_printf("StatsPeriod: %u\n", opts->stats_period);
#endif /* DEBUG_OPTS */
	} else if (!strncasecmp(name, "OpenFilesLimit", 15)) {
		opts_set_open_files_limit(value, line_num);
	} else {
#ifdef DEBUG_OPTS
		log_dbg_printf("Skipping option '%s' on line %d\n", name, line_num);
#endif /* DEBUG_OPTS */
	}

	retval = 0;
leave:
	return retval;
}

/*
 * Separator param is needed for command line options only.
 * Conf file option separator is ' '.
 */
static int
get_name_value(char **name, char **value, const char sep)
{
	char *n, *v, *value_end;
	int retval = -1;

	/* Skip to the end of option name and terminate it with '\0' */
	for (n = *name;; n++) {
		/* White spaces possible around separator,
		 * if the command line option is passed between the quotes */
		if (*n == ' ' || *n == '\t' || *n == sep) {
			*n = '\0';
			n++;
			break;
		}
		if (*n == '\0') {
			n = NULL;
			break;
		}
	}

	/* No option name */
	if (n == NULL) {
		fprintf(stderr, "Error in option: No option name\n");
		goto leave;
	}

	/* White spaces possible before value and around separator,
	 * if the command line option is passed between the quotes */
	while (*n == ' ' || *n == '\t' || *n == sep) {
		n++;
	}

	*value = n;

	/* Find end of value and terminate it with '\0'
	 * Find first occurrence of trailing white space */
	value_end = NULL;
	for (v = *value;; v++) {
		if (*v == '\0') {
			break;
		}
		if (*v == '\r' || *v == '\n') {
			*v = '\0';
			break;
		}
		if (*v == ' ' || *v == '\t') {
			if (!value_end) {
				value_end = v;
			}
		} else {
			value_end = NULL;
		}
	}

	if (value_end) {
		*value_end = '\0';
	}

	retval = 0;
leave:
	return retval;
}

int
opts_set_option(opts_t *opts, const char *argv0, const char *optarg)
{
	char *name, *value;
	int retval = -1;
	char *line = strdup(optarg);

	/* White spaces possible before option name,
	 * if the command line option is passed between the quotes */
	for (name = line; *name == ' ' || *name == '\t'; name++); 

	/* Command line option separator is '=' */
	retval = get_name_value(&name, &value, '=');
	if (retval == 0) {
		/* Line number param is for conf file, pass 0 for command line options */
		retval = set_option(opts, argv0, name, value, 0);
	}

	if (line)
		free(line);
	return retval;
}

int
opts_load_conffile(opts_t *opts, const char *argv0)
{
	int retval, line_num;
	char *line, *name, *value;
	size_t line_len;
	FILE *f;
	
	f = fopen(opts->conffile, "r");
	if (!f) {
		fprintf(stderr, "Error opening conf file '%s': %s\n", opts->conffile, strerror(errno));
		return -1;
	}

	line = NULL;
	line_num = 0;
	retval = -1;
	while (!feof(f)) {
		if (getline(&line, &line_len, f) == -1) {
			break;
		}
		if (line == NULL) {
			fprintf(stderr, "Error in conf file: getline() returns NULL line after line %d\n", line_num);
			goto leave;
		}
		line_num++;

		/* Skip white space */
		for (name = line; *name == ' ' || *name == '\t'; name++); 

		/* Skip comments and empty lines */
		if ((name[0] == '\0') || (name[0] == '#') || (name[0] == ';') ||
			(name[0] == '\r') || (name[0] == '\n')) {
			continue;
		}

		retval = get_name_value(&name, &value, ' ');
		if (retval == 0) {
			retval = set_option(opts, argv0, name, value, line_num);
		}

		if (retval == -1) {
			goto leave;
		}
		free(line);
		line = NULL;
	}

leave:
	fclose(f);
	if (line)
		free(line);
	return retval;
}

/* vim: set noet ft=c: */
