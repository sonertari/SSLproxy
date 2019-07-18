/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
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

/* silence daemon(3) deprecation warning on Mac OS X */
#if __APPLE__
#define daemon xdaemon
#endif /* __APPLE__ */

#include "opts.h"
#include "proxy.h"
#include "privsep.h"
#include "sys.h"
#include "log.h"
#include "build.h"
#include "defaults.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

#ifndef __BSD__
#include <getopt.h>
#endif /* !__BSD__ */

#include <event2/event.h>

#if __APPLE__
#undef daemon
extern int daemon(int, int);
#endif /* __APPLE__ */

/*
 * Print version information to stderr.
 */
static void
main_version(void)
{
	fprintf(stderr, "%s %s (built %s)\n",
	                PKGLABEL, build_version, build_date);
	if (strlen(build_version) < 5) {
		/*
		 * Note to package maintainers:  If you break the version
		 * string in your build, it will be impossible to provide
		 * proper upstream support to the users of the package,
		 * because it will be difficult or impossible to identify
		 * the exact codebase that is being used by the user
		 * reporting a bug.  The version string is provided through
		 * different means depending on whether the code is a git
		 * checkout, a tarball downloaded from GitHub or a release.
		 * See GNUmakefile for the gory details.
		 */
		fprintf(stderr, "---------------------------------------"
		                "---------------------------------------\n");
		fprintf(stderr, "WARNING: Something is wrong with the "
		                "version compiled into lp!\n");
		fprintf(stderr, "The version should contain a release "
		                "number and/or a git commit reference.\n");
		fprintf(stderr, "If using a package, please report a bug "
		                "to the distro package maintainer.\n");
		fprintf(stderr, "---------------------------------------"
		                "---------------------------------------\n");
	}
	fprintf(stderr, "Copyright (c) 2017-2019, Soner Tari <sonertari@gmail.com>\n");
	fprintf(stderr, "https://github.com/sonertari/SSLproxy\n");
	fprintf(stderr, "Copyright (c) 2009-2018, "
	                "Daniel Roethlisberger <daniel@roe.ch>\n");
	fprintf(stderr, "https://www.roe.ch/SSLsplit\n");
	if (build_info[0]) {
		fprintf(stderr, "Build info: %s\n", build_info);
	}
	if (build_features[0]) {
		fprintf(stderr, "Features: %s\n", build_features);
	}
	fprintf(stderr, "compiled against libevent %s\n", LIBEVENT_VERSION);
	fprintf(stderr, "rtlinked against libevent %s\n", event_get_version());
	fprintf(stderr, "%d CPU cores detected\n", sys_get_cpu_cores());
}

/*
 * Print usage to stderr.
 */
static void
main_usage(void)
{
	const char *usagefmt =
"Usage: %s [-D] [-f conffile] [-o opt=val] [options...] [proxyspecs...]\n"
"  -f conffile use conffile to load configuration from\n"
"  -o opt=val  override conffile option opt with value val\n"
"  -u user     drop privileges to user (default if run as root: " DFLT_DROPUSER ")\n"
"  -m group    when using -u, override group (default: primary group of user)\n"
"  -j jaildir  chroot() to jaildir (impacts sni proxyspecs, see manual page)\n"
"  -p pidfile  write pid to pidfile (default: no pid file)\n"
"  -l logfile  connect log: log one line summary per connection to logfile\n"
"  -J          enable connection statistics logging\n"
"  -L logfile  content log: full data to file or named pipe (excludes -S/-F)\n"
"  -S logdir   content log: full data to separate files in dir (excludes -L/-F)\n"
"  -F pathspec content log: full data to sep files with %% subst (excl. -L/-S):\n"
"              %%T - initial connection time as an ISO 8601 UTC timestamp\n"
"              %%d - destination host and port\n"
"              %%D - destination host\n"
"              %%p - destination port\n"
"              %%s - source host and port\n"
"              %%S - source host\n"
"              %%q - source port\n"
"              %%%% - literal '%%'\n"
"  -d          daemon mode: run in background, log error messages to syslog\n"
"  -D          debug mode: run in foreground, log debug messages on stderr\n"
"  -V          print version information and exit\n"
"  -h          print usage information and exit\n"
"  proxyspec = listenaddr+port\n"
"      e.g.    127.0.0.1 8080 # tcp/4; static\n"
"                             # et al\n"
"Example:\n"
"  %s  127.0.0.1 8080\n";

	fprintf(stderr, usagefmt, build_pkgname, build_pkgname);
}

/*
 * Main entry point.
 */
int
main(int argc, char *argv[])
{
	const char *argv0;
	int ch;
	opts_t *opts;
	int pidfd = -1;
	int rv = EXIT_FAILURE;

	argv0 = argv[0];
	opts = opts_new();

	while ((ch = getopt(argc, argv,
	                    "u:m:j:p:l:L:S:F:dD::Vhf:o:J")) != -1) {
		switch (ch) {
			case 'f':
				if (opts->conffile)
					free(opts->conffile);
				opts->conffile = strdup(optarg);
				if (!opts->conffile)
					oom_die(argv0);
				if (opts_load_conffile(opts, argv0) == -1) {
					exit(EXIT_FAILURE);
				}
#ifdef DEBUG_OPTS
				log_dbg_printf("Conf file: %s\n", opts->conffile);
#endif /* DEBUG_OPTS */
				break;
			case 'o':
				if (opts_set_option(opts, argv0, optarg) == -1) {
					exit(EXIT_FAILURE);
				}
				break;
			case 'u':
				opts_set_user(opts, argv0, optarg);
				break;
			case 'm':
				opts_set_group(opts, argv0, optarg);
				break;
			case 'p':
				opts_set_pidfile(opts, argv0, optarg);
				break;
			case 'j':
				opts_set_jaildir(opts, argv0, optarg);
				break;
			case 'l':
				opts_set_connectlog(opts, argv0, optarg);
				break;
			case 'J':
				opts_set_statslog(opts);
				break;
			case 'L':
				opts_set_contentlog(opts, argv0, optarg);
				break;
			case 'S':
				opts_set_contentlogdir(opts, argv0, optarg);
				break;
			case 'F':
				opts_set_contentlogpathspec(opts, argv0, optarg);
				break;
			case 'd':
				opts_set_daemon(opts);
				break;
			case 'D':
				opts_set_debug(opts);
				if (optarg) {
					opts_set_debug_level(optarg);
				}
				break;
			case 'V':
				main_version();
				exit(EXIT_SUCCESS);
			case 'h':
				main_usage();
				exit(EXIT_SUCCESS);
			case '?':
				exit(EXIT_FAILURE);
			default:
				main_usage();
				exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;
	proxyspec_parse(&argc, &argv, &opts->spec);

	/* usage checks before defaults */
	if (opts->detach && OPTS_DEBUG(opts)) {
		fprintf(stderr, "%s: -d and -D are mutually exclusive.\n",
		                argv0);
		exit(EXIT_FAILURE);
	}
	if (!opts->spec) {
		fprintf(stderr, "%s: no proxyspec specified.\n", argv0);
		exit(EXIT_FAILURE);
	}
	for (proxyspec_t *spec = opts->spec; spec; spec = spec->next) {
		if (spec->connect_addrlen)
			continue;
	}
#ifdef __APPLE__
	if (opts->dropuser && !!strcmp(opts->dropuser, "root") &&
	    nat_used("pf")) {
		fprintf(stderr, "%s: cannot use 'pf' proxyspec with -u due "
		                "to Apple bug\n", argv0);
		exit(EXIT_FAILURE);
	}
#endif /* __APPLE__ */

	/* prevent multiple instances running */
	if (opts->pidfile) {
		pidfd = sys_pidf_open(opts->pidfile);
		if (pidfd == -1) {
			fprintf(stderr, "%s: cannot open PID file '%s' "
			                "- process already running?\n",
			                argv0, opts->pidfile);
			exit(EXIT_FAILURE);
		}
	}

	if (!opts->dropuser && !geteuid() && !getuid() &&
	    sys_isuser(DFLT_DROPUSER)) {
#ifdef __APPLE__
		/* Apple broke ioctl(/dev/pf) for EUID != 0 so we do not
		 * want to automatically drop privileges to nobody there
		 * if pf has been used in any proxyspec */
		if (!nat_used("pf")) {
#endif /* __APPLE__ */
		opts->dropuser = strdup(DFLT_DROPUSER);
		if (!opts->dropuser)
			oom_die(argv0);
#ifdef __APPLE__
		}
#endif /* __APPLE__ */
	}
	if (opts->dropuser && sys_isgeteuid(opts->dropuser)) {
		if (opts->dropgroup) {
			fprintf(stderr, "%s: cannot use -m when -u is "
			        "current user\n", argv0);
			exit(EXIT_FAILURE);
		}
		free(opts->dropuser);
		opts->dropuser = NULL;
	}

	/* usage checks after defaults */
	if (opts->dropgroup && !opts->dropuser) {
		fprintf(stderr, "%s: -m depends on -u\n", argv0);
		exit(EXIT_FAILURE);
	}

	/* Warn about options that require per-connection privileged operations
	 * to be executed through privsep, but only if dropuser is set and is
	 * not root, because privsep will fastpath in that situation, skipping
	 * the latency-incurring overhead. */
	int privsep_warn = 0;
	if (opts->dropuser) {
		if (opts->contentlog_isdir) {
			log_dbg_printf("| Warning: -F requires a privileged "
			               "operation for each connection!\n");
			privsep_warn = 1;
		}
		if (opts->contentlog_isspec) {
			log_dbg_printf("| Warning: -S requires a privileged "
			               "operation for each connection!\n");
			privsep_warn = 1;
		}
	}
	if (privsep_warn) {
		log_dbg_printf("| Privileged operations require communication "
		               "between parent and child process\n"
		               "| and will negatively impact latency and "
		               "performance on each connection.\n");
	}

	/* debug log, part 1 */
	if (OPTS_DEBUG(opts)) {
		main_version();
	}

	/* debug log, part 2 */
	if (OPTS_DEBUG(opts)) {
		log_dbg_printf("proxyspecs:\n");
		for (proxyspec_t *spec = opts->spec; spec; spec = spec->next) {
			char *specstr = proxyspec_str(spec);
			if (!specstr) {
				fprintf(stderr, "%s: out of memory\n", argv0);
				exit(EXIT_FAILURE);
			}
			log_dbg_printf("- %s\n", specstr);
			free(specstr);
		}
	}

	/*
	 * Initialize as much as possible before daemon() in order to be
	 * able to provide direct feedback to the user when failing.
	 */
	if (log_preinit(opts) == -1) {
		fprintf(stderr, "%s: failed to preinit logging.\n", argv0);
		exit(EXIT_FAILURE);
	}

	/* Detach from tty; from this point on, only canonicalized absolute
	 * paths should be used (-j, -F, -S). */
	if (opts->detach) {
		if (OPTS_DEBUG(opts)) {
			log_dbg_printf("Detaching from TTY, see syslog for "
			               "errors after this point\n");
		}
		if (daemon(0, 0) == -1) {
			fprintf(stderr, "%s: failed to detach from TTY: %s\n",
			                argv0, strerror(errno));
			exit(EXIT_FAILURE);
		}
		log_err_mode(LOG_ERR_MODE_SYSLOG);
	}

	if (opts->pidfile && (sys_pidf_write(pidfd) == -1)) {
		log_err_level_printf(LOG_CRIT, "Failed to write PID to PID file '%s': %s (%i)"
		               "\n", opts->pidfile, strerror(errno), errno);
		return -1;
	}

	descriptor_table_size = getdtablesize();

	/* Fork into parent monitor process and (potentially unprivileged)
	 * child process doing the actual work.  We request 6 privsep client
	 * sockets: five logger threads, and the child process main thread,
	 * which will become the main proxy thread.  First slot is main thread,
	 * remaining slots are passed down to log subsystem. */
	int clisock[6];
	if (privsep_fork(opts, clisock,
	                 sizeof(clisock)/sizeof(clisock[0])) != 0) {
		/* parent has exited the monitor loop after waiting for child,
		 * or an error occurred */
		if (opts->pidfile) {
			sys_pidf_close(pidfd, opts->pidfile);
		}
		goto out_parent;
	}
	/* child */

	/* close pidfile in child */
	if (opts->pidfile)
		close(pidfd);

	/* Initialize proxy before dropping privs */
	proxy_ctx_t *proxy = proxy_new(opts, clisock[0]);
	if (!proxy) {
		log_err_level_printf(LOG_CRIT, "Failed to initialize proxy.\n");
		exit(EXIT_FAILURE);
	}

	/* Drop privs, chroot */
	if (sys_privdrop(opts->dropuser, opts->dropgroup,
	                 opts->jaildir) == -1) {
		log_err_level_printf(LOG_CRIT, "Failed to drop privileges: %s (%i)\n",
		               strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	log_dbg_printf("Dropped privs to user %s group %s chroot %s\n",
	               opts->dropuser  ? opts->dropuser  : "-",
	               opts->dropgroup ? opts->dropgroup : "-",
	               opts->jaildir   ? opts->jaildir   : "-");
	/* Post-privdrop/chroot/detach initialization, thread spawning */
	if (log_init(opts, proxy, &clisock[1]) == -1) {
		fprintf(stderr, "%s: failed to init log facility: %s\n",
		                argv0, strerror(errno));
		goto out_log_failed;
	}
	rv = EXIT_SUCCESS;

	proxy_run(proxy);

	proxy_free(proxy);
	log_fini();
out_log_failed:
out_parent:
	opts_free(opts);
	return rv;
}

/* vim: set noet ft=c: */
