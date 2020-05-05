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

#ifndef LOG_H
#define LOG_H

#include "opts.h"
#include "proxy.h"
#include "logger.h"
#include "attrib.h"

int log_err_printf(const char *, ...) PRINTF(1,2);
int log_err_level_printf(int, const char *, ...) PRINTF(2,3);
void log_err_mode(int);
#define LOG_ERR_MODE_STDERR 0
#define LOG_ERR_MODE_SYSLOG 1

int log_dbg_printf(const char *, ...) PRINTF(1,2);
int log_dbg_level_printf(int, const char *, int, long long unsigned int, evutil_socket_t, const char *, ...) PRINTF(6,7);
int log_dbg_print_free(char *);
int log_dbg_write_free(void *, size_t);
void log_dbg_mode(int);

#define LOG_DBG_MODE_NONE 0
#define LOG_DBG_MODE_ERRLOG 1
#define LOG_DBG_MODE_FINE 2
#define LOG_DBG_MODE_FINER 3
#define LOG_DBG_MODE_FINEST 4

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
#define __FUNCTION__ __func__
#else
#define __FUNCTION__ ((const char *) 0)
#endif

#ifdef DEBUG_PROXY
// FINE
#define log_fine_main_va(format_str, ...) \
		log_dbg_level_printf(LOG_DBG_MODE_FINE, __FUNCTION__, 0, 0, 0, (format_str), __VA_ARGS__)
#define log_fine(str) \
		log_dbg_level_printf(LOG_DBG_MODE_FINE, __FUNCTION__, ctx->thr ? ctx->thr->id : 0, ctx->id, ctx->fd, (str))
#define log_fine_va(format_str, ...) \
		log_dbg_level_printf(LOG_DBG_MODE_FINE, __FUNCTION__, ctx->thr ? ctx->thr->id : 0, ctx->id, ctx->fd, (format_str), __VA_ARGS__)

// FINER
#define log_finer_main_va(format_str, ...) \
		log_dbg_level_printf(LOG_DBG_MODE_FINER, __FUNCTION__, 0, 0, 0, (format_str), __VA_ARGS__)
#define log_finer(str) \
		log_dbg_level_printf(LOG_DBG_MODE_FINER, __FUNCTION__, ctx->thr ? ctx->thr->id : 0, ctx->id, ctx->fd, (str))
#define log_finer_va(format_str, ...) \
		log_dbg_level_printf(LOG_DBG_MODE_FINER, __FUNCTION__, ctx->thr ? ctx->thr->id : 0, ctx->id, ctx->fd, (format_str), __VA_ARGS__)

// FINEST
#define log_finest_main(str) \
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, __FUNCTION__, 0, 0, 0, (str))
#define log_finest_main_va(format_str, ...) \
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, __FUNCTION__, 0, 0, 0, (format_str), __VA_ARGS__)
#define log_finest(str) \
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, __FUNCTION__, ctx->thr ? ctx->thr->id : 0, ctx->id, ctx->fd, (str))
#define log_finest_va(format_str, ...) \
		log_dbg_level_printf(LOG_DBG_MODE_FINEST, __FUNCTION__, ctx->thr ? ctx->thr->id : 0, ctx->id, ctx->fd, (format_str), __VA_ARGS__)
#else /* !DEBUG_PROXY */
#define log_fine_main_va(format_str, ...) ((void)0)
#define log_fine(str) ((void)0)
#define log_fine_va(format_str, ...) ((void)0)

#define log_finer_main_va(format_str, ...) ((void)0)
#define log_finer(str) ((void)0)
#define log_finer_va(format_str, ...) ((void)0)

#define log_finest_main(str) ((void)0)
#define log_finest_main_va(format_str, ...) ((void)0)
#define log_finest(str) ((void)0)
#define log_finest_va(format_str, ...) ((void)0)
#endif /* !DEBUG_PROXY */

extern logger_t *masterkey_log;
#define log_masterkey_printf(fmt, ...) \
        logger_printf(masterkey_log, NULL, 0, (fmt), __VA_ARGS__)
#define log_masterkey_print(s) \
        logger_print(masterkey_log, NULL, 0, (s))
#define log_masterkey_write(buf, sz) \
        logger_write(masterkey_log, NULL, 0, (buf), (sz))
#define log_masterkey_print_free(s) \
        logger_print_freebuf(masterkey_log, NULL, 0, (s))
#define log_masterkey_write_free(buf, sz) \
        logger_write_freebuf(masterkey_log, NULL, 0, (buf), (sz))

extern logger_t *connect_log;
#define log_connect_printf(fmt, ...) \
        logger_printf(connect_log, NULL, 0, (fmt), __VA_ARGS__)
#define log_connect_print(s) \
        logger_print(connect_log, NULL, 0, (s))
#define log_connect_write(buf, sz) \
        logger_write(connect_log, NULL, 0, (buf), (sz))
#define log_connect_print_free(s) \
        logger_print_freebuf(connect_log, NULL, 0, (s))
#define log_connect_write_free(buf, sz) \
        logger_write_freebuf(connect_log, NULL, 0, (buf), (sz))

#define log_err_level(level, str) { log_err_level_printf((level), (str"\n")); log_fine((str)); }

int log_stats(const char *);
int log_conn(const char *);

typedef struct log_content_ctx log_content_ctx_t;
struct log_content_file_ctx;
struct log_content_ctx {
	struct log_content_file_ctx *file;
};
int log_content_open(log_content_ctx_t *, opts_t *,
                     char *, char *, char *, char *,
                     char *, char *, char *) NONNULL(1,2) WUNRES;
int log_content_submit(log_content_ctx_t *, logbuf_t *, int)
                       NONNULL(1,2) WUNRES;
int log_content_close(log_content_ctx_t *, int) NONNULL(1) WUNRES;
int log_content_split_pathspec(const char *, char **,
                               char **) NONNULL(1,2,3) WUNRES;

int log_preinit(opts_t *) NONNULL(1) WUNRES;
void log_preinit_undo(void);
int log_init(opts_t *, proxy_ctx_t *, int[3]) NONNULL(1,2) WUNRES;
void log_fini(void);
int log_reopen(void) WUNRES;
void log_exceptcb(void);

#endif /* !LOG_H */

/* vim: set noet ft=c: */
