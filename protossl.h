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

#ifndef PROTOSSL_H
#define PROTOSSL_H

#include "pxyconn.h"

int protossl_log_masterkey(pxy_conn_ctx_t *, pxy_conn_desc_t *);
void protossl_log_ssl_error(struct bufferevent *, pxy_conn_ctx_t *);

// @todo Used externally by pxy_log_connect_src(), create tcp and ssl versions of that function instead
void protossl_srccert_write(pxy_conn_ctx_t *);
SSL *protossl_dstssl_create(pxy_conn_ctx_t *);

int protossl_setup_src_ssl(pxy_conn_ctx_t *);
int protossl_setup_src_sslbev(pxy_conn_ctx_t *);

int protossl_setup_dst_ssl_child(pxy_conn_child_ctx_t *);
int protossl_setup_dst_sslbev_child(pxy_conn_child_ctx_t *);
int protossl_setup_dst_child(pxy_conn_child_ctx_t *);

void protossl_bev_eventcb(struct bufferevent *, short, void *);
void protossl_bev_eventcb_child(struct bufferevent *, short, void *);

void protossl_bufferevent_free_and_close_fd(struct bufferevent *, pxy_conn_ctx_t *);
void protossl_free(pxy_conn_ctx_t *) NONNULL(1);

void protossl_conn_connect(pxy_conn_ctx_t *);
void protossl_fd_readcb(evutil_socket_t, short, void *);

void protossl_connect_child(pxy_conn_child_ctx_t *);

enum protocol protossl_setup(pxy_conn_ctx_t *);
enum protocol protossl_setup_child(pxy_conn_child_ctx_t *);

#endif /* PROTOSSL_H */

