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

#ifndef PROTOTCP_H
#define PROTOTCP_H

#include "pxyconn.h"

void prototcp_bev_eventcb_connected_src(struct bufferevent *, pxy_conn_ctx_t *);
void prototcp_bev_eventcb_eof_src(struct bufferevent *, pxy_conn_ctx_t *);
void prototcp_bev_eventcb_error_src(struct bufferevent *, pxy_conn_ctx_t *);

void prototcp_bev_eventcb_connected_dst(struct bufferevent *, pxy_conn_ctx_t *);
void prototcp_bev_eventcb_eof_dst(struct bufferevent *, pxy_conn_ctx_t *);
void prototcp_bev_eventcb_error_dst(struct bufferevent *, pxy_conn_ctx_t *);

void prototcp_bev_eventcb_connected_srv_dst(struct bufferevent *, pxy_conn_ctx_t *);
void prototcp_bev_eventcb_eof_srv_dst(struct bufferevent *, pxy_conn_ctx_t *);
void prototcp_bev_eventcb_error_srv_dst(struct bufferevent *, pxy_conn_ctx_t *);

void prototcp_bev_eventcb_src_child(struct bufferevent *, short events, void *);

void prototcp_bev_eventcb_eof_dst_child(struct bufferevent *, pxy_conn_child_ctx_t *);
void prototcp_bev_eventcb_error_dst_child(struct bufferevent *, pxy_conn_child_ctx_t *);

void prototcp_bev_readcb(struct bufferevent *, void *);
void prototcp_bev_writecb(struct bufferevent *, void *);
void prototcp_bev_eventcb(struct bufferevent *, short, void *);

void prototcp_bev_readcb_child(struct bufferevent *, void *);
void prototcp_bev_writecb_child(struct bufferevent *, void *);
void prototcp_bev_eventcb_child(struct bufferevent *, short, void *);

void prototcp_bufferevent_free_and_close_fd(struct bufferevent *, pxy_conn_ctx_t *);

void prototcp_conn_connect(pxy_conn_ctx_t *);
void prototcp_connect_child(pxy_conn_child_ctx_t *);

void prototcp_fd_readcb(evutil_socket_t, short, void *);

enum protocol prototcp_setup(pxy_conn_ctx_t *);
enum protocol prototcp_setup_child(pxy_conn_child_ctx_t *);

#endif /* PROTOTCP_H */

