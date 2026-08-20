/*-
 * SSLproxy
 *
 * Copyright (c) 2017-2026, Soner Tari <sonertari@gmail.com>.
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

#ifndef PROTOHTTP2_H
#define PROTOHTTP2_H

#include "pxyconn.h"
#include "protohttp.h"
#include "icap.h"

#include <nghttp2/nghttp2.h>

typedef struct protohttp2_stream_ctx {
    PROTOHTTPX_STREAM_CTX

    struct protohttp2_stream_ctx *next;

    nghttp2_nv *headers;
    nghttp2_data_provider provider;
} protohttp2_stream_ctx_t;

typedef struct protohttp2_ctx {
    nghttp2_session *src_session;
    nghttp2_session *dst_session;

    pxy_conn_ctx_t *ctx;

    protohttp2_stream_ctx_t *streams;
} protohttp2_ctx_t;

#ifndef WITHOUT_ICAP
// Forward declaration
struct icap_service_ctx;

void protohttp2_close_stream(protohttp2_stream_ctx_t *);

void protohttp2_icap_send_data_to_src_cb(icap_ctx_t *) NONNULL(1);
void protohttp2_icap_send_data_to_dst_cb(icap_ctx_t *) NONNULL(1);
void protohttp2_icap_failopen_to_dest_cb(struct icap_service_ctx *) NONNULL(1);
#endif /* !WITHOUT_ICAP */

int protohttp2_icap_is_finished(pxy_conn_ctx_t *) NONNULL(1);
void protohttp2_free(pxy_conn_ctx_t *) NONNULL(1);
protocol_t protohttp2_setup(pxy_conn_ctx_t *) NONNULL(1);
void protohttp2_request_free_stream_ctx(protohttp2_stream_ctx_t *) NONNULL(1);

#endif /* !PROTOHTTP2_H */

/* vim: set noet ft=c: */
