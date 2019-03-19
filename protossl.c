/*-
 * SSLsplit - transparent SSL/TLS interception
 * https://www.roe.ch/SSLsplit
 *
 * Copyright (c) 2009-2018, Daniel Roethlisberger <daniel@roe.ch>.
 * Copyright (c) 2017-2019, Soner Tari <sonertari@gmail.com>.
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

#include "protossl.h"
#include "prototcp.h"
#include "protopassthrough.h"

#include "pxysslshut.h"
#include "cachemgr.h"

#include <string.h>
#include <sys/param.h>
#include <event2/bufferevent_ssl.h>

/*
 * Context used for all server sessions.
 */
#ifdef USE_SSL_SESSION_ID_CONTEXT
static unsigned long ssl_session_context = 0x31415926;
#endif /* USE_SSL_SESSION_ID_CONTEXT */

void
protossl_log_ssl_error(struct bufferevent *bev, UNUSED pxy_conn_ctx_t *ctx)
{
	unsigned long sslerr;

	/* Can happen for socket errs, ssl errs;
	 * may happen for unclean ssl socket shutdowns. */
	sslerr = bufferevent_get_openssl_error(bev);
	if (!errno && !sslerr) {
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
		/* We have disabled notification for unclean shutdowns
		 * so this should not happen; log a warning. */
		log_err_level_printf(LOG_WARNING, "Spurious error from bufferevent (errno=0,sslerr=0)\n");
#else /* LIBEVENT_VERSION_NUMBER < 0x02010000 */
		/* Older versions of libevent will report these. */
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Unclean SSL shutdown, fd=%d\n", ctx->fd);
		}
#endif /* LIBEVENT_VERSION_NUMBER < 0x02010000 */
	} else if (ERR_GET_REASON(sslerr) == SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE) {
		/* these can happen due to client cert auth,
		 * only log error if debugging is activated */
		log_dbg_printf("Error from bufferevent: %i:%s %lu:%i:%s:%i:%s:%i:%s\n",
					   errno, errno ? strerror(errno) : "-", sslerr,
					   ERR_GET_REASON(sslerr), sslerr ? ERR_reason_error_string(sslerr) : "-",
					   ERR_GET_LIB(sslerr), sslerr ? ERR_lib_error_string(sslerr) : "-",
					   ERR_GET_FUNC(sslerr), sslerr ? ERR_func_error_string(sslerr) : "-");
		while ((sslerr = bufferevent_get_openssl_error(bev))) {
			log_dbg_printf("Additional SSL error: %lu:%i:%s:%i:%s:%i:%s\n",
						   sslerr,
						   ERR_GET_REASON(sslerr), ERR_reason_error_string(sslerr),
						   ERR_GET_LIB(sslerr), ERR_lib_error_string(sslerr),
						   ERR_GET_FUNC(sslerr), ERR_func_error_string(sslerr));
		}
	} else {
		/* real errors */
		log_err_printf("Error from bufferevent: %i:%s %lu:%i:%s:%i:%s:%i:%s\n",
					   errno, errno ? strerror(errno) : "-",
					   sslerr,
					   ERR_GET_REASON(sslerr), sslerr ? ERR_reason_error_string(sslerr) : "-",
					   ERR_GET_LIB(sslerr), sslerr ? ERR_lib_error_string(sslerr) : "-",
					   ERR_GET_FUNC(sslerr), sslerr ? ERR_func_error_string(sslerr) : "-");
		while ((sslerr = bufferevent_get_openssl_error(bev))) {
			log_err_printf("Additional SSL error: %lu:%i:%s:%i:%s:%i:%s\n",
						   sslerr,
						   ERR_GET_REASON(sslerr), ERR_reason_error_string(sslerr),
						   ERR_GET_LIB(sslerr), ERR_lib_error_string(sslerr),
						   ERR_GET_FUNC(sslerr), ERR_func_error_string(sslerr));
		}
	}
}

int
protossl_log_masterkey(pxy_conn_ctx_t *ctx, pxy_conn_desc_t *this)
{
	// XXX: Remove ssl check? But the caller function is called by non-ssl protos.
	if (this->ssl) {
		/* log master key */
		if (ctx->opts->masterkeylog) {
			char *keystr;
			keystr = ssl_ssl_masterkey_to_str(this->ssl);
			if ((keystr == NULL) ||
				(log_masterkey_print_free(keystr) == -1)) {
				if (errno == ENOMEM)
					ctx->enomem = 1;
				pxy_conn_term(ctx, 1);
				return -1;
			}
		}
	}
	return 0;
}

/* forward declaration of OpenSSL callbacks */
#ifndef OPENSSL_NO_TLSEXT
static int protossl_ossl_servername_cb(SSL *ssl, int *al, void *arg);
#endif /* !OPENSSL_NO_TLSEXT */
static int protossl_ossl_sessnew_cb(SSL *, SSL_SESSION *);
static void protossl_ossl_sessremove_cb(SSL_CTX *, SSL_SESSION *);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20800000L)
static SSL_SESSION * protossl_ossl_sessget_cb(SSL *, unsigned char *, int, int *);
#else /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
static SSL_SESSION * protossl_ossl_sessget_cb(SSL *, const unsigned char *, int, int *);
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

/*
 * Dump information on a certificate to the debug log.
 */
static void
protossl_debug_crt(X509 *crt)
{
	char *sj = ssl_x509_subject(crt);
	if (sj) {
		log_dbg_printf("Subject DN: %s\n", sj);
		free(sj);
	}

	char *names = ssl_x509_names_to_str(crt);
	if (names) {
		log_dbg_printf("Common Names: %s\n", names);
		free(names);
	}

	char *fpr;
	if (!(fpr = ssl_x509_fingerprint(crt, 1))) {
		log_err_level_printf(LOG_WARNING, "Error generating X509 fingerprint\n");
	} else {
		log_dbg_printf("Fingerprint: %s\n", fpr);
		free(fpr);
	}

#ifdef DEBUG_CERTIFICATE
	/* dump certificate */
	log_dbg_print_free(ssl_x509_to_str(crt));
	log_dbg_print_free(ssl_x509_to_pem(crt));
#endif /* DEBUG_CERTIFICATE */
}

/*
 * Called by OpenSSL when a new src SSL session is created.
 * OpenSSL increments the refcount before calling the callback and will
 * decrement it again if we return 0.  Returning 1 will make OpenSSL skip
 * the refcount decrementing.  In other words, return 0 if we did not
 * keep a pointer to the object (which we never do here).
 */
#ifdef HAVE_SSLV2
#define MAYBE_UNUSED 
#else /* !HAVE_SSLV2 */
#define MAYBE_UNUSED UNUSED
#endif /* !HAVE_SSLV2 */
static int
protossl_ossl_sessnew_cb(MAYBE_UNUSED SSL *ssl, SSL_SESSION *sess)
#undef MAYBE_UNUSED
{
#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL new session callback:\n");
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	} else {
		log_dbg_printf("(null)\n");
	}
#endif /* DEBUG_SESSION_CACHE */
#ifdef HAVE_SSLV2
	/* Session resumption seems to fail for SSLv2 with protocol
	 * parsing errors, so we disable caching for SSLv2. */
	if (SSL_version(ssl) == SSL2_VERSION) {
		log_err_level_printf(LOG_WARNING, "Session resumption denied to SSLv2"
		               "client.\n");
		return 0;
	}
#endif /* HAVE_SSLV2 */
	if (sess) {
		cachemgr_ssess_set(sess);
	}
	return 0;
}

/*
 * Called by OpenSSL when a src SSL session should be removed.
 * OpenSSL calls SSL_SESSION_free() after calling the callback;
 * we do not need to free the reference here.
 */
static void
protossl_ossl_sessremove_cb(UNUSED SSL_CTX *sslctx, SSL_SESSION *sess)
{
#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL remove session callback:\n");
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	} else {
		log_dbg_printf("(null)\n");
	}
#endif /* DEBUG_SESSION_CACHE */
	if (sess) {
		cachemgr_ssess_del(sess);
	}
}

/*
 * Called by OpenSSL when a src SSL session is requested by the client.
 */
static SSL_SESSION *
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20800000L)
protossl_ossl_sessget_cb(UNUSED SSL *ssl, unsigned char *id, int idlen, int *copy)
#else /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
protossl_ossl_sessget_cb(UNUSED SSL *ssl, const unsigned char *id, int idlen, int *copy)
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */
{
	SSL_SESSION *sess;

#ifdef DEBUG_SESSION_CACHE
	log_dbg_printf("===> OpenSSL get session callback:\n");
#endif /* DEBUG_SESSION_CACHE */

	*copy = 0; /* SSL should not increment reference count of session */
	sess = cachemgr_ssess_get(id, idlen);

#ifdef DEBUG_SESSION_CACHE
	if (sess) {
		log_dbg_print_free(ssl_session_to_str(sess));
	}
#endif /* DEBUG_SESSION_CACHE */

	log_dbg_printf("SSL session cache: %s\n", sess ? "HIT" : "MISS");
	return sess;
}

/*
 * Set SSL_CTX options that are the same for incoming and outgoing SSL_CTX.
 */
static void
protossl_sslctx_setoptions(SSL_CTX *sslctx, pxy_conn_ctx_t *ctx)
{
	SSL_CTX_set_options(sslctx, SSL_OP_ALL);
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	SSL_CTX_set_options(sslctx, SSL_OP_TLS_ROLLBACK_BUG);
#endif /* SSL_OP_TLS_ROLLBACK_BUG */
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
	SSL_CTX_set_options(sslctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif /* SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION */
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	SSL_CTX_set_options(sslctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
#endif /* SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS */
#ifdef SSL_OP_NO_TICKET
	SSL_CTX_set_options(sslctx, SSL_OP_NO_TICKET);
#endif /* SSL_OP_NO_TICKET */

#ifdef SSL_OP_NO_SSLv2
#ifdef HAVE_SSLV2
	if (ctx->opts->no_ssl2) {
#endif /* HAVE_SSLV2 */
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv2);
#ifdef HAVE_SSLV2
	}
#endif /* HAVE_SSLV2 */
#endif /* !SSL_OP_NO_SSLv2 */
#ifdef HAVE_SSLV3
	if (ctx->opts->no_ssl3) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_SSLv3);
	}
#endif /* HAVE_SSLV3 */
#ifdef HAVE_TLSV10
	if (ctx->opts->no_tls10) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1);
	}
#endif /* HAVE_TLSV10 */
#ifdef HAVE_TLSV11
	if (ctx->opts->no_tls11) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1_1);
	}
#endif /* HAVE_TLSV11 */
#ifdef HAVE_TLSV12
	if (ctx->opts->no_tls12) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_TLSv1_2);
	}
#endif /* HAVE_TLSV12 */

#ifdef SSL_OP_NO_COMPRESSION
	if (!ctx->opts->sslcomp) {
		SSL_CTX_set_options(sslctx, SSL_OP_NO_COMPRESSION);
	}
#endif /* SSL_OP_NO_COMPRESSION */

	SSL_CTX_set_cipher_list(sslctx, ctx->opts->ciphers);
}

/*
 * Create and set up a new SSL_CTX instance for terminating SSL.
 * Set up all the necessary callbacks, the certificate, the cert chain and key.
 */
static SSL_CTX *
protossl_srcsslctx_create(pxy_conn_ctx_t *ctx, X509 *crt, STACK_OF(X509) *chain,
                     EVP_PKEY *key)
{
	SSL_CTX *sslctx = SSL_CTX_new(ctx->opts->sslmethod());
	if (!sslctx)
		return NULL;

	protossl_sslctx_setoptions(sslctx, ctx);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	if (ctx->opts->sslversion) {
		if (SSL_CTX_set_min_proto_version(sslctx, ctx->opts->sslversion) == 0 ||
			SSL_CTX_set_max_proto_version(sslctx, ctx->opts->sslversion) == 0) {
			SSL_CTX_free(sslctx);
			return NULL;
		}
	}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

	SSL_CTX_sess_set_new_cb(sslctx, protossl_ossl_sessnew_cb);
	SSL_CTX_sess_set_remove_cb(sslctx, protossl_ossl_sessremove_cb);
	SSL_CTX_sess_set_get_cb(sslctx, protossl_ossl_sessget_cb);
	SSL_CTX_set_session_cache_mode(sslctx, SSL_SESS_CACHE_SERVER |
	                                       SSL_SESS_CACHE_NO_INTERNAL);
#ifdef USE_SSL_SESSION_ID_CONTEXT
	SSL_CTX_set_session_id_context(sslctx, (void *)(&ssl_session_context),
	                                       sizeof(ssl_session_context));
#endif /* USE_SSL_SESSION_ID_CONTEXT */
#ifndef OPENSSL_NO_TLSEXT
	SSL_CTX_set_tlsext_servername_callback(sslctx, protossl_ossl_servername_cb);
	SSL_CTX_set_tlsext_servername_arg(sslctx, ctx);
#endif /* !OPENSSL_NO_TLSEXT */
#ifndef OPENSSL_NO_DH
	if (ctx->opts->dh) {
		SSL_CTX_set_tmp_dh(sslctx, ctx->opts->dh);
	} else {
		SSL_CTX_set_tmp_dh_callback(sslctx, ssl_tmp_dh_callback);
	}
#endif /* !OPENSSL_NO_DH */
#ifndef OPENSSL_NO_ECDH
	if (ctx->opts->ecdhcurve) {
		EC_KEY *ecdh = ssl_ec_by_name(ctx->opts->ecdhcurve);
		SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
		EC_KEY_free(ecdh);
	} else {
		EC_KEY *ecdh = ssl_ec_by_name(NULL);
		SSL_CTX_set_tmp_ecdh(sslctx, ecdh);
		EC_KEY_free(ecdh);
	}
#endif /* !OPENSSL_NO_ECDH */
	SSL_CTX_use_certificate(sslctx, crt);
	SSL_CTX_use_PrivateKey(sslctx, key);
	for (int i = 0; i < sk_X509_num(chain); i++) {
		X509 *c = sk_X509_value(chain, i);
		ssl_x509_refcount_inc(c); /* next call consumes a reference */
		SSL_CTX_add_extra_chain_cert(sslctx, c);
	}

#ifdef DEBUG_SESSION_CACHE
	if (OPTS_DEBUG(ctx->opts)) {
		int mode = SSL_CTX_get_session_cache_mode(sslctx);
		log_dbg_printf("SSL session cache mode: %08x\n", mode);
		if (mode == SSL_SESS_CACHE_OFF)
			log_dbg_printf("SSL_SESS_CACHE_OFF\n");
		if (mode & SSL_SESS_CACHE_CLIENT)
			log_dbg_printf("SSL_SESS_CACHE_CLIENT\n");
		if (mode & SSL_SESS_CACHE_SERVER)
			log_dbg_printf("SSL_SESS_CACHE_SERVER\n");
		if (mode & SSL_SESS_CACHE_NO_AUTO_CLEAR)
			log_dbg_printf("SSL_SESS_CACHE_NO_AUTO_CLEAR\n");
		if (mode & SSL_SESS_CACHE_NO_INTERNAL_LOOKUP)
			log_dbg_printf("SSL_SESS_CACHE_NO_INTERNAL_LOOKUP\n");
		if (mode & SSL_SESS_CACHE_NO_INTERNAL_STORE)
			log_dbg_printf("SSL_SESS_CACHE_NO_INTERNAL_STORE\n");
	}
#endif /* DEBUG_SESSION_CACHE */

	return sslctx;
}

static int
protossl_srccert_write_to_gendir(pxy_conn_ctx_t *ctx, X509 *crt, int is_orig)
{
	char *fn;
	int rv;

	if (!ctx->sslctx->origcrtfpr)
		return -1;
	if (is_orig) {
		rv = asprintf(&fn, "%s/%s.crt", ctx->opts->certgendir,
		              ctx->sslctx->origcrtfpr);
	} else {
		if (!ctx->sslctx->usedcrtfpr)
			return -1;
		rv = asprintf(&fn, "%s/%s-%s.crt", ctx->opts->certgendir,
		              ctx->sslctx->origcrtfpr, ctx->sslctx->usedcrtfpr);
	}
	if (rv == -1) {
		ctx->enomem = 1;
		return -1;
	}
	rv = log_cert_submit(fn, crt);
	free(fn);
	return rv;
}

void
protossl_srccert_write(pxy_conn_ctx_t *ctx)
{
	if (ctx->opts->certgen_writeall || ctx->sslctx->generated_cert) {
		if (protossl_srccert_write_to_gendir(ctx,
		                SSL_get_certificate(ctx->src.ssl), 0) == -1) {
			log_err_level_printf(LOG_CRIT, "Failed to write used certificate\n");
		}
	}
	if (ctx->opts->certgen_writeall) {
		if (protossl_srccert_write_to_gendir(ctx, ctx->sslctx->origcrt, 1) == -1) {
			log_err_level_printf(LOG_CRIT, "Failed to write orig certificate\n");
		}
	}
}

static cert_t *
protossl_srccert_create(pxy_conn_ctx_t *ctx)
{
	cert_t *cert = NULL;

	if (ctx->opts->tgcrtdir) {
		if (ctx->sslctx->sni) {
			cert = cachemgr_tgcrt_get(ctx->sslctx->sni);
			if (!cert) {
				char *wildcarded;
				wildcarded = ssl_wildcardify(ctx->sslctx->sni);
				if (!wildcarded) {
					ctx->enomem = 1;
					return NULL;
				}
				cert = cachemgr_tgcrt_get(wildcarded);
				free(wildcarded);
			}
			if (cert && OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Target cert by SNI\n");
			}
		} else if (ctx->sslctx->origcrt) {
			char **names = ssl_x509_names(ctx->sslctx->origcrt);
			for (char **p = names; *p; p++) {
				if (!cert) {
					cert = cachemgr_tgcrt_get(*p);
				}
				if (!cert) {
					char *wildcarded;
					wildcarded = ssl_wildcardify(*p);
					if (!wildcarded) {
						ctx->enomem = 1;
					} else {
						cert = cachemgr_tgcrt_get(
						       wildcarded);
						free(wildcarded);
					}
				}
				free(*p);
			}
			free(names);
			if (ctx->enomem) {
				return NULL;
			}
			if (cert && OPTS_DEBUG(ctx->opts)) {
				log_dbg_printf("Target cert by origcrt\n");
			}
		}

		if (cert) {
			ctx->sslctx->immutable_cert = 1;
		}
	}

	if (!cert && ctx->sslctx->origcrt && ctx->opts->key) {
		cert = cert_new();

		cert->crt = cachemgr_fkcrt_get(ctx->sslctx->origcrt);
		if (cert->crt) {
			if (OPTS_DEBUG(ctx->opts))
				log_dbg_printf("Certificate cache: HIT\n");
		} else {
			if (OPTS_DEBUG(ctx->opts))
				log_dbg_printf("Certificate cache: MISS\n");
			cert->crt = ssl_x509_forge(ctx->opts->cacrt,
			                           ctx->opts->cakey,
			                           ctx->sslctx->origcrt,
			                           ctx->opts->key,
			                           NULL,
			                           ctx->opts->crlurl);
			cachemgr_fkcrt_set(ctx->sslctx->origcrt, cert->crt);
		}
		cert_set_key(cert, ctx->opts->key);
		cert_set_chain(cert, ctx->opts->chain);
		ctx->sslctx->generated_cert = 1;
	}

	if ((WANT_CONNECT_LOG(ctx) || ctx->opts->certgendir) && ctx->sslctx->origcrt) {
		ctx->sslctx->origcrtfpr = ssl_x509_fingerprint(ctx->sslctx->origcrt, 0);
		if (!ctx->sslctx->origcrtfpr)
			ctx->enomem = 1;
	}
	if ((WANT_CONNECT_LOG(ctx) || ctx->opts->certgen_writeall) &&
	    cert && cert->crt) {
		ctx->sslctx->usedcrtfpr = ssl_x509_fingerprint(cert->crt, 0);
		if (!ctx->sslctx->usedcrtfpr)
			ctx->enomem = 1;
	}

	return cert;
}

/*
 * Create new SSL context for the incoming connection, based on the original
 * destination SSL certificate.
 * Returns NULL if no suitable certificate could be found.
 */
static SSL *
protossl_srcssl_create(pxy_conn_ctx_t *ctx, SSL *origssl)
{
	cert_t *cert;

	cachemgr_dsess_set((struct sockaddr*)&ctx->dstaddr,
	                   ctx->dstaddrlen, ctx->sslctx->sni,
	                   SSL_get0_session(origssl));

	ctx->sslctx->origcrt = SSL_get_peer_certificate(origssl);

	if (OPTS_DEBUG(ctx->opts)) {
		if (ctx->sslctx->origcrt) {
			log_dbg_printf("===> Original server certificate:\n");
			protossl_debug_crt(ctx->sslctx->origcrt);
		} else {
			log_dbg_printf("===> Original server has no cert!\n");
		}
	}

	cert = protossl_srccert_create(ctx);
	if (!cert)
		return NULL;

	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("===> Forged server certificate:\n");
		protossl_debug_crt(cert->crt);
	}

	if (WANT_CONNECT_LOG(ctx)) {
		ctx->sslctx->ssl_names = ssl_x509_names_to_str(ctx->sslctx->origcrt ?
		                                       ctx->sslctx->origcrt :
		                                       cert->crt);
		if (!ctx->sslctx->ssl_names)
			ctx->enomem = 1;
	}

	SSL_CTX *sslctx = protossl_srcsslctx_create(ctx, cert->crt, cert->chain,
	                                       cert->key);
	cert_free(cert);
	if (!sslctx) {
		ctx->enomem = 1;
		return NULL;
	}
	SSL *ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
	if (!ssl) {
		ctx->enomem = 1;
		return NULL;
	}
#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */
	return ssl;
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * OpenSSL servername callback, called when OpenSSL receives a servername
 * TLS extension in the clientHello.  Must switch to a new SSL_CTX with
 * a different certificate if we want to replace the server cert here.
 * We generate a new certificate if the current one does not match the
 * supplied servername.  This should only happen if the original destination
 * server supplies a certificate which does not match the server name we
 * indicate to it.
 */
static int
protossl_ossl_servername_cb(SSL *ssl, UNUSED int *al, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
	const char *sn;
	X509 *sslcrt;

	if (!(sn = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)))
		return SSL_TLSEXT_ERR_NOACK;

	if (!ctx->sslctx->sni) {
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Warning: SNI parser yielded no "
			               "hostname, copying OpenSSL one: "
			               "[NULL] != [%s]\n", sn);
		}
		ctx->sslctx->sni = strdup(sn);
		if (!ctx->sslctx->sni) {
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
	}
	if (OPTS_DEBUG(ctx->opts)) {
		if (!!strcmp(sn, ctx->sslctx->sni)) {
			/*
			 * This may happen if the client resumes a session, but
			 * uses a different SNI hostname when resuming than it
			 * used when the session was created.  OpenSSL
			 * correctly ignores the SNI in the ClientHello in this
			 * case, but since we have already sent the SNI onwards
			 * to the original destination, there is no way back.
			 * We log an error and hope this never happens.
			 */
			log_dbg_printf("Warning: SNI parser yielded different "
			               "hostname than OpenSSL callback for "
			               "the same ClientHello message: "
			               "[%s] != [%s]\n", ctx->sslctx->sni, sn);
		}
	}

	/* generate a new certificate with sn as additional altSubjectName
	 * and replace it both in the current SSL ctx and in the cert cache */
	if (ctx->opts->allow_wrong_host && !ctx->sslctx->immutable_cert &&
	    !ssl_x509_names_match((sslcrt = SSL_get_certificate(ssl)), sn)) {
		X509 *newcrt;
		SSL_CTX *newsslctx;

		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Certificate cache: UPDATE "
			               "(SNI mismatch)\n");
		}
		newcrt = ssl_x509_forge(ctx->opts->cacrt, ctx->opts->cakey,
		                        sslcrt, ctx->opts->key,
		                        sn, ctx->opts->crlurl);
		if (!newcrt) {
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
		cachemgr_fkcrt_set(ctx->sslctx->origcrt, newcrt);
		ctx->sslctx->generated_cert = 1;
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("===> Updated forged server "
			               "certificate:\n");
			protossl_debug_crt(newcrt);
		}
		if (WANT_CONNECT_LOG(ctx)) {
			if (ctx->sslctx->ssl_names) {
				free(ctx->sslctx->ssl_names);
			}
			ctx->sslctx->ssl_names = ssl_x509_names_to_str(newcrt);
			if (!ctx->sslctx->ssl_names) {
				ctx->enomem = 1;
			}
		}
		if (WANT_CONNECT_LOG(ctx) || ctx->opts->certgendir) {
			if (ctx->sslctx->usedcrtfpr) {
				free(ctx->sslctx->usedcrtfpr);
			}
			ctx->sslctx->usedcrtfpr = ssl_x509_fingerprint(newcrt, 0);
			if (!ctx->sslctx->usedcrtfpr) {
				ctx->enomem = 1;
			}
		}

		newsslctx = protossl_srcsslctx_create(ctx, newcrt, ctx->opts->chain,
		                                 ctx->opts->key);
		if (!newsslctx) {
			X509_free(newcrt);
			ctx->enomem = 1;
			return SSL_TLSEXT_ERR_NOACK;
		}
		SSL_set_SSL_CTX(ssl, newsslctx); /* decr's old incr new refc */
		SSL_CTX_free(newsslctx);
		X509_free(newcrt);
	} else if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("Certificate cache: KEEP (SNI match or "
		               "target mode)\n");
	}

	return SSL_TLSEXT_ERR_OK;
}
#endif /* !OPENSSL_NO_TLSEXT */

/*
 * Create new SSL context for outgoing connections to the original destination.
 * If hostname sni is provided, use it for Server Name Indication.
 */
SSL *
protossl_dstssl_create(pxy_conn_ctx_t *ctx)
{
	SSL_CTX *sslctx;
	SSL *ssl;
	SSL_SESSION *sess;

	sslctx = SSL_CTX_new(ctx->opts->sslmethod());
	if (!sslctx) {
		ctx->enomem = 1;
		return NULL;
	}

	protossl_sslctx_setoptions(sslctx, ctx);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	if (ctx->opts->sslversion) {
		if (SSL_CTX_set_min_proto_version(sslctx, ctx->opts->sslversion) == 0 ||
			SSL_CTX_set_max_proto_version(sslctx, ctx->opts->sslversion) == 0) {
			SSL_CTX_free(sslctx);
			ctx->enomem = 1;
			return NULL;
		}
	}
#endif /* OPENSSL_VERSION_NUMBER >= 0x10100000L */

	if (ctx->opts->verify_peer) {
		SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_set_default_verify_paths(sslctx);
	} else {
		SSL_CTX_set_verify(sslctx, SSL_VERIFY_NONE, NULL);
	}

	if (ctx->opts->clientcrt) {
		if (!SSL_CTX_use_certificate(sslctx, ctx->opts->clientcrt))
			log_dbg_printf("loading client certificate failed");
	}
	if (ctx->opts->clientkey) {
		if (!SSL_CTX_use_PrivateKey(sslctx, ctx->opts->clientkey))
			log_dbg_printf("loading client key failed");
	}

	ssl = SSL_new(sslctx);
	SSL_CTX_free(sslctx); /* SSL_new() increments refcount */
	if (!ssl) {
		ctx->enomem = 1;
		return NULL;
	}
#ifndef OPENSSL_NO_TLSEXT
	if (ctx->sslctx->sni) {
		SSL_set_tlsext_host_name(ssl, ctx->sslctx->sni);
	}
#endif /* !OPENSSL_NO_TLSEXT */

#ifdef SSL_MODE_RELEASE_BUFFERS
	/* lower memory footprint for idle connections */
	SSL_set_mode(ssl, SSL_get_mode(ssl) | SSL_MODE_RELEASE_BUFFERS);
#endif /* SSL_MODE_RELEASE_BUFFERS */

	/* session resuming based on remote endpoint address and port */
	sess = cachemgr_dsess_get((struct sockaddr *)&ctx->dstaddr,
	                          ctx->dstaddrlen, ctx->sslctx->sni); /* new sess inst */
	if (sess) {
		if (OPTS_DEBUG(ctx->opts)) {
			log_dbg_printf("Attempt reuse dst SSL session\n");
		}
		SSL_set_session(ssl, sess); /* increments sess refcount */
		SSL_SESSION_free(sess);
	}

	return ssl;
}

/*
 * Set up a bufferevent structure for either a dst or src connection,
 * optionally with or without SSL.  Sets all callbacks, enables read
 * and write events, but does not call bufferevent_socket_connect().
 *
 * For dst connections, pass -1 as fd.  Pass a pointer to an initialized
 * SSL struct as ssl if the connection should use SSL.
 *
 * Returns pointer to initialized bufferevent structure, as returned
 * by bufferevent_socket_new() or bufferevent_openssl_socket_new().
 */
static struct bufferevent * NONNULL(1,3)
protossl_bufferevent_setup(pxy_conn_ctx_t *ctx, evutil_socket_t fd, SSL *ssl)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_bufferevent_setup: ENTER, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	struct bufferevent *bev = bufferevent_openssl_socket_new(ctx->evbase, fd, ssl,
			((fd == -1) ? BUFFEREVENT_SSL_CONNECTING : BUFFEREVENT_SSL_ACCEPTING), BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
		return NULL;
	}
#if LIBEVENT_VERSION_NUMBER >= 0x02010000
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_bufferevent_setup: bufferevent_openssl_set_allow_dirty_shutdown\n");
#endif /* DEBUG_PROXY */

	/* Prevent unclean (dirty) shutdowns to cause error
	 * events on the SSL socket bufferevent. */
	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	// @attention Do not set callbacks here, srvdst does not set r cb
	//bufferevent_setcb(bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	// @todo Should we enable events here?
	//bufferevent_enable(bev, EV_READ|EV_WRITE);
	return bev;
}

static struct bufferevent * NONNULL(1,3)
protossl_bufferevent_setup_child(pxy_conn_child_ctx_t *ctx, evutil_socket_t fd, SSL *ssl)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_bufferevent_setup_child: ENTER, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	struct bufferevent *bev = bufferevent_openssl_socket_new(ctx->conn->evbase, fd, ssl,
			((fd == -1) ? BUFFEREVENT_SSL_CONNECTING : BUFFEREVENT_SSL_ACCEPTING), BEV_OPT_DEFER_CALLBACKS);
	if (!bev) {
		log_err_level_printf(LOG_CRIT, "Error creating bufferevent socket\n");
		return NULL;
	}

#if LIBEVENT_VERSION_NUMBER >= 0x02010000
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_bufferevent_setup_child: bufferevent_openssl_set_allow_dirty_shutdown\n");
#endif /* DEBUG_PROXY */

	/* Prevent unclean (dirty) shutdowns to cause error
	 * events on the SSL socket bufferevent. */
	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
#endif /* LIBEVENT_VERSION_NUMBER >= 0x02010000 */

	bufferevent_setcb(bev, pxy_bev_readcb_child, pxy_bev_writecb_child, pxy_bev_eventcb_child, ctx);

	// @attention We cannot enable events here, because src events will be deferred until after dst is connected
	//bufferevent_enable(bev, EV_READ|EV_WRITE);
	return bev;
}

/*
 * Free bufferenvent and close underlying socket properly.
 * For OpenSSL bufferevents, this will shutdown the SSL connection.
 */
static void
protossl_bufferevent_free_and_close_fd(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
	evutil_socket_t fd = bufferevent_getfd(bev);

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protossl_bufferevent_free_and_close_fd: in=%zu, out=%zu, fd=%d\n",
			evbuffer_get_length(bufferevent_get_input(bev)), evbuffer_get_length(bufferevent_get_output(bev)), fd);
#endif /* DEBUG_PROXY */

	SSL *ssl = bufferevent_openssl_get_ssl(bev); /* does not inc refc */

	// @todo Do we need to NULL all cbs?
	// @see https://stackoverflow.com/questions/31688709/knowing-all-callbacks-have-run-with-libevent-and-bufferevent-free
	//bufferevent_setcb(bev, NULL, NULL, NULL, NULL);
	bufferevent_free(bev); /* does not free SSL unless the option BEV_OPT_CLOSE_ON_FREE was set */
	pxy_ssl_shutdown(ctx->opts, ctx->evbase, ssl, fd);
}

void
protossl_free(pxy_conn_ctx_t *ctx)
{
	if (ctx->sslctx->ssl_names) {
		free(ctx->sslctx->ssl_names);
	}
	if (ctx->sslctx->origcrtfpr) {
		free(ctx->sslctx->origcrtfpr);
	}
	if (ctx->sslctx->usedcrtfpr) {
		free(ctx->sslctx->usedcrtfpr);
	}
	if (ctx->sslctx->origcrt) {
		X509_free(ctx->sslctx->origcrt);
	}
	if (ctx->sslctx->sni) {
		free(ctx->sslctx->sni);
	}
	if (ctx->sslctx->srvdst_ssl_version) {
		free(ctx->sslctx->srvdst_ssl_version);
	}
	if (ctx->sslctx->srvdst_ssl_cipher) {
		free(ctx->sslctx->srvdst_ssl_cipher);
	}
	free(ctx->sslctx);
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * The SNI hostname has been resolved.  Fill the first resolved address into
 * the context and continue connecting.
 */
static void
protossl_sni_resolve_cb(int errcode, struct evutil_addrinfo *ai, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_sni_resolve_cb: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (errcode) {
		log_err_printf("Cannot resolve SNI hostname '%s': %s\n", ctx->sslctx->sni, evutil_gai_strerror(errcode));
		evutil_closesocket(ctx->fd);
		pxy_conn_ctx_free(ctx, 1);
		return;
	}

	memcpy(&ctx->dstaddr, ai->ai_addr, ai->ai_addrlen);
	ctx->dstaddrlen = ai->ai_addrlen;
	evutil_freeaddrinfo(ai);
	pxy_conn_connect(ctx);
}
#endif /* !OPENSSL_NO_TLSEXT */

#ifndef OPENSSL_NO_TLSEXT
#define MAYBE_UNUSED 
#else /* OPENSSL_NO_TLSEXT */
#define MAYBE_UNUSED UNUSED
#endif /* OPENSSL_NO_TLSEXT */
void
protossl_fd_readcb(MAYBE_UNUSED evutil_socket_t fd, UNUSED short what, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_fd_readcb: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

#ifndef OPENSSL_NO_TLSEXT
	// ctx->ev is NULL during initial conn setup
	if (!ctx->ev) {
		/* for SSL, defer dst connection setup to initial_readcb */
		ctx->ev = event_new(ctx->evbase, ctx->fd, EV_READ, ctx->protoctx->fd_readcb, ctx);
		if (!ctx->ev)
			goto out;
		if (event_add(ctx->ev, NULL) == -1)
			goto out;
		return;
	}

	// Child connections will use the sni info obtained by the parent conn
	/* for SSL, peek ClientHello and parse SNI from it */

	unsigned char buf[1024];
	ssize_t n;
	const unsigned char *chello;
	int rv;

	n = recv(fd, buf, sizeof(buf), MSG_PEEK);
	if (n == -1) {
		log_err_printf("Error peeking on fd, aborting connection\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "ERROR: Error peeking on fd, aborting connection, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		goto out;
	}
	if (n == 0) {
		/* socket got closed while we were waiting */
		log_err_printf("Socket got closed while waiting\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "ERROR: Socket got closed while waiting, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		goto out;
	}

	rv = ssl_tls_clienthello_parse(buf, n, 0, &chello, &ctx->sslctx->sni);
	if ((rv == 1) && !chello) {
		log_err_printf("Peeking did not yield a (truncated) ClientHello message, aborting connection\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "ERROR: Peeking did not yield a (truncated) ClientHello message, aborting connection, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
		goto out;
	}
	if (OPTS_DEBUG(ctx->opts)) {
		log_dbg_printf("SNI peek: [%s] [%s], fd=%d\n", ctx->sslctx->sni ? ctx->sslctx->sni : "n/a",
					   ((rv == 1) && chello) ? "incomplete" : "complete", ctx->fd);
	}
	if ((rv == 1) && chello && (ctx->sslctx->sni_peek_retries++ < 50)) {
		/* ssl_tls_clienthello_parse indicates that we
		 * should retry later when we have more data, and we
		 * haven't reached the maximum retry count yet.
		 * Reschedule this event as timeout-only event in
		 * order to prevent busy looping over the read event.
		 * Because we only peeked at the pending bytes and
		 * never actually read them, fd is still ready for
		 * reading now.  We use 25 * 0.2 s = 5 s timeout. */
		struct timeval retry_delay = {0, 100};

		event_free(ctx->ev);
		ctx->ev = event_new(ctx->evbase, fd, 0, ctx->protoctx->fd_readcb, ctx);
		if (!ctx->ev) {
			log_err_level_printf(LOG_CRIT, "Error creating retry event, aborting connection\n");
#ifdef DEBUG_PROXY
			log_dbg_level_printf(LOG_DBG_MODE_FINE, "ERROR: Error creating retry event, aborting connection, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */
			goto out;
		}
		if (event_add(ctx->ev, &retry_delay) == -1)
			goto out;
		return;
	}
	event_free(ctx->ev);
	ctx->ev = NULL;

	if (ctx->sslctx->sni && !ctx->dstaddrlen && ctx->spec->sni_port) {
		char sniport[6];
		struct evutil_addrinfo hints;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = ctx->af;
		hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;

		snprintf(sniport, sizeof(sniport), "%i", ctx->spec->sni_port);
		evdns_getaddrinfo(ctx->dnsbase, ctx->sslctx->sni, sniport, &hints, protossl_sni_resolve_cb, ctx);
		return;
	}
#endif /* !OPENSSL_NO_TLSEXT */

	pxy_conn_connect(ctx);
	return;
out:
	evutil_closesocket(fd);
	pxy_conn_ctx_free(ctx, 1);
}

int
protossl_setup_srvdst_ssl(pxy_conn_ctx_t *ctx)
{
	ctx->srvdst.ssl = protossl_dstssl_create(ctx);
	if (!ctx->srvdst.ssl) {
		log_err_level_printf(LOG_CRIT, "Error creating SSL for srvdst\n");
		pxy_conn_term(ctx, 1);
		return -1;
	}
	return 0;
}

static int NONNULL(1)
protossl_setup_srvdst(pxy_conn_ctx_t *ctx)
{
	if (protossl_setup_srvdst_ssl(ctx) == -1) {
		return -1;
	}

	ctx->srvdst.bev = protossl_bufferevent_setup(ctx, -1, ctx->srvdst.ssl);
	if (!ctx->srvdst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating srvdst\n");
		SSL_free(ctx->srvdst.ssl);
		ctx->srvdst.ssl = NULL;
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->srvdst.free = protossl_bufferevent_free_and_close_fd;
	return 0;
}

int
protossl_setup_srvdst_new_bev_ssl_connecting(pxy_conn_ctx_t *ctx)
{
	ctx->srvdst.bev = bufferevent_openssl_filter_new(ctx->evbase, ctx->srvdst.bev, ctx->srvdst.ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->srvdst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating srvdst bufferevent\n");
		SSL_free(ctx->srvdst.ssl);
		ctx->srvdst.ssl = NULL;
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->srvdst.free = protossl_bufferevent_free_and_close_fd;
	return 0;
}

int
protossl_conn_connect(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	// Make a copy of fd, to prevent multithreading issues in case the conn is terminated
	int fd = ctx->fd;
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_conn_connect: ENTER, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

	/* create server-side socket and eventbuffer */
	if (protossl_setup_srvdst(ctx) == -1) {
		return -1;
	}

	// Conn setup is successful, so add the conn to the conn list of its thread now
	pxy_thrmgr_add_conn(ctx);

	// @attention Sometimes dst write cb fires but not event cb, especially if this listener cb is not finished yet, so the conn stalls.
	// @todo Why does event cb not fire sometimes?
	// @attention BEV_OPT_DEFER_CALLBACKS seems responsible for the issue with srvdst, libevent acts as if we call event connect() ourselves.
	// @see Launching connections on socket-based bufferevents at http://www.wangafu.net/~nickm/libevent-book/Ref6_bufferevent.html
	// Disable and NULL r cb, we do nothing for srvdst in r cb
	bufferevent_setcb(ctx->srvdst.bev, NULL, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	
	/* initiate connection */
	if (bufferevent_socket_connect(ctx->srvdst.bev, (struct sockaddr *)&ctx->dstaddr, ctx->dstaddrlen) == -1) {
		log_err_level_printf(LOG_CRIT, "protossl_conn_connect: bufferevent_socket_connect for srvdst failed\n");
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "protossl_conn_connect: bufferevent_socket_connect for srvdst failed, fd=%d\n", fd);
#endif /* DEBUG_PROXY */

		// @attention Do not try to term/close conns or do anything else with conn ctx on the thrmgr thread after setting event callbacks and/or socket connect. Just return 0.
	}
	return 0;
}

int
protossl_setup_dst_ssl_child(pxy_conn_child_ctx_t *ctx)
{
	// Children rely on the findings of parent
	ctx->dst.ssl = protossl_dstssl_create(ctx->conn);
	if (!ctx->dst.ssl) {
		log_err_level_printf(LOG_CRIT, "Error creating SSL\n");
		// pxy_conn_free()>pxy_conn_free_child() will close the fd, since we have a non-NULL src.bev now
		pxy_conn_term(ctx->conn, 1);
		return -1;
	}
	return 0;
}

int
protossl_setup_dst_child(pxy_conn_child_ctx_t *ctx)
{
	if (protossl_setup_dst_ssl_child(ctx) == -1) {
		return -1;
	}

	ctx->dst.bev = protossl_bufferevent_setup_child(ctx, -1, ctx->dst.ssl);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating dst bufferevent\n");
		SSL_free(ctx->dst.ssl);
		ctx->dst.ssl = NULL;
		pxy_conn_term(ctx->conn, 1);
		return -1;
	}
	ctx->dst.free = protossl_bufferevent_free_and_close_fd;
	return 0;
}

void
protossl_connect_child(pxy_conn_child_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_connect_child: ENTER, child fd=%d, fd=%d\n", ctx->fd, ctx->conn->fd);
#endif /* DEBUG_PROXY */

	/* create server-side socket and eventbuffer */
	protossl_setup_dst_child(ctx);
}

int
protossl_setup_src_ssl(pxy_conn_ctx_t *ctx)
{
	// @todo Make srvdst.ssl the origssl param
	ctx->src.ssl = protossl_srcssl_create(ctx, ctx->srvdst.ssl);
	if (!ctx->src.ssl) {
		if (ctx->opts->passthrough && !ctx->enomem) {
			log_err_level_printf(LOG_WARNING, "No cert found; falling back to passthrough\n");
			protopassthrough_engage(ctx);
			// report protocol change by returning 1
			return 1;
		}
		pxy_conn_term(ctx, 1);
		return -1;
	}
	return 0;
}

static int NONNULL(1)
protossl_setup_src(pxy_conn_ctx_t *ctx)
{
	int rv;
	if ((rv = protossl_setup_src_ssl(ctx)) != 0) {
		return rv;
	}
		
	ctx->src.bev = protossl_bufferevent_setup(ctx, ctx->fd, ctx->src.ssl);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating src bufferevent\n");
		SSL_free(ctx->src.ssl);
		ctx->src.ssl = NULL;
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->src.free = protossl_bufferevent_free_and_close_fd;
	return 0;
}

int
protossl_setup_src_new_bev_ssl_accepting(pxy_conn_ctx_t *ctx)
{
	ctx->src.bev = bufferevent_openssl_filter_new(ctx->evbase, ctx->src.bev, ctx->src.ssl,
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->src.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating src bufferevent\n");
		SSL_free(ctx->src.ssl);
		ctx->src.ssl = NULL;
		pxy_conn_term(ctx, 1);
		return -1;
	}
	ctx->src.free = protossl_bufferevent_free_and_close_fd;
	return 0;
}

int
protossl_setup_dst_new_bev_ssl_connecting_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->dst.bev = bufferevent_openssl_filter_new(ctx->conn->evbase, ctx->dst.bev, ctx->dst.ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
	if (!ctx->dst.bev) {
		log_err_level_printf(LOG_CRIT, "Error creating dst bufferevent\n");
		SSL_free(ctx->dst.ssl);
		ctx->dst.ssl = NULL;
		pxy_conn_term(ctx->conn, 1);
		return -1;
	}
	ctx->dst.free = protossl_bufferevent_free_and_close_fd;
	return 0;
}

static void NONNULL(1)
protossl_close_srvdst(pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protossl_close_srvdst: Closing srvdst, fd=%d, srvdst fd=%d\n", ctx->fd, bufferevent_getfd(ctx->srvdst.bev));
#endif /* DEBUG_PROXY */

	// @attention Free the srvdst of the conn asap, we don't need it anymore, but we need its fd
	// So save its ssl info for logging
	ctx->sslctx->srvdst_ssl_version = strdup(SSL_get_version(ctx->srvdst.ssl));
	ctx->sslctx->srvdst_ssl_cipher = strdup(SSL_get_cipher(ctx->srvdst.ssl));

	// @attention When both eventcb and writecb for srvdst are enabled, either eventcb or writecb may get a NULL srvdst bev, causing a crash with signal 10.
	// So, from this point on, we should check if srvdst is NULL or not.
	ctx->srvdst.free(ctx->srvdst.bev, ctx);
	ctx->srvdst.bev = NULL;
	ctx->srvdst.closed = 1;
}

static int NONNULL(1)
protossl_enable_src(pxy_conn_ctx_t *ctx)
{
	int rv;
	if ((rv = protossl_setup_src(ctx)) != 0) {
		// Might have switched to passthrough mode
		return rv;
	}
	bufferevent_setcb(ctx->src.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);

	protossl_close_srvdst(ctx);

	if (pxy_setup_child_listener(ctx) == -1) {
		return -1;
	}

#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINER, "protossl_enable_src: Enabling src, %s, fd=%d, child_fd=%d\n", ctx->sslproxy_header, ctx->fd, ctx->child_fd);
#endif /* DEBUG_PROXY */

	// Now open the gates
	bufferevent_enable(ctx->src.bev, EV_READ|EV_WRITE);
	return 0;
}

static void NONNULL(1,2)
protossl_bev_eventcb_connected_dst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_bev_eventcb_connected_dst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->dst_connected = 1;

	if (ctx->srvdst_connected && ctx->dst_connected && !ctx->connected) {
		ctx->connected = 1;

		if (protossl_enable_src(ctx) == -1) {
			return;
		}
	}
}

static void NONNULL(1,2)
protossl_bev_eventcb_connected_srvdst(UNUSED struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINEST, "protossl_bev_eventcb_connected_srvdst: ENTER, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	ctx->srvdst_connected = 1;
	bufferevent_enable(ctx->srvdst.bev, EV_WRITE);
	
	if (prototcp_setup_dst(ctx) == -1) {
		return;
	}
	bufferevent_setcb(ctx->dst.bev, pxy_bev_readcb, pxy_bev_writecb, pxy_bev_eventcb, ctx);
	bufferevent_enable(ctx->dst.bev, EV_READ|EV_WRITE);
	if (bufferevent_socket_connect(ctx->dst.bev, (struct sockaddr *)&ctx->spec->conn_dst_addr, ctx->spec->conn_dst_addrlen) == -1) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "protossl_bev_eventcb_connected_srvdst: FAILED bufferevent_socket_connect for dst, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		pxy_conn_term(ctx, 1);
		return;
	}

	if (ctx->srvdst_connected && ctx->dst_connected && !ctx->connected) {
		ctx->connected = 1;

		if (protossl_enable_src(ctx) == -1) {
			return;
		}
	}

	if (!ctx->term && !ctx->enomem) {
		pxy_userauth(ctx);
	}
}

static void NONNULL(1,2)
protossl_bev_eventcb_error_srvdst(struct bufferevent *bev, pxy_conn_ctx_t *ctx)
{
#ifdef DEBUG_PROXY
	log_dbg_level_printf(LOG_DBG_MODE_FINE, "protossl_bev_eventcb_error_srvdst: BEV_EVENT_ERROR, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

	if (!ctx->connected) {
#ifdef DEBUG_PROXY
		log_dbg_level_printf(LOG_DBG_MODE_FINE, "protossl_bev_eventcb_error_srvdst: ERROR !ctx->connected, fd=%d\n", ctx->fd);
#endif /* DEBUG_PROXY */

		/* the callout to the original destination failed,
		 * e.g. because it asked for client cert auth, so
		 * close the accepted socket and clean up */
		if (ctx->opts->passthrough && bufferevent_get_openssl_error(bev)) {
			/* ssl callout failed, fall back to plain TCP passthrough of SSL connection */
			log_err_level_printf(LOG_WARNING, "SSL srvdst connection failed; falling back to passthrough\n");
			protopassthrough_engage(ctx);
			return;
		}
		pxy_conn_term(ctx, 0);
	}
}

static void NONNULL(1)
protossl_bev_eventcb_dst(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protossl_bev_eventcb_connected_dst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_dst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		prototcp_bev_eventcb_error_dst(bev, ctx);
	}
}

static void NONNULL(1)
protossl_bev_eventcb_srvdst(struct bufferevent *bev, short events, pxy_conn_ctx_t *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		protossl_bev_eventcb_connected_srvdst(bev, ctx);
	} else if (events & BEV_EVENT_EOF) {
		prototcp_bev_eventcb_eof_srvdst(bev, ctx);
	} else if (events & BEV_EVENT_ERROR) {
		protossl_bev_eventcb_error_srvdst(bev, ctx);
	}
}

void
protossl_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_ctx_t *ctx = arg;

	if (events & BEV_EVENT_ERROR) {
		protossl_log_ssl_error(bev, ctx);
	}

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src(bev, events, ctx);
	} else if (bev == ctx->dst.bev) {
		protossl_bev_eventcb_dst(bev, events, ctx);
	} else if (bev == ctx->srvdst.bev) {
		protossl_bev_eventcb_srvdst(bev, events, ctx);
	} else {
		log_err_printf("protossl_bev_eventcb: UNKWN conn end\n");
	}
}

void
protossl_bev_eventcb_child(struct bufferevent *bev, short events, void *arg)
{
	pxy_conn_child_ctx_t *ctx = arg;

	if (events & BEV_EVENT_ERROR) {
		protossl_log_ssl_error(bev, ctx->conn);
	}

	if (bev == ctx->src.bev) {
		prototcp_bev_eventcb_src_child(bev, events, ctx);
	} else if (bev == ctx->dst.bev) {
		prototcp_bev_eventcb_dst_child(bev, events, ctx);
	} else {
		log_err_printf("protossl_bev_eventcb_child: UNKWN conn end\n");
	}
}

protocol_t
protossl_setup(pxy_conn_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_SSL;
	ctx->protoctx->connectcb = protossl_conn_connect;
	ctx->protoctx->fd_readcb = protossl_fd_readcb;
	
	ctx->protoctx->bev_eventcb = protossl_bev_eventcb;

	ctx->protoctx->proto_free = protossl_free;

	ctx->sslctx = malloc(sizeof(ssl_ctx_t));
	if (!ctx->sslctx) {
		return PROTO_ERROR;
	}
	memset(ctx->sslctx, 0, sizeof(ssl_ctx_t));

	return PROTO_SSL;
}

protocol_t
protossl_setup_child(pxy_conn_child_ctx_t *ctx)
{
	ctx->protoctx->proto = PROTO_SSL;
	ctx->protoctx->connectcb = protossl_connect_child;

	ctx->protoctx->bev_eventcb = protossl_bev_eventcb_child;

	return PROTO_SSL;
}

/* vim: set noet ft=c: */
