/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "curl_setup.h"

#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGTCP2) && defined(USE_NGHTTP3)

#include <ngtcp2/ngtcp2.h>

#ifdef USE_OPENSSL
#include <openssl/err.h>
#if defined(OPENSSL_IS_AWSLC) || defined(OPENSSL_IS_BORINGSSL)
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#elif defined(OPENSSL_QUIC_API2)
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#else
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#endif
#include "vtls/openssl.h"
#elif defined(USE_GNUTLS)
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include "vtls/gtls.h"
#elif defined(USE_WOLFSSL)
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#include "vtls/wolfssl.h"
#endif

#include <nghttp3/nghttp3.h>

#include "urldata.h"
#include "url.h"
#include "uint-hash.h"
#include "curl_trc.h"
#include "rand.h"
#include "multiif.h"
#include "cfilters.h"
#include "cf-dns.h"
#include "cf-socket.h"
#include "connect.h"
#include "progress.h"
#include "curlx/fopen.h"
#include "curlx/dynbuf.h"
#include "http1.h"
#include "select.h"
#include "sockaddr.h"
#include "strcase.h"
#include "transfer.h"
#include "bufref.h"
#include "vquic/vquic.h"
#include "vquic/vquic_int.h"
#include "vquic/vquic-tls.h"
#include "vtls/vtls.h"
#include "vtls/vtls_scache.h"
#include "vquic/cf-ngtcp2-cmn.h"

/*
 * Store ngtcp2 version info in this buffer.
 */
void Curl_ngtcp2_ver(char *p, size_t len)
{
  const ngtcp2_info *ng2 = ngtcp2_version(0);
  const nghttp3_info *ht3 = nghttp3_version(0);
  (void)curl_msnprintf(p, len, "ngtcp2/%s nghttp3/%s",
                       ng2->version_str, ht3->version_str);
}

void Curl_cf_ngtcp2_h3_stream_ctx_free(struct h3_stream_ctx *stream)
{
  Curl_bufq_free(&stream->sendbuf);
  Curl_h1_req_parse_free(&stream->h1);
  curlx_free(stream);
}

static void h3_stream_hash_free(unsigned int id, void *stream)
{
  (void)id;
  DEBUGASSERT(stream);
  Curl_cf_ngtcp2_h3_stream_ctx_free((struct h3_stream_ctx *)stream);
}

static bool cf_ngtcp2_h3_err_is_fatal(int code)
{
  return (NGHTTP3_ERR_FATAL >= code) ||
         (NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM == code);
}

void Curl_cf_ngtcp2_h3_err_set(struct Curl_cfilter *cf,
                               struct Curl_easy *data, int code)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  if(!ctx->last_error.error_code) {
    ngtcp2_ccerr_set_application_error(&ctx->last_error,
      nghttp3_err_infer_quic_app_error_code(code), NULL, 0);
  }
  if(cf_ngtcp2_h3_err_is_fatal(code))
    Curl_cf_ngtcp2_cmn_conn_close(cf, data);
}

CURLcode Curl_cf_ngtcp2_ctx_init(struct cf_ngtcp2_ctx *ctx,
                                 struct Curl_peer *origin,
                                 struct Curl_peer *peer,
                                 struct ssl_primary_config *sslc,
                                 struct connectdata *conn,
                                 cf_ngtcp2_init_h3_conn *init_h3_conn_cb)
{
  DEBUGASSERT(!ctx->initialized);
  ctx->qlogfd = -1;
  ctx->tunnel_inbuf = NULL;
  ctx->tunnel_inbuf_len = 0;
  ctx->version = NGTCP2_PROTO_VER_MAX;
  Curl_bufcp_init(&ctx->stream_bufcp, H3_STREAM_CHUNK_SIZE,
                  H3_STREAM_POOL_SPARES);
  curlx_dyn_init(&ctx->scratch, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&ctx->tp_raw, CURL_MAX_INPUT_LENGTH);
  Curl_uint32_hash_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->init_h3_conn_cb = init_h3_conn_cb;
  ctx->initialized = TRUE;
  return Curl_vquic_tls_peer_init(origin, peer, sslc, &ctx->ssl_peer, conn);
}

void Curl_cf_ngtcp2_ctx_cleanup(struct cf_ngtcp2_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_vquic_tls_cleanup(&ctx->tls);
    vquic_ctx_free(&ctx->q);
    Curl_bufcp_free(&ctx->stream_bufcp);
    curlx_dyn_free(&ctx->scratch);
    curlx_dyn_free(&ctx->tp_raw);
    Curl_uint32_hash_destroy(&ctx->streams);
    Curl_ssl_peer_cleanup(&ctx->ssl_peer);
    curlx_safefree(ctx->tunnel_inbuf);
    ctx->tunnel_inbuf_len = 0;
    if(ctx->qlogfd != -1) {
      curlx_close(ctx->qlogfd);
      ctx->qlogfd = -1;
    }
  }
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  struct Curl_cfilter *cf = conn_ref->user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  return ctx->qconn;
}

#ifdef DEBUG_NGTCP2
static void quic_printf(void *user_data, const char *fmt, ...)
{
  va_list ap;
  (void)user_data;
  va_start(ap, fmt);
  curl_mvfprintf(stderr, fmt, ap);
  va_end(ap);
  curl_mfprintf(stderr, "\n");
}
#endif

static void qlog_callback(void *user_data, uint32_t flags,
                          const void *data, size_t datalen)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  (void)flags;
  if(ctx->qlogfd != -1) {
    ssize_t rc = write(ctx->qlogfd, data, datalen);
    if(rc == -1) {
      /* on write error, stop further write attempts */
      curlx_close(ctx->qlogfd);
      ctx->qlogfd = -1;
    }
  }
}

/* Walk the filter chain to find the active socket for QUIC logging. */
static CURLcode cf_ngtcp2_peek_socket(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      curl_socket_t *psock,
                                      const struct Curl_sockaddr_ex **paddr,
                                      struct ip_quadruple *pip)
{
  bool got_sock = FALSE;
  bool got_addr = FALSE;
  bool got_ip = FALSE;
  int dummy = 0;

  for(; cf; cf = cf->next) {
    if(!got_sock && (psock || pip) &&
       !Curl_cf_socket_peek(cf, data, psock, NULL, pip)) {
      got_sock = (psock != NULL);
      got_ip = (pip != NULL);
    }
    if(paddr && !got_addr) {
      const struct Curl_sockaddr_ex *addr = NULL;
      if(!cf->cft->query(cf, data, CF_QUERY_REMOTE_ADDR, &dummy, &addr) &&
         addr) {
        *paddr = addr;
        got_addr = TRUE;
      }
    }
    if((!psock || got_sock) && (!paddr || got_addr) && (!pip || got_ip))
      return CURLE_OK;
  }
  return CURLE_FAILED_INIT;
}

static bool quic_has_empty_initial_scid(const char *params)
{
  const char *p = params;

  if(!p || !*p)
    return FALSE;

  while(*p) {
    const char *end;
    size_t len;

    while(*p == ';')
      ++p;
    if(!*p)
      break;

    end = strchr(p, ';');
    len = end ? (size_t)(end - p) : strlen(p);
    if((len == 3) && (p[0] == '1') && (p[1] == '5') && (p[2] == ':'))
      return TRUE;

    p = end ? (end + 1) : (p + len);
  }

  return FALSE;
}

/* https://www.iana.org/assignments/quic/quic.xhtml */
static CURLcode quic_apply_transport_param(ngtcp2_transport_params *t,
                                           uint64_t id,
                                           uint64_t value,
                                           bool has_value,
                                           struct Curl_easy *data)
{
  switch(id) {
  case 0x00: /* original_destination_connection_id (server only) */
  case 0x02: /* stateless_reset_token (server only) */
  case 0x0d: /* preferred_address (server only) */
  case 0x10: /* retry_source_connection_id (server only) */
  case 0x11: /* version_information (server only) */
    failf(data, "QUIC transport param %" PRIu64 " is server-only",
          (uint64_t)id);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case 0x0f: /* initial_source_connection_id (set by library) */
    failf(data, "QUIC transport param %" PRIu64
          " is managed by the library", (uint64_t)id);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case 0x01: /* max_idle_timeout (milliseconds) */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->max_idle_timeout = (ngtcp2_duration)value * NGTCP2_MILLISECONDS;
    break;
  case 0x03: /* max_udp_payload_size */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->max_udp_payload_size = value;
    break;
  case 0x04: /* initial_max_data */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->initial_max_data = value;
    break;
  case 0x05: /* initial_max_stream_data_bidi_local */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->initial_max_stream_data_bidi_local = value;
    break;
  case 0x06: /* initial_max_stream_data_bidi_remote */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->initial_max_stream_data_bidi_remote = value;
    break;
  case 0x07: /* initial_max_stream_data_uni */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->initial_max_stream_data_uni = value;
    break;
  case 0x08: /* initial_max_streams_bidi */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->initial_max_streams_bidi = value;
    break;
  case 0x09: /* initial_max_streams_uni */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->initial_max_streams_uni = value;
    break;
  case 0x0a: /* ack_delay_exponent */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->ack_delay_exponent = value;
    break;
  case 0x0b: /* max_ack_delay (milliseconds) */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->max_ack_delay = (ngtcp2_duration)value * NGTCP2_MILLISECONDS;
    break;
  case 0x0c: /* disable_active_migration */
    t->disable_active_migration = (uint8_t)(!has_value || value);
    break;
  case 0x0e: /* active_connection_id_limit */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->active_connection_id_limit = value;
    break;
  case 0x20: /* max_datagram_frame_size */
    if(!has_value)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    t->max_datagram_frame_size = value;
    break;
  case 0x2ab2: /* grease_quic_bit */
    t->grease_quic_bit = (uint8_t)(!has_value || value);
    break;
  default:
    infof(data, "QUIC transport param %" PRIu64
          " is not mapped to ngtcp2_transport_params",
          (uint64_t)id);
    break;
  }

  return CURLE_OK;
}

#define QUIC_VARINT_MAX UINT64_C(0x3fffffffffffffff)
#define QUIC_TP_INITIAL_SOURCE_CONNECTION_ID UINT64_C(0x0f)
#define QUIC_TP_VERSION_INFORMATION          UINT64_C(0x11)
#define QUIC_TP_INITIAL_RTT                  UINT64_C(0x3127)
#define QUIC_TP_GOOGLE_VERSION               UINT64_C(0x4752)
#define QUIC_TP_GREASE_ID_BASE              UINT64_C(27)
#define QUIC_TP_GREASE_ID_STEP              UINT64_C(31)
#define QUIC_TP_GREASE_VALUE_MAXLEN         8
#define QUIC_INITIAL_RTT_US_BASE             UINT64_C(333000)
#define QUIC_INITIAL_RTT_US_JITTER           UINT64_C(50000)

static uint64_t quic_initial_rtt_auto_us(struct Curl_easy *data)
{
  /* Use RFC9002 default initial RTT with moderate jitter for
   * fingerprinting. */
  uint64_t value = QUIC_INITIAL_RTT_US_BASE;
  unsigned char rnd[2];
  uint64_t span;
  uint64_t off;

  if(Curl_rand(data, rnd, sizeof(rnd)))
    return value;

  span = (QUIC_INITIAL_RTT_US_JITTER * 2) + 1;
  off = ((((uint64_t)rnd[0]) << 8) | rnd[1]) % span;
  value = (QUIC_INITIAL_RTT_US_BASE - QUIC_INITIAL_RTT_US_JITTER) + off;
  return value;
}

static uint32_t quic_version_grease(struct Curl_easy *data)
{
  unsigned char rnd[4];
  uint32_t v = 0x0a0a0a0aU;

  if(Curl_rand(data, rnd, sizeof(rnd)))
    return v;

  v = (uint32_t)(((rnd[0] & 0xf0U) | 0x0aU) << 24);
  v |= (uint32_t)(((rnd[1] & 0xf0U) | 0x0aU) << 16);
  v |= (uint32_t)(((rnd[2] & 0xf0U) | 0x0aU) << 8);
  v |= (uint32_t)((rnd[3] & 0xf0U) | 0x0aU);
  return v;
}

static CURLcode quic_rand_u64(struct Curl_easy *data, uint64_t *val)
{
  unsigned char rnd[sizeof(uint64_t)];
  CURLcode result;
  size_t i;

  result = Curl_rand(data, rnd, sizeof(rnd));
  if(result)
    return result;

  *val = 0;
  for(i = 0; i < sizeof(rnd); ++i)
    *val = (*val << 8) | rnd[i];

  return CURLE_OK;
}

static CURLcode quic_generate_grease_tp(struct Curl_easy *data,
                                        uint64_t *pid,
                                        unsigned char *value,
                                        size_t *vlen)
{
  uint64_t n;
  uint64_t max_n = (QUIC_VARINT_MAX - QUIC_TP_GREASE_ID_BASE) /
                   QUIC_TP_GREASE_ID_STEP;
  unsigned char lenrnd;
  CURLcode result;

  result = quic_rand_u64(data, &n);
  if(result)
    return result;

  *pid = (QUIC_TP_GREASE_ID_STEP * (n % (max_n + 1))) +
         QUIC_TP_GREASE_ID_BASE;

  result = Curl_rand(data, &lenrnd, sizeof(lenrnd));
  if(result)
    return result;

  *vlen = (size_t)(lenrnd % QUIC_TP_GREASE_VALUE_MAXLEN) + 1;
  return Curl_rand(data, value, *vlen);
}

static CURLcode quic_permute_token_order(char **tokens, size_t ntokens,
                                         struct Curl_easy *data)
{
  size_t i;

  DEBUGASSERT(ntokens > 1);
  for(i = ntokens - 1; i > 0; --i) {
    uint64_t r;
    size_t j;
    char *tmp;
    CURLcode result = quic_rand_u64(data, &r);
    if(result)
      return result;
    j = (size_t)(r % (i + 1));
    if(i == j)
      continue;
    tmp = tokens[i];
    tokens[i] = tokens[j];
    tokens[j] = tmp;
  }

  return CURLE_OK;
}

static size_t quic_varint_encode(uint8_t *buf, uint64_t value)
{
  if(value <= UINT64_C(0x3f)) {
    buf[0] = (uint8_t)value;
    return 1;
  }
  if(value <= UINT64_C(0x3fff)) {
    buf[0] = (uint8_t)(0x40 | (value >> 8));
    buf[1] = (uint8_t)value;
    return 2;
  }
  if(value <= UINT64_C(0x3fffffff)) {
    buf[0] = (uint8_t)(0x80 | (value >> 24));
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)value;
    return 4;
  }
  if(value <= QUIC_VARINT_MAX) {
    buf[0] = (uint8_t)(0xc0 | (value >> 56));
    buf[1] = (uint8_t)(value >> 48);
    buf[2] = (uint8_t)(value >> 40);
    buf[3] = (uint8_t)(value >> 32);
    buf[4] = (uint8_t)(value >> 24);
    buf[5] = (uint8_t)(value >> 16);
    buf[6] = (uint8_t)(value >> 8);
    buf[7] = (uint8_t)value;
    return 8;
  }
  return 0;
}

static CURLcode quic_raw_append_param(struct dynbuf *raw,
                                      uint64_t id,
                                      uint64_t value,
                                      bool has_value)
{
  uint8_t idbuf[8];
  uint8_t lenbuf[8];
  uint8_t valbuf[8];
  size_t idlen;
  size_t vlen = 0;
  size_t lenlen;
  CURLcode result;

  idlen = quic_varint_encode(idbuf, id);
  if(!idlen)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(has_value) {
    vlen = quic_varint_encode(valbuf, value);
    if(!vlen)
      return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  lenlen = quic_varint_encode(lenbuf, (uint64_t)vlen);
  if(!lenlen)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  result = curlx_dyn_addn(raw, (const char *)idbuf, idlen);
  if(result)
    return result;
  result = curlx_dyn_addn(raw, (const char *)lenbuf, lenlen);
  if(result)
    return result;
  if(vlen) {
    result = curlx_dyn_addn(raw, (const char *)valbuf, vlen);
    if(result)
      return result;
  }

  return CURLE_OK;
}

static CURLcode quic_raw_append_param_bytes(struct dynbuf *raw,
                                            uint64_t id,
                                            const uint8_t *value,
                                            size_t vlen)
{
  uint8_t idbuf[8];
  uint8_t lenbuf[8];
  size_t idlen;
  size_t lenlen;
  CURLcode result;

  if(vlen && !value)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  idlen = quic_varint_encode(idbuf, id);
  if(!idlen)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  lenlen = quic_varint_encode(lenbuf, (uint64_t)vlen);
  if(!lenlen)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  result = curlx_dyn_addn(raw, (const char *)idbuf, idlen);
  if(result)
    return result;
  result = curlx_dyn_addn(raw, (const char *)lenbuf, lenlen);
  if(result)
    return result;
  if(vlen) {
    result = curlx_dyn_addn(raw, (const char *)value, vlen);
    if(result)
      return result;
  }

  return CURLE_OK;
}

static CURLcode quic_dyn_add_u32be(struct dynbuf *db, uint32_t value)
{
  unsigned char b[4];
  b[0] = (unsigned char)(value >> 24);
  b[1] = (unsigned char)(value >> 16);
  b[2] = (unsigned char)(value >> 8);
  b[3] = (unsigned char)value;
  return curlx_dyn_addn(db, (const char *)b, sizeof(b));
}

static CURLcode quic_parse_version_token(const char *tok,
                                         bool allow_grease,
                                         struct Curl_easy *data,
                                         uint32_t *pver)
{
  unsigned long long v;
  char *end = NULL;

  if(allow_grease && curl_strequal(tok, "GREASE")) {
    *pver = quic_version_grease(data);
    return CURLE_OK;
  }

  v = strtoull(tok, &end, 0);
  if(!*tok || (end && *end) || (v > 0xffffffffULL))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  *pver = (uint32_t)v;
  return CURLE_OK;
}

static CURLcode quic_append_version_information(struct dynbuf *raw,
                                                const char *value_str,
                                                struct Curl_easy *data)
{
  struct dynbuf vb;
  CURLcode result = CURLE_OK;
  char *tmp;
  char *chosen_tok;
  char *available_list;
  char *p;
  char *sep;
  size_t available_count = 0;
  uint32_t ver;

  if(!value_str || !*value_str)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  tmp = curlx_strdup(value_str);
  if(!tmp)
    return CURLE_OUT_OF_MEMORY;

  sep = strchr(tmp, '@');
  if(!sep || !*tmp || !*(sep + 1)) {
    curlx_free(tmp);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  *sep = '\0';
  chosen_tok = tmp;
  available_list = sep + 1;

  curlx_dyn_init(&vb, 64);
  result = quic_parse_version_token(chosen_tok, FALSE, data, &ver);
  if(result)
    goto out;
  result = quic_dyn_add_u32be(&vb, ver);
  if(result)
    goto out;

  p = available_list;
  while(*p) {
    char *comma = strchr(p, ',');
    if(comma)
      *comma = '\0';
    result = quic_parse_version_token(p, TRUE, data, &ver);
    if(result)
      goto out;
    result = quic_dyn_add_u32be(&vb, ver);
    if(result)
      goto out;
    ++available_count;
    if(!comma)
      break;
    if(!*(comma + 1)) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
    p = comma + 1;
  }

  if(!available_count) {
    result = CURLE_BAD_FUNCTION_ARGUMENT;
    goto out;
  }

  result = quic_raw_append_param_bytes(raw, QUIC_TP_VERSION_INFORMATION,
                                       (const uint8_t *)curlx_dyn_ptr(&vb),
                                       curlx_dyn_len(&vb));

out:
  curlx_free(tmp);
  curlx_dyn_free(&vb);
  return result;
}

static CURLcode quic_transport_params_from_string(ngtcp2_transport_params *t,
                                                  struct dynbuf *raw,
                                                  const ngtcp2_cid *scid,
                                                  struct Curl_easy *data)
{
  const char *params = data->set.str[STRING_QUIC_TRANSPORT_PARAMETERS];
  bool permute = Curl_ssl_http3_permute_extensions(data);
  char *tmp;
  char *p;
  char **tokens = NULL;
  size_t ntokens = 0;
  size_t talloc = 0;
  size_t i;
  char *setting;
  CURLcode result = CURLE_OK;

  if(!params || !*params)
    return CURLE_OK;

  tmp = curlx_strdup(params);
  if(!tmp)
    return CURLE_OUT_OF_MEMORY;

  p = tmp;
  while(*p) {
    char **newtokens;
    size_t newalloc;

    while(*p == ';')
      ++p;
    if(!*p)
      break;

    if(ntokens == talloc) {
      newalloc = talloc ? (talloc * 2) : 8;
      newtokens = curlx_realloc(tokens, newalloc * sizeof(*tokens));
      if(!newtokens) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      tokens = newtokens;
      talloc = newalloc;
    }

    tokens[ntokens++] = p;
    while(*p && (*p != ';'))
      ++p;
    if(*p) {
      *p = '\0';
      ++p;
    }
  }

  if(permute && (ntokens > 1)) {
    result = quic_permute_token_order(tokens, ntokens, data);
    if(result)
      goto out;
  }

  for(i = 0; i < ntokens; ++i) {
    char *colon;
    char *value_str = NULL;
    char *end = NULL;
    uint64_t id;
    uint64_t value = 0;
    bool has_value = FALSE;
    bool value_is_auto = FALSE;
    bool value_is_empty_initial_scid = FALSE;
    bool value_is_initial_rtt_auto = FALSE;
    bool value_is_hex_bytes = FALSE;

    setting = tokens[i];
    colon = strchr(setting, ':');

    if(curl_strequal(setting, "GREASE")) {
      unsigned char grease_value[QUIC_TP_GREASE_VALUE_MAXLEN];
      size_t grease_vlen;

      result = quic_generate_grease_tp(data, &id, grease_value,
                                        &grease_vlen);
      if(result)
        goto out;
      result = quic_raw_append_param_bytes(raw, id, grease_value,
                                            grease_vlen);
      if(result)
        goto out;
      continue;
    }

    if(colon) {
      *colon = '\0';
      has_value = TRUE;
      value_str = colon + 1;
    }

    id = strtoull(setting, &end, 10);
    if(!*setting || (end && *end)) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
    if(has_value) {
      if(id == QUIC_TP_INITIAL_SOURCE_CONNECTION_ID &&
         curl_strequal(value_str, "AUTO"))
        value_is_auto = TRUE;
      else if(id == QUIC_TP_INITIAL_SOURCE_CONNECTION_ID && !*value_str)
        value_is_empty_initial_scid = TRUE;
      else if(id == QUIC_TP_INITIAL_RTT &&
              (curl_strequal(value_str, "AUTO") ||
               curl_strequal(value_str, "RANDOM")))
        value_is_initial_rtt_auto = TRUE;
      else if(id == QUIC_TP_VERSION_INFORMATION) {
        /* Parsed by dedicated handler below. */
      }
      else if(value_str[0] == '0' && (value_str[1] == 'x' ||
                                       value_str[1] == 'X'))
        value_is_hex_bytes = TRUE;
      else {
        value = strtoull(value_str, &end, 10);
        if(!*value_str || (end && *end)) {
          result = CURLE_BAD_FUNCTION_ARGUMENT;
          goto out;
        }
      }
    }

    if(has_value && id == QUIC_TP_VERSION_INFORMATION) {
      result = quic_append_version_information(raw, value_str, data);
      if(result)
        goto out;
      continue;
    }
    if(id == QUIC_TP_GOOGLE_VERSION) {
      unsigned char ver[4];

      if(!has_value || (value > UINT_MAX)) {
        failf(data, "QUIC transport param %" PRIu64
              " requires a 32-bit version value", (uint64_t)id);
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      ver[0] = (unsigned char)(value >> 24);
      ver[1] = (unsigned char)(value >> 16);
      ver[2] = (unsigned char)(value >> 8);
      ver[3] = (unsigned char)value;
      result = quic_apply_transport_param(t, id, value, has_value, data);
      if(result)
        goto out;
      result = quic_raw_append_param_bytes(raw, id, ver, sizeof(ver));
      if(result)
        goto out;
      continue;
    }

    if(value_is_auto) {
      if(!scid) {
        failf(data, "QUIC transport param 15:AUTO has no local SCID pointer");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      result = quic_raw_append_param_bytes(raw, id,
                                           (const uint8_t *)scid->data,
                                           scid->datalen);
      if(result)
        goto out;
      continue;
    }
    if(value_is_empty_initial_scid) {
      result = quic_raw_append_param_bytes(raw, id, NULL, 0);
      if(result)
        goto out;
      continue;
    }
    if(value_is_hex_bytes) {
      const char *hex = value_str + 2; /* skip "0x" */
      size_t hex_len = strlen(hex);
      size_t byte_len;
      unsigned char *bytes;
      size_t j;

      if((hex_len == 0) || (hex_len % 2 != 0)) {
        failf(data, "QUIC transport param %" PRIu64
              " has invalid hex value", (uint64_t)id);
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      byte_len = hex_len / 2;
      bytes = curlx_malloc(byte_len);
      if(!bytes) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      for(j = 0; j < byte_len; j++) {
        unsigned int byte_val;
        if(sscanf(hex + 2 * j, "%2x", &byte_val) != 1) {
          curlx_free(bytes);
          failf(data, "QUIC transport param %" PRIu64
                " has invalid hex value", (uint64_t)id);
          result = CURLE_BAD_FUNCTION_ARGUMENT;
          goto out;
        }
        bytes[j] = (unsigned char)byte_val;
      }
      result = quic_raw_append_param_bytes(raw, id, bytes, byte_len);
      curlx_free(bytes);
      if(result)
        goto out;
      continue;
    }
    if(value_is_initial_rtt_auto)
      value = quic_initial_rtt_auto_us(data);

    if(id > QUIC_VARINT_MAX || (has_value && value > QUIC_VARINT_MAX)) {
      failf(data, "QUIC transport param value exceeds varint range");
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    result = quic_apply_transport_param(t, id, value, has_value, data);
    if(result)
      goto out;
    result = quic_raw_append_param(raw, id, value, has_value);
    if(result)
      goto out;
  }

out:
  curlx_free(tokens);
  curlx_free(tmp);
  return result;
}


static CURLcode quic_settings(struct cf_ngtcp2_ctx *ctx,
                              struct Curl_easy *data,
                              struct cf_ngtcp2_io_ctx *pktx)
{
  ngtcp2_settings *s = &ctx->settings;
  ngtcp2_transport_params *t = &ctx->transport_params;
  CURLcode result;

  ngtcp2_settings_default(s);
  ngtcp2_transport_params_default(t);
#ifdef DEBUG_NGTCP2
  s->log_printf = quic_printf;
#else
  s->log_printf = NULL;
#endif

  s->initial_ts = pktx->ts;
  s->handshake_timeout = (data->set.connecttimeout > 0) ?
    data->set.connecttimeout * NGTCP2_MILLISECONDS : QUIC_HANDSHAKE_TIMEOUT;
  s->max_window = H3_CONN_WINDOW_SIZE_MAX;
  s->max_stream_window = 0; /* disable ngtcp2 auto-tuning of window */
  s->no_pmtud = FALSE;
#ifdef NGTCP2_SETTINGS_V3
  /* try ten times the ngtcp2 defaults here for problems with Caddy */
  s->glitch_ratelim_burst = 1000 * 10;
  s->glitch_ratelim_rate = 33 * 10;
#endif
  t->initial_max_data = s->max_window;
  t->initial_max_stream_data_bidi_local = H3_STREAM_WINDOW_SIZE_INITIAL;
  t->initial_max_stream_data_bidi_remote = H3_STREAM_WINDOW_SIZE_INITIAL;
  t->initial_max_stream_data_uni = t->initial_max_data;
  t->initial_max_streams_bidi = QUIC_MAX_STREAMS;
  t->initial_max_streams_uni = QUIC_MAX_STREAMS;
  t->max_idle_timeout = 0; /* no idle timeout from our side */
  if(ctx->qlogfd != -1) {
    s->qlog_write = qlog_callback;
  }
  curlx_dyn_reset(&ctx->tp_raw);
  result = quic_transport_params_from_string(t, &ctx->tp_raw, &ctx->scid,
                                             data);
  return result;
}

#if defined(_MSC_VER) && defined(_DLL)
#pragma warning(push)
#pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

static int cb_ngtcp2_handshake_completed(ngtcp2_conn *tconn, void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf ? cf->ctx : NULL;
  struct Curl_easy *data;

  (void)tconn;
  DEBUGASSERT(ctx);
  data = CF_DATA_CURRENT(cf);
  DEBUGASSERT(data);
  if(!ctx || !data)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  ctx->handshake_at = *Curl_pgrs_now(data);
  ctx->tls_handshake_complete = TRUE;
  Curl_vquic_report_handshake(&ctx->tls, cf, data);

  ctx->tls_vrfy_result = Curl_vquic_tls_verify_peer(&ctx->tls, cf,
                                                    data, &ctx->ssl_peer);
  if(ctx->tls_vrfy_result)
    return NGTCP2_ERR_CALLBACK_FAILURE;

#ifdef CURLVERBOSE
  if(Curl_trc_is_verbose(data)) {
    const ngtcp2_transport_params *rp;
    rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
    CURL_TRC_CF(data, cf, "handshake complete after %" FMT_TIMEDIFF_T
                "ms, remote transport[max_udp_payload=%" PRIu64
                ", initial_max_data=%" PRIu64 "]",
                curlx_ptimediff_ms(&ctx->handshake_at, &ctx->started_at),
                rp->max_udp_payload_size, rp->initial_max_data);
  }
#endif

  /* In case of earlydata, where we simulate being connected, update
   * the handshake time when we really did connect */
  if(ctx->use_earlydata)
    Curl_pgrsTimeWas(data, TIMER_APPCONNECT, ctx->handshake_at);
  if(ctx->use_earlydata) {
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA)
    ctx->earlydata_accepted =
      (SSL_get_early_data_status(ctx->tls.ossl.ssl) !=
       SSL_EARLY_DATA_REJECTED);
#endif
#ifdef USE_GNUTLS
    int flags = gnutls_session_get_flags(ctx->tls.gtls.session);
    ctx->earlydata_accepted = !!(flags & GNUTLS_SFLAGS_EARLY_DATA);
#endif
#ifdef USE_WOLFSSL
#ifdef WOLFSSL_EARLY_DATA
    ctx->earlydata_accepted =
      (wolfSSL_get_early_data_status(ctx->tls.wssl.ssl) !=
       WOLFSSL_EARLY_DATA_REJECTED);
#else
    DEBUGASSERT(0); /* should not come here if ED is disabled. */
    ctx->earlydata_accepted = FALSE;
#endif /* WOLFSSL_EARLY_DATA */
#endif
    CURL_TRC_CF(data, cf, "server did%s accept %zu bytes of early data",
                ctx->earlydata_accepted ? "" : " not", ctx->earlydata_skip);
    Curl_pgrsEarlyData(data, ctx->earlydata_accepted ?
                              (curl_off_t)ctx->earlydata_skip :
                             -(curl_off_t)ctx->earlydata_skip);
  }
  return 0;
}

static int cb_recv_stream_data(ngtcp2_conn *tconn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *buf, size_t buflen,
                               void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  nghttp3_ssize rc;
  uint64_t nconsumed;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)offset;

  rc = nghttp3_conn_read_stream(ctx->h3conn, stream_id, buf, buflen, fin);
  if(rc < 0) {
    if(data && stream) {
      CURL_TRC_CF(data, cf, "[%" PRId64 "] error on known stream, "
                  "reset=%d, closed=%d",
                  stream_id, stream->reset, stream->closed);
    }
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  nconsumed = (uint64_t)rc;
  if(nconsumed) {
    /* number of bytes inside buflen which consists of framing overhead
     * including QPACK HEADERS. In other words, it does not consume payload of
     * DATA frame. */
    ngtcp2_conn_extend_max_stream_offset(tconn, stream_id, nconsumed);
    ngtcp2_conn_extend_max_offset(tconn, nconsumed);
    if(stream) {
      stream->rx_offset += nconsumed;
      stream->rx_offset_max += nconsumed;
    }
  }
  return 0;
}

static int cb_acked_stream_data_offset(ngtcp2_conn *tconn, int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rv;
  (void)stream_id;
  (void)tconn;
  (void)offset;
  (void)datalen;
  (void)stream_user_data;

  rv = nghttp3_conn_add_ack_offset(ctx->h3conn, stream_id, datalen);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_close(ngtcp2_conn *tconn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  int rv;

  (void)tconn;
  /* stream is closed... */
  if(!data)
    data = CF_DATA_CURRENT(cf);
  if(!data)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  if(!(flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET)) {
    app_error_code = NGHTTP3_H3_NO_ERROR;
  }

  rv = nghttp3_conn_close_stream(ctx->h3conn, stream_id, app_error_code);
  CURL_TRC_CF(data, cf, "[%" PRId64 "] quic close(app_error=%"
              PRIu64 ") -> %d", stream_id, app_error_code, rv);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    Curl_cf_ngtcp2_h3_err_set(cf, data, rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_reset(ngtcp2_conn *tconn, int64_t stream_id,
                           uint64_t final_size, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  int rv;
  (void)tconn;
  (void)final_size;
  (void)app_error_code;

  rv = nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
  CURL_TRC_CF(data, cf, "[%" PRId64 "] reset -> %d", stream_id, rv);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_stop_sending(ngtcp2_conn *tconn, int64_t stream_id,
                                  uint64_t app_error_code, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rv;
  (void)tconn;
  (void)app_error_code;
  (void)stream_user_data;

  rv = nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_extend_max_local_streams_bidi(ngtcp2_conn *tconn,
                                            uint64_t max_streams,
                                            void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);

  (void)tconn;
  ctx->max_bidi_streams = max_streams;
  if(data)
    CURL_TRC_CF(data, cf, "max bidi streams now %" PRIu64 ", used %" PRIu64,
                ctx->max_bidi_streams, ctx->used_bidi_streams);
  return 0;
}

static int cb_extend_max_stream_data(ngtcp2_conn *tconn, int64_t stream_id,
                                     uint64_t max_data, void *user_data,
                                     void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *s_data = stream_user_data;
  struct h3_stream_ctx *stream;
  int rv;
  (void)tconn;
  (void)max_data;

  rv = nghttp3_conn_unblock_stream(ctx->h3conn, stream_id);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  stream = H3_STREAM_CTX(ctx, s_data);
  if(stream && stream->quic_flow_blocked) {
    CURL_TRC_CF(s_data, cf, "[%" PRId64 "] unblock quic flow", stream_id);
    stream->quic_flow_blocked = FALSE;
    Curl_multi_mark_dirty(s_data);
  }
  return 0;
}

static void cb_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx)
{
  CURLcode result;
  (void)rand_ctx;

  result = Curl_rand(NULL, dest, destlen);
  if(result) {
    /* cb_rand is only used for non-cryptographic context. If Curl_rand
       failed, fill 0 and call it *random*. */
    memset(dest, 0, destlen);
  }
}

/* for ngtcp2 <v1.22.0 */
static int cb_get_new_connection_id(ngtcp2_conn *tconn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data)
{
  CURLcode result;
  (void)tconn;
  (void)user_data;

  result = Curl_rand(NULL, cid->data, cidlen);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;

  result = Curl_rand(NULL, token, NGTCP2_STATELESS_RESET_TOKENLEN);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}

#ifdef NGTCP2_CALLBACKS_V3  /* ngtcp2 v1.22.0+ */
static int cb_get_new_connection_id2(
  ngtcp2_conn *tconn, ngtcp2_cid *cid,
  struct ngtcp2_stateless_reset_token *token, size_t cidlen, void *user_data)
{
  CURLcode result;
  (void)tconn;
  (void)user_data;

  result = Curl_rand(NULL, cid->data, cidlen);
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;
  cid->datalen = cidlen;

  result = Curl_rand(NULL, token->data, sizeof(token->data));
  if(result)
    return NGTCP2_ERR_CALLBACK_FAILURE;

  return 0;
}
#endif

static int cb_recv_rx_key(ngtcp2_conn *tconn, ngtcp2_encryption_level level,
                          void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf ? cf->ctx : NULL;
  struct Curl_easy *data = CF_DATA_CURRENT(cf);
  (void)tconn;

  if(level != NGTCP2_ENCRYPTION_LEVEL_1RTT)
    return 0;

  DEBUGASSERT(ctx);
  DEBUGASSERT(data);
  if(ctx && data && !ctx->h3conn && ctx->init_h3_conn_cb) {
    if(ctx->init_h3_conn_cb(cf, data, ctx))
      return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static ngtcp2_callbacks ng_callbacks = {
  ngtcp2_crypto_client_initial_cb,
  NULL, /* recv_client_initial */
  ngtcp2_crypto_recv_crypto_data_cb,
  cb_ngtcp2_handshake_completed,
  NULL, /* recv_version_negotiation */
  ngtcp2_crypto_encrypt_cb,
  ngtcp2_crypto_decrypt_cb,
  ngtcp2_crypto_hp_mask_cb,
  cb_recv_stream_data,
  cb_acked_stream_data_offset,
  NULL, /* stream_open */
  cb_stream_close,
  NULL, /* recv_stateless_reset */
  ngtcp2_crypto_recv_retry_cb,
  cb_extend_max_local_streams_bidi,
  NULL, /* extend_max_local_streams_uni */
  cb_rand,
  cb_get_new_connection_id, /* for ngtcp2 <v1.22.0 */
  NULL, /* remove_connection_id */
  ngtcp2_crypto_update_key_cb, /* update_key */
  NULL, /* path_validation */
  NULL, /* select_preferred_addr */
  cb_stream_reset,
  NULL, /* extend_max_remote_streams_bidi */
  NULL, /* extend_max_remote_streams_uni */
  cb_extend_max_stream_data,
  NULL, /* dcid_status */
  NULL, /* handshake_confirmed */
  NULL, /* recv_new_token */
  ngtcp2_crypto_delete_crypto_aead_ctx_cb,
  ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  NULL, /* recv_datagram */
  NULL, /* ack_datagram */
  NULL, /* lost_datagram */
  ngtcp2_crypto_get_path_challenge_data_cb,
  cb_stream_stop_sending,
  NULL, /* version_negotiation */
  cb_recv_rx_key,
  NULL, /* recv_tx_key */
  NULL, /* early_data_rejected */
#ifdef NGTCP2_CALLBACKS_V2  /* ngtcp2 v1.14.0+ */
  NULL, /* begin_path_validation */
#endif
#ifdef NGTCP2_CALLBACKS_V3  /* ngtcp2 v1.22.0+ */
  NULL, /* recv_stateless_reset2 */
  cb_get_new_connection_id2, /* get_new_connection_id2 */
  NULL, /* dcid_status2 */
  ngtcp2_crypto_get_path_challenge_data2_cb, /* get_path_challenge_data2 */
#endif
};

#if defined(_MSC_VER) && defined(_DLL)
#pragma warning(pop)
#endif

static bool cf_ngtcp2_need_httpsrr(struct Curl_easy *data)
{
#ifdef USE_OPENSSL
  return Curl_ossl_need_httpsrr(data);
#elif defined(USE_WOLFSSL)
  return Curl_wssl_need_httpsrr(data);
#else
  (void)data;
  return FALSE;
#endif
}

#ifdef USE_OPENSSL
/* The "new session" callback must return zero if the session can be removed
 * or non-zero if the session has been put into the session cache.
 */
static int quic_ossl_new_session_cb(SSL *ssl, SSL_SESSION *ssl_sessionid)
{
  struct Curl_cfilter *cf;
  struct cf_ngtcp2_ctx *ctx;
  struct Curl_easy *data;
  ngtcp2_crypto_conn_ref *cref;

  cref = (ngtcp2_crypto_conn_ref *)SSL_get_app_data(ssl);
  cf = cref ? cref->user_data : NULL;
  ctx = cf ? cf->ctx : NULL;
  data = cf ? CF_DATA_CURRENT(cf) : NULL;
  if(cf && data && ctx) {
    unsigned char *quic_tp = NULL;
    size_t quic_tp_len = 0;
#ifdef HAVE_OPENSSL_EARLYDATA
    ngtcp2_ssize tplen;
    uint8_t tpbuf[256];

    tplen = ngtcp2_conn_encode_0rtt_transport_params(ctx->qconn, tpbuf,
                                                     sizeof(tpbuf));
    if(tplen < 0)
      CURL_TRC_CF(data, cf, "error encoding 0RTT transport data: %s",
                  ngtcp2_strerror((int)tplen));
    else {
      quic_tp = (unsigned char *)tpbuf;
      quic_tp_len = (size_t)tplen;
    }
#endif
    Curl_ossl_add_session(cf, data, ctx->ssl_peer.scache_key, ssl_sessionid,
                          SSL_version(ssl), "h3", quic_tp, quic_tp_len);
  }
  return 0;
}
#endif /* USE_OPENSSL */

#ifdef USE_GNUTLS

#ifdef CURLVERBOSE
static const char *gtls_hs_msg_name(int mtype)
{
  switch(mtype) {
  case 1:
    return "ClientHello";
  case 2:
    return "ServerHello";
  case 4:
    return "SessionTicket";
  case 8:
    return "EncryptedExtensions";
  case 11:
    return "Certificate";
  case 13:
    return "CertificateRequest";
  case 15:
    return "CertificateVerify";
  case 20:
    return "Finished";
  case 24:
    return "KeyUpdate";
  case 254:
    return "MessageHash";
  }
  return "Unknown";
}
#endif

static int quic_gtls_handshake_cb(gnutls_session_t session, unsigned int htype,
                                  unsigned when, unsigned int incoming,
                                  const gnutls_datum_t *msg)
{
  ngtcp2_crypto_conn_ref *conn_ref = gnutls_session_get_ptr(session);
  struct Curl_cfilter *cf = conn_ref ? conn_ref->user_data : NULL;
  struct cf_ngtcp2_ctx *ctx = cf ? cf->ctx : NULL;

  (void)msg;
  (void)incoming;
  if(when && cf && ctx) { /* after message has been processed */
    struct Curl_easy *data = CF_DATA_CURRENT(cf);
    DEBUGASSERT(data);
    if(!data)
      return 0;
    CURL_TRC_CF(data, cf, "SSL message: %s %s [%u]",
                incoming ? "<-" : "->", gtls_hs_msg_name(htype), htype);
    switch(htype) {
    case GNUTLS_HANDSHAKE_NEW_SESSION_TICKET: {
      ngtcp2_ssize tplen;
      uint8_t tpbuf[256];
      unsigned char *quic_tp = NULL;
      size_t quic_tp_len = 0;

      tplen = ngtcp2_conn_encode_0rtt_transport_params(ctx->qconn, tpbuf,
                                                       sizeof(tpbuf));
      if(tplen < 0)
        CURL_TRC_CF(data, cf, "error encoding 0RTT transport data: %s",
                    ngtcp2_strerror((int)tplen));
      else {
        quic_tp = (unsigned char *)tpbuf;
        quic_tp_len = (size_t)tplen;
      }
      (void)Curl_gtls_cache_session(cf, data, ctx->ssl_peer.scache_key,
                                    session, 0, "h3", quic_tp, quic_tp_len);
      break;
    }
    default:
      break;
    }
  }
  return 0;
}
#endif /* USE_GNUTLS */

#ifdef USE_WOLFSSL
static int wssl_quic_new_session_cb(WOLFSSL *ssl, WOLFSSL_SESSION *session)
{
  ngtcp2_crypto_conn_ref *conn_ref = wolfSSL_get_app_data(ssl);
  struct Curl_cfilter *cf = conn_ref ? conn_ref->user_data : NULL;

  DEBUGASSERT(cf);
  if(cf && session) {
    struct cf_ngtcp2_ctx *ctx = cf->ctx;
    struct Curl_easy *data = CF_DATA_CURRENT(cf);
    DEBUGASSERT(data);
    if(data && ctx) {
      ngtcp2_ssize tplen;
      uint8_t tpbuf[256];
      unsigned char *quic_tp = NULL;
      size_t quic_tp_len = 0;

      tplen = ngtcp2_conn_encode_0rtt_transport_params(ctx->qconn, tpbuf,
                                                       sizeof(tpbuf));
      if(tplen < 0)
        CURL_TRC_CF(data, cf, "error encoding 0RTT transport data: %s",
                    ngtcp2_strerror((int)tplen));
      else {
        quic_tp = (unsigned char *)tpbuf;
        quic_tp_len = (size_t)tplen;
      }
      (void)Curl_wssl_cache_session(cf, data, ctx->ssl_peer.scache_key,
                                    session, wolfSSL_version(ssl),
                                    "h3", quic_tp, quic_tp_len);
    }
  }
  return 0;
}
#endif /* USE_WOLFSSL */

static CURLcode cf_ngtcp2_tls_ctx_setup(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        void *user_data)
{
  struct curl_tls_ctx *ctx = user_data;

#ifdef USE_OPENSSL
#if defined(OPENSSL_IS_AWSLC) || defined(OPENSSL_IS_BORINGSSL)
  if(ngtcp2_crypto_boringssl_configure_client_context(ctx->ossl.ssl_ctx)
     != 0) {
    failf(data, "ngtcp2_crypto_boringssl_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
#elif defined(OPENSSL_QUIC_API2)
  /* nothing to do */
#else
  if(ngtcp2_crypto_quictls_configure_client_context(ctx->ossl.ssl_ctx) != 0) {
    failf(data, "ngtcp2_crypto_quictls_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
#endif /* !OPENSSL_IS_AWSLC && !OPENSSL_IS_BORINGSSL */
  if(Curl_ssl_scache_use(cf, data)) {
    /* Enable the session cache because it is a prerequisite for the
     * "new session" callback. Use the "external storage" mode to prevent
     * OpenSSL from creating an internal session cache.
     */
    SSL_CTX_set_session_cache_mode(ctx->ossl.ssl_ctx,
                                   SSL_SESS_CACHE_CLIENT |
                                   SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_new_cb(ctx->ossl.ssl_ctx, quic_ossl_new_session_cb);
  }

#elif defined(USE_GNUTLS)
  if(ngtcp2_crypto_gnutls_configure_client_session(ctx->gtls.session) != 0) {
    failf(data, "ngtcp2_crypto_gnutls_configure_client_session failed");
    return CURLE_FAILED_INIT;
  }
  if(Curl_ssl_scache_use(cf, data)) {
    gnutls_handshake_set_hook_function(ctx->gtls.session,
                                       GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_POST,
                                       quic_gtls_handshake_cb);
  }

#elif defined(USE_WOLFSSL)
  if(ngtcp2_crypto_wolfssl_configure_client_context(ctx->wssl.ssl_ctx) != 0) {
    failf(data, "ngtcp2_crypto_wolfssl_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
  if(Curl_ssl_scache_use(cf, data)) {
    /* Register to get notified when a new session is received */
    wolfSSL_CTX_sess_set_new_cb(ctx->wssl.ssl_ctx, wssl_quic_new_session_cb);
  }
#endif
  return CURLE_OK;
}

static CURLcode cf_ngtcp2_on_session_reuse(struct Curl_cfilter *cf,
                                           struct Curl_easy *data,
                                           struct alpn_spec *alpns,
                                           struct Curl_ssl_session *scs,
                                           bool *do_early_data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;

  *do_early_data = FALSE;
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA)
  ctx->earlydata_max = scs->earlydata_max;
#endif
#ifdef USE_GNUTLS
  ctx->earlydata_max =
    gnutls_record_get_max_early_data_size(ctx->tls.gtls.session);
#endif
#ifdef USE_WOLFSSL
#ifdef WOLFSSL_EARLY_DATA
  ctx->earlydata_max = scs->earlydata_max;
#else
  ctx->earlydata_max = 0;
#endif /* WOLFSSL_EARLY_DATA */
#endif
#if defined(USE_GNUTLS) || defined(USE_WOLFSSL) || \
  (defined(USE_OPENSSL) && defined(HAVE_OPENSSL_EARLYDATA))
  if(!ctx->earlydata_max) {
    CURL_TRC_CF(data, cf, "SSL session does not allow earlydata");
  }
  else if(!Curl_alpn_contains_proto(alpns, scs->alpn)) {
    CURL_TRC_CF(data, cf, "SSL session from different ALPN, no early data");
  }
  else if(!scs->quic_tp || !scs->quic_tp_len) {
    CURL_TRC_CF(data, cf, "no 0RTT transport parameters, no early data");
  }
  else {
    int rv;
    rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(
      ctx->qconn, (const uint8_t *)scs->quic_tp, scs->quic_tp_len);
    if(rv)
      CURL_TRC_CF(data, cf, "no early data, failed to set 0RTT transport "
                  "parameters: %s", ngtcp2_strerror(rv));
    else if(ctx->init_h3_conn_cb) {
      infof(data, "SSL session allows %zu bytes of early data, "
            "reusing ALPN '%s'", ctx->earlydata_max, scs->alpn);
      result = ctx->init_h3_conn_cb(cf, data, ctx);
      if(!result) {
        ctx->use_earlydata = TRUE;
        cf->connected = TRUE;
        *do_early_data = TRUE;
      }
    }
    else { /* h3_conn_init set, assume done */
        ctx->use_earlydata = TRUE;
        cf->connected = TRUE;
        *do_early_data = TRUE;
    }
  }
#else /* not supported in the TLS backend */
  (void)data;
  (void)ctx;
  (void)scs;
  (void)alpns;
#endif
  return result;
}

/*
 * Might be called twice for happy eyeballs.
 */
static CURLcode cf_connect_start(struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 struct cf_ngtcp2_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rc;
  int rv;
  CURLcode result;
  const char *cid_profile = data->set.str[STRING_QUIC_CID_LENGTH];
  size_t dcidlen = NGTCP2_MAX_CIDLEN;
  size_t scidlen = NGTCP2_MAX_CIDLEN;
  const struct Curl_sockaddr_ex *sockaddr = NULL;
  int qfd;
  static const struct alpn_spec ALPN_SPEC_H3 = { { "h3" }, 1 };

  DEBUGASSERT(ctx->initialized);
  if(cid_profile) {
    if(!strcmp(cid_profile, "webkit")) {
      dcidlen = 8;
      scidlen = 0;
    }
    else if(!strcmp(cid_profile, "firefox")) {
      unsigned char v;

      result = Curl_rand(data, &v, sizeof(v));
      if(result)
        return result;
      dcidlen = 5 + (v & (v >> 4));
      if(dcidlen < 8)
        dcidlen = 8;
      scidlen = 3;
    }
  }

  ctx->dcid.datalen = dcidlen;
  result = Curl_rand(data, ctx->dcid.data, ctx->dcid.datalen);
  if(result)
    return result;

  ctx->scid.datalen = scidlen;
  if(!cid_profile && quic_has_empty_initial_scid(
       data->set.str[STRING_QUIC_TRANSPORT_PARAMETERS]))
    ctx->scid.datalen = 0;
  if(ctx->scid.datalen) {
    result = Curl_rand(data, ctx->scid.data, ctx->scid.datalen);
    if(result)
      return result;
  }

  (void)Curl_qlogdir(data, ctx->scid.data, ctx->scid.datalen, &qfd);
  ctx->qlogfd = qfd; /* -1 if failure above */
  result = quic_settings(ctx, data, pktx);
  if(result)
    return result;

  result = vquic_ctx_init(data, &ctx->q);
  if(result)
    return result;

  /* Query socket and remote address from sub-chain */
  if(cf_ngtcp2_peek_socket(cf->next, data, &ctx->q.sockfd,
                           &sockaddr, NULL)) {
    /* No direct socket - must be tunneled QUIC (CONNECT-UDP through proxy) */
    ctx->q.sockfd = CURL_SOCKET_BAD;
  }

  if(ctx->q.sockfd != CURL_SOCKET_BAD) {
    /* Direct UDP socket - get local address for ngtcp2 */
    ctx->q.local_addrlen = sizeof(ctx->q.local_addr);
    rv = getsockname(ctx->q.sockfd, (struct sockaddr *)&ctx->q.local_addr,
                     &ctx->q.local_addrlen);
    if(rv == -1)
      return CURLE_QUIC_CONNECT_ERROR;

    ngtcp2_addr_init(&ctx->connected_path.local,
                     (struct sockaddr *)&ctx->q.local_addr,
                     ctx->q.local_addrlen);
    ngtcp2_addr_init(&ctx->connected_path.remote,
                     &sockaddr->curl_sa_addr, (socklen_t)sockaddr->addrlen);

    rc = ngtcp2_conn_client_new(&ctx->qconn, &ctx->dcid, &ctx->scid,
                                &ctx->connected_path,
                                NGTCP2_PROTO_VER_V1, &ng_callbacks,
                                &ctx->settings, &ctx->transport_params,
                                Curl_ngtcp2_mem(), cf);
    if(rc)
      return CURLE_QUIC_CONNECT_ERROR;

    ctx->conn_ref.get_conn = get_conn;
    ctx->conn_ref.user_data = cf;
  }

  else {
    /* Tunneled QUIC (e.g. CONNECT-UDP): get remote address
       from the connected filter below */
    const struct Curl_sockaddr_ex *remote = NULL;
    if(cf->next->cft->query(cf->next, data, CF_QUERY_REMOTE_ADDR, NULL,
                            CURL_UNCONST(&remote)))
      return CURLE_QUIC_CONNECT_ERROR;
    if(!remote)
      return CURLE_QUIC_CONNECT_ERROR;

    memset(&ctx->q.local_addr, 0, sizeof(ctx->q.local_addr));
    switch(remote->family) {
    case AF_INET:
      ((struct sockaddr_in *)&ctx->q.local_addr)->sin_family = AF_INET;
      ctx->q.local_addrlen = sizeof(struct sockaddr_in);
      break;
#ifdef USE_IPV6
    case AF_INET6:
      ((struct sockaddr_in6 *)&ctx->q.local_addr)->sin6_family = AF_INET6;
      ctx->q.local_addrlen = sizeof(struct sockaddr_in6);
      break;
#endif
    default:
      return CURLE_QUIC_CONNECT_ERROR;
    }

    ngtcp2_addr_init(&ctx->connected_path.local,
                     (struct sockaddr *)&ctx->q.local_addr,
                     ctx->q.local_addrlen);
    ngtcp2_addr_init(&ctx->connected_path.remote,
                     &remote->curl_sa_addr,
                     (socklen_t)remote->addrlen);

    rc = ngtcp2_conn_client_new(&ctx->qconn, &ctx->dcid, &ctx->scid,
                                &ctx->connected_path,
                                NGTCP2_PROTO_VER_V1, &ng_callbacks,
                                &ctx->settings, &ctx->transport_params,
                                Curl_ngtcp2_mem(), cf);
    if(rc)
      return CURLE_QUIC_CONNECT_ERROR;

    ctx->conn_ref.get_conn = get_conn;
    ctx->conn_ref.user_data = cf;
  }

  if(curlx_dyn_len(&ctx->tp_raw)) {
    ngtcp2_transport_params_raw raw = {
      (const uint8_t *)curlx_dyn_ptr(&ctx->tp_raw),
      curlx_dyn_len(&ctx->tp_raw)
    };
    rc = ngtcp2_conn_set_local_transport_params_raw(ctx->qconn, &raw);
    if(rc) {
      failf(data, "error setting local QUIC transport params: %s",
            ngtcp2_strerror(rc));
      return CURLE_QUIC_CONNECT_ERROR;
    }
  }

  result = Curl_vquic_tls_init(&ctx->tls, cf, data,
                               &ctx->ssl_peer, &ALPN_SPEC_H3,
                               cf_ngtcp2_tls_ctx_setup, &ctx->tls,
                               &ctx->conn_ref,
                               cf_ngtcp2_on_session_reuse);
  if(result)
    return result;

#if defined(USE_OPENSSL) && defined(OPENSSL_QUIC_API2)
  if(ngtcp2_crypto_ossl_ctx_new(&ctx->ossl_ctx, ctx->tls.ossl.ssl) != 0) {
    failf(data, "ngtcp2_crypto_ossl_ctx_new failed");
    return CURLE_FAILED_INIT;
  }
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->ossl_ctx);
  if(ngtcp2_crypto_ossl_configure_client_session(ctx->tls.ossl.ssl) != 0) {
    failf(data, "ngtcp2_crypto_ossl_configure_client_session failed");
    return CURLE_FAILED_INIT;
  }
#elif defined(USE_OPENSSL)
  SSL_set_quic_use_legacy_codepoint(ctx->tls.ossl.ssl, 0);
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.ossl.ssl);
#elif defined(USE_GNUTLS)
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.gtls.session);
#elif defined(USE_WOLFSSL)
  ngtcp2_conn_set_tls_native_handle(ctx->qconn, ctx->tls.wssl.ssl);
#else
#error "ngtcp2 TLS backend not defined"
#endif

  ngtcp2_ccerr_default(&ctx->last_error);

  return CURLE_OK;
}

CURLcode Curl_cf_ngtcp2_cmn_connect(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *done)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;
  struct cf_ngtcp2_io_ctx pktx;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the sub-chain */
  if(cf->next && !cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;

  if(cf_ngtcp2_need_httpsrr(data) &&
     !Curl_conn_dns_resolved_https(data, cf->sockindex, ctx->ssl_peer.peer)) {
    CURL_TRC_CF(data, cf, "need HTTPS-RR, delaying connect");
    return CURLE_OK;
  }

  Curl_cf_ngtcp2_io_ctx_init(&pktx, cf, data);
  CF_DATA_SAVE(save, cf, data);

  if(!ctx->qconn) {
    ctx->started_at = *Curl_pgrs_now(data);
    result = cf_connect_start(cf, data, &pktx);
    if(result)
      goto out;
    if(cf->connected) {
      *done = TRUE;
      goto out;
    }
    result = Curl_cf_ngtcp2_progress_egress(cf, data, &pktx);
    /* we do not expect to be able to recv anything yet */
    goto out;
  }

  result = Curl_cf_ngtcp2_progress_ingress(cf, data, &pktx);
  if(result)
    goto out;

  result = Curl_cf_ngtcp2_progress_egress(cf, data, &pktx);
  if(result)
    goto out;

  if(ngtcp2_conn_get_handshake_completed(ctx->qconn)) {
    result = ctx->tls_vrfy_result;
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      cf->connected = TRUE;
      *done = TRUE;
    }
  }

out:
  if(ctx->tls_vrfy_result)
    result = ctx->tls_vrfy_result;
  if(ctx->qconn &&
     ((result == CURLE_RECV_ERROR) || (result == CURLE_SEND_ERROR)) &&
     ngtcp2_conn_in_draining_period(ctx->qconn)) {
    const ngtcp2_ccerr *cerr = ngtcp2_conn_get_ccerr(ctx->qconn);

    result = CURLE_COULDNT_CONNECT;
    if(cerr) {
      CURL_TRC_CF(data, cf, "connect error, type=%d, code=%" PRIu64,
                  (int)cerr->type, cerr->error_code);
      switch(cerr->type) {
      case NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION:
        CURL_TRC_CF(data, cf, "error in version negotiation");
        break;
      default:
        if(cerr->error_code >= NGTCP2_CRYPTO_ERROR) {
          CURL_TRC_CF(data, cf, "crypto error, tls alert=%u",
                      (unsigned int)(cerr->error_code & 0xffU));
        }
        else if(cerr->error_code == NGTCP2_CONNECTION_REFUSED) {
          CURL_TRC_CF(data, cf, "connection refused by server");
          /* When a QUIC server instance is shutting down, it may send us a
           * CONNECTION_CLOSE with this code right away. We want
           * to keep on trying in this case. */
          result = CURLE_WEIRD_SERVER_REPLY;
        }
      }
    }
  }

#ifdef CURLVERBOSE
  if(result) {
    if(ctx->q.sockfd != CURL_SOCKET_BAD) {
      /* Direct UDP socket - get IP info for error reporting */
      struct ip_quadruple ip;

      if(!cf_ngtcp2_peek_socket(cf->next, data, NULL, NULL, &ip))
        infof(data, "QUIC connect to %s port %u failed: %s",
              ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
    }
  }
#endif
  if(!result && ctx->qconn) {
    result = Curl_cf_ngtcp2_cmn_set_expiry(cf, data, &pktx);
  }
  if(result || *done)
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", (int)result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
}

CURLcode Curl_cf_ngtcp2_cmn_shutdown(struct Curl_cfilter *cf,
                                     struct Curl_easy *data, bool *done)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  struct cf_ngtcp2_io_ctx pktx;
  CURLcode result = CURLE_OK;

  if(cf->shutdown || !ctx->qconn) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(!cf->next) {
    Curl_bufq_reset(&ctx->q.sendbuf);
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);
  *done = FALSE;
  Curl_cf_ngtcp2_io_ctx_init(&pktx, cf, data);

  if(!ctx->shutdown_started) {
    char buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
    ngtcp2_ssize nwritten;

    if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
      CURL_TRC_CF(data, cf, "shutdown, flushing sendbuf");
      result = Curl_cf_ngtcp2_progress_egress(cf, data, &pktx);
      if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
        CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
        result = CURLE_OK;
        goto out;
      }
      else if(result) {
        CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf",
                    (int)result);
        *done = TRUE;
        goto out;
      }
    }

    DEBUGASSERT(Curl_bufq_is_empty(&ctx->q.sendbuf));
    ctx->shutdown_started = TRUE;
    nwritten = ngtcp2_conn_write_connection_close(
      ctx->qconn, NULL, /* path */
      NULL, /* pkt_info */
      (uint8_t *)buffer, sizeof(buffer),
      &ctx->last_error, pktx.ts);
    CURL_TRC_CF(data, cf, "start shutdown(err_type=%d, err_code=%"
                PRIu64 ") -> %zd", (int)ctx->last_error.type,
                ctx->last_error.error_code, (ssize_t)nwritten);
    /* there are cases listed in ngtcp2 documentation where this call
     * may fail. Since we are doing a connection shutdown as graceful
     * as we can, such an error is ignored here. */
    if(nwritten > 0) {
      /* Ignore amount written. sendbuf was empty and has always room for
       * NGTCP2_MAX_UDP_PAYLOAD_SIZE. It can only completely fail, in which
       * case `result` is set non zero. */
      size_t n;
      result = Curl_bufq_write(&ctx->q.sendbuf, (const unsigned char *)buffer,
                               (size_t)nwritten, &n);
      if(result) {
        CURL_TRC_CF(data, cf, "error %d adding shutdown packets to sendbuf, "
                    "aborting shutdown", (int)result);
        goto out;
      }

      ctx->q.no_gso = TRUE;
      ctx->q.gsolen = (size_t)nwritten;
      ctx->q.split_len = 0;
    }
  }

  if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    CURL_TRC_CF(data, cf, "shutdown, flushing egress");
    result = vquic_flush(cf, data, &ctx->q);
    if(result == CURLE_AGAIN) {
      CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
      result = CURLE_OK;
      goto out;
    }
    else if(result) {
      CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf",
                  (int)result);
      *done = TRUE;
      goto out;
    }
  }

  if(Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    /* Sent everything off. ngtcp2 seems to have no support for graceful
     * shutdowns. We are done. */
    CURL_TRC_CF(data, cf, "shutdown completely sent off, done");
    *done = TRUE;
    result = CURLE_OK;
  }
out:
  CF_DATA_RESTORE(cf, save);
  return result;
}

void Curl_cf_ngtcp2_cmn_conn_close(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  bool done;
  Curl_cf_ngtcp2_cmn_shutdown(cf, data, &done);
}

static bool cf_ngtcp2_err_is_fatal(int code)
{
  return (NGTCP2_ERR_FATAL >= code) ||
         (NGTCP2_ERR_DROP_CONN == code) ||
         (NGTCP2_ERR_IDLE_CLOSE == code);
}

void Curl_cf_ngtcp2_cmn_err_set(struct Curl_cfilter *cf,
                                struct Curl_easy *data, int code)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  if(!ctx->last_error.error_code) {
    if(NGTCP2_ERR_CRYPTO == code) {
      ngtcp2_ccerr_set_tls_alert(&ctx->last_error,
                                 ngtcp2_conn_get_tls_alert(ctx->qconn),
                                 NULL, 0);
    }
    else {
      ngtcp2_ccerr_set_liberr(&ctx->last_error, code, NULL, 0);
    }
  }
  if(cf_ngtcp2_err_is_fatal(code))
    Curl_cf_ngtcp2_cmn_conn_close(cf, data);
}

void Curl_cf_ngtcp2_io_ctx_init(struct cf_ngtcp2_io_ctx *io_ctx,
                                struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  const struct curltime *pnow = Curl_pgrs_now(data);

  io_ctx->cf = cf;
  io_ctx->data = data;
  ngtcp2_path_storage_zero(&io_ctx->ps);
  vquic_ctx_set_time(&ctx->q, pnow);
  io_ctx->ts = ((ngtcp2_tstamp)pnow->tv_sec * NGTCP2_SECONDS) +
               ((ngtcp2_tstamp)pnow->tv_usec * NGTCP2_MICROSECONDS);
}

void Curl_cf_ngtcp2_io_ctx_update_time(struct Curl_easy *data,
                                       struct cf_ngtcp2_io_ctx *pktx,
                                       struct Curl_cfilter *cf)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  const struct curltime *pnow = Curl_pgrs_now(data);

  vquic_ctx_update_time(&ctx->q, pnow);
  pktx->ts = ((ngtcp2_tstamp)pnow->tv_sec * NGTCP2_SECONDS) +
             ((ngtcp2_tstamp)pnow->tv_usec * NGTCP2_MICROSECONDS);
}

#if NGTCP2_VERSION_NUM < 0x011100
struct cf_ngtcp2_sfind_ctx {
  int64_t stream_id;
  struct h3_stream_ctx *stream;
  uint32_t mid;
};

static bool cf_ngtcp2_sfind(uint32_t mid, void *value, void *user_data)
{
  struct cf_ngtcp2_sfind_ctx *fctx = user_data;
  struct h3_stream_ctx *stream = value;

  if(fctx->stream_id == stream->id) {
    fctx->mid = mid;
    fctx->stream = stream;
    return FALSE;
  }
  return TRUE; /* continue */
}

static struct h3_stream_ctx *cf_ngtcp2_get_stream(struct cf_ngtcp2_ctx *ctx,
                                                  int64_t stream_id)
{
  struct cf_ngtcp2_sfind_ctx fctx;
  fctx.stream_id = stream_id;
  fctx.stream = NULL;
  Curl_uint32_hash_visit(&ctx->streams, cf_ngtcp2_sfind, &fctx);
  return fctx.stream;
}
#else
static struct h3_stream_ctx *cf_ngtcp2_get_stream(struct cf_ngtcp2_ctx *ctx,
                                                  int64_t stream_id)
{
  struct Curl_easy *data =
    ngtcp2_conn_get_stream_user_data(ctx->qconn, stream_id);

  if(!data) {
    return NULL;
  }

  return H3_STREAM_CTX(ctx, data);
}
#endif

/**
 * Read a network packet to send from ngtcp2 into `buf`.
 * Return number of bytes written or -1 with *err set.
 */
static CURLcode read_pkt_to_send(void *userp,
                                 unsigned char *buf, size_t buflen,
                                 size_t *pnread)
{
  struct cf_ngtcp2_io_ctx *x = userp;
  struct cf_ngtcp2_ctx *ctx = x->cf->ctx;
  nghttp3_vec vec[16];
  nghttp3_ssize veccnt;
  ngtcp2_ssize ndatalen;
  uint32_t flags;
  int64_t stream_id;
  int fin;
  ssize_t n;

  *pnread = 0;
  veccnt = 0;
  stream_id = -1;
  fin = 0;

  /* ngtcp2 may want to put several frames from different streams into
   * this packet. `NGTCP2_WRITE_STREAM_FLAG_MORE` tells it to do so.
   * When `NGTCP2_ERR_WRITE_MORE` is returned, we *need* to make
   * another iteration.
   * When ngtcp2 is happy (because it has no other frame that would fit
   * or it has nothing more to send), it returns the total length
   * of the assembled packet. This may be 0 if there was nothing to send. */
  for(;;) {

    if(ctx->h3conn && ngtcp2_conn_get_max_data_left(ctx->qconn)) {
      veccnt = nghttp3_conn_writev_stream(ctx->h3conn, &stream_id, &fin, vec,
                                          CURL_ARRAYSIZE(vec));
      if(veccnt < 0) {
        failf(x->data, "nghttp3_conn_writev_stream returned error: %s",
              nghttp3_strerror((int)veccnt));
        Curl_cf_ngtcp2_h3_err_set(x->cf, x->data, (int)veccnt);
        return CURLE_SEND_ERROR;
      }
    }

    flags = NGTCP2_WRITE_STREAM_FLAG_MORE |
            (fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0);
    n = ngtcp2_conn_writev_stream(ctx->qconn, &x->ps.path,
                                  NULL, buf, buflen,
                                  &ndatalen, flags, stream_id,
                                  (const ngtcp2_vec *)vec, veccnt, x->ts);
    if(n == 0) {
      /* nothing to send */
      return CURLE_AGAIN;
    }
    else if(n < 0) {
      switch(n) {
      case NGTCP2_ERR_STREAM_DATA_BLOCKED: {
        struct h3_stream_ctx *stream;
        DEBUGASSERT(ndatalen == -1);
        nghttp3_conn_block_stream(ctx->h3conn, stream_id);
        CURL_TRC_CF(x->data, x->cf, "[%" PRId64 "] block quic flow",
                    stream_id);
        stream = cf_ngtcp2_get_stream(ctx, stream_id);
        if(stream) /* it might be not one of our h3 streams? */
          stream->quic_flow_blocked = TRUE;
        n = 0;
        break;
      }
      case NGTCP2_ERR_STREAM_SHUT_WR:
        DEBUGASSERT(ndatalen == -1);
        nghttp3_conn_shutdown_stream_write(ctx->h3conn, stream_id);
        n = 0;
        break;
      case NGTCP2_ERR_WRITE_MORE:
        /* ngtcp2 wants to send more. update the flow of the stream whose data
         * is in the buffer and continue */
        DEBUGASSERT(ndatalen >= 0);
        n = 0;
        break;
      default:
        DEBUGASSERT(ndatalen == -1);
        failf(x->data, "ngtcp2_conn_writev_stream returned error: %s",
              ngtcp2_strerror((int)n));
        Curl_cf_ngtcp2_cmn_err_set(x->cf, x->data, (int)n);
        return CURLE_SEND_ERROR;
      }
    }

    if(ndatalen >= 0) {
      /* we add the amount of data bytes to the flow windows */
      int rv = nghttp3_conn_add_write_offset(ctx->h3conn, stream_id, ndatalen);
      if(rv) {
        failf(x->data, "nghttp3_conn_add_write_offset returned error: %s",
              nghttp3_strerror(rv));
        return CURLE_SEND_ERROR;
      }
    }

    if(n > 0) {
      /* packet assembled, leave */
      *pnread = (size_t)n;
      return CURLE_OK;
    }
  }
}

CURLcode Curl_cf_ngtcp2_progress_egress(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct cf_ngtcp2_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  size_t nread;
  size_t max_payload_size, path_max_payload_size;
  size_t pktcnt = 0;
  size_t gsolen = 0;  /* this disables gso until we have a clue */
  size_t send_quantum;
  CURLcode result;
  struct cf_ngtcp2_io_ctx local_pktx;

  if(!pktx) {
    Curl_cf_ngtcp2_io_ctx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    Curl_cf_ngtcp2_io_ctx_update_time(data, pktx, cf);
    ngtcp2_path_storage_zero(&pktx->ps);
  }

  result = vquic_flush(cf, data, &ctx->q);
  if(result) {
    if(result == CURLE_AGAIN) {
      Curl_expire(data, 1, EXPIRE_QUIC);
      return CURLE_OK;
    }
    return result;
  }

  /* In UDP, there is a maximum theoretical packet payload length and
   * a minimum payload length that is "guaranteed" to work.
   * To detect if this minimum payload can be increased, ngtcp2 sends
   * now and then a packet payload larger than the minimum. It that
   * is ACKed by the peer, both parties know that it works and
   * the subsequent packets can use a larger one.
   * This is called PMTUD (Path Maximum Transmission Unit Discovery).
   * Since a PMTUD might be rejected right on send, we do not want it
   * be followed by other packets of lesser size. Because those would
   * also fail then. If we detect a PMTUD while buffering, we flush.
   */
  max_payload_size = ngtcp2_conn_get_max_tx_udp_payload_size(ctx->qconn);
  path_max_payload_size =
    ngtcp2_conn_get_path_max_tx_udp_payload_size(ctx->qconn);
  send_quantum = ngtcp2_conn_get_send_quantum(ctx->qconn);
  CURL_TRC_CF(data, cf, "egress, collect and send packets, quantum=%zu",
              send_quantum);
  for(;;) {
    /* add the next packet to send, if any, to our buffer */
    result = Curl_bufq_sipn(&ctx->q.sendbuf, max_payload_size,
                            read_pkt_to_send, pktx, &nread);
    if(result == CURLE_AGAIN)
      break;
    else if(result)
      return result;
    else {
      size_t buflen = Curl_bufq_len(&ctx->q.sendbuf);
      if((buflen >= send_quantum) ||
         ((buflen + gsolen) >= ctx->q.sendbuf.chunk_size))
        break;
      DEBUGASSERT(nread > 0);
      ++pktcnt;
      if(pktcnt == 1) {
        /* first packet in buffer. This is either of a known, "good"
         * payload size or it is a PMTUD. We shall see. */
        gsolen = nread;
      }
      else if(nread > gsolen ||
              (gsolen > path_max_payload_size && nread != gsolen)) {
        /* The added packet is a PMTUD *or* the one(s) before the
         * added were PMTUD and the last one is smaller.
         * Flush the buffer before the last add. */
        result = vquic_send_tail_split(cf, data, &ctx->q,
                                       gsolen, nread, nread);
        if(result) {
          if(result == CURLE_AGAIN) {
            Curl_expire(data, 1, EXPIRE_QUIC);
            return CURLE_OK;
          }
          return result;
        }
        pktcnt = 0;
      }
      else if(nread < gsolen) {
        /* Reached capacity of our buffer *or*
         * last add was shorter than the previous ones, flush */
        break;
      }
    }
  }

  if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    /* time to send */
    CURL_TRC_CF(data, cf, "egress, send collected %zu packets in %zu bytes",
                pktcnt, Curl_bufq_len(&ctx->q.sendbuf));
    result = vquic_send(cf, data, &ctx->q, gsolen);
    if(result) {
      if(result == CURLE_AGAIN) {
        Curl_expire(data, 1, EXPIRE_QUIC);
        return CURLE_OK;
      }
      return result;
    }
    Curl_cf_ngtcp2_io_ctx_update_time(data, pktx, cf);
    ngtcp2_conn_update_pkt_tx_time(ctx->qconn, pktx->ts);
  }
  return CURLE_OK;
}

struct cf_ngtcp2_recv_ctx {
  struct cf_ngtcp2_io_ctx *pktx;
  size_t pkt_count;
};

static CURLcode cf_ngtcp2_recv_pkts(const unsigned char *buf, size_t buflen,
                                    size_t gso_size,
                                    struct sockaddr_storage *remote_addr,
                                    socklen_t remote_addrlen, int ecn,
                                    void *userp)
{
  struct cf_ngtcp2_recv_ctx *rctx = userp;
  struct cf_ngtcp2_io_ctx *pktx = rctx->pktx;
  struct cf_ngtcp2_ctx *ctx = pktx->cf->ctx;
  ngtcp2_pkt_info pi;
  ngtcp2_path path;
  size_t offset, pktlen;
  int rv;

  if(!rctx->pkt_count) {
    Curl_cf_ngtcp2_io_ctx_update_time(pktx->data, pktx, pktx->cf);
    ngtcp2_path_storage_zero(&pktx->ps);
  }

  if(ecn)
    CURL_TRC_CF(pktx->data, pktx->cf, "vquic_recv(len=%zu, gso=%zu, ecn=%x)",
                buflen, gso_size, (unsigned int)ecn);
  ngtcp2_addr_init(&path.local, (struct sockaddr *)&ctx->q.local_addr,
                   ctx->q.local_addrlen);
  ngtcp2_addr_init(&path.remote, (struct sockaddr *)remote_addr,
                   remote_addrlen);
  pi.ecn = (uint8_t)ecn;

  for(offset = 0; offset < buflen; offset += gso_size) {
    rctx->pkt_count++;
    pktlen = ((offset + gso_size) <= buflen) ? gso_size : (buflen - offset);
    rv = ngtcp2_conn_read_pkt(ctx->qconn, &path, &pi,
                              buf + offset, pktlen, pktx->ts);
    if(rv) {
      CURL_TRC_CF(pktx->data, pktx->cf, "ingress, read_pkt -> %s (%d)",
                  ngtcp2_strerror(rv), rv);
      Curl_cf_ngtcp2_cmn_err_set(pktx->cf, pktx->data, rv);

      if(rv == NGTCP2_ERR_CRYPTO)
        /* this is a "TLS problem", but a failed certificate verification
           is a common reason for this */
        return CURLE_PEER_FAILED_VERIFICATION;
      return CURLE_RECV_ERROR;
    }
  }
  return CURLE_OK;
}

CURLcode Curl_cf_ngtcp2_progress_ingress(struct Curl_cfilter *cf,
                                         struct Curl_easy *data,
                                         struct cf_ngtcp2_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_ngtcp2_io_ctx local_pktx;
  struct cf_ngtcp2_recv_ctx rctx;
  CURLcode result = CURLE_OK;

  if(!pktx) {
    Curl_cf_ngtcp2_io_ctx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }

  result = Curl_vquic_tls_before_recv(&ctx->tls, cf, data);
  if(result)
    return result;

  rctx.pktx = pktx;
  rctx.pkt_count = 0;

  if(ctx->q.sockfd != CURL_SOCKET_BAD) {
    /* Direct UDP socket (via happy eyeballs) */
    CURL_TRC_CF(data, cf, "progress_ingress(socket)");
    return vquic_recv_packets(cf, data, &ctx->q, 1000,
                              cf_ngtcp2_recv_pkts, &rctx);
  }
  else {
    /* Tunneled QUIC (CONNECT-UDP through proxy) */
    unsigned char *buf;
    size_t max_udp_payload = QUIC_TUNNEL_INBUF_SIZE;
    size_t pkt_limit = QUIC_TUNNEL_INGRESS_PKT_LIMIT;
    size_t nread;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;

    CURL_TRC_CF(data, cf, "progress_ingress(sub-filters)");
    if(ctx->qconn) {
      size_t max_path_payload;
      max_path_payload =
        ngtcp2_conn_get_path_max_tx_udp_payload_size(ctx->qconn);
      if(max_path_payload > max_udp_payload)
        max_udp_payload = max_path_payload;
    }

    if(ctx->tunnel_inbuf_len < max_udp_payload) {
      unsigned char *newbuf = curlx_realloc(ctx->tunnel_inbuf,
                                            max_udp_payload);
      if(!newbuf)
        return CURLE_OUT_OF_MEMORY;
      ctx->tunnel_inbuf = newbuf;
      ctx->tunnel_inbuf_len = max_udp_payload;
    }
    buf = ctx->tunnel_inbuf;

    while(pkt_limit--) {
      result = Curl_conn_cf_recv(cf->next, data, (char *)buf,
                                 ctx->tunnel_inbuf_len, &nread);
      if(result == CURLE_AGAIN) {
        /* no more data available at the moment */
        return CURLE_OK;
      }
      if(result) {
        CURL_TRC_CF(data, cf, "ingress, recv from tunnel failed: %d",
                    (int)result);
        return result;
      }
      if(nread == 0) {
        /* tunnel closed */
        return CURLE_OK;
      }

      memcpy(&remote_addr, ctx->connected_path.remote.addr,
             ctx->connected_path.remote.addrlen);
      remote_addrlen = (socklen_t)ctx->connected_path.remote.addrlen;
      result = cf_ngtcp2_recv_pkts(buf, nread, nread, &remote_addr,
                                   remote_addrlen, 0, &rctx);
      if(result)
        return result;

      if(!ctx->q.got_first_byte) {
        ctx->q.got_first_byte = TRUE;
        ctx->q.first_byte_at = ctx->q.last_op;
      }
      ctx->q.last_io = ctx->q.last_op;
    }
    return CURLE_OK;
  }
}

/**
 * Connection maintenance like timeouts on packet ACKs etc. are done by us, not
 * the OS like for TCP. POLL events on the socket therefore are not
 * sufficient.
 * ngtcp2 tells us when it wants to be invoked again. We handle that via
 * the `Curl_expire()` mechanisms.
 */
CURLcode Curl_cf_ngtcp2_cmn_set_expiry(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       struct cf_ngtcp2_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_ngtcp2_io_ctx local_pktx;
  ngtcp2_tstamp expiry;

  if(!pktx) {
    Curl_cf_ngtcp2_io_ctx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    Curl_cf_ngtcp2_io_ctx_update_time(data, pktx, cf);
  }

  expiry = ngtcp2_conn_get_expiry(ctx->qconn);
  if(expiry != UINT64_MAX) {
    if(expiry <= pktx->ts) {
      CURLcode result;
      int rv = ngtcp2_conn_handle_expiry(ctx->qconn, pktx->ts);
      if(rv) {
        failf(data, "ngtcp2_conn_handle_expiry returned error: %s",
              ngtcp2_strerror(rv));
        Curl_cf_ngtcp2_cmn_err_set(cf, data, rv);
        return CURLE_SEND_ERROR;
      }
      result = Curl_cf_ngtcp2_progress_ingress(cf, data, pktx);
      if(result)
        return result;
      result = Curl_cf_ngtcp2_progress_egress(cf, data, pktx);
      if(result)
        return result;
      /* ask again, things might have changed */
      expiry = ngtcp2_conn_get_expiry(ctx->qconn);
    }

    if(expiry > pktx->ts) {
      ngtcp2_duration timeout = expiry - pktx->ts;
      if(timeout % NGTCP2_MILLISECONDS) {
        timeout += NGTCP2_MILLISECONDS;
      }
      Curl_expire(data, (timediff_t)(timeout / NGTCP2_MILLISECONDS),
                  EXPIRE_QUIC);
    }
  }
  return CURLE_OK;
}

static ngtcp2_duration
cf_ngtcp2_effective_idle_timeout(struct cf_ngtcp2_ctx *ctx)
{
  const ngtcp2_transport_params *lp;
  const ngtcp2_transport_params *rp;
  ngtcp2_duration timeout = 0;

  if(!ctx->qconn)
    return 0;

  lp = ngtcp2_conn_get_local_transport_params(ctx->qconn);
  rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
  if(lp)
    timeout = lp->max_idle_timeout;
  if(rp && rp->max_idle_timeout &&
     (!timeout || rp->max_idle_timeout < timeout))
    timeout = rp->max_idle_timeout;
  return timeout;
}

static void cf_ngtcp2_setup_keep_alive(struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  ngtcp2_duration idle_timeout;

  /* If either endpoint announces a positive `max_idle_timeout`, the
   * connection closes when it remains idle for the effective timeout.
   *
   * Some servers use this as a keep-alive timer at a rather low
   * value. We are doing HTTP/3 here and waiting for the response
   * to a request may take a considerable amount of time. We need
   * to prevent the peer's QUIC stack from closing in this case.
   */
  if(!ctx->qconn)
    return;

  idle_timeout = cf_ngtcp2_effective_idle_timeout(ctx);
  if(!idle_timeout) {
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, UINT64_MAX);
    CURL_TRC_CF(data, cf, "no idle timeout, unset keep-alive");
  }
  else if(!Curl_uint32_hash_count(&ctx->streams)) {
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, UINT64_MAX);
    CURL_TRC_CF(data, cf, "no active streams, unset keep-alive");
  }
  else {
    ngtcp2_duration keep_ns;
    keep_ns = (idle_timeout > 1) ? (idle_timeout / 2) : 1;
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, keep_ns);
    CURL_TRC_CF(data, cf, "effective idle timeout is %" PRIu64 "ms, "
                "set keep-alive to %" PRIu64 " ms.",
                (idle_timeout / NGTCP2_MILLISECONDS),
                (keep_ns / NGTCP2_MILLISECONDS));
  }
}

CURLcode Curl_cf_ngtcp2_h3_stream_setup(struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  if(!data)
    return CURLE_FAILED_INIT;

  if(stream)
    return CURLE_OK;

  stream = curlx_calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->id = -1;
  stream->rx_offset = 0;
  stream->rx_offset_max = H3_STREAM_WINDOW_SIZE_INITIAL;

  /* on send, we control how much we put into the buffer */
  Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                  H3_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  stream->sendbuf_len_in_flight = 0;
  stream->window_size_max = H3_STREAM_WINDOW_SIZE_INITIAL;
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);

  if(!Curl_uint32_hash_set(&ctx->streams, data->mid, stream)) {
    Curl_cf_ngtcp2_h3_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  if(Curl_uint32_hash_count(&ctx->streams) == 1)
    cf_ngtcp2_setup_keep_alive(cf, data);

  return CURLE_OK;
}

void Curl_cf_ngtcp2_h3_stream_close(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct h3_stream_ctx *stream)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  DEBUGASSERT(data);
  DEBUGASSERT(stream);
  if(!stream->closed && ctx->qconn && ctx->h3conn) {
    CURLcode result;

    nghttp3_conn_set_stream_user_data(ctx->h3conn, stream->id, NULL);
    ngtcp2_conn_set_stream_user_data(ctx->qconn, stream->id, NULL);
    stream->closed = TRUE;
    (void)ngtcp2_conn_shutdown_stream(ctx->qconn, 0, stream->id,
                                      NGHTTP3_H3_REQUEST_CANCELLED);
    result = Curl_cf_ngtcp2_progress_egress(cf, data, NULL);
    if(result)
      CURL_TRC_CF(data, cf, "[%" PRId64 "] cancel stream -> %d",
                  stream->id, (int)result);
  }
}

void Curl_cf_ngtcp2_h3_stream_done(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)cf;
  if(stream) {
    CURL_TRC_CF(data, cf, "[%" PRId64 "] easy handle is done", stream->id);
    Curl_cf_ngtcp2_h3_stream_close(cf, data, stream);
    Curl_uint32_hash_remove(&ctx->streams, data->mid);
    if(!Curl_uint32_hash_count(&ctx->streams))
      cf_ngtcp2_setup_keep_alive(cf, data);
  }
}

bool Curl_cf_ngtcp2_cmn_conn_is_alive(struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *input_pending)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  bool alive = FALSE;
  bool expiry_handled = FALSE;
  ngtcp2_tstamp expiry;
  ngtcp2_tstamp now_ts;
  const struct curltime *now;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  *input_pending = FALSE;
  if(!ctx->qconn || ctx->shutdown_started)
    goto out;

  /* Let ngtcp2 apply all timer rules, including the negotiated idle timeout,
   * the 3 PTO minimum and the QUIC idle timer reset rules. */
  now = Curl_pgrs_now(data);
  now_ts = ((ngtcp2_tstamp)now->tv_sec * NGTCP2_SECONDS) +
           ((ngtcp2_tstamp)now->tv_usec * NGTCP2_MICROSECONDS);
  expiry = ngtcp2_conn_get_expiry(ctx->qconn);
  if((expiry != UINT64_MAX) && (expiry <= now_ts)) {
    int rv = ngtcp2_conn_handle_expiry(ctx->qconn, now_ts);
    if(rv) {
      Curl_cf_ngtcp2_cmn_err_set(cf, data, rv);
      goto out;
    }
    expiry_handled = TRUE;
  }

  if(!cf->next || !cf->next->cft->is_alive(cf->next, data, input_pending))
    goto out;

  alive = TRUE;
  if(*input_pending) {
    CURLcode result;
    /* This happens before we have sent off a request and the connection is
       not in use by any other transfer, there should not be any data here,
       only "protocol frames" */
    *input_pending = FALSE;
    result = Curl_cf_ngtcp2_progress_ingress(cf, data, NULL);
    CURL_TRC_CF(data, cf, "is_alive, progress ingress -> %d", (int)result);
    alive = result ? FALSE : TRUE;
  }
  if(alive && expiry_handled) {
    CURLcode result = Curl_cf_ngtcp2_progress_egress(cf, data, NULL);
    CURL_TRC_CF(data, cf, "is_alive, progress egress -> %d", (int)result);
    alive = result ? FALSE : TRUE;
  }

out:
  CF_DATA_RESTORE(cf, save);
  return alive;
}

CURLcode Curl_cf_ngtcp2_h3_init_ctrls(struct cf_ngtcp2_ctx *ctx,
                                      struct Curl_easy *data)
{
  int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
  int rc;

  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &ctrl_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 control stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }
  rc = nghttp3_conn_bind_control_stream(ctx->h3conn, ctrl_stream_id);
  if(rc) {
    failf(data, "error binding HTTP/3 control stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }
  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &qpack_enc_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 qpack encoding stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }
  rc = ngtcp2_conn_open_uni_stream(ctx->qconn, &qpack_dec_stream_id, NULL);
  if(rc) {
    failf(data, "error creating HTTP/3 qpack decoding stream: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }
  rc = nghttp3_conn_bind_qpack_streams(ctx->h3conn, qpack_enc_stream_id,
                                       qpack_dec_stream_id);
  if(rc) {
    failf(data, "error binding HTTP/3 qpack streams: %s", ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }
  return CURLE_OK;
}

#endif /* !CURL_DISABLE_HTTP && USE_NGTCP2 && USE_NGHTTP3 */
