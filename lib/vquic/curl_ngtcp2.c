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

#include "../curl_setup.h"

#if defined(USE_NGTCP2) && defined(USE_NGHTTP3)
#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#ifdef USE_OPENSSL
#include <openssl/err.h>
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#elif defined(OPENSSL_QUIC_API2)
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#else
#include <ngtcp2/ngtcp2_crypto_quictls.h>
#endif
#include "../vtls/openssl.h"
#elif defined(USE_GNUTLS)
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include "../vtls/gtls.h"
#elif defined(USE_WOLFSSL)
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>
#include "../vtls/wolfssl.h"
#endif

#include "../urldata.h"
#include "../url.h"
#include "../uint-hash.h"
#include "../sendf.h"
#include "../strdup.h"
#include "../rand.h"
#include "../multiif.h"
#include "../cfilters.h"
#include "../cf-socket.h"
#include "../connect.h"
#include "../socks.h"
#include "../progress.h"
#include "../strerror.h"
#include "../strcase.h"
#include "../curlx/dynbuf.h"
#include "../http1.h"
#include "../select.h"
#include "../curlx/inet_pton.h"
#include "../transfer.h"
#include "vquic.h"
#include "vquic_int.h"
#include "vquic-tls.h"
#include "../vtls/keylog.h"
#include "../vtls/vtls.h"
#include "../vtls/vtls_scache.h"
#include "curl_ngtcp2.h"

#include "../curlx/warnless.h"

/* The last 3 #include files should be in this order */
#include "../curl_printf.h"
#include "../curl_memory.h"
#include "../memdebug.h"


#define QUIC_MAX_STREAMS (256*1024)
#define QUIC_MAX_DATA (1*1024*1024)
#define QUIC_HANDSHAKE_TIMEOUT (10*NGTCP2_SECONDS)

/* A stream window is the maximum amount we need to buffer for
 * each active transfer. We use HTTP/3 flow control and only ACK
 * when we take things out of the buffer.
 * Chunk size is large enough to take a full DATA frame */
#define H3_STREAM_WINDOW_SIZE (128 * 1024)

static const struct alpn_spec ALPN_SPEC_H3 = {
  { "h3" }, 1
};

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
    if(!got_sock && (psock || pip)) {
      if(!Curl_cf_socket_peek(cf, data, psock, NULL, pip)) {
        got_sock = (psock != NULL);
        got_ip = (pip != NULL);
      }
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
#define H3_STREAM_CHUNK_SIZE   (16 * 1024)
#if H3_STREAM_CHUNK_SIZE < NGTCP2_MAX_UDP_PAYLOAD_SIZE
#error H3_STREAM_CHUNK_SIZE smaller than NGTCP2_MAX_UDP_PAYLOAD_SIZE
#endif

/* The pool keeps spares around and half of a full stream windows
 * seems good. More does not seem to improve performance.
 * The benefit of the pool is that stream buffer to not keep
 * spares. Memory consumption goes down when streams run empty,
 * have a large upload done, etc. */
#define H3_STREAM_POOL_SPARES \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE ) / 2
/* Receive and Send max number of chunks just follows from the
 * chunk size and window size */
#define H3_STREAM_RECV_CHUNKS \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)
#define H3_STREAM_SEND_CHUNKS \
          (H3_STREAM_WINDOW_SIZE / H3_STREAM_CHUNK_SIZE)


/*
 * Store ngtcp2 version info in this buffer.
 */
void Curl_ngtcp2_ver(char *p, size_t len)
{
  const ngtcp2_info *ng2 = ngtcp2_version(0);
  const nghttp3_info *ht3 = nghttp3_version(0);
  (void)msnprintf(p, len, "ngtcp2/%s nghttp3/%s",
                  ng2->version_str, ht3->version_str);
}

struct cf_ngtcp2_ctx {
  struct cf_quic_ctx q;
  struct ssl_peer peer;
  struct curl_tls_ctx tls;
#ifdef OPENSSL_QUIC_API2
  ngtcp2_crypto_ossl_ctx *ossl_ctx;
#endif
  ngtcp2_path connected_path;
  ngtcp2_conn *qconn;
  ngtcp2_cid dcid;
  ngtcp2_cid scid;
  uint32_t version;
  ngtcp2_settings settings;
  ngtcp2_transport_params transport_params;
  ngtcp2_ccerr last_error;
  ngtcp2_crypto_conn_ref conn_ref;
  struct cf_call_data call_data;
  nghttp3_conn *h3conn;
  nghttp3_settings h3settings;
  struct curltime started_at;        /* time the current attempt started */
  struct curltime handshake_at;      /* time connect handshake finished */
  struct bufc_pool stream_bufcp;     /* chunk pool for streams */
  struct dynbuf scratch;             /* temp buffer for header construction */
  struct dynbuf tp_raw;              /* serialized local QUIC TP bytes */
  struct uint_hash streams;          /* hash `data->mid` to `h3_stream_ctx` */
  size_t max_stream_window;          /* max flow window for one stream */
  uint64_t used_bidi_streams;        /* bidi streams we have opened */
  uint64_t max_bidi_streams;         /* max bidi streams we can open */
  size_t earlydata_max;              /* max amount of early data supported by
                                        server on session reuse */
  size_t earlydata_skip;            /* sending bytes to skip when earlydata
                                     * is accepted by peer */
  CURLcode tls_vrfy_result;          /* result of TLS peer verification */
  int qlogfd;
  BIT(initialized);
  BIT(tls_handshake_complete);       /* TLS handshake is done */
  BIT(use_earlydata);                /* Using 0RTT data */
  BIT(earlydata_accepted);           /* 0RTT was acceptd by server */
  BIT(shutdown_started);             /* queued shutdown packets */
};

/* How to access `call_data` from a cf_ngtcp2 filter */
#undef CF_CTX_CALL_DATA
#define CF_CTX_CALL_DATA(cf)  \
  ((struct cf_ngtcp2_ctx *)(cf)->ctx)->call_data

static void h3_stream_hash_free(unsigned int id, void *stream);

static void cf_ngtcp2_ctx_init(struct cf_ngtcp2_ctx *ctx)
{
  DEBUGASSERT(!ctx->initialized);
  ctx->qlogfd = -1;
  ctx->version = NGTCP2_PROTO_VER_MAX;
  ctx->max_stream_window = H3_STREAM_WINDOW_SIZE;
  Curl_bufcp_init(&ctx->stream_bufcp, H3_STREAM_CHUNK_SIZE,
                  H3_STREAM_POOL_SPARES);
  curlx_dyn_init(&ctx->scratch, CURL_MAX_HTTP_HEADER);
  curlx_dyn_init(&ctx->tp_raw, CURL_MAX_INPUT_LENGTH);
  Curl_uint_hash_init(&ctx->streams, 63, h3_stream_hash_free);
  ctx->initialized = TRUE;
}

static void cf_ngtcp2_ctx_free(struct cf_ngtcp2_ctx *ctx)
{
  if(ctx && ctx->initialized) {
    Curl_vquic_tls_cleanup(&ctx->tls);
    vquic_ctx_free(&ctx->q);
    Curl_bufcp_free(&ctx->stream_bufcp);
    curlx_dyn_free(&ctx->scratch);
    curlx_dyn_free(&ctx->tp_raw);
    Curl_uint_hash_destroy(&ctx->streams);
    Curl_ssl_peer_cleanup(&ctx->peer);
  }
  free(ctx);
}

static void cf_ngtcp2_setup_keep_alive(struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  const ngtcp2_transport_params *rp;
  /* Peer should have sent us its transport parameters. If it
  * announces a positive `max_idle_timeout` it will close the
  * connection when it does not hear from us for that time.
  *
  * Some servers use this as a keep-alive timer at a rather low
  * value. We are doing HTTP/3 here and waiting for the response
  * to a request may take a considerable amount of time. We need
  * to prevent the peer's QUIC stack from closing in this case.
  */
  if(!ctx->qconn)
    return;

  rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
  if(!rp || !rp->max_idle_timeout) {
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, UINT64_MAX);
    CURL_TRC_CF(data, cf, "no peer idle timeout, unset keep-alive");
  }
  else if(!Curl_uint_hash_count(&ctx->streams)) {
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, UINT64_MAX);
    CURL_TRC_CF(data, cf, "no active streams, unset keep-alive");
  }
  else {
    ngtcp2_duration keep_ns;
    keep_ns = (rp->max_idle_timeout > 1) ? (rp->max_idle_timeout / 2) : 1;
    ngtcp2_conn_set_keep_alive_timeout(ctx->qconn, keep_ns);
    CURL_TRC_CF(data, cf, "peer idle timeout is %" FMT_PRIu64 "ms, "
                "set keep-alive to %" FMT_PRIu64 " ms.",
                (curl_uint64_t)(rp->max_idle_timeout / NGTCP2_MILLISECONDS),
                (curl_uint64_t)(keep_ns / NGTCP2_MILLISECONDS));
  }
}


struct pkt_io_ctx;
static CURLcode cf_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct pkt_io_ctx *pktx);
static CURLcode cf_progress_egress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct pkt_io_ctx *pktx);

/**
 * All about the H3 internals of a stream
 */
struct h3_stream_ctx {
  curl_int64_t id; /* HTTP/3 protocol identifier */
  struct bufq sendbuf;   /* h3 request body */
  struct h1_req_parser h1; /* h1 request parsing */
  size_t sendbuf_len_in_flight; /* sendbuf amount "in flight" */
  curl_uint64_t error3; /* HTTP/3 stream error code */
  curl_off_t upload_left; /* number of request bytes left to upload */
  int status_code; /* HTTP status code */
  CURLcode xfer_result; /* result from xfer_resp_write(_hd) */
  BIT(resp_hds_complete); /* we have a complete, final response */
  BIT(closed); /* TRUE on stream close */
  BIT(reset);  /* TRUE on stream reset */
  BIT(send_closed); /* stream is local closed */
  BIT(quic_flow_blocked); /* stream is blocked by QUIC flow control */
};

static void h3_stream_ctx_free(struct h3_stream_ctx *stream)
{
  Curl_bufq_free(&stream->sendbuf);
  Curl_h1_req_parse_free(&stream->h1);
  free(stream);
}

static void h3_stream_hash_free(unsigned int id, void *stream)
{
  (void)id;
  DEBUGASSERT(stream);
  h3_stream_ctx_free((struct h3_stream_ctx *)stream);
}

static CURLcode h3_data_setup(struct Curl_cfilter *cf,
                              struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  if(!data)
    return CURLE_FAILED_INIT;

  if(stream)
    return CURLE_OK;

  stream = calloc(1, sizeof(*stream));
  if(!stream)
    return CURLE_OUT_OF_MEMORY;

  stream->id = -1;
  /* on send, we control how much we put into the buffer */
  Curl_bufq_initp(&stream->sendbuf, &ctx->stream_bufcp,
                  H3_STREAM_SEND_CHUNKS, BUFQ_OPT_NONE);
  stream->sendbuf_len_in_flight = 0;
  Curl_h1_req_parse_init(&stream->h1, H1_PARSE_DEFAULT_MAX_LINE_LEN);

  if(!Curl_uint_hash_set(&ctx->streams, data->mid, stream)) {
    h3_stream_ctx_free(stream);
    return CURLE_OUT_OF_MEMORY;
  }

  if(Curl_uint_hash_count(&ctx->streams) == 1)
    cf_ngtcp2_setup_keep_alive(cf, data);

  return CURLE_OK;
}

static void cf_ngtcp2_stream_close(struct Curl_cfilter *cf,
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
    result = cf_progress_egress(cf, data, NULL);
    if(result)
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cancel stream -> %d",
                  stream->id, result);
  }
}

static void h3_data_done(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)cf;
  if(stream) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] easy handle is done",
                stream->id);
    cf_ngtcp2_stream_close(cf, data, stream);
    Curl_uint_hash_remove(&ctx->streams, data->mid);
    if(!Curl_uint_hash_count(&ctx->streams))
      cf_ngtcp2_setup_keep_alive(cf, data);
  }
}

/* ngtcp2 default congestion controller does not perform pacing. Limit
   the maximum packet burst to MAX_PKT_BURST packets. */
#define MAX_PKT_BURST 10

struct pkt_io_ctx {
  struct Curl_cfilter *cf;
  struct Curl_easy *data;
  ngtcp2_tstamp ts;
  ngtcp2_path_storage ps;
};

static void pktx_update_time(struct pkt_io_ctx *pktx,
                             struct Curl_cfilter *cf)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;

  vquic_ctx_update_time(&ctx->q);
  pktx->ts = (ngtcp2_tstamp)ctx->q.last_op.tv_sec * NGTCP2_SECONDS +
             (ngtcp2_tstamp)ctx->q.last_op.tv_usec * NGTCP2_MICROSECONDS;
}

static void pktx_init(struct pkt_io_ctx *pktx,
                      struct Curl_cfilter *cf,
                      struct Curl_easy *data)
{
  pktx->cf = cf;
  pktx->data = data;
  ngtcp2_path_storage_zero(&pktx->ps);
  pktx_update_time(pktx, cf);
}

static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                uint64_t datalen, void *user_data,
                                void *stream_user_data);

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
  struct Curl_cfilter *cf = conn_ref->user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  return ctx->qconn;
}

#ifdef DEBUG_NGTCP2
static void quic_printf(void *user_data, const char *fmt, ...)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;

  (void)ctx;  /* need an easy handle to infof() message */
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
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
      close(ctx->qlogfd);
      ctx->qlogfd = -1;
    }
  }

}

static CURLcode quic_transport_params_from_string(ngtcp2_transport_params *t,
                                                  struct dynbuf *raw,
                                                  const ngtcp2_cid *scid,
                                                  struct Curl_easy *data);
static bool quic_has_empty_initial_scid(const char *params);

static CURLcode quic_settings(struct cf_ngtcp2_ctx *ctx,
                              struct Curl_easy *data,
                              struct pkt_io_ctx *pktx)
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
  s->handshake_timeout = QUIC_HANDSHAKE_TIMEOUT;
  s->max_window = 100 * ctx->max_stream_window;
  s->max_stream_window = 10 * ctx->max_stream_window;

  t->initial_max_data = 10 * ctx->max_stream_window;
  t->initial_max_stream_data_bidi_local = ctx->max_stream_window;
  t->initial_max_stream_data_bidi_remote = ctx->max_stream_window;
  t->initial_max_stream_data_uni = ctx->max_stream_window;
  t->initial_max_streams_bidi = QUIC_MAX_STREAMS;
  t->initial_max_streams_uni = QUIC_MAX_STREAMS;
  t->max_idle_timeout = 0; /* no idle timeout from our side */
  if(ctx->qlogfd != -1) {
    s->qlog_write = qlog_callback;
  }
  curlx_dyn_reset(&ctx->tp_raw);
  result = quic_transport_params_from_string(t, &ctx->tp_raw, &ctx->scid,
                                             data);
  if(result)
    return result;

  return CURLE_OK;
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

// https://www.iana.org/assignments/quic/quic.xhtml
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
    failf(data, "QUIC transport param %" FMT_PRIu64 " is server-only",
          (curl_uint64_t)id);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case 0x0f: /* initial_source_connection_id (set by library) */
    failf(data, "QUIC transport param %" FMT_PRIu64
          " is managed by the library", (curl_uint64_t)id);
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
    infof(data, "QUIC transport param %" FMT_PRIu64
          " is not mapped to ngtcp2_transport_params",
          (curl_uint64_t)id);
    break;
  }

  return CURLE_OK;
}

#define QUIC_VARINT_MAX UINT64_C(0x3fffffffffffffff)
#define QUIC_TP_INITIAL_SOURCE_CONNECTION_ID UINT64_C(0x0f)
#define QUIC_TP_VERSION_INFORMATION          UINT64_C(0x11)
#define QUIC_TP_VERSION_INFORMATION_DRAFT    UINT64_C(0xff73db)
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
                                                uint64_t id,
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

  tmp = strdup(value_str);
  if(!tmp)
    return CURLE_OUT_OF_MEMORY;

  sep = strchr(tmp, '@');
  if(!sep || !*tmp || !*(sep + 1)) {
    free(tmp);
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

  result = quic_raw_append_param_bytes(raw, id,
                                       (const uint8_t *)curlx_dyn_ptr(&vb),
                                       curlx_dyn_len(&vb));

out:
  free(tmp);
  curlx_dyn_free(&vb);
  return result;
}

static bool quic_tp_is_version_information(uint64_t id)
{
  return id == QUIC_TP_VERSION_INFORMATION ||
         id == QUIC_TP_VERSION_INFORMATION_DRAFT;
}

static CURLcode quic_transport_params_from_string(ngtcp2_transport_params *t,
                                                  struct dynbuf *raw,
                                                  const ngtcp2_cid *scid,
                                                  struct Curl_easy *data)
{
  const char *params = data->set.str[STRING_QUIC_TRANSPORT_PARAMETERS];
  bool permute = data->set.ssl_permute_extensions;
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

  tmp = strdup(params);
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
      newtokens = realloc(tokens, newalloc * sizeof(*tokens));
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

    if(curl_strequal(setting, "version_information"))
      id = QUIC_TP_VERSION_INFORMATION;
    else if(curl_strequal(setting, "version_information_draft"))
      id = QUIC_TP_VERSION_INFORMATION_DRAFT;
    else {
      int base = (setting[0] == '0' && (setting[1] == 'x' ||
                                        setting[1] == 'X')) ? 16 : 10;

      id = strtoull(setting, &end, base);
      if(!*setting || (end && *end)) {
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
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
      else if(quic_tp_is_version_information(id)) {
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

    if(has_value && quic_tp_is_version_information(id)) {
      result = quic_append_version_information(raw, id, value_str, data);
      if(result)
        goto out;
      continue;
    }
    if(id == QUIC_TP_GOOGLE_VERSION) {
      unsigned char ver[4];

      if(!has_value || (value > UINT_MAX)) {
        failf(data, "QUIC transport param %" FMT_PRIu64
              " requires a 32-bit version value", (curl_uint64_t)id);
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
        failf(data, "QUIC transport param %" FMT_PRIu64
              " has invalid hex value", (curl_uint64_t)id);
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      byte_len = hex_len / 2;
      bytes = malloc(byte_len);
      if(!bytes) {
        result = CURLE_OUT_OF_MEMORY;
        goto out;
      }
      for(j = 0; j < byte_len; j++) {
        unsigned int byte_val;
        if(sscanf(hex + 2 * j, "%2x", &byte_val) != 1) {
          free(bytes);
          failf(data, "QUIC transport param %" FMT_PRIu64
                " has invalid hex value", (curl_uint64_t)id);
          result = CURLE_BAD_FUNCTION_ARGUMENT;
          goto out;
        }
        bytes[j] = (unsigned char)byte_val;
      }
      result = quic_raw_append_param_bytes(raw, id, bytes, byte_len);
      free(bytes);
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
  free(tokens);
  free(tmp);
  return result;
}

static void h3_apply_setting(nghttp3_settings *settings,
                             unsigned long id, uint64_t value)
{
  switch(id) {
  case 1: /* SETTINGS_QPACK_MAX_TABLE_CAPACITY */
    if(value > SIZE_T_MAX)
      value = SIZE_T_MAX;
    settings->qpack_max_dtable_capacity = (size_t)value;
    settings->qpack_encoder_max_dtable_capacity = (size_t)value;
    break;
  case 6: /* SETTINGS_MAX_FIELD_SECTION_SIZE */
    settings->max_field_section_size = value;
    break;
  case 7: /* SETTINGS_QPACK_BLOCKED_STREAMS */
    if(value > SIZE_T_MAX)
      value = SIZE_T_MAX;
    settings->qpack_blocked_streams = (size_t)value;
    break;
  case 8: /* SETTINGS_ENABLE_CONNECT_PROTOCOL */
    settings->enable_connect_protocol = (uint8_t)(value ? 1 : 0);
    break;
  case 51: /* SETTINGS_H3_DATAGRAM */
    settings->h3_datagram = (uint8_t)(value ? 1 : 0);
    break;
  default:
    break;
  }
}

static bool h3_setting_supported(unsigned long id)
{
  switch(id) {
  case 1:
  case 6:
  case 7:
  case 8:
  case 51:
  case 727725890:
  case 16765559:
    return TRUE;
  default:
    return FALSE;
  }
}

/* HTTP/3 GREASE setting identifiers follow: 0x1f * N + 0x21 */
#define H3_SETTINGS_GREASE_ID_BASE  UINT64_C(0x21)
#define H3_SETTINGS_GREASE_ID_STEP  UINT64_C(0x1f)

/* Chrome uses a narrower uint32_t range than RFC 9114 allows:
   https://quiche.googlesource.com/quiche/+/refs/heads/main/quiche/quic/core/http/quic_send_control_stream.cc */
static bool h3_rand_u32(struct Curl_easy *data, uint32_t *val)
{
  unsigned char rnd[sizeof(uint32_t)];
  CURLcode result;
  size_t i;

  result = Curl_rand(data, rnd, sizeof(rnd));
  if(result)
    return FALSE;

  *val = 0;
  for(i = 0; i < sizeof(rnd); ++i)
    *val = (*val << 8) | rnd[i];

  return TRUE;
}

static bool h3_generate_grease_setting(struct Curl_easy *data,
                                       nghttp3_settings_entry *iv)
{
  uint32_t n;
  uint32_t value;

  if(!h3_rand_u32(data, &n) || !h3_rand_u32(data, &value))
    return FALSE;

  iv->id = (H3_SETTINGS_GREASE_ID_STEP * (uint64_t)n) +
           H3_SETTINGS_GREASE_ID_BASE;
  iv->value = value;
  return TRUE;
}

static size_t h3_settings_count(const char *h3_settings)
{
  size_t count = 0;

  if(h3_settings && *h3_settings) {
    const char *p;

    count = 1;
    for(p = h3_settings; *p; ++p) {
      if(*p == ';')
        ++count;
    }
  }

  return count;
}

static size_t populate_h3_settings(nghttp3_settings_entry *iv,
                                   size_t ivlen,
                                   nghttp3_settings *settings,
                                   struct Curl_easy *data)
{
  const char *h3_settings = data->set.str[STRING_HTTP3_SETTINGS];
  char *tmp;
  char *setting;
  size_t i = 0;

  if(!h3_settings || !*h3_settings)
    return 0;

  tmp = strdup(h3_settings);
  if(!tmp)
    return 0;

  setting = strtok(tmp, ";");
  while(setting) {
    char *colon = strchr(setting, ':');
    char *end = NULL;
    unsigned long id;
    unsigned long long value;

    if(curl_strequal(setting, "GREASE")) {
      if(iv && (i < ivlen)) {
        if(h3_generate_grease_setting(data, &iv[i]))
          ++i;
      }
      setting = strtok(NULL, ";");
      continue;
    }

    if(!colon) {
      setting = strtok(NULL, ";");
      continue;
    }
    *colon = '\0';
    id = strtoul(setting, &end, 10);
    if(!*setting || (end && *end)) {
      setting = strtok(NULL, ";");
      continue;
    }
    value = strtoull(colon + 1, &end, 10);
    if(!*(colon + 1) || (end && *end)) {
      setting = strtok(NULL, ";");
      continue;
    }

    if(!h3_setting_supported(id)) {
      setting = strtok(NULL, ";");
      continue;
    }

    h3_apply_setting(settings, id, (uint64_t)value);
    if(iv && (i < ivlen)) {
      iv[i].id = id;
      iv[i].value = (uint64_t)value;
      ++i;
    }
    setting = strtok(NULL, ";");
  }

  free(tmp);
  return i;
}

static CURLcode init_ngh3_conn(struct Curl_cfilter *cf,
                               struct Curl_easy *data);

static int cf_ngtcp2_handshake_completed(ngtcp2_conn *tconn, void *user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf ? cf->ctx : NULL;
  struct Curl_easy *data;

  (void)tconn;
  DEBUGASSERT(ctx);
  data = CF_DATA_CURRENT(cf);
  DEBUGASSERT(data);
  if(!ctx || !data)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  ctx->handshake_at = curlx_now();
  ctx->tls_handshake_complete = TRUE;
  cf->conn->bits.multiplex = TRUE; /* at least potentially multiplexed */
  Curl_vquic_report_handshake(&ctx->tls, cf, data);

  ctx->tls_vrfy_result = Curl_vquic_tls_verify_peer(&ctx->tls, cf,
                                                    data, &ctx->peer);
  CURL_TRC_CF(data, cf, "handshake complete after %dms",
             (int)curlx_timediff(ctx->handshake_at, ctx->started_at));
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

static void cf_ngtcp2_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data);

static bool cf_ngtcp2_err_is_fatal(int code)
{
  return (NGTCP2_ERR_FATAL >= code) ||
         (NGTCP2_ERR_DROP_CONN == code) ||
         (NGTCP2_ERR_IDLE_CLOSE == code);
}

static void cf_ngtcp2_err_set(struct Curl_cfilter *cf,
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
    cf_ngtcp2_conn_close(cf, data);
}

static bool cf_ngtcp2_h3_err_is_fatal(int code)
{
  return (NGHTTP3_ERR_FATAL >= code) ||
         (NGHTTP3_ERR_H3_CLOSED_CRITICAL_STREAM == code);
}

static void cf_ngtcp2_h3_err_set(struct Curl_cfilter *cf,
                                 struct Curl_easy *data, int code)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  if(!ctx->last_error.error_code) {
    ngtcp2_ccerr_set_application_error(&ctx->last_error,
      nghttp3_err_infer_quic_app_error_code(code), NULL, 0);
  }
  if(cf_ngtcp2_h3_err_is_fatal(code))
    cf_ngtcp2_conn_close(cf, data);
}

static int cb_recv_stream_data(ngtcp2_conn *tconn, uint32_t flags,
                               int64_t sid, uint64_t offset,
                               const uint8_t *buf, size_t buflen,
                               void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  nghttp3_ssize nconsumed;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  struct Curl_easy *data = stream_user_data;
  (void)offset;
  (void)data;

  nconsumed =
    nghttp3_conn_read_stream(ctx->h3conn, stream_id, buf, buflen, fin);
  if(!data)
    data = CF_DATA_CURRENT(cf);
  if(data)
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read_stream(len=%zu) -> %zd",
                stream_id, buflen, nconsumed);
  if(nconsumed < 0) {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if(data && stream) {
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] error on known stream, "
                  "reset=%d, closed=%d",
                  stream_id, stream->reset, stream->closed);
    }
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* number of bytes inside buflen which consists of framing overhead
   * including QPACK HEADERS. In other words, it does not consume payload of
   * DATA frame. */
  ngtcp2_conn_extend_max_stream_offset(tconn, stream_id, (uint64_t)nconsumed);
  ngtcp2_conn_extend_max_offset(tconn, (uint64_t)nconsumed);

  return 0;
}

static int
cb_acked_stream_data_offset(ngtcp2_conn *tconn, int64_t stream_id,
                            uint64_t offset, uint64_t datalen, void *user_data,
                            void *stream_user_data)
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
                           int64_t sid, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = (curl_int64_t)sid;
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
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] quic close(app_error=%"
              FMT_PRIu64 ") -> %d", stream_id, (curl_uint64_t)app_error_code,
              rv);
  if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
    cf_ngtcp2_h3_err_set(cf, data, rv);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_stream_reset(ngtcp2_conn *tconn, int64_t sid,
                           uint64_t final_size, uint64_t app_error_code,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct Curl_easy *data = stream_user_data;
  int rv;
  (void)tconn;
  (void)final_size;
  (void)app_error_code;
  (void)data;

  rv = nghttp3_conn_shutdown_stream_read(ctx->h3conn, stream_id);
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reset -> %d", stream_id, rv);
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
    CURL_TRC_CF(data, cf, "max bidi streams now %" FMT_PRIu64
                ", used %" FMT_PRIu64, (curl_uint64_t)ctx->max_bidi_streams,
                (curl_uint64_t)ctx->used_bidi_streams);
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
    CURL_TRC_CF(s_data, cf, "[%" FMT_PRId64 "] unblock quic flow",
                (curl_int64_t)stream_id);
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
       failed, just fill 0 and call it *random*. */
    memset(dest, 0, destlen);
  }
}

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
  if(ctx && data && !ctx->h3conn) {
    if(init_ngh3_conn(cf, data))
      return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(push)
#  pragma warning(disable:4232) /* MSVC extension, dllimport identity */
#endif

static ngtcp2_callbacks ng_callbacks = {
  ngtcp2_crypto_client_initial_cb,
  NULL, /* recv_client_initial */
  ngtcp2_crypto_recv_crypto_data_cb,
  cf_ngtcp2_handshake_completed,
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
  cb_get_new_connection_id,
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
};

#if defined(_MSC_VER) && defined(_DLL)
#  pragma warning(pop)
#endif

/**
 * Connection maintenance like timeouts on packet ACKs etc. are done by us, not
 * the OS like for TCP. POLL events on the socket therefore are not
 * sufficient.
 * ngtcp2 tells us when it wants to be invoked again. We handle that via
 * the `Curl_expire()` mechanisms.
 */
static CURLcode check_and_set_expiry(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct pkt_io_ctx local_pktx;
  ngtcp2_tstamp expiry;

  if(!pktx) {
    pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    pktx_update_time(pktx, cf);
  }

  expiry = ngtcp2_conn_get_expiry(ctx->qconn);
  if(expiry != UINT64_MAX) {
    if(expiry <= pktx->ts) {
      CURLcode result;
      int rv = ngtcp2_conn_handle_expiry(ctx->qconn, pktx->ts);
      if(rv) {
        failf(data, "ngtcp2_conn_handle_expiry returned error: %s",
              ngtcp2_strerror(rv));
        cf_ngtcp2_err_set(cf, data, rv);
        return CURLE_SEND_ERROR;
      }
      result = cf_progress_ingress(cf, data, pktx);
      if(result)
        return result;
      result = cf_progress_egress(cf, data, pktx);
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

static void cf_ngtcp2_adjust_pollset(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     struct easy_pollset *ps)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  bool want_recv, want_send;

  if(!ctx->qconn)
    return;

  Curl_pollset_check(data, ps, ctx->q.sockfd, &want_recv, &want_send);
  if(!want_send && !Curl_bufq_is_empty(&ctx->q.sendbuf))
    want_send = TRUE;

  if(want_recv || want_send) {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    struct cf_call_data save;
    bool c_exhaust, s_exhaust;

    CF_DATA_SAVE(save, cf, data);
    c_exhaust = want_send && (!ngtcp2_conn_get_cwnd_left(ctx->qconn) ||
                !ngtcp2_conn_get_max_data_left(ctx->qconn));
    s_exhaust = want_send && stream && stream->id >= 0 &&
                stream->quic_flow_blocked;
    want_recv = (want_recv || c_exhaust || s_exhaust);
    want_send = (!s_exhaust && want_send) ||
                 !Curl_bufq_is_empty(&ctx->q.sendbuf);

    Curl_pollset_set(data, ps, ctx->q.sockfd, want_recv, want_send);
    CF_DATA_RESTORE(cf, save);
  }
}

static int cb_h3_stream_close(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)conn;
  (void)stream_id;

  /* we might be called by nghttp3 after we already cleaned up */
  if(!stream)
    return 0;

  stream->closed = TRUE;
  stream->error3 = (curl_uint64_t)app_error_code;
  if(stream->error3 != NGHTTP3_H3_NO_ERROR) {
    stream->reset = TRUE;
    stream->send_closed = TRUE;
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] RESET: error %" FMT_PRIu64,
                stream->id, stream->error3);
  }
  else {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] CLOSED", stream->id);
  }
  Curl_multi_mark_dirty(data);
  return 0;
}

static void h3_xfer_write_resp_hd(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_stream_ctx *stream,
                                  const char *buf, size_t blen, bool eos)
{

  /* If we already encountered an error, skip further writes */
  if(!stream->xfer_result) {
    stream->xfer_result = Curl_xfer_write_resp_hd(data, buf, blen, eos);
    if(stream->xfer_result)
      CURL_TRC_CF(data, cf, "[%"FMT_PRId64"] error %d writing %zu "
                  "bytes of headers", stream->id, stream->xfer_result, blen);
  }
}

static void h3_xfer_write_resp(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               struct h3_stream_ctx *stream,
                               const char *buf, size_t blen, bool eos)
{

  /* If we already encountered an error, skip further writes */
  if(!stream->xfer_result) {
    stream->xfer_result = Curl_xfer_write_resp(data, buf, blen, eos);
    /* If the transfer write is errored, we do not want any more data */
    if(stream->xfer_result) {
      CURL_TRC_CF(data, cf, "[%"FMT_PRId64"] error %d writing %zu bytes "
                  "of data", stream->id, stream->xfer_result, blen);
    }
  }
}

static int cb_h3_recv_data(nghttp3_conn *conn, int64_t stream3_id,
                           const uint8_t *buf, size_t blen,
                           void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);

  (void)conn;
  (void)stream3_id;

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;

  h3_xfer_write_resp(cf, data, stream, (const char *)buf, blen, FALSE);
  if(blen) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] ACK %zu bytes of DATA",
                stream->id, blen);
    ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream->id, blen);
    ngtcp2_conn_extend_max_offset(ctx->qconn, blen);
  }
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] DATA len=%zu", stream->id, blen);
  return 0;
}

static int cb_h3_deferred_consume(nghttp3_conn *conn, int64_t stream3_id,
                                  size_t consumed, void *user_data,
                                  void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  (void)conn;
  (void)stream_user_data;

  /* nghttp3 has consumed bytes on the QUIC stream and we need to
   * tell the QUIC connection to increase its flow control */
  ngtcp2_conn_extend_max_stream_offset(ctx->qconn, stream3_id, consumed);
  ngtcp2_conn_extend_max_offset(ctx->qconn, consumed);
  return 0;
}

static int cb_h3_end_headers(nghttp3_conn *conn, int64_t sid,
                             int fin, void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  (void)conn;
  (void)stream_id;
  (void)fin;
  (void)cf;

  if(!stream)
    return 0;
  /* add a CRLF only if we have received some headers */
  h3_xfer_write_resp_hd(cf, data, stream, STRCONST("\r\n"), stream->closed);

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] end_headers, status=%d",
              stream_id, stream->status_code);
  if(stream->status_code / 100 != 1) {
    stream->resp_hds_complete = TRUE;
  }
  Curl_multi_mark_dirty(data);
  return 0;
}

static int cb_h3_recv_header(nghttp3_conn *conn, int64_t sid,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *user_data, void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  nghttp3_vec h3name = nghttp3_rcbuf_get_buf(name);
  nghttp3_vec h3val = nghttp3_rcbuf_get_buf(value);
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  CURLcode result = CURLE_OK;
  (void)conn;
  (void)stream_id;
  (void)token;
  (void)flags;
  (void)cf;

  /* we might have cleaned up this transfer already */
  if(!stream)
    return 0;

  if(token == NGHTTP3_QPACK_TOKEN__STATUS) {

    result = Curl_http_decode_status(&stream->status_code,
                                     (const char *)h3val.base, h3val.len);
    if(result)
      return -1;
    curlx_dyn_reset(&ctx->scratch);
    result = curlx_dyn_addn(&ctx->scratch, STRCONST("HTTP/3 "));
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch,
                              (const char *)h3val.base, h3val.len);
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch, STRCONST(" \r\n"));
    if(!result)
      h3_xfer_write_resp_hd(cf, data, stream, curlx_dyn_ptr(&ctx->scratch),
                            curlx_dyn_len(&ctx->scratch), FALSE);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] status: %s",
                stream_id, curlx_dyn_ptr(&ctx->scratch));
    if(result) {
      return -1;
    }
  }
  else {
    /* store as an HTTP1-style header */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] header: %.*s: %.*s",
                stream_id, (int)h3name.len, h3name.base,
                (int)h3val.len, h3val.base);
    curlx_dyn_reset(&ctx->scratch);
    result = curlx_dyn_addn(&ctx->scratch,
                            (const char *)h3name.base, h3name.len);
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch, STRCONST(": "));
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch,
                              (const char *)h3val.base, h3val.len);
    if(!result)
      result = curlx_dyn_addn(&ctx->scratch, STRCONST("\r\n"));
    if(!result)
      h3_xfer_write_resp_hd(cf, data, stream, curlx_dyn_ptr(&ctx->scratch),
                            curlx_dyn_len(&ctx->scratch), FALSE);
  }
  return 0;
}

static int cb_h3_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rv;
  (void)conn;
  (void)stream_user_data;

  rv = ngtcp2_conn_shutdown_stream_read(ctx->qconn, 0, stream_id,
                                        app_error_code);
  if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int cb_h3_reset_stream(nghttp3_conn *conn, int64_t sid,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data) {
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  curl_int64_t stream_id = (curl_int64_t)sid;
  struct Curl_easy *data = stream_user_data;
  int rv;
  (void)conn;
  (void)data;

  rv = ngtcp2_conn_shutdown_stream_write(ctx->qconn, 0, stream_id,
                                         app_error_code);
  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] reset -> %d", stream_id, rv);
  if(rv && rv != NGTCP2_ERR_STREAM_NOT_FOUND) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static nghttp3_callbacks ngh3_callbacks = {
  cb_h3_acked_req_body, /* acked_stream_data */
  cb_h3_stream_close,
  cb_h3_recv_data,
  cb_h3_deferred_consume,
  NULL, /* begin_headers */
  cb_h3_recv_header,
  cb_h3_end_headers,
  NULL, /* begin_trailers */
  cb_h3_recv_header,
  NULL, /* end_trailers */
  cb_h3_stop_sending,
  NULL, /* end_stream */
  cb_h3_reset_stream,
  NULL, /* shutdown */
  NULL /* recv_settings */
};

static CURLcode init_ngh3_conn(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int64_t ctrl_stream_id, qpack_enc_stream_id, qpack_dec_stream_id;
  const char *h3_settings = data->set.str[STRING_HTTP3_SETTINGS];
  nghttp3_settings_entry *h3iv = NULL;
  size_t h3ivalloc = 0;
  size_t h3ivlen = 0;
  int rc;

  if(ngtcp2_conn_get_streams_uni_left(ctx->qconn) < 3) {
    failf(data, "QUIC connection lacks 3 uni streams to run HTTP/3");
    return CURLE_QUIC_CONNECT_ERROR;
  }

  h3ivalloc = h3_settings_count(h3_settings);
  if(h3ivalloc) {
    h3iv = malloc(h3ivalloc * sizeof(*h3iv));
    if(!h3iv)
      return CURLE_OUT_OF_MEMORY;
  }

  nghttp3_settings_default(&ctx->h3settings);
  h3ivlen = populate_h3_settings(h3iv, h3ivalloc, &ctx->h3settings, data);

  rc = nghttp3_conn_client_new(&ctx->h3conn,
                               &ngh3_callbacks,
                               &ctx->h3settings,
                               nghttp3_mem_default(),
                               cf);
  if(rc) {
    free(h3iv);
    failf(data, "error creating nghttp3 connection instance");
    return CURLE_OUT_OF_MEMORY;
  }

  if(h3ivlen) {
    rc = nghttp3_conn_submit_settings(ctx->h3conn, 0, h3iv, h3ivlen);
    free(h3iv);
    if(rc) {
      failf(data, "error submitting HTTP/3 settings: %s",
            nghttp3_strerror(rc));
      return CURLE_QUIC_CONNECT_ERROR;
    }
  }
  else
    free(h3iv);

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
    failf(data, "error binding HTTP/3 qpack streams: %s",
          ngtcp2_strerror(rc));
    return CURLE_QUIC_CONNECT_ERROR;
  }

  return CURLE_OK;
}

static ssize_t recv_closed_stream(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  struct h3_stream_ctx *stream,
                                  CURLcode *err)
{
  ssize_t nread = -1;

  (void)cf;
  if(stream->reset) {
    failf(data, "HTTP/3 stream %" FMT_PRId64 " reset by server", stream->id);
    *err = data->req.bytecount ? CURLE_PARTIAL_FILE : CURLE_HTTP3;
    goto out;
  }
  else if(!stream->resp_hds_complete) {
    failf(data,
          "HTTP/3 stream %" FMT_PRId64 " was closed cleanly, but before "
          "getting all response header fields, treated as error",
          stream->id);
    *err = CURLE_HTTP3;
    goto out;
  }
  *err = CURLE_OK;
  nread = 0;

out:
  return nread;
}

/* incoming data frames on the h3 stream */
static CURLcode cf_ngtcp2_recv(struct Curl_cfilter *cf, struct Curl_easy *data,
                               char *buf, size_t blen, size_t *pnread)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  struct pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  (void)ctx;
  (void)buf;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  *pnread = 0;

  /* handshake verification failed in callback, do not recv anything */
  if(ctx->tls_vrfy_result)
    return ctx->tls_vrfy_result;

  pktx_init(&pktx, cf, data);

  if(!stream || ctx->shutdown_started) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  if(cf_progress_ingress(cf, data, &pktx)) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  if(stream->xfer_result) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] xfer write failed", stream->id);
    cf_ngtcp2_stream_close(cf, data, stream);
    result = stream->xfer_result;
    goto out;
  }
  else if(stream->closed) {
    ssize_t nread = recv_closed_stream(cf, data, stream, &result);
    if(nread > 0)
      *pnread = (size_t)nread;
    goto out;
  }
  result = CURLE_AGAIN;

out:
  result = Curl_1st_err(result, cf_progress_egress(cf, data, &pktx));
  result = Curl_1st_err(result, check_and_set_expiry(cf, data, &pktx));

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_recv(blen=%zu) -> %dm, %zu",

              stream ? stream->id : -1, blen, result, *pnread);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static int cb_h3_acked_req_body(nghttp3_conn *conn, int64_t stream_id,
                                uint64_t datalen, void *user_data,
                                void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  size_t skiplen;

  (void)cf;
  if(!stream)
    return 0;
  /* The server acknowledged `datalen` of bytes from our request body.
   * This is a delta. We have kept this data in `sendbuf` for
   * re-transmissions and can free it now. */
  if(datalen >= (uint64_t)stream->sendbuf_len_in_flight)
    skiplen = stream->sendbuf_len_in_flight;
  else
    skiplen = (size_t)datalen;
  Curl_bufq_skip(&stream->sendbuf, skiplen);
  stream->sendbuf_len_in_flight -= skiplen;

  /* Resume upload processing if we have more data to send */
  if(stream->sendbuf_len_in_flight < Curl_bufq_len(&stream->sendbuf)) {
    int rv = nghttp3_conn_resume_stream(conn, stream_id);
    if(rv && rv != NGHTTP3_ERR_STREAM_NOT_FOUND) {
      return NGHTTP3_ERR_CALLBACK_FAILURE;
    }
  }
  return 0;
}

static nghttp3_ssize
cb_h3_read_req_body(nghttp3_conn *conn, int64_t stream_id,
                    nghttp3_vec *vec, size_t veccnt,
                    uint32_t *pflags, void *user_data,
                    void *stream_user_data)
{
  struct Curl_cfilter *cf = user_data;
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct Curl_easy *data = stream_user_data;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  ssize_t nwritten = 0;
  size_t nvecs = 0;
  (void)cf;
  (void)conn;
  (void)stream_id;
  (void)user_data;
  (void)veccnt;

  if(!stream)
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  /* nghttp3 keeps references to the sendbuf data until it is ACKed
   * by the server (see `cb_h3_acked_req_body()` for updates).
   * `sendbuf_len_in_flight` is the amount of bytes in `sendbuf`
   * that we have already passed to nghttp3, but which have not been
   * ACKed yet.
   * Any amount beyond `sendbuf_len_in_flight` we need still to pass
   * to nghttp3. Do that now, if we can. */
  if(stream->sendbuf_len_in_flight < Curl_bufq_len(&stream->sendbuf)) {
    nvecs = 0;
    while(nvecs < veccnt &&
          Curl_bufq_peek_at(&stream->sendbuf,
                            stream->sendbuf_len_in_flight,
                            CURL_UNCONST(&vec[nvecs].base),
                            &vec[nvecs].len)) {
      stream->sendbuf_len_in_flight += vec[nvecs].len;
      nwritten += vec[nvecs].len;
      ++nvecs;
    }
    DEBUGASSERT(nvecs > 0); /* we SHOULD have been be able to peek */
  }

  if(nwritten > 0 && stream->upload_left != -1)
    stream->upload_left -= nwritten;

  /* When we stopped sending and everything in `sendbuf` is "in flight",
   * we are at the end of the request body. */
  if(stream->upload_left == 0) {
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    stream->send_closed = TRUE;
  }
  else if(!nwritten) {
    /* Not EOF, and nothing to give, we signal WOULDBLOCK. */
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read req body -> AGAIN",
                stream->id);
    return NGHTTP3_ERR_WOULDBLOCK;
  }

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] read req body -> "
              "%d vecs%s with %zu (buffered=%zu, left=%" FMT_OFF_T ")",
              stream->id, (int)nvecs,
              *pflags == NGHTTP3_DATA_FLAG_EOF ? " EOF" : "",
              nwritten, Curl_bufq_len(&stream->sendbuf),
              stream->upload_left);
  return (nghttp3_ssize)nvecs;
}

/* Index where :authority header field will appear in request header
   field list. */
#define AUTHORITY_DST_IDX 3

static CURLcode h3_stream_open(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               const void *buf, size_t len,
                               size_t *pnwritten)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = NULL;
  int64_t sid;
  struct dynhds h2_headers;
  size_t nheader;
  nghttp3_nv *nva = NULL;
  int rc = 0;
  unsigned int i;
  ssize_t nwritten = -1;
  nghttp3_data_reader reader;
  nghttp3_data_reader *preader = NULL;
  CURLcode result;

  *pnwritten = 0;
  Curl_dynhds_init(&h2_headers, 0, DYN_HTTP_REQUEST);

  result = h3_data_setup(cf, data);
  if(result)
    goto out;
  stream = H3_STREAM_CTX(ctx, data);
  DEBUGASSERT(stream);
  if(!stream) {
    result = CURLE_FAILED_INIT;
    goto out;
  }

  nwritten = Curl_h1_req_parse_read(&stream->h1, buf, len, NULL, 0, &result);
  if(nwritten < 0)
    goto out;
  *pnwritten = (size_t)nwritten;

  if(!stream->h1.done) {
    /* need more data */
    goto out;
  }
  DEBUGASSERT(stream->h1.req);

  result = Curl_http_req_to_h2(&h2_headers, stream->h1.req, data);
  if(result)
    goto out;

  /* no longer needed */
  Curl_h1_req_parse_free(&stream->h1);

  nheader = Curl_dynhds_count(&h2_headers);
  nva = malloc(sizeof(nghttp3_nv) * nheader);
  if(!nva) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }

  for(i = 0; i < nheader; ++i) {
    struct dynhds_entry *e = Curl_dynhds_getn(&h2_headers, i);
    nva[i].name = (unsigned char *)e->name;
    nva[i].namelen = e->namelen;
    nva[i].value = (unsigned char *)e->value;
    nva[i].valuelen = e->valuelen;
    nva[i].flags = NGHTTP3_NV_FLAG_NONE;
  }

  rc = ngtcp2_conn_open_bidi_stream(ctx->qconn, &sid, data);
  if(rc) {
    failf(data, "can get bidi streams");
    result = CURLE_SEND_ERROR;
    goto out;
  }
  stream->id = (curl_int64_t)sid;
  ++ctx->used_bidi_streams;

  switch(data->state.httpreq) {
  case HTTPREQ_POST:
  case HTTPREQ_POST_FORM:
  case HTTPREQ_POST_MIME:
  case HTTPREQ_PUT:
    /* known request body size or -1 */
    if(data->state.infilesize != -1)
      stream->upload_left = data->state.infilesize;
    else
      /* data sending without specifying the data amount up front */
      stream->upload_left = -1; /* unknown */
    break;
  default:
    /* there is not request body */
    stream->upload_left = 0; /* no request body */
    break;
  }

  stream->send_closed = (stream->upload_left == 0);
  if(!stream->send_closed) {
    reader.read_data = cb_h3_read_req_body;
    preader = &reader;
  }

  rc = nghttp3_conn_submit_request(ctx->h3conn, stream->id,
                                   nva, nheader, preader, data);
  if(rc) {
    switch(rc) {
    case NGHTTP3_ERR_CONN_CLOSING:
      CURL_TRC_CF(data, cf, "h3sid[%" FMT_PRId64 "] failed to send, "
                  "connection is closing", stream->id);
      break;
    default:
      CURL_TRC_CF(data, cf, "h3sid[%" FMT_PRId64 "] failed to send -> "
                  "%d (%s)", stream->id, rc, nghttp3_strerror(rc));
      break;
    }
    result = CURLE_SEND_ERROR;
    goto out;
  }

  if(Curl_trc_is_verbose(data)) {
    infof(data, "[HTTP/3] [%" FMT_PRId64 "] OPENED stream for %s",
          stream->id, data->state.url);
    for(i = 0; i < nheader; ++i) {
      infof(data, "[HTTP/3] [%" FMT_PRId64 "] [%.*s: %.*s]", stream->id,
            (int)nva[i].namelen, nva[i].name,
            (int)nva[i].valuelen, nva[i].value);
    }
  }

out:
  free(nva);
  Curl_dynhds_free(&h2_headers);
  return result;
}

static CURLcode cf_ngtcp2_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                               const void *buf, size_t len, bool eos,
                               size_t *pnwritten)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
  struct cf_call_data save;
  struct pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  CF_DATA_SAVE(save, cf, data);
  DEBUGASSERT(cf->connected);
  DEBUGASSERT(ctx->qconn);
  DEBUGASSERT(ctx->h3conn);
  pktx_init(&pktx, cf, data);
  *pnwritten = 0;

  /* handshake verification failed in callback, do not send anything */
  if(ctx->tls_vrfy_result)
    return ctx->tls_vrfy_result;

  (void)eos; /* use for stream EOF and block handling */
  result = cf_progress_ingress(cf, data, &pktx);
  if(result)
    goto out;

  if(!stream || stream->id < 0) {
    if(ctx->shutdown_started) {
      CURL_TRC_CF(data, cf, "cannot open stream on closed connection");
      result = CURLE_SEND_ERROR;
      goto out;
    }
    result = h3_stream_open(cf, data, buf, len, pnwritten);
    if(result) {
      CURL_TRC_CF(data, cf, "failed to open stream -> %d", result);
      goto out;
    }
    stream = H3_STREAM_CTX(ctx, data);
  }
  else if(stream->xfer_result) {
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] xfer write failed", stream->id);
    cf_ngtcp2_stream_close(cf, data, stream);
    result = stream->xfer_result;
    goto out;
  }
  else if(stream->closed) {
    if(stream->resp_hds_complete) {
      /* Server decided to close the stream after having sent us a final
       * response. This is valid if it is not interested in the request
       * body. This happens on 30x or 40x responses.
       * We silently discard the data sent, since this is not a transport
       * error situation. */
      CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] discarding data"
                  "on closed stream with response", stream->id);
      result = CURLE_OK;
      *pnwritten = len;
      goto out;
    }
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] send_body(len=%zu) "
                "-> stream closed", stream->id, len);
    result = CURLE_HTTP3;
    goto out;
  }
  else if(ctx->shutdown_started) {
    CURL_TRC_CF(data, cf, "cannot send on closed connection");
    result = CURLE_SEND_ERROR;
    goto out;
  }
  else {
    result = Curl_bufq_write(&stream->sendbuf, buf, len, pnwritten);
    CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_send, add to "
                "sendbuf(len=%zu) -> %d, %zu",
                stream->id, len, result, *pnwritten);
    if(result)
      goto out;
    (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
  }

  if(*pnwritten > 0 && !ctx->tls_handshake_complete && ctx->use_earlydata)
    ctx->earlydata_skip += *pnwritten;

  DEBUGASSERT(!result);
  result = cf_progress_egress(cf, data, &pktx);

out:
  result = Curl_1st_err(result, check_and_set_expiry(cf, data, &pktx));

  CURL_TRC_CF(data, cf, "[%" FMT_PRId64 "] cf_send(len=%zu) -> %d, %zu",
              stream ? stream->id : -1, len, result, *pnwritten);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode recv_pkt(const unsigned char *pkt, size_t pktlen,
                         struct sockaddr_storage *remote_addr,
                         socklen_t remote_addrlen, int ecn,
                         void *userp)
{
  struct pkt_io_ctx *pktx = userp;
  struct cf_ngtcp2_ctx *ctx = pktx->cf->ctx;
  ngtcp2_pkt_info pi;
  ngtcp2_path path;
  int rv;

  ngtcp2_addr_init(&path.local, (struct sockaddr *)&ctx->q.local_addr,
                   (socklen_t)ctx->q.local_addrlen);
  ngtcp2_addr_init(&path.remote, (struct sockaddr *)remote_addr,
                   remote_addrlen);
  pi.ecn = (uint8_t)ecn;

  rv = ngtcp2_conn_read_pkt(ctx->qconn, &path, &pi, pkt, pktlen, pktx->ts);
  if(rv) {
    CURL_TRC_CF(pktx->data, pktx->cf, "ingress, read_pkt -> %s (%d)",
                ngtcp2_strerror(rv), rv);
    cf_ngtcp2_err_set(pktx->cf, pktx->data, rv);

    if(rv == NGTCP2_ERR_CRYPTO)
      /* this is a "TLS problem", but a failed certificate verification
         is a common reason for this */
      return CURLE_PEER_FAILED_VERIFICATION;
    return CURLE_RECV_ERROR;
  }

  return CURLE_OK;
}

static CURLcode cf_progress_ingress(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct pkt_io_ctx local_pktx;
  CURLcode result = CURLE_OK;

  if(!pktx) {
    pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }

  result = Curl_vquic_tls_before_recv(&ctx->tls, cf, data);
  if(result)
    return result;

  return vquic_recv_packets(cf, data, &ctx->q, 1000, recv_pkt, pktx);
}

/**
 * Read a network packet to send from ngtcp2 into `buf`.
 * Return number of bytes written or -1 with *err set.
 */
static CURLcode read_pkt_to_send(void *userp,
                                 unsigned char *buf, size_t buflen,
                                 size_t *pnread)
{
  struct pkt_io_ctx *x = userp;
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
        cf_ngtcp2_h3_err_set(x->cf, x->data, (int)veccnt);
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
        struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, x->data);
        DEBUGASSERT(ndatalen == -1);
        nghttp3_conn_block_stream(ctx->h3conn, stream_id);
        CURL_TRC_CF(x->data, x->cf, "[%" FMT_PRId64 "] block quic flow",
                    (curl_int64_t)stream_id);
        DEBUGASSERT(stream);
        if(stream)
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
        cf_ngtcp2_err_set(x->cf, x->data, (int)n);
        return CURLE_SEND_ERROR;
      }
    }

    if(ndatalen >= 0) {
      /* we add the amount of data bytes to the flow windows */
      int rv = nghttp3_conn_add_write_offset(ctx->h3conn, stream_id, ndatalen);
      if(rv) {
        failf(x->data, "nghttp3_conn_add_write_offset returned error: %s\n",
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

static CURLcode cf_progress_egress(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  size_t nread;
  size_t max_payload_size, path_max_payload_size, max_pktcnt;
  size_t pktcnt = 0;
  size_t gsolen = 0;  /* this disables gso until we have a clue */
  CURLcode curlcode;
  struct pkt_io_ctx local_pktx;

  if(!pktx) {
    pktx_init(&local_pktx, cf, data);
    pktx = &local_pktx;
  }
  else {
    pktx_update_time(pktx, cf);
    ngtcp2_path_storage_zero(&pktx->ps);
  }

  curlcode = vquic_flush(cf, data, &ctx->q);
  if(curlcode) {
    if(curlcode == CURLE_AGAIN) {
      Curl_expire(data, 1, EXPIRE_QUIC);
      return CURLE_OK;
    }
    return curlcode;
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
   * also fail then. So, if we detect a PMTUD while buffering, we flush.
   */
  max_payload_size = ngtcp2_conn_get_max_tx_udp_payload_size(ctx->qconn);
  path_max_payload_size =
      ngtcp2_conn_get_path_max_tx_udp_payload_size(ctx->qconn);
  /* maximum number of packets buffered before we flush to the socket */
  max_pktcnt = CURLMIN(MAX_PKT_BURST,
                       ctx->q.sendbuf.chunk_size / max_payload_size);

  for(;;) {
    /* add the next packet to send, if any, to our buffer */
    curlcode = Curl_bufq_sipn(&ctx->q.sendbuf, max_payload_size,
                              read_pkt_to_send, pktx, &nread);
    if(curlcode) {
      if(curlcode != CURLE_AGAIN)
        return curlcode;
      /* Nothing more to add, flush and leave */
      curlcode = vquic_send(cf, data, &ctx->q, gsolen);
      if(curlcode) {
        if(curlcode == CURLE_AGAIN) {
          Curl_expire(data, 1, EXPIRE_QUIC);
          return CURLE_OK;
        }
        return curlcode;
      }
      goto out;
    }

    DEBUGASSERT(nread > 0);
    if(pktcnt == 0) {
      /* first packet in buffer. This is either of a known, "good"
       * payload size or it is a PMTUD. We will see. */
      gsolen = nread;
    }
    else if(nread > gsolen ||
            (gsolen > path_max_payload_size && nread != gsolen)) {
      /* The just added packet is a PMTUD *or* the one(s) before the
       * just added were PMTUD and the last one is smaller.
       * Flush the buffer before the last add. */
      curlcode = vquic_send_tail_split(cf, data, &ctx->q,
                                       gsolen, nread, nread);
      if(curlcode) {
        if(curlcode == CURLE_AGAIN) {
          Curl_expire(data, 1, EXPIRE_QUIC);
          return CURLE_OK;
        }
        return curlcode;
      }
      pktcnt = 0;
      continue;
    }

    if(++pktcnt >= max_pktcnt || nread < gsolen) {
      /* Reached MAX_PKT_BURST *or*
       * the capacity of our buffer *or*
       * last add was shorter than the previous ones, flush */
      curlcode = vquic_send(cf, data, &ctx->q, gsolen);
      if(curlcode) {
        if(curlcode == CURLE_AGAIN) {
          Curl_expire(data, 1, EXPIRE_QUIC);
          return CURLE_OK;
        }
        return curlcode;
      }
      /* pktbuf has been completely sent */
      pktcnt = 0;
    }
  }

out:
  return CURLE_OK;
}

static CURLcode h3_data_pause(struct Curl_cfilter *cf,
                              struct Curl_easy *data,
                              bool pause)
{
  /* There seems to exist no API in ngtcp2 to shrink/enlarge the streams
   * windows. As we do in HTTP/2. */
  (void)cf;
  if(!pause)
    Curl_multi_mark_dirty(data);
  return CURLE_OK;
}

static CURLcode cf_ngtcp2_data_event(struct Curl_cfilter *cf,
                                     struct Curl_easy *data,
                                     int event, int arg1, void *arg2)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  (void)arg1;
  (void)arg2;
  switch(event) {
  case CF_CTRL_DATA_SETUP:
    break;
  case CF_CTRL_DATA_PAUSE:
    result = h3_data_pause(cf, data, (arg1 != 0));
    break;
  case CF_CTRL_DATA_DONE:
    h3_data_done(cf, data);
    break;
  case CF_CTRL_DATA_DONE_SEND: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    if(stream && !stream->send_closed) {
      stream->send_closed = TRUE;
      stream->upload_left = Curl_bufq_len(&stream->sendbuf) -
        stream->sendbuf_len_in_flight;
      (void)nghttp3_conn_resume_stream(ctx->h3conn, stream->id);
    }
    break;
  }
  case CF_CTRL_DATA_IDLE: {
    struct h3_stream_ctx *stream = H3_STREAM_CTX(ctx, data);
    CURL_TRC_CF(data, cf, "data idle");
    if(stream && !stream->closed) {
      result = check_and_set_expiry(cf, data, NULL);
      if(result)
        CURL_TRC_CF(data, cf, "data idle, check_and_set_expiry -> %d", result);
    }
    break;
  }
  default:
    break;
  }
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_ngtcp2_ctx_close(struct cf_ngtcp2_ctx *ctx)
{
  struct cf_call_data save = ctx->call_data;

  if(!ctx->initialized)
    return;
  if(ctx->qlogfd != -1) {
    close(ctx->qlogfd);
  }
  ctx->qlogfd = -1;
  Curl_vquic_tls_cleanup(&ctx->tls);
  vquic_ctx_free(&ctx->q);
  if(ctx->h3conn) {
    nghttp3_conn_del(ctx->h3conn);
    ctx->h3conn = NULL;
  }
  if(ctx->qconn) {
    ngtcp2_conn_del(ctx->qconn);
    ctx->qconn = NULL;
  }
#ifdef OPENSSL_QUIC_API2
  if(ctx->ossl_ctx) {
    ngtcp2_crypto_ossl_ctx_del(ctx->ossl_ctx);
    ctx->ossl_ctx = NULL;
  }
#endif
  ctx->call_data = save;
}

static CURLcode cf_ngtcp2_shutdown(struct Curl_cfilter *cf,
                                   struct Curl_easy *data, bool *done)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_call_data save;
  struct pkt_io_ctx pktx;
  CURLcode result = CURLE_OK;

  if(cf->shutdown || !ctx->qconn) {
    *done = TRUE;
    return CURLE_OK;
  }

  CF_DATA_SAVE(save, cf, data);
  *done = FALSE;
  pktx_init(&pktx, cf, data);

  if(!ctx->shutdown_started) {
    char buffer[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
    ngtcp2_ssize nwritten;

    if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
      CURL_TRC_CF(data, cf, "shutdown, flushing sendbuf");
      result = cf_progress_egress(cf, data, &pktx);
      if(!Curl_bufq_is_empty(&ctx->q.sendbuf)) {
        CURL_TRC_CF(data, cf, "sending shutdown packets blocked");
        result = CURLE_OK;
        goto out;
      }
      else if(result) {
        CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf", result);
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
                FMT_PRIu64 ") -> %d", ctx->last_error.type,
                (curl_uint64_t)ctx->last_error.error_code, (int)nwritten);
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
                    "aborting shutdown", result);
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
      CURL_TRC_CF(data, cf, "shutdown, error %d flushing sendbuf", result);
      *done = TRUE;
      goto out;
    }
  }

  if(Curl_bufq_is_empty(&ctx->q.sendbuf)) {
    /* Sent everything off. ngtcp2 seems to have no support for graceful
     * shutdowns. So, we are done. */
    CURL_TRC_CF(data, cf, "shutdown completely sent off, done");
    *done = TRUE;
    result = CURLE_OK;
  }
out:
  CF_DATA_RESTORE(cf, save);
  return result;
}

static void cf_ngtcp2_conn_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{
  bool done;
  cf_ngtcp2_shutdown(cf, data, &done);
}

static void cf_ngtcp2_close(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  if(ctx && ctx->qconn) {
    cf_ngtcp2_conn_close(cf, data);
    cf_ngtcp2_ctx_close(ctx);
    CURL_TRC_CF(data, cf, "close");
  }
  cf->connected = FALSE;
  CF_DATA_RESTORE(cf, save);
}

static void cf_ngtcp2_destroy(struct Curl_cfilter *cf, struct Curl_easy *data)
{
  CURL_TRC_CF(data, cf, "destroy");
  if(cf->ctx) {
    cf_ngtcp2_close(cf, data);
    cf_ngtcp2_ctx_free(cf->ctx);
    cf->ctx = NULL;
  }
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
    Curl_ossl_add_session(cf, data, ctx->peer.scache_key, ssl_sessionid,
                          SSL_version(ssl), "h3", quic_tp, quic_tp_len);
    return 1;
  }
  return 0;
}
#endif /* USE_OPENSSL */

#ifdef USE_GNUTLS

static const char *gtls_hs_msg_name(int mtype)
{
  switch(mtype) {
    case 1: return "ClientHello";
    case 2: return "ServerHello";
    case 4: return "SessionTicket";
    case 8: return "EncryptedExtensions";
    case 11: return "Certificate";
    case 13: return "CertificateRequest";
    case 15: return "CertificateVerify";
    case 20: return "Finished";
    case 24: return "KeyUpdate";
    case 254: return "MessageHash";
  }
  return "Unknown";
}

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
    CURL_TRC_CF(data, cf, "SSL message: %s %s [%d]",
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
      (void)Curl_gtls_cache_session(cf, data, ctx->peer.scache_key,
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

  DEBUGASSERT(cf != NULL);
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
      (void)Curl_wssl_cache_session(cf, data, ctx->peer.scache_key,
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
  struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);

#ifdef USE_OPENSSL
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
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
#endif /* !OPENSSL_IS_BORINGSSL && !OPENSSL_IS_AWSLC */
  if(ssl_config->primary.cache_session) {
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
  if(ssl_config->primary.cache_session) {
    gnutls_handshake_set_hook_function(ctx->gtls.session,
                                       GNUTLS_HANDSHAKE_ANY, GNUTLS_HOOK_POST,
                                       quic_gtls_handshake_cb);
  }

#elif defined(USE_WOLFSSL)
  if(ngtcp2_crypto_wolfssl_configure_client_context(ctx->wssl.ssl_ctx) != 0) {
    failf(data, "ngtcp2_crypto_wolfssl_configure_client_context failed");
    return CURLE_FAILED_INIT;
  }
  if(ssl_config->primary.cache_session) {
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
  if((!ctx->earlydata_max)) {
    CURL_TRC_CF(data, cf, "SSL session does not allow earlydata");
  }
  else if(!Curl_alpn_contains_proto(alpns, scs->alpn)) {
    CURL_TRC_CF(data, cf, "SSL session from different ALPN, no early data");
  }
  else if(!scs->quic_tp || !scs->quic_tp_len) {
    CURL_TRC_CF(data, cf, "no 0RTT transport parameters, no early data, ");
  }
  else {
    int rv;
    rv = ngtcp2_conn_decode_and_set_0rtt_transport_params(
      ctx->qconn, (const uint8_t *)scs->quic_tp, scs->quic_tp_len);
    if(rv)
      CURL_TRC_CF(data, cf, "no early data, failed to set 0RTT transport "
                  "parameters: %s", ngtcp2_strerror(rv));
    else {
      infof(data, "SSL session allows %zu bytes of early data, "
            "reusing ALPN '%s'", ctx->earlydata_max, scs->alpn);
      result = init_ngh3_conn(cf, data);
      if(!result) {
        ctx->use_earlydata = TRUE;
        cf->connected = TRUE;
        *do_early_data = TRUE;
      }
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
                                 struct pkt_io_ctx *pktx)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  int rc;
  int rv;
  CURLcode result;
  const struct Curl_sockaddr_ex *sockaddr = NULL;
  int qfd;

  DEBUGASSERT(ctx->initialized);
  ctx->dcid.datalen = NGTCP2_MAX_CIDLEN;
  result = Curl_rand(data, ctx->dcid.data, NGTCP2_MAX_CIDLEN);
  if(result)
    return result;

  ctx->scid.datalen = NGTCP2_MAX_CIDLEN;
  if(quic_has_empty_initial_scid(
       data->set.str[STRING_QUIC_TRANSPORT_PARAMETERS])) {
    ctx->scid.datalen = 0;
  }
  else {
    result = Curl_rand(data, ctx->scid.data, ctx->scid.datalen);
    if(result)
      return result;
  }

  (void)Curl_qlogdir(data, ctx->scid.data, ctx->scid.datalen, &qfd);
  ctx->qlogfd = qfd; /* -1 if failure above */
  result = quic_settings(ctx, data, pktx);
  if(result)
    return result;

  result = vquic_ctx_init(&ctx->q);
  if(result)
    return result;

  cf_ngtcp2_peek_socket(cf->next, data, &ctx->q.sockfd, &sockaddr, NULL);
  if(!sockaddr)
    return CURLE_QUIC_CONNECT_ERROR;
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
                              NULL, cf);
  if(rc)
    return CURLE_QUIC_CONNECT_ERROR;

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

  ctx->conn_ref.get_conn = get_conn;
  ctx->conn_ref.user_data = cf;

  result = Curl_vquic_tls_init(&ctx->tls, cf, data, &ctx->peer, &ALPN_SPEC_H3,
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

static CURLcode cf_ngtcp2_connect(struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  bool *done)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  CURLcode result = CURLE_OK;
  struct cf_call_data save;
  struct curltime now;
  struct pkt_io_ctx pktx;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  /* Connect the UDP filter first */
  if(!cf->next->connected) {
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      return result;
  }

  *done = FALSE;
  now = curlx_now();
  pktx_init(&pktx, cf, data);

  CF_DATA_SAVE(save, cf, data);

  if(!ctx->qconn) {
    ctx->started_at = now;
    result = cf_connect_start(cf, data, &pktx);
    if(result)
      goto out;
    if(cf->connected) {
      cf->conn->alpn = CURL_HTTP_VERSION_3;
      *done = TRUE;
      goto out;
    }
    result = cf_progress_egress(cf, data, &pktx);
    /* we do not expect to be able to recv anything yet */
    goto out;
  }

  result = cf_progress_ingress(cf, data, &pktx);
  if(result)
    goto out;

  result = cf_progress_egress(cf, data, &pktx);
  if(result)
    goto out;

  if(ngtcp2_conn_get_handshake_completed(ctx->qconn)) {
    result = ctx->tls_vrfy_result;
    if(!result) {
      CURL_TRC_CF(data, cf, "peer verified");
      cf->connected = TRUE;
      cf->conn->alpn = CURL_HTTP_VERSION_3;
      *done = TRUE;
      connkeep(cf->conn, "HTTP/3 default");
    }
  }

out:
  if(result == CURLE_RECV_ERROR && ctx->qconn &&
     ngtcp2_conn_in_draining_period(ctx->qconn)) {
    /* When a QUIC server instance is shutting down, it may send us a
     * CONNECTION_CLOSE right away. Our connection then enters the DRAINING
     * state. The CONNECT may work in the near future again. Indicate
     * that as a "weird" reply. */
    result = CURLE_WEIRD_SERVER_REPLY;
  }

#ifndef CURL_DISABLE_VERBOSE_STRINGS
  if(result) {
    struct ip_quadruple ip;

    cf_ngtcp2_peek_socket(cf->next, data, NULL, NULL, &ip);
    infof(data, "QUIC connect to %s port %u failed: %s",
          ip.remote_ip, ip.remote_port, curl_easy_strerror(result));
  }
#endif
  if(!result && ctx->qconn) {
    result = check_and_set_expiry(cf, data, &pktx);
  }
  if(result || *done)
    CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result, *done);
  CF_DATA_RESTORE(cf, save);
  return result;
}

static CURLcode cf_ngtcp2_query(struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                int query, int *pres1, void *pres2)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  struct cf_call_data save;

  switch(query) {
  case CF_QUERY_MAX_CONCURRENT: {
    DEBUGASSERT(pres1);
    CF_DATA_SAVE(save, cf, data);
    /* Set after transport params arrived and continually updated
     * by callback. QUIC counts the number over the lifetime of the
     * connection, ever increasing.
     * We count the *open* transfers plus the budget for new ones. */
    if(!ctx->qconn || ctx->shutdown_started) {
      *pres1 = 0;
    }
    else if(ctx->max_bidi_streams) {
      uint64_t avail_bidi_streams = 0;
      uint64_t max_streams = CONN_ATTACHED(cf->conn);
      if(ctx->max_bidi_streams > ctx->used_bidi_streams)
        avail_bidi_streams = ctx->max_bidi_streams - ctx->used_bidi_streams;
      max_streams += avail_bidi_streams;
      *pres1 = (max_streams > INT_MAX) ? INT_MAX : (int)max_streams;
    }
    else  /* transport params not arrived yet? take our default. */
      *pres1 = (int)Curl_multi_max_concurrent_streams(data->multi);
    CURL_TRC_CF(data, cf, "query conn[%" FMT_OFF_T "]: "
                "MAX_CONCURRENT -> %d (%u in use)",
                cf->conn->connection_id, *pres1, CONN_ATTACHED(cf->conn));
    CF_DATA_RESTORE(cf, save);
    return CURLE_OK;
  }
  case CF_QUERY_CONNECT_REPLY_MS:
    if(ctx->q.got_first_byte) {
      timediff_t ms = curlx_timediff(ctx->q.first_byte_at, ctx->started_at);
      *pres1 = (ms < INT_MAX) ? (int)ms : INT_MAX;
    }
    else
      *pres1 = -1;
    return CURLE_OK;
  case CF_QUERY_TIMER_CONNECT: {
    struct curltime *when = pres2;
    if(ctx->q.got_first_byte)
      *when = ctx->q.first_byte_at;
    return CURLE_OK;
  }
  case CF_QUERY_TIMER_APPCONNECT: {
    struct curltime *when = pres2;
    if(cf->connected)
      *when = ctx->handshake_at;
    return CURLE_OK;
  }
  case CF_QUERY_HTTP_VERSION:
    *pres1 = 30;
    return CURLE_OK;
  case CF_QUERY_SSL_INFO:
  case CF_QUERY_SSL_CTX_INFO: {
    struct curl_tlssessioninfo *info = pres2;
    if(Curl_vquic_tls_get_ssl_info(&ctx->tls,
                                   (query == CF_QUERY_SSL_INFO), info))
      return CURLE_OK;
    break;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

static bool cf_ngtcp2_conn_is_alive(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    bool *input_pending)
{
  struct cf_ngtcp2_ctx *ctx = cf->ctx;
  bool alive = FALSE;
  const ngtcp2_transport_params *rp;
  struct cf_call_data save;

  CF_DATA_SAVE(save, cf, data);
  *input_pending = FALSE;
  if(!ctx->qconn || ctx->shutdown_started)
    goto out;

  /* We do not announce a max idle timeout, but when the peer does
   * it will close the connection when it expires. */
  rp = ngtcp2_conn_get_remote_transport_params(ctx->qconn);
  if(rp && rp->max_idle_timeout) {
    timediff_t idletime = curlx_timediff(curlx_now(), ctx->q.last_io);
    if(idletime > 0 && (uint64_t)idletime > rp->max_idle_timeout)
      goto out;
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
    result = cf_progress_ingress(cf, data, NULL);
    CURL_TRC_CF(data, cf, "is_alive, progress ingress -> %d", result);
    alive = result ? FALSE : TRUE;
  }

out:
  CF_DATA_RESTORE(cf, save);
  return alive;
}

struct Curl_cftype Curl_cft_http3 = {
  "HTTP/3",
  CF_TYPE_IP_CONNECT | CF_TYPE_SSL | CF_TYPE_MULTIPLEX | CF_TYPE_HTTP,
  0,
  cf_ngtcp2_destroy,
  cf_ngtcp2_connect,
  cf_ngtcp2_close,
  cf_ngtcp2_shutdown,
  cf_ngtcp2_adjust_pollset,
  Curl_cf_def_data_pending,
  cf_ngtcp2_send,
  cf_ngtcp2_recv,
  cf_ngtcp2_data_event,
  cf_ngtcp2_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  cf_ngtcp2_query,
};

CURLcode Curl_cf_ngtcp2_create(struct Curl_cfilter **pcf,
                               struct Curl_easy *data,
                               struct connectdata *conn,
                               const struct Curl_addrinfo *ai)
{
  struct cf_ngtcp2_ctx *ctx = NULL;
  struct Curl_cfilter *cf = NULL;
  struct Curl_cfilter *udp_cf = NULL;
  struct Curl_cfilter *socks_cf = NULL;
  struct Curl_cfilter *tcp_cf = NULL;
  CURLcode result;

  (void)data;
  ctx = calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  cf_ngtcp2_ctx_init(ctx);

  result = Curl_cf_create(&cf, &Curl_cft_http3, ctx);
  if(result)
    goto out;

  cf->conn = conn;
  if(conn->bits.socksproxy) {
    /* Build SOCKS->TCP chain for the proxy control channel. */
    result = Curl_cf_create(&socks_cf, &Curl_cft_socks_proxy, NULL);
    if(result)
      goto out;
    socks_cf->conn = cf->conn;
    socks_cf->sockindex = cf->sockindex;
    result = Curl_cf_tcp_create(&tcp_cf, data, conn, ai, TRNSPRT_TCP);
    if(result)
      goto out;
    tcp_cf->conn = cf->conn;
    tcp_cf->sockindex = cf->sockindex;
    socks_cf->next = tcp_cf;
    cf->next = socks_cf;
  }
  else {
    result = Curl_cf_udp_create(&udp_cf, data, conn, ai, TRNSPRT_QUIC);
    if(result)
      goto out;

    udp_cf->conn = cf->conn;
    udp_cf->sockindex = cf->sockindex;
    cf->next = udp_cf;
  }

out:
  *pcf = (!result) ? cf : NULL;
  if(result) {
    if(udp_cf)
      Curl_conn_cf_discard_sub(cf, udp_cf, data, TRUE);
    if(socks_cf)
      Curl_conn_cf_discard_sub(cf, socks_cf, data, TRUE);
    if(tcp_cf)
      Curl_conn_cf_discard_sub(cf, tcp_cf, data, TRUE);
    Curl_safefree(cf);
    cf_ngtcp2_ctx_free(ctx);
  }
  return result;
}

bool Curl_conn_is_ngtcp2(const struct Curl_easy *data,
                         const struct connectdata *conn,
                         int sockindex)
{
  struct Curl_cfilter *cf = conn ? conn->cfilter[sockindex] : NULL;

  (void)data;
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_http3)
      return TRUE;
    if(cf->cft->flags & CF_TYPE_IP_CONNECT)
      return FALSE;
  }
  return FALSE;
}

#endif
