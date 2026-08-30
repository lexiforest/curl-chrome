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

#ifndef CURL_DISABLE_PROXY

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "urldata.h"
#include "bufq.h"
#include "curl_addrinfo.h"
#include "curl_trc.h"
#include "select.h"
#include "cfilters.h"
#include "cf-dns.h"
#include "connect.h"
#include "cf-socket.h"
#include "sockaddr.h"
#include "socks.h"
#include "curlx/inet_pton.h"
#include "curlx/inet_ntop.h"

/* for the (SOCKS) connect state machine */
enum socks_state_t {
  SOCKS_ST_INIT,
  /* SOCKS Version 4 states */
  SOCKS4_ST_START,
  SOCKS4_ST_RESOLVING,
  SOCKS4_ST_SEND,
  SOCKS4_ST_RECV,
  /* SOCKS Version 5 states */
  SOCKS5_ST_START,
  SOCKS5_ST_REQ0_SEND,
  SOCKS5_ST_RESP0_RECV, /* set up read */
  SOCKS5_ST_GSSAPI_INIT,
  SOCKS5_ST_AUTH_INIT, /* setup outgoing auth buffer */
  SOCKS5_ST_AUTH_SEND, /* send auth */
  SOCKS5_ST_AUTH_RECV, /* read auth response */
  SOCKS5_ST_REQ1_INIT,  /* init SOCKS "request" */
  SOCKS5_ST_RESOLVING,
  SOCKS5_ST_REQ1_SEND,
  SOCKS5_ST_RESP1_RECV,
  /* Terminal states, all SOCKS versions */
  SOCKS_ST_SUCCESS,
  SOCKS_ST_FAILED
};

#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
static const char * const cf_socks_statename[] = {
  "SOCKS_INIT",
  "SOCKS4_START",
  "SOCKS4_RESOLVING",
  "SOCKS4_SEND",
  "SOCKS4_RECV",
  "SOCKS5_START",
  "SOCKS5_REQ0_SEND",
  "SOCKS5_RESP0_RECV",
  "SOCKS5_GSSAPI_INIT",
  "SOCKS5_AUTH_INIT",
  "SOCKS5_AUTH_SEND",
  "SOCKS5_AUTH_RECV",
  "SOCKS5_REQ1_INIT",
  "SOCKS5_RESOLVING",
  "SOCKS5_REQ1_SEND",
  "SOCKS5_RESP1_RECV",
  "SOCKS_SUCCESS",
  "SOCKS_FAILED"
};
#endif

#define SOCKS_CHUNK_SIZE    1024
#define SOCKS_CHUNKS        1

#define SOCKS5_ATYP_IPV4    1
#define SOCKS5_ATYP_DOMAIN  3
#define SOCKS5_ATYP_IPV6    4
#define SOCKS5_HEADER_LEN    4
#define SOCKS5_PORT_LEN      2
#define SOCKS5_IPV4_LEN      4
#define SOCKS5_IPV6_LEN     16

struct socks_ctx {
  enum socks_state_t state;
  struct bufq iobuf;
  struct Curl_peer *dest;
  struct Curl_creds *creds;

  /* curl-impersonate: SOCKS5 UDP ASSOCIATE state. See RFC 1928 section 7. */
  struct Curl_cfilter *tcp_cf; /* SOCKS proxy TCP control channel */
  struct Curl_cfilter *udp_cf; /* SOCKS proxy UDP relay data path */
  struct Curl_sockaddr_ex udp_peer_addr; /* QUIC peer address */
  CURLproxycode presult;
  uint32_t resolv_id;
  unsigned char udp_relay_addr[SOCKS5_IPV6_LEN]; /* relay address */
  unsigned char udp_dest_addr[SOCKS5_IPV6_LEN]; /* QUIC destination */
  unsigned char udp_dest_domain[256]; /* remotely resolved destination */
  size_t udp_dest_domain_len;
  int udp_relay_port;
  int udp_relay_family;
  int udp_dest_port;
  int udp_dest_atyp; /* SOCKS5 ATYP for UDP destination */
  uint8_t ip_version;
  uint8_t proxy_type;
  unsigned char version;
  BIT(resolve_local);
  BIT(start_resolving);
  BIT(socks4a);
  BIT(udp_associate); /* use UDP ASSOCIATE instead of CONNECT */
  BIT(udp_dest_set); /* destination cached for UDP headers */
  BIT(udp_peer_set); /* udp_peer_addr is available */
};

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
/*
 * Helper read-from-socket functions. Does the same as Curl_read() but it
 * blocks until all bytes amount of buffersize will be read. No more, no less.
 *
 * This is STUPID BLOCKING behavior. Only used by the SOCKS GSSAPI functions.
 */
CURLcode Curl_blockread_all(struct Curl_cfilter *cf,
                            struct Curl_easy *data,
                            char *buf,             /* store read data here */
                            size_t blen,           /* space in buf */
                            size_t *pnread)        /* amount bytes read */
{
  size_t nread = 0;
  CURLcode result;

  *pnread = 0;
  for(;;) {
    timediff_t timeout_ms = Curl_timeleft_ms(data);
    curl_socket_t sock = Curl_conn_cf_get_socket(cf, data);

    if(timeout_ms < 0) {
      /* we already got the timeout */
      return CURLE_OPERATION_TIMEDOUT;
    }
    if(!timeout_ms)
      timeout_ms = TIMEDIFF_T_MAX;
    if(SOCKET_READABLE(sock, timeout_ms) <= 0)
      return CURLE_OPERATION_TIMEDOUT;
    result = Curl_conn_cf_recv(cf->next, data, buf, blen, &nread);
    if(result == CURLE_AGAIN)
      continue;
    else if(result)
      return result;

    if(blen == nread) {
      *pnread += nread;
      return CURLE_OK;
    }
    if(!nread) /* EOF */
      return CURLE_RECV_ERROR;

    buf += nread;
    blen -= nread;
    *pnread += nread;
  }
}
#endif

#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
#define sxstate(x, c, d, y) socksstate(x, c, d, y, __LINE__)
#else
#define sxstate(x, c, d, y) socksstate(x, c, d, y)
#endif

/* always use this function to change state, to make debugging easier */
static void socksstate(struct socks_ctx *sx,
                       struct Curl_cfilter *cf,
                       struct Curl_easy *data,
                       enum socks_state_t state
#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
                       , int lineno
#endif
)
{
  enum socks_state_t oldstate = sx->state;

  if(oldstate == state)
    /* do not bother when the new state is the same as the old state */
    return;

  sx->state = state;

#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
  CURL_TRC_CF(data, cf, "[%s] -> [%s] (line %d)",
              cf_socks_statename[oldstate],
              cf_socks_statename[sx->state], lineno);
#else
  (void)cf;
  (void)data;
#endif
}

static CURLproxycode socks_failed(struct socks_ctx *sx,
                                  struct Curl_cfilter *cf,
                                  struct Curl_easy *data,
                                  CURLproxycode presult)
{
  sxstate(sx, cf, data, SOCKS_ST_FAILED);
  sx->presult = presult;
  return presult;
}

static CURLproxycode socks_flush(struct socks_ctx *sx,
                                 struct Curl_cfilter *cf,
                                 struct Curl_easy *data,
                                 bool *done)
{
  CURLcode result;
  size_t nwritten;

  *done = FALSE;
  while(!Curl_bufq_is_empty(&sx->iobuf)) {
    result = Curl_cf_send_bufq(cf->next, data, &sx->iobuf, NULL, 0,
                               &nwritten);
    if(result == CURLE_AGAIN)
      return CURLPX_OK;
    else if(result) {
      failf(data, "Failed to send SOCKS request: %s",
            curl_easy_strerror(result));
      return socks_failed(sx, cf, data, CURLPX_SEND_CONNECT);
    }
  }
  *done = TRUE;
  return CURLPX_OK;
}

static CURLproxycode socks_recv(struct socks_ctx *sx,
                                struct Curl_cfilter *cf,
                                struct Curl_easy *data,
                                size_t min_bytes,
                                bool *done)
{
  CURLcode result;
  size_t nread;

  *done = FALSE;
  while(Curl_bufq_len(&sx->iobuf) < min_bytes) {
    result = Curl_cf_recv_bufq(cf->next, data, &sx->iobuf,
                               min_bytes - Curl_bufq_len(&sx->iobuf),
                               &nread);
    if(result == CURLE_AGAIN)
      return CURLPX_OK;
    else if(result) {
      failf(data, "Failed to receive SOCKS response: %s",
            curl_easy_strerror(result));
      return CURLPX_RECV_CONNECT;
    }
    else if(!nread) { /* EOF */
      if(Curl_bufq_len(&sx->iobuf) < min_bytes) {
        failf(data, "Failed to receive SOCKS response, "
              "proxy closed connection");
        return CURLPX_RECV_CONNECT;
      }
      break;
    }
  }
  *done = TRUE;
  return CURLPX_OK;
}

static CURLproxycode socks4_req_add_hd(struct socks_ctx *sx,
                                       struct Curl_easy *data)
{
  unsigned char buf[4];
  size_t nwritten;
  CURLcode result;

  (void)data;
  buf[0] = 4; /* version (SOCKS4) */
  buf[1] = 1; /* connect */
  buf[2] = (unsigned char)((sx->dest->port >> 8) & 0xffU); /* MSB */
  buf[3] = (unsigned char)(sx->dest->port & 0xffU);        /* LSB */

  result = Curl_bufq_write(&sx->iobuf, buf, 4, &nwritten);
  if(result || (nwritten != 4))
    return CURLPX_SEND_REQUEST;
  return CURLPX_OK;
}

static CURLproxycode socks4_req_add_user(struct socks_ctx *sx,
                                         struct Curl_easy *data)
{
  CURLcode result;
  size_t nwritten;

  if(sx->creds) {
    size_t plen = strlen(sx->creds->user);
    if(plen > 255) {
      /* there is no real size limit to this field in the protocol, but
         SOCKS5 limits the proxy user field to 255 bytes and it seems likely
         that a longer field is either a mistake or malicious input */
      failf(data, "Too long SOCKS proxy username");
      return CURLPX_LONG_USER;
    }
    /* add proxy name WITH trailing zero */
    result = Curl_bufq_cwrite(&sx->iobuf, sx->creds->user, plen + 1,
                              &nwritten);
    if(result || (nwritten != (plen + 1)))
      return CURLPX_SEND_REQUEST;
  }
  else {
    /* empty username */
    unsigned char b = 0;
    result = Curl_bufq_write(&sx->iobuf, &b, 1, &nwritten);
    if(result || (nwritten != 1))
      return CURLPX_SEND_REQUEST;
  }
  return CURLPX_OK;
}

static CURLproxycode socks4_resolving(struct socks_ctx *sx,
                                      struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *done)
{
  const struct Curl_addrinfo *ai = NULL;
  CURLcode result;
  size_t nwritten;
  bool dns_done;

  *done = FALSE;
  if(sx->start_resolving) {
    /* need to resolve hostname to add destination address */
    sx->start_resolving = FALSE;
    result = Curl_cf_dns_insert_after(
      cf, data, Curl_resolv_dns_queries(data, sx->ip_version),
      sx->dest, TRNSPRT_TCP, TRUE);
    if(result) {
      failf(data, "unable to create DNS filter for socks");
      return CURLPX_UNKNOWN_FAIL;
    }
  }

  /* resolve the hostname by connecting the DNS filter */
  result = Curl_conn_cf_connect(cf->next, data, &dns_done);
  if(result) {
    failf(data, "Failed to resolve \"%s\" for SOCKS4 connect.",
          sx->dest->hostname);
    return CURLPX_RESOLVE_HOST;
  }
  else if(!dns_done)
    return CURLPX_OK;

  ai = Curl_cf_dns_get_ai(cf->next, data, sx->dest, AF_INET, 0);
  if(ai) {
    struct sockaddr_in *saddr_in;
    char ipbuf[64];

    Curl_printable_address(ai, ipbuf, sizeof(ipbuf));
    CURL_TRC_CF(data, cf, "SOCKS4 connect to IPv4 %s (locally resolved)",
                ipbuf);

    saddr_in = (struct sockaddr_in *)(void *)ai->ai_addr;
    result = Curl_bufq_write(&sx->iobuf,
                             (unsigned char *)&saddr_in->sin_addr.s_addr, 4,
                             &nwritten);

    if(result || (nwritten != 4))
      return CURLPX_SEND_REQUEST;
  }
  else {
    /* No ipv4 address resolved */
    failf(data, "SOCKS4 connection to %s not supported", sx->dest->hostname);
    return CURLPX_RESOLVE_HOST;
  }

  *done = TRUE;
  return CURLPX_OK;
}

static CURLproxycode socks4_check_resp(struct socks_ctx *sx,
                                       struct Curl_cfilter *cf,
                                       struct Curl_easy *data)
{
  const unsigned char *resp;
  size_t rlen;

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < 8) {
    failf(data, "SOCKS4 reply is incomplete.");
    return CURLPX_RECV_CONNECT;
  }

  DEBUGASSERT(rlen == 8);
  /*
   * Response format
   *
   *     +----+----+----+----+----+----+----+----+
   *     | VN | CD | DSTPORT |      DSTIP        |
   *     +----+----+----+----+----+----+----+----+
   * # of bytes:  1    1      2              4
   *
   * VN is the version of the reply code and should be 0. CD is the result
   * code with one of the following values:
   *
   * 90: request granted
   * 91: request rejected or failed
   * 92: request rejected because SOCKS server cannot connect to
   *     identd on the client
   * 93: request rejected because the client program and identd
   *     report different user-ids
   */

  /* wrong version ? */
  if(resp[0]) {
    failf(data, "SOCKS4 reply has wrong version, version should be 0.");
    return CURLPX_BAD_VERSION;
  }

  /* Result */
  switch(resp[1]) {
  case 90:
    CURL_TRC_CF(data, cf, "SOCKS4%s request granted.", sx->socks4a ? "a" : "");
    Curl_bufq_skip(&sx->iobuf, 8);
    return CURLPX_OK;
  case 91:
    failf(data,
          "[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"
          ", request rejected or failed.",
          resp[4], resp[5], resp[6], resp[7],
          (unsigned int)((resp[2] << 8) | resp[3]), resp[1]);
    return CURLPX_REQUEST_FAILED;
  case 92:
    failf(data,
          "[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"
          ", request rejected because SOCKS server cannot connect to "
          "identd on the client.",
          resp[4], resp[5], resp[6], resp[7],
          (unsigned int)((resp[2] << 8) | resp[3]), resp[1]);
    return CURLPX_IDENTD;
  case 93:
    failf(data,
          "[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"
          ", request rejected because the client program and identd "
          "report different user-ids.",
          resp[4], resp[5], resp[6], resp[7],
          (unsigned int)((resp[2] << 8) | resp[3]), resp[1]);
    return CURLPX_IDENTD_DIFFER;
  default:
    failf(data,
          "[SOCKS] cannot complete SOCKS4 connection to %u.%u.%u.%u:%u. (%u)"
          ", Unknown.",
          resp[4], resp[5], resp[6], resp[7],
          (unsigned int)((resp[2] << 8) | resp[3]), resp[1]);
    return CURLPX_UNKNOWN_FAIL;
  }
}

/*
 * This function logs in to a SOCKS4 proxy and sends the specifics to the final
 * destination server.
 *
 * Reference :
 *   https://www.openssh.com/txt/socks4.protocol
 *
 * Note :
 *   Set protocol4a=true for  "SOCKS 4A (Simple Extension to SOCKS 4 Protocol)"
 *   Nonsupport "Identification Protocol (RFC1413)"
 */
static CURLproxycode socks4_connect(struct Curl_cfilter *cf,
                                    struct socks_ctx *sx,
                                    struct Curl_easy *data)
{
  size_t nwritten;
  CURLproxycode presult;
  CURLcode result;
  bool done;

process_state:
  switch(sx->state) {
  case SOCKS_ST_INIT:
    sx->version = 4;
    sxstate(sx, cf, data, SOCKS4_ST_START);
    FALLTHROUGH();

  case SOCKS4_ST_START:
    Curl_bufq_reset(&sx->iobuf);
    sx->start_resolving = FALSE;
    sx->socks4a = (sx->proxy_type == CURLPROXY_SOCKS4A);
    sx->resolve_local = !sx->socks4a;
    sx->presult = CURLPX_OK;

    /* SOCKS4 can only do IPv4, insist! */
    sx->ip_version = CURL_IPRESOLVE_V4;
    CURL_TRC_CF(data, cf, "SOCKS4%s connecting to %s:%u",
                sx->socks4a ? "a" : "",
                sx->dest->hostname, sx->dest->port);

    /*
     * Compose socks4 request
     *
     * Request format
     *
     *     +----+----+----+----+----+----+----+----+----+----+....+----+
     *     | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
     *     +----+----+----+----+----+----+----+----+----+----+....+----+
     * # of bytes:  1    1      2              4           variable       1
     */
    presult = socks4_req_add_hd(sx, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);

    /* DNS resolve only for SOCKS4, not SOCKS4a */
    if(!sx->resolve_local) {
      /* socks4a, not resolving locally, sends the hostname.
       * add an invalid address + user + hostname */
      unsigned char buf[4] = { 0, 0, 0, 1 };
      size_t hlen = strlen(sx->dest->hostname) + 1; /* including NUL */

      if(hlen > 255) {
        failf(data, "SOCKS4: too long hostname");
        return socks_failed(sx, cf, data, CURLPX_LONG_HOSTNAME);
      }
      result = Curl_bufq_write(&sx->iobuf, buf, 4, &nwritten);
      if(result || (nwritten != 4))
        return socks_failed(sx, cf, data, CURLPX_SEND_REQUEST);
      presult = socks4_req_add_user(sx, data);
      if(presult)
        return socks_failed(sx, cf, data, presult);
      result = Curl_bufq_cwrite(&sx->iobuf, sx->dest->hostname, hlen,
                                &nwritten);
      if(result || (nwritten != hlen))
        return socks_failed(sx, cf, data, CURLPX_SEND_REQUEST);
      /* request complete */
      sxstate(sx, cf, data, SOCKS4_ST_SEND);
      goto process_state;
    }
    sx->start_resolving = TRUE;
    sxstate(sx, cf, data, SOCKS4_ST_RESOLVING);
    FALLTHROUGH();

  case SOCKS4_ST_RESOLVING:
    presult = socks4_resolving(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    if(!done)
      return CURLPX_OK;
    /* append user */
    presult = socks4_req_add_user(sx, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    sxstate(sx, cf, data, SOCKS4_ST_SEND);
    FALLTHROUGH();

  case SOCKS4_ST_SEND:
    presult = socks_flush(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    sxstate(sx, cf, data, SOCKS4_ST_RECV);
    FALLTHROUGH();

  case SOCKS4_ST_RECV:
    /* Receive 8-byte response */
    presult = socks_recv(sx, cf, data, 8, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    presult = socks4_check_resp(sx, cf, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    sxstate(sx, cf, data, SOCKS_ST_SUCCESS);
    FALLTHROUGH();

  case SOCKS_ST_SUCCESS:
    return CURLPX_OK;

  case SOCKS_ST_FAILED:
    DEBUGASSERT(sx->presult);
    return sx->presult;

  default:
    DEBUGASSERT(0);
    return socks_failed(sx, cf, data, CURLPX_SEND_REQUEST);
  }
}

static CURLproxycode socks5_req0_init(struct Curl_cfilter *cf,
                                      struct socks_ctx *sx,
                                      struct Curl_easy *data)
{
  const unsigned char auth = data->set.socks5auth;
  unsigned char req[5]; /* version + len + 3 possible auth methods */
  unsigned char nauths;
  size_t req_len, nwritten;
  CURLcode result;

  (void)cf;
  /* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
  if(!sx->resolve_local && strlen(sx->dest->hostname) > 255) {
    failf(data, "SOCKS5: the destination hostname is too long to be "
          "resolved remotely by the proxy.");
    return CURLPX_LONG_HOSTNAME;
  }

  if(auth & ~(CURLAUTH_BASIC | CURLAUTH_GSSAPI))
    infof(data, "warning: unsupported value passed to "
          "CURLOPT_SOCKS5_AUTH: %u", auth);
  if(!(auth & CURLAUTH_BASIC))
    /* disable username/password auth */
    Curl_creds_unlink(&sx->creds);

  req[0] = 5;   /* version */
  nauths = 1;
  req[1 + nauths] = 0;   /* 1. no authentication */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  if(auth & CURLAUTH_GSSAPI) {
    ++nauths;
    req[1 + nauths] = 1; /* GSS-API */
  }
#endif
  if(sx->creds) {
    ++nauths;
    req[1 + nauths] = 2; /* username/password */
  }
  req[1] = nauths;
  req_len = 2 + nauths;

  result = Curl_bufq_write(&sx->iobuf, req, req_len, &nwritten);
  if(result || (nwritten != req_len))
    return CURLPX_SEND_REQUEST;
  return CURLPX_OK;
}

static CURLproxycode socks5_check_resp0(struct socks_ctx *sx,
                                        struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  const unsigned char *resp;
  unsigned char auth_mode;
  size_t rlen;

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < 2) {
    failf(data, "SOCKS5 initial reply is incomplete.");
    return CURLPX_RECV_CONNECT;
  }

  if(resp[0] != 5) {
    failf(data, "Received invalid version in initial SOCKS5 response.");
    return CURLPX_BAD_VERSION;
  }

  auth_mode = resp[1];
  Curl_bufq_skip(&sx->iobuf, 2);

  switch(auth_mode) {
  case 0:
    /* DONE! No authentication needed. Send request. */
    sxstate(sx, cf, data, SOCKS5_ST_REQ1_INIT);
    return CURLPX_OK;
  case 1:
    if(data->set.socks5auth & CURLAUTH_GSSAPI) {
      sxstate(sx, cf, data, SOCKS5_ST_GSSAPI_INIT);
      return CURLPX_OK;
    }
    failf(data, "SOCKS5 GSSAPI per-message authentication is not enabled.");
    return CURLPX_GSSAPI_PERMSG;
  case 2:
    /* regular name + password authentication */
    if(data->set.socks5auth & CURLAUTH_BASIC) {
      sxstate(sx, cf, data, SOCKS5_ST_AUTH_INIT);
      return CURLPX_OK;
    }
    failf(data, "BASIC authentication proposed but not enabled.");
    return CURLPX_NO_AUTH;
  case 255:
    failf(data, "No authentication method was acceptable.");
    return CURLPX_NO_AUTH;
  default:
    failf(data, "Unknown SOCKS5 mode attempted to be used by server.");
    return CURLPX_UNKNOWN_MODE;
  }
}

static CURLproxycode socks5_auth_init(struct Curl_cfilter *cf,
                                      struct socks_ctx *sx,
                                      struct Curl_easy *data)
{
  /* Needs username and password */
  size_t ulen = 0, plen = 0, nwritten;
  unsigned char buf[2];
  CURLcode result;

  if(sx->creds) {
    ulen = strlen(sx->creds->user);
    plen = strlen(sx->creds->passwd);
    /* the lengths must fit in a single byte */
    if(ulen > 255) {
      failf(data, "Excessive username length for proxy auth");
      return CURLPX_LONG_USER;
    }
    if(plen > 255) {
      failf(data, "Excessive password length for proxy auth");
      return CURLPX_LONG_PASSWD;
    }
  }

  /*   username/password request looks like
   * +----+------+----------+------+----------+
   * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
   * +----+------+----------+------+----------+
   * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
   * +----+------+----------+------+----------+
   */
  buf[0] = 1;    /* username/pw subnegotiation version */
  buf[1] = (unsigned char)ulen;
  result = Curl_bufq_write(&sx->iobuf, buf, 2, &nwritten);
  if(result || (nwritten != 2))
    return CURLPX_SEND_REQUEST;
  if(ulen) {
    result = Curl_bufq_cwrite(&sx->iobuf, sx->creds->user, ulen, &nwritten);
    if(result || (nwritten != ulen))
      return CURLPX_SEND_REQUEST;
  }
  buf[0] = (unsigned char)plen;
  result = Curl_bufq_write(&sx->iobuf, buf, 1, &nwritten);
  if(result || (nwritten != 1))
    return CURLPX_SEND_REQUEST;
  if(plen) {
    result = Curl_bufq_cwrite(&sx->iobuf, sx->creds->passwd, plen, &nwritten);
    if(result || (nwritten != plen))
      return CURLPX_SEND_REQUEST;
  }
  sxstate(sx, cf, data, SOCKS5_ST_AUTH_SEND);
  return CURLPX_OK;
}

static CURLproxycode socks5_check_auth_resp(struct socks_ctx *sx,
                                            struct Curl_cfilter *cf,
                                            struct Curl_easy *data)
{
  const unsigned char *resp;
  unsigned char auth_status;
  size_t rlen;

  (void)cf;
  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < 2) {
    failf(data, "SOCKS5 sub-negotiation response incomplete.");
    return CURLPX_RECV_CONNECT;
  }

  /* ignore the first (VER) byte */
  auth_status = resp[1];
  if(auth_status) {
    failf(data, "User was rejected by the SOCKS5 server (%d %d).",
          resp[0], resp[1]);
    return CURLPX_USER_REJECTED;
  }
  Curl_bufq_skip(&sx->iobuf, 2);
  return CURLPX_OK;
}

/* curl-impersonate: cache the address QUIC uses as its UDP peer. */
static void socks5_udp_set_peer(struct socks_ctx *sx,
                                int family,
                                const unsigned char *address,
                                int port)
{
  memset(&sx->udp_peer_addr, 0, sizeof(sx->udp_peer_addr));
  if(family == AF_INET) {
    struct sockaddr_in *sa =
      (struct sockaddr_in *)(void *)&sx->udp_peer_addr.curl_sa_addr;
    sa->sin_family = AF_INET;
    memcpy(&sa->sin_addr, address, sizeof(struct in_addr));
    sa->sin_port = htons((unsigned short)port);
    sx->udp_peer_addr.family = AF_INET;
    sx->udp_peer_addr.addrlen = sizeof(struct sockaddr_in);
  }
#ifdef USE_IPV6
  else if(family == AF_INET6) {
    struct sockaddr_in6 *sa6 =
      (struct sockaddr_in6 *)(void *)&sx->udp_peer_addr.curl_sa_addr;
    sa6->sin6_family = AF_INET6;
    memcpy(&sa6->sin6_addr, address, sizeof(struct in6_addr));
    sa6->sin6_port = htons((unsigned short)port);
    sx->udp_peer_addr.family = AF_INET6;
    sx->udp_peer_addr.addrlen = sizeof(struct sockaddr_in6);
  }
#endif
  else
    return;
  sx->udp_peer_addr.socktype = SOCK_DGRAM;
  sx->udp_peer_addr.protocol = IPPROTO_UDP;
  sx->udp_peer_set = TRUE;
}

/* curl-impersonate: cache the resolved target for SOCKS5 UDP headers. */
static void socks5_udp_set_dest(struct socks_ctx *sx,
                                int family,
                                const unsigned char *address)
{
  size_t addrlen = SOCKS5_IPV4_LEN;
  sx->udp_dest_atyp = SOCKS5_ATYP_IPV4;
#ifdef USE_IPV6
  if(family == AF_INET6) {
    addrlen = SOCKS5_IPV6_LEN;
    sx->udp_dest_atyp = SOCKS5_ATYP_IPV6;
  }
#else
  (void)family;
#endif
  memcpy(sx->udp_dest_addr, address, addrlen);
  sx->udp_dest_port = sx->dest->port;
  sx->udp_dest_set = TRUE;
  socks5_udp_set_peer(sx, family, address, sx->udp_dest_port);
}

/* curl-impersonate: cache a target which the SOCKS5 proxy resolves. */
static CURLproxycode socks5_udp_set_domain(struct socks_ctx *sx,
                                           struct Curl_easy *data)
{
  size_t hlen = strlen(sx->dest->hostname);
  if(!hlen || hlen > 255) {
    failf(data, "SOCKS5 UDP destination hostname is invalid");
    return CURLPX_LONG_HOSTNAME;
  }
  sx->udp_dest_atyp = SOCKS5_ATYP_DOMAIN;
  memcpy(sx->udp_dest_domain, sx->dest->hostname, hlen);
  sx->udp_dest_domain_len = hlen;
  sx->udp_dest_port = sx->dest->port;
  sx->udp_dest_set = TRUE;
  return CURLPX_OK;
}

static CURLproxycode socks5_req1_init(struct socks_ctx *sx,
                                      struct Curl_cfilter *cf,
                                      struct Curl_easy *data)
{
  unsigned char req[5];
  unsigned char ipbuf[16];
  const unsigned char *destination;
  unsigned char desttype, destlen, hdlen;
  size_t nwritten;
  CURLcode result;

  req[0] = 5; /* version (SOCKS5) */
  /* curl-impersonate: use UDP ASSOCIATE for a QUIC data path. */
  req[1] = sx->udp_associate ? 3 : 1; /* UDP ASSOCIATE or CONNECT */
  req[2] = 0; /* must be zero */
  if(sx->resolve_local) {
    /* rest of request is added after resolving */
    result = Curl_bufq_write(&sx->iobuf, req, 3, &nwritten);
    if(result || (nwritten != 3))
      return CURLPX_SEND_REQUEST;
    return CURLPX_OK;
  }

  /* remote resolving, send what type+addr/string to resolve */
#ifdef USE_IPV6
  if(strchr(sx->dest->hostname, ':')) {
    desttype = 4;
    destination = ipbuf;
    destlen = 16;
    if(curlx_inet_pton(AF_INET6, sx->dest->hostname, ipbuf) != 1)
      return CURLPX_BAD_ADDRESS_TYPE;
  }
  else
#endif
  if(curlx_inet_pton(AF_INET, sx->dest->hostname, ipbuf) == 1) {
    desttype = 1;
    destination = ipbuf;
    destlen = 4;
  }
  else {
    const size_t hostname_len = strlen(sx->dest->hostname);
    /* socks5_req0_init() already rejects hostnames longer than 255 bytes, so
       this cast to unsigned char is safe. Assert to guard against future
       refactoring that might remove or reorder that earlier check. */
    DEBUGASSERT(hostname_len <= 255);
    desttype = 3;
    destination = (const unsigned char *)sx->dest->hostname;
    destlen = (unsigned char)hostname_len; /* 1-byte length */
  }

  if(sx->udp_associate) {
    CURLproxycode presult;

    /* Preserve the real target for the per-datagram SOCKS5 UDP header. */
    if(desttype == SOCKS5_ATYP_IPV4)
      socks5_udp_set_dest(sx, AF_INET, destination);
#ifdef USE_IPV6
    else if(desttype == SOCKS5_ATYP_IPV6)
      socks5_udp_set_dest(sx, AF_INET6, destination);
#endif
    else {
      presult = socks5_udp_set_domain(sx, data);
      if(presult)
        return presult;
    }

    /* The UDP endpoint is not bound yet. Request an unspecified relay. */
    memset(ipbuf, 0, sizeof(ipbuf));
#ifdef USE_IPV6
    if(data->set.ipver == CURL_IPRESOLVE_V6) {
      desttype = SOCKS5_ATYP_IPV6;
      destlen = SOCKS5_IPV6_LEN;
    }
    else
#endif
    {
      desttype = SOCKS5_ATYP_IPV4;
      destlen = SOCKS5_IPV4_LEN;
    }
    destination = ipbuf;
  }

  req[3] = desttype;
  req[4] = destlen;
  hdlen = (desttype == 3) ? 5 : 4; /* no length byte for ip addresses */
  result = Curl_bufq_write(&sx->iobuf, req, hdlen, &nwritten);
  if(result || (nwritten != hdlen))
    return CURLPX_SEND_REQUEST;
  result = Curl_bufq_write(&sx->iobuf, destination, destlen, &nwritten);
  if(result || (nwritten != destlen))
    return CURLPX_SEND_REQUEST;
  /* An unbound UDP endpoint requests port zero per RFC 1928. */
  /* PORT MSB+LSB */
  req[0] = sx->udp_associate ? 0 :
    (unsigned char)((sx->dest->port >> 8) & 0xff);
  req[1] = sx->udp_associate ? 0 :
    (unsigned char)(sx->dest->port & 0xff);
  result = Curl_bufq_write(&sx->iobuf, req, 2, &nwritten);
  if(result || (nwritten != 2))
    return CURLPX_SEND_REQUEST;
  CURL_TRC_CF(data, cf, "SOCKS5 connect to %s:%u (remotely resolved)",
              sx->dest->hostname, sx->dest->port);
  return CURLPX_OK;
}

static CURLproxycode socks5_resolving(struct socks_ctx *sx,
                                      struct Curl_cfilter *cf,
                                      struct Curl_easy *data,
                                      bool *done)
{
  const struct Curl_addrinfo *ai = NULL;
  char dest[MAX_IPADR_LEN];  /* printable address */
  const unsigned char *destination = NULL;
  unsigned char desttype = 1, destlen = 4;
  unsigned char bind_addr[SOCKS5_IPV6_LEN] = { 0 };
  unsigned char req[2];
  CURLcode result;
  CURLproxycode presult = CURLPX_OK;
  size_t nwritten;
  bool dns_done;

  *done = FALSE;
  if(sx->start_resolving) {
    /* need to resolve hostname to add destination address */
    sx->start_resolving = FALSE;
    result = Curl_cf_dns_insert_after(
      cf, data, Curl_resolv_dns_queries(data, sx->ip_version),
      sx->dest, TRNSPRT_TCP, TRUE);
    if(result) {
      failf(data, "unable to create DNS filter for socks");
      return CURLPX_UNKNOWN_FAIL;
    }
  }

  /* resolve the hostname by connecting the DNS filter */
  result = Curl_conn_cf_connect(cf->next, data, &dns_done);
  if(result) {
    failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
          sx->dest->hostname);
    return CURLPX_RESOLVE_HOST;
  }
  else if(!dns_done)
    return CURLPX_OK;

#ifdef USE_IPV6
  if(data->set.ipver != CURL_IPRESOLVE_V4)
    ai = Curl_cf_dns_get_ai(cf->next, data, sx->dest, AF_INET6, 0);
#endif
  if(!ai)
    ai = Curl_cf_dns_get_ai(cf->next, data, sx->dest, AF_INET, 0);

  if(!ai) {
    failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
          sx->dest->hostname);
    presult = CURLPX_RESOLVE_HOST;
    goto out;
  }

  Curl_printable_address(ai, dest, sizeof(dest));

  if(ai->ai_family == AF_INET) {
    struct sockaddr_in *saddr_in;
    desttype = 1; /* ATYP: IPv4 = 1 */
    destlen = 4;
    saddr_in = (struct sockaddr_in *)(void *)ai->ai_addr;
    destination = (const unsigned char *)&saddr_in->sin_addr.s_addr;
    CURL_TRC_CF(data, cf, "SOCKS5 connect to %s:%u (locally resolved)",
                dest, sx->dest->port);
  }
#ifdef USE_IPV6
  else if(ai->ai_family == AF_INET6) {
    struct sockaddr_in6 *saddr_in6;
    desttype = 4; /* ATYP: IPv6 = 4 */
    destlen = 16;
    saddr_in6 = (struct sockaddr_in6 *)(void *)ai->ai_addr;
    destination = (const unsigned char *)&saddr_in6->sin6_addr.s6_addr;
    CURL_TRC_CF(data, cf, "SOCKS5 connect to [%s]:%u (locally resolved)",
                dest, sx->dest->port);
  }
#endif

  if(!destination) {
    failf(data, "SOCKS5 connection to %s not supported", dest);
    presult = CURLPX_RESOLVE_HOST;
    goto out;
  }

  if(sx->udp_associate) {
    /* Preserve the locally resolved target for SOCKS5 UDP headers. */
    socks5_udp_set_dest(sx, ai->ai_family, destination);
    destination = bind_addr;
  }

  req[0] = desttype;
  result = Curl_bufq_write(&sx->iobuf, req, 1, &nwritten);
  if(result || (nwritten != 1)) {
    presult = CURLPX_SEND_REQUEST;
    goto out;
  }
  result = Curl_bufq_write(&sx->iobuf, destination, destlen, &nwritten);
  if(result || (nwritten != destlen)) {
    presult = CURLPX_SEND_REQUEST;
    goto out;
  }
  /* An unbound UDP endpoint requests port zero per RFC 1928. */
  /* PORT MSB+LSB */
  req[0] = sx->udp_associate ? 0 :
    (unsigned char)((sx->dest->port >> 8) & 0xffU);
  req[1] = sx->udp_associate ? 0 :
    (unsigned char)(sx->dest->port & 0xffU);
  result = Curl_bufq_write(&sx->iobuf, req, 2, &nwritten);
  if(result || (nwritten != 2)) {
    presult = CURLPX_SEND_REQUEST;
    goto out;
  }

out:
  *done = (presult == CURLPX_OK);
  return presult;
}

static CURLproxycode socks5_recv_resp1(struct socks_ctx *sx,
                                       struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool *done)
{
  const unsigned char *resp;
  size_t rlen, resp_len = 8; /* minimum response length */
  CURLproxycode presult;

  presult = socks_recv(sx, cf, data, resp_len, done);
  if(presult)
    return presult;
  else if(!*done)
    return CURLPX_OK;

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < resp_len) {
    failf(data, "SOCKS5 response is incomplete.");
    return CURLPX_RECV_CONNECT;
  }

  /* Response packet includes BND.ADDR is variable length parameter by RFC
     1928, so the response packet MUST be read until the end to avoid errors
     at subsequent protocol level.

     +----+-----+-------+------+----------+----------+
     |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
     +----+-----+-------+------+----------+----------+
     | 1  |  1  | 0x00  |  1   | Variable |    2     |
     +----+-----+-------+------+----------+----------+

     ATYP:
     o IPv4 address: 0x01, BND.ADDR = 4-byte
     o domain name:  0x03, BND.ADDR = [ 1-byte length, string ]
     o IPv6 address: 0x04, BND.ADDR = 16-byte
  */
  if(resp[0] != 5) { /* version */
    failf(data, "SOCKS5 reply has wrong version, version should be 5.");
    return CURLPX_BAD_VERSION;
  }
  else if(resp[1]) { /* Anything besides 0 is an error */
    CURLproxycode rc = CURLPX_REPLY_UNASSIGNED;
    int code = resp[1];
    failf(data, "cannot complete SOCKS5 connection to %s. (%d)",
          sx->dest->hostname, code);
    if(code < 9) {
      /* RFC 1928 section 6 lists: */
      static const CURLproxycode lookup[] = {
        CURLPX_OK,
        CURLPX_REPLY_GENERAL_SERVER_FAILURE,
        CURLPX_REPLY_NOT_ALLOWED,
        CURLPX_REPLY_NETWORK_UNREACHABLE,
        CURLPX_REPLY_HOST_UNREACHABLE,
        CURLPX_REPLY_CONNECTION_REFUSED,
        CURLPX_REPLY_TTL_EXPIRED,
        CURLPX_REPLY_COMMAND_NOT_SUPPORTED,
        CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
      };
      rc = lookup[code];
    }
    return rc;
  }

  /* Calculate real packet size */
  switch(resp[3]) {
  case 1: /* IPv4 */
    resp_len = 4 + 4 + 2;
    break;
  case 3: /* domain name */
    resp_len = 4 + 1 + resp[4] + 2; /* header, var length, var bytes, port */
    break;
  case 4: /* IPv6 */
    resp_len = 4 + 16 + 2;
    break;
  default:
    failf(data, "SOCKS5 reply has wrong address type.");
    return CURLPX_BAD_ADDRESS_TYPE;
  }

  /* receive the rest of the response */
  presult = socks_recv(sx, cf, data, resp_len, done);
  if(presult)
    return presult;
  else if(!*done)
    return CURLPX_OK;

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < resp_len) {
    failf(data, "SOCKS5 response is incomplete.");
    return CURLPX_RECV_CONNECT;
  }
  /* got it all */
  *done = TRUE;
  return CURLPX_OK;
}

/* curl-impersonate: parse BND.ADDR and BND.PORT from the UDP ASSOCIATE
 * response and store the proxy's UDP relay endpoint. */
static CURLproxycode socks5_udp_set_relay(struct socks_ctx *sx,
                                          struct Curl_easy *data)
{
  const unsigned char *resp;
  const unsigned char *address;
  size_t rlen;
  size_t addrlen;
  char addrbuf[MAX_IPADR_LEN];

  if(!Curl_bufq_peek(&sx->iobuf, &resp, &rlen) || rlen < 8)
    return CURLPX_RECV_CONNECT;

  address = &resp[SOCKS5_HEADER_LEN];
  switch(resp[3]) {
  case SOCKS5_ATYP_IPV4:
    addrlen = SOCKS5_IPV4_LEN;
    sx->udp_relay_family = AF_INET;
    break;
#ifdef USE_IPV6
  case SOCKS5_ATYP_IPV6:
    addrlen = SOCKS5_IPV6_LEN;
    sx->udp_relay_family = AF_INET6;
    break;
#endif
  default:
    failf(data, "SOCKS5 UDP relay has unsupported address type");
    return CURLPX_BAD_ADDRESS_TYPE;
  }

  if(rlen < SOCKS5_HEADER_LEN + addrlen + SOCKS5_PORT_LEN)
    return CURLPX_RECV_CONNECT;
  memcpy(sx->udp_relay_addr, address, addrlen);
  sx->udp_relay_port = (int)((address[addrlen] << 8) |
                             address[addrlen + 1]);
  if(!sx->udp_relay_port) {
    failf(data, "SOCKS5 UDP relay returned port 0");
    return CURLPX_BAD_ADDRESS_TYPE;
  }
  if(!curlx_inet_ntop(sx->udp_relay_family, sx->udp_relay_addr,
                      addrbuf, sizeof(addrbuf)))
    strcpy(addrbuf, "unknown");
  infof(data, "SOCKS5 UDP relay is %s:%d", addrbuf,
        sx->udp_relay_port);
  return CURLPX_OK;
}

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the final
 * destination server.
 */
static CURLproxycode socks5_connect(struct Curl_cfilter *cf,
                                    struct socks_ctx *sx,
                                    struct Curl_easy *data)
{
  CURLproxycode presult;
  bool done;

process_state:
  switch(sx->state) {
  case SOCKS_ST_INIT:
    sx->version = 5;
    sx->resolve_local = (sx->proxy_type == CURLPROXY_SOCKS5);
    sxstate(sx, cf, data, SOCKS5_ST_START);
    FALLTHROUGH();

  case SOCKS5_ST_START:
    CURL_TRC_CF(data, cf, "SOCKS5: connecting to %s:%u",
                sx->dest->hostname, sx->dest->port);
    presult = socks5_req0_init(cf, sx, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    sxstate(sx, cf, data, SOCKS5_ST_REQ0_SEND);
    FALLTHROUGH();

  case SOCKS5_ST_REQ0_SEND:
    presult = socks_flush(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    /* done sending! */
    sxstate(sx, cf, data, SOCKS5_ST_RESP0_RECV);
    FALLTHROUGH();

  case SOCKS5_ST_RESP0_RECV:
    presult = socks_recv(sx, cf, data, 2, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    presult = socks5_check_resp0(sx, cf, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    /* socks5_check_resp0() sets next socks state */
    goto process_state;

  case SOCKS5_ST_GSSAPI_INIT: {
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    /* GSSAPI stuff done non-blocking */
    CURLcode result = Curl_SOCKS5_gssapi_negotiate(cf, data, sx->creds);
    if(result) {
      failf(data, "Unable to negotiate SOCKS5 GSS-API context.");
      return CURLPX_GSSAPI;
    }
    sxstate(sx, cf, data, SOCKS5_ST_REQ1_INIT);
    goto process_state;
#else
    failf(data, "SOCKS5 GSSAPI per-message authentication is not supported.");
    return socks_failed(sx, cf, data, CURLPX_GSSAPI_PERMSG);
#endif
  }

  case SOCKS5_ST_AUTH_INIT:
    presult = socks5_auth_init(cf, sx, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    sxstate(sx, cf, data, SOCKS5_ST_AUTH_SEND);
    FALLTHROUGH();

  case SOCKS5_ST_AUTH_SEND:
    presult = socks_flush(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    sxstate(sx, cf, data, SOCKS5_ST_AUTH_RECV);
    FALLTHROUGH();

  case SOCKS5_ST_AUTH_RECV:
    presult = socks_recv(sx, cf, data, 2, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
    presult = socks5_check_auth_resp(sx, cf, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    /* Everything is good so far, user was authenticated! */
    sxstate(sx, cf, data, SOCKS5_ST_REQ1_INIT);
    FALLTHROUGH();

  case SOCKS5_ST_REQ1_INIT:
    presult = socks5_req1_init(sx, cf, data);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    if(!sx->resolve_local) {
      /* we do not resolve, request is complete */
      sxstate(sx, cf, data, SOCKS5_ST_REQ1_SEND);
      goto process_state;
    }
    /* curl-impersonate: locally resolve the QUIC target before caching it
     * for the SOCKS5 UDP header. */
    sx->start_resolving = TRUE;
    sxstate(sx, cf, data, SOCKS5_ST_RESOLVING);
    FALLTHROUGH();

  case SOCKS5_ST_RESOLVING:
    presult = socks5_resolving(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    if(!done)
      return CURLPX_OK;
    sxstate(sx, cf, data, SOCKS5_ST_REQ1_SEND);
    FALLTHROUGH();

  case SOCKS5_ST_REQ1_SEND:
    presult = socks_flush(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    else if(!done)
      return CURLPX_OK;
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(cf->conn->socks5_gssapi_enctype) {
      failf(data, "SOCKS5 GSS-API protection not yet implemented.");
      return CURLPX_GSSAPI_PROTECTION;
    }
#endif
    sxstate(sx, cf, data, SOCKS5_ST_RESP1_RECV);
    FALLTHROUGH();

  case SOCKS5_ST_RESP1_RECV:
    presult = socks5_recv_resp1(sx, cf, data, &done);
    if(presult)
      return socks_failed(sx, cf, data, presult);
    if(!done)
      return CURLPX_OK;
    if(sx->udp_associate) {
      presult = socks5_udp_set_relay(sx, data);
      if(presult)
        return socks_failed(sx, cf, data, presult);
    }
    CURL_TRC_CF(data, cf, "SOCKS5 request granted.");
    sxstate(sx, cf, data, SOCKS_ST_SUCCESS);
    FALLTHROUGH();

  case SOCKS_ST_SUCCESS:
    return CURLPX_OK;

  case SOCKS_ST_FAILED:
    DEBUGASSERT(sx->presult);
    return sx->presult;

  default:
    DEBUGASSERT(0);
    return socks_failed(sx, cf, data, CURLPX_SEND_REQUEST);
  }
}

/* curl-impersonate: create the UDP relay data path while retaining the TCP
 * control channel required for the lifetime of the association. */
static CURLcode socks5_udp_create(struct Curl_cfilter *cf,
                                  struct socks_ctx *sx,
                                  struct Curl_easy *data)
{
  const struct Curl_sockaddr_ex *proxy_addr = NULL;
  struct Curl_sockaddr_ex relay_addr;
  struct Curl_peer *origin;
  size_t addrlen;
  size_t i;
  bool is_zero = TRUE;
  int dummy = 0;
  CURLcode result;

  addrlen = SOCKS5_IPV4_LEN;
#ifdef USE_IPV6
  if(sx->udp_relay_family == AF_INET6)
    addrlen = SOCKS5_IPV6_LEN;
#endif
  for(i = 0; i < addrlen; ++i) {
    if(sx->udp_relay_addr[i]) {
      is_zero = FALSE;
      break;
    }
  }
  /* If the relay address is 0.0.0.0 or ::, reuse the proxy's TCP peer. */
  if(is_zero && cf->next &&
     !cf->next->cft->query(cf->next, data, CF_QUERY_REMOTE_ADDR,
                           &dummy, &proxy_addr) && proxy_addr) {
    if(proxy_addr->family == AF_INET) {
      const struct sockaddr_in *sa =
        (const struct sockaddr_in *)(const void *)&proxy_addr->curl_sa_addr;
      memcpy(sx->udp_relay_addr, &sa->sin_addr, sizeof(sa->sin_addr));
      sx->udp_relay_family = AF_INET;
      is_zero = FALSE;
    }
#ifdef USE_IPV6
    else if(proxy_addr->family == AF_INET6) {
      const struct sockaddr_in6 *sa6 =
        (const struct sockaddr_in6 *)(const void *)&proxy_addr->curl_sa_addr;
      memcpy(sx->udp_relay_addr, &sa6->sin6_addr, sizeof(sa6->sin6_addr));
      sx->udp_relay_family = AF_INET6;
      is_zero = FALSE;
    }
#endif
  }
  if(is_zero)
    return CURLE_COULDNT_CONNECT;

  memset(&relay_addr, 0, sizeof(relay_addr));
  if(sx->udp_relay_family == AF_INET) {
    struct sockaddr_in *sa =
      (struct sockaddr_in *)(void *)&relay_addr.curl_sa_addr;
    sa->sin_family = AF_INET;
    memcpy(&sa->sin_addr, sx->udp_relay_addr, sizeof(sa->sin_addr));
    sa->sin_port = htons((unsigned short)sx->udp_relay_port);
    relay_addr.family = AF_INET;
    relay_addr.addrlen = sizeof(*sa);
  }
#ifdef USE_IPV6
  else if(sx->udp_relay_family == AF_INET6) {
    struct sockaddr_in6 *sa6 =
      (struct sockaddr_in6 *)(void *)&relay_addr.curl_sa_addr;
    sa6->sin6_family = AF_INET6;
    memcpy(&sa6->sin6_addr, sx->udp_relay_addr, sizeof(sa6->sin6_addr));
    sa6->sin6_port = htons((unsigned short)sx->udp_relay_port);
    relay_addr.family = AF_INET6;
    relay_addr.addrlen = sizeof(*sa6);
  }
#endif
  else
    return CURLE_COULDNT_CONNECT;
  relay_addr.socktype = SOCK_DGRAM;
  relay_addr.protocol = IPPROTO_UDP;

  /* QUIC needs a connected UDP socket when using UDP ASSOCIATE. */
  origin = Curl_conn_get_origin(cf->conn, cf->sockindex);
  result = Curl_cf_udp_create(&sx->udp_cf, data, origin, sx->dest,
                              TRNSPRT_QUIC, cf->conn, &relay_addr,
                              NULL, TRNSPRT_QUIC);
  if(result)
    return result;
  sx->udp_cf->conn = cf->conn;
  sx->udp_cf->sockindex = cf->sockindex;
  return CURLE_OK;
}

static void socks_proxy_ctx_free(struct socks_ctx *ctx,
                                 struct Curl_easy *data)
{
  if(ctx) {
    if(ctx->tcp_cf)
      Curl_conn_cf_discard_chain(&ctx->tcp_cf, data);
    Curl_peer_unlink(&ctx->dest);
    Curl_creds_unlink(&ctx->creds);
    Curl_bufq_free(&ctx->iobuf);
    curlx_free(ctx);
  }
}

/* After a TCP connection to the proxy has been verified, this function does
   the next magic steps. If 'done' is not set TRUE, it is not done yet and
   must be called again.

   Note: this function's sub-functions call failf()

*/
static CURLcode socks_proxy_cf_connect(struct Curl_cfilter *cf,
                                       struct Curl_easy *data,
                                       bool *done)
{
  struct socks_ctx *ctx = cf->ctx;
  CURLproxycode pxresult = CURLPX_OK;
  CURLcode result;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  result = cf->next->cft->do_connect(cf->next, data, done);
  if(result || !*done)
    return result;

  switch(ctx->proxy_type) {
  case CURLPROXY_SOCKS5:
  case CURLPROXY_SOCKS5_HOSTNAME:
    pxresult = socks5_connect(cf, ctx, data);
    break;

  case CURLPROXY_SOCKS4:
  case CURLPROXY_SOCKS4A:
    pxresult = socks4_connect(cf, ctx, data);
    break;

  default:
    DEBUGASSERT(0); /* should not come here, checked it at creation time */
    result = CURLE_COULDNT_CONNECT;
    goto out;
  }

  if(pxresult) {
    result = CURLE_PROXY;
    data->info.pxcode = pxresult;
    goto out;
  }
  else if(ctx->state != SOCKS_ST_SUCCESS)
    goto out;

  if(ctx->udp_associate) {
    if(!ctx->udp_cf) {
      result = socks5_udp_create(cf, ctx, data);
      if(result)
        goto out;
      /* Keep the TCP control channel and switch the data path to the UDP
       * relay. Closing the control channel terminates the association. */
      ctx->tcp_cf = cf->next;
      cf->next = ctx->udp_cf;
      CURL_TRC_CF(data, cf, "switched from SOCKS TCP control to UDP relay");
    }
    result = Curl_conn_cf_connect(cf->next, data, done);
    if(result || !*done)
      goto out;
  }

#ifdef CURLVERBOSE
  if(Curl_trc_is_verbose(data)) {
    struct ip_quadruple ipquad;
    bool is_ipv6;
    if(!Curl_conn_cf_get_ip_info(cf->next, data, &is_ipv6, &ipquad))
      infof(data, "Opened %sSOCKS connection from %s port %d to %s port %d "
            "(via %s port %u)",
            (cf->sockindex == SECONDARYSOCKET) ? "2nd " : "",
            ipquad.local_ip, ipquad.local_port,
            ctx->dest->hostname, ctx->dest->port,
            ipquad.remote_ip, ipquad.remote_port);
    else
      infof(data, "Opened %sSOCKS connection",
            (cf->sockindex == SECONDARYSOCKET) ? "2nd " : "");
  }
#endif
  cf->connected = TRUE;

out:
  *done = (bool)cf->connected;
  if(*done || result)
    Curl_creds_unlink(&ctx->creds);
  return result;
}

/* curl-impersonate: wrap outgoing QUIC datagrams in SOCKS5 UDP headers. */
static CURLcode socks_proxy_cf_send(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    const uint8_t *buf, size_t len, bool eos,
                                    size_t *pnwritten)
{
  struct socks_ctx *sx = cf->ctx;
  unsigned char *packet;
  unsigned char atyp;
  size_t addrlen;
  size_t header_len;
  size_t nwritten = 0;
  CURLcode result;

  *pnwritten = 0;
  if(!sx || !sx->udp_associate)
    return Curl_cf_def_send(cf, data, buf, len, eos, pnwritten);
  if(!sx->udp_dest_set)
    return CURLE_SEND_ERROR;

  switch(sx->udp_dest_atyp) {
#ifdef USE_IPV6
  case SOCKS5_ATYP_IPV6:
    atyp = SOCKS5_ATYP_IPV6;
    addrlen = SOCKS5_IPV6_LEN;
    break;
#endif
  case SOCKS5_ATYP_DOMAIN:
    atyp = SOCKS5_ATYP_DOMAIN;
    addrlen = 1 + sx->udp_dest_domain_len;
    break;
  default:
    atyp = SOCKS5_ATYP_IPV4;
    addrlen = SOCKS5_IPV4_LEN;
    break;
  }

  header_len = SOCKS5_HEADER_LEN + addrlen + SOCKS5_PORT_LEN;
  if(len > SIZE_MAX - header_len)
    return CURLE_OUT_OF_MEMORY;
  packet = curlx_malloc(header_len + len);
  if(!packet)
    return CURLE_OUT_OF_MEMORY;

  packet[0] = 0; /* RSV */
  packet[1] = 0; /* RSV */
  packet[2] = 0; /* FRAG */
  packet[3] = atyp;
  if(atyp == SOCKS5_ATYP_DOMAIN) {
    packet[4] = (unsigned char)sx->udp_dest_domain_len;
    memcpy(&packet[5], sx->udp_dest_domain, sx->udp_dest_domain_len);
  }
  else
    memcpy(&packet[4], sx->udp_dest_addr, addrlen);
  packet[SOCKS5_HEADER_LEN + addrlen] =
    (unsigned char)((sx->udp_dest_port >> 8) & 0xffU);
  packet[SOCKS5_HEADER_LEN + addrlen + 1] =
    (unsigned char)(sx->udp_dest_port & 0xffU);
  memcpy(&packet[header_len], buf, len);

  result = cf->next->cft->do_send(cf->next, data, packet,
                                  header_len + len, eos, &nwritten);
  curlx_free(packet);
  if(result)
    return result;
  if(nwritten != header_len + len)
    return CURLE_SEND_ERROR;
  *pnwritten = len;
  return CURLE_OK;
}

/* curl-impersonate: strip SOCKS5 UDP headers before passing QUIC payloads
 * upward. */
static CURLcode socks_proxy_cf_recv(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    char *buf, size_t len, size_t *pnread)
{
  struct socks_ctx *sx = cf->ctx;
  const size_t max_header = SOCKS5_HEADER_LEN + 1 + 255 + SOCKS5_PORT_LEN;
  unsigned char *packet;
  size_t packet_len;
  size_t addrlen;
  size_t offset;
  size_t nread = 0;
  CURLcode result;

  *pnread = 0;
  if(!sx || !sx->udp_associate)
    return Curl_cf_def_recv(cf, data, buf, len, pnread);
  if(len > SIZE_MAX - max_header)
    return CURLE_OUT_OF_MEMORY;
  packet_len = len + max_header;
  packet = curlx_malloc(packet_len);
  if(!packet)
    return CURLE_OUT_OF_MEMORY;

  result = cf->next->cft->do_recv(cf->next, data, (char *)packet,
                                  packet_len, &nread);
  if(result)
    goto out;
  if(nread < SOCKS5_HEADER_LEN || packet[0] || packet[1] || packet[2]) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  offset = SOCKS5_HEADER_LEN;
  switch(packet[3]) {
  case SOCKS5_ATYP_IPV4:
    addrlen = SOCKS5_IPV4_LEN;
    break;
#ifdef USE_IPV6
  case SOCKS5_ATYP_IPV6:
    addrlen = SOCKS5_IPV6_LEN;
    break;
#endif
  case SOCKS5_ATYP_DOMAIN:
    if(nread < SOCKS5_HEADER_LEN + 1) {
      result = CURLE_RECV_ERROR;
      goto out;
    }
    addrlen = 1 + packet[SOCKS5_HEADER_LEN];
    break;
  default:
    result = CURLE_RECV_ERROR;
    goto out;
  }
  if(nread < offset + addrlen + SOCKS5_PORT_LEN) {
    result = CURLE_RECV_ERROR;
    goto out;
  }

  /* For socks5h with a domain target, leave udp_peer_set false so the socket
   * filter reports the relay as QUIC's network peer. For locally resolved
   * targets and IP literals, cache the source address from the UDP header. */
  if((packet[3] == SOCKS5_ATYP_IPV4
#ifdef USE_IPV6
      || packet[3] == SOCKS5_ATYP_IPV6
#endif
     ) &&
     sx->udp_dest_atyp != SOCKS5_ATYP_DOMAIN) {
    int port = (int)((packet[offset + addrlen] << 8) |
                     packet[offset + addrlen + 1]);
#ifdef USE_IPV6
    socks5_udp_set_peer(sx,
                        packet[3] == SOCKS5_ATYP_IPV4 ? AF_INET : AF_INET6,
                        &packet[offset], port);
#else
    socks5_udp_set_peer(sx, AF_INET, &packet[offset], port);
#endif
  }

  offset += addrlen + SOCKS5_PORT_LEN;
  if(nread > offset) {
    size_t payload_len = nread - offset;
    if(payload_len > len)
      payload_len = len;
    memcpy(buf, &packet[offset], payload_len);
    *pnread = payload_len;
  }

out:
  curlx_free(packet);
  return result;
}

static CURLcode socks_cf_adjust_pollset(struct Curl_cfilter *cf,
                                        struct Curl_easy *data,
                                        struct easy_pollset *ps)
{
  struct socks_ctx *sx = cf->ctx;
  CURLcode result = CURLE_OK;

  if(!cf->connected && sx) {
    /* If we are not connected, the filter below is and has nothing
     * to wait on, we determine what to wait for. */
    curl_socket_t sock = Curl_conn_cf_get_socket(cf, data);
    switch(sx->state) {
    case SOCKS4_ST_SEND:
    case SOCKS5_ST_REQ0_SEND:
    case SOCKS5_ST_AUTH_SEND:
    case SOCKS5_ST_REQ1_SEND:
      CURL_TRC_CF(data, cf, "adjust pollset out (%d)", (int)sx->state);
      result = Curl_pollset_set_out_only(data, ps, sock);
      break;
    default:
      CURL_TRC_CF(data, cf, "adjust pollset in (%d)", (int)sx->state);
      result = Curl_pollset_set_in_only(data, ps, sock);
      break;
    }
  }
  return result;
}

static void socks_proxy_cf_destroy(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  socks_proxy_ctx_free(cf->ctx, data);
  cf->ctx = NULL;
}

static CURLcode socks_cf_query(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               int query, int *pres1, void *pres2)
{
  struct socks_ctx *sx = cf->ctx;

  switch(query) {
  case CF_QUERY_REMOTE_ADDR:
    /* Return the target for local DNS/IP literals. For socks5h domain names,
     * fall through so the UDP relay address is returned instead. */
    if(sx && sx->udp_associate && sx->udp_peer_set) {
      *((const struct Curl_sockaddr_ex **)pres2) = &sx->udp_peer_addr;
      return CURLE_OK;
    }
    break;
  case CF_QUERY_HOST_PORT:
    if(sx) {
      *pres1 = sx->dest->port;
      *((const char **)pres2) = sx->dest->hostname;
      return CURLE_OK;
    }
    break;
  case CF_QUERY_ALPN_NEGOTIATED: {
    const char **palpn = pres2;
    DEBUGASSERT(palpn);
    *palpn = NULL;
    return CURLE_OK;
  }
  default:
    break;
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

struct Curl_cftype Curl_cft_socks_proxy = {
  "SOCKS",
  CF_TYPE_IP_CONNECT | CF_TYPE_PROXY,
  0,
  socks_proxy_cf_destroy,
  socks_proxy_cf_connect,
  Curl_cf_def_shutdown,
  socks_cf_adjust_pollset,
  Curl_cf_def_data_pending,
  socks_proxy_cf_send,
  socks_proxy_cf_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  socks_cf_query,
};

bool Curl_cf_socks_proxy_is_udp_associate(struct Curl_cfilter *cf)
{
  for(; cf; cf = cf->next) {
    if(cf->cft == &Curl_cft_socks_proxy) {
      struct socks_ctx *sx = cf->ctx;
      return sx && sx->udp_associate;
    }
  }
  return FALSE;
}

CURLcode Curl_cf_socks_proxy_insert_after(struct Curl_cfilter *cf_at,
                                          struct Curl_easy *data,
                                          struct Curl_peer *dest,
                                          uint8_t transport,
                                          uint8_t ip_version,
                                          uint8_t proxy_type,
                                          struct Curl_creds *creds)
{
  struct Curl_cfilter *cf;
  struct socks_ctx *ctx;
  CURLcode result;

  if(!dest)
    return CURLE_FAILED_INIT;

  switch(proxy_type) {
  case CURLPROXY_SOCKS5:
  case CURLPROXY_SOCKS5_HOSTNAME:
  case CURLPROXY_SOCKS4:
  case CURLPROXY_SOCKS4A:
    break; /* all supported */
  default:
    failf(data, "unknown proxytype %d option given", proxy_type);
    return CURLE_COULDNT_CONNECT;
  }
  if((transport == TRNSPRT_QUIC) &&
     !cf_at->conn->http_proxy.peer &&
     (proxy_type != CURLPROXY_SOCKS5) &&
     (proxy_type != CURLPROXY_SOCKS5_HOSTNAME)) {
    failf(data, "SOCKS UDP ASSOCIATE requires SOCKS5");
    return CURLE_UNSUPPORTED_PROTOCOL;
  }

  /* NUL byte already part of struct size */
  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    return CURLE_OUT_OF_MEMORY;
  }

  Curl_peer_link(&ctx->dest, dest);
  ctx->ip_version = ip_version;
  ctx->proxy_type = proxy_type;
  /* curl-impersonate: QUIC through a direct SOCKS proxy uses UDP ASSOCIATE.
   * A nested HTTP proxy continues through its TCP CONNECT path. */
  ctx->udp_associate =
    (transport == TRNSPRT_QUIC) &&
    !cf_at->conn->http_proxy.peer;
  Curl_creds_link(&ctx->creds, creds);
  Curl_bufq_init2(&ctx->iobuf, SOCKS_CHUNK_SIZE, SOCKS_CHUNKS,
                  BUFQ_OPT_SOFT_LIMIT);

  result = Curl_cf_create(&cf, &Curl_cft_socks_proxy, ctx);
  if(!result)
    Curl_conn_cf_insert_after(cf_at, cf);
  else
    socks_proxy_ctx_free(ctx, data);
  return result;
}

#endif /* CURL_DISABLE_PROXY */
