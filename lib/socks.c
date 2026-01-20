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

#if !defined(CURL_DISABLE_PROXY)

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "urldata.h"
#include "sendf.h"
#include "select.h"
#include "cfilters.h"
#include "connect.h"
#include "cf-socket.h"
#if defined(USE_NGTCP2) && defined(USE_NGHTTP3)
#include "vquic/curl_ngtcp2.h"
#endif
#include "curlx/timeval.h"
#include "socks.h"
#include "multiif.h" /* for getsock macros */
#include "curl_addrinfo.h"
#include "curlx/inet_pton.h"
#include "curlx/inet_ntop.h"
#include "url.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

/* for the (SOCKS) connect state machine */
enum connect_t {
  CONNECT_INIT,
  CONNECT_SOCKS_INIT, /* 1 */
  CONNECT_SOCKS_SEND, /* 2 waiting to send more first data */
  CONNECT_SOCKS_READ_INIT, /* 3 set up read */
  CONNECT_SOCKS_READ, /* 4 read server response */
  CONNECT_GSSAPI_INIT, /* 5 */
  CONNECT_AUTH_INIT, /* 6 setup outgoing auth buffer */
  CONNECT_AUTH_SEND, /* 7 send auth */
  CONNECT_AUTH_READ, /* 8 read auth response */
  CONNECT_REQ_INIT,  /* 9 init SOCKS "request" */
  CONNECT_RESOLVING, /* 10 */
  CONNECT_RESOLVED,  /* 11 */
  CONNECT_RESOLVE_REMOTE, /* 12 */
  CONNECT_REQ_SEND,  /* 13 */
  CONNECT_REQ_SENDING, /* 14 */
  CONNECT_REQ_READ,  /* 15 */
  CONNECT_REQ_READ_MORE, /* 16 */
  CONNECT_DONE /* 17 connected fine to the remote or the SOCKS proxy */
};

enum socks5_atyp {
  SOCKS5_ATYP_IPV4 = 1,
  SOCKS5_ATYP_DOMAIN = 3,
  SOCKS5_ATYP_IPV6 = 4
};

#define CURL_SOCKS_BUF_SIZE 600

/* make sure we configure it not too low */
#if CURL_SOCKS_BUF_SIZE < 600
#error CURL_SOCKS_BUF_SIZE must be at least 600
#endif


struct socks_state {
  enum connect_t state;
  size_t outstanding;  /* send this many bytes more */
  unsigned char buffer[CURL_SOCKS_BUF_SIZE];
  unsigned char *outp; /* send from this pointer */

  const char *hostname;
  int remote_port;
  const char *proxy_user;
  const char *proxy_password;

  // See more in RFC 1928
  size_t replylen;                  /* SOCKS5 reply length to read after fixed header */
  struct Curl_cfilter *tcp_cf;      /* TCP control channel to the SOCKS proxy for UDP */
  struct Curl_cfilter *udp_cf;      /* UDP data relay channel to the SOCKS proxy */

  unsigned char udp_relay_addr[16]; /* relay address, port and family */
  int udp_relay_port;
  int udp_relay_family;
  int udp_dest_atyp;                /* SOCKS5 ATYP for UDP destination */
  unsigned char udp_dest_addr[16];  /* QUIC destination address, port and family */
  int udp_dest_port;
  int udp_dest_family;
  unsigned char udp_dest_domain[256];
  size_t udp_dest_domain_len;
  struct Curl_sockaddr_ex udp_peer_addr;
  BIT(udp_peer_set);
  BIT(udp_associate);               /* use SOCKS5 UDP ASSOCIATE instead of CONNECT */
  BIT(udp_dest_set);                /* QUIC destination cached for UDP headers */
};

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
/*
 * Helper read-from-socket functions. Does the same as Curl_read() but it
 * blocks until all bytes amount of buffersize will be read. No more, no less.
 *
 * This is STUPID BLOCKING behavior. Only used by the SOCKS GSSAPI functions.
 */
int Curl_blockread_all(struct Curl_cfilter *cf,
                       struct Curl_easy *data,   /* transfer */
                       char *buf,                /* store read data here */
                       size_t blen,              /* space in buf */
                       size_t *pnread)           /* amount bytes read */
{
  size_t nread = 0;
  CURLcode err;

  *pnread = 0;
  for(;;) {
    timediff_t timeout_ms = Curl_timeleft(data, NULL, TRUE);
    if(timeout_ms < 0) {
      /* we already got the timeout */
      return CURLE_OPERATION_TIMEDOUT;
    }
    if(!timeout_ms)
      timeout_ms = TIMEDIFF_T_MAX;
    if(SOCKET_READABLE(cf->conn->sock[cf->sockindex], timeout_ms) <= 0) {
      return ~CURLE_OK;
    }
    err = Curl_conn_cf_recv(cf->next, data, buf, blen, &nread);
    if(CURLE_AGAIN == err)
      continue;
    else if(err)
      return (int)err;

    if(blen == nread) {
      *pnread += nread;
      return CURLE_OK;
    }
    if(!nread) /* EOF */
      return ~CURLE_OK;

    buf += nread;
    blen -= nread;
    *pnread += nread;
  }
}
#endif

#if defined(DEBUGBUILD) && !defined(CURL_DISABLE_VERBOSE_STRINGS)
#define DEBUG_AND_VERBOSE
#define sxstate(x,d,y) socksstate(x,d,y, __LINE__)
#else
#define sxstate(x,d,y) socksstate(x,d,y)
#endif

/* always use this function to change state, to make debugging easier */
static void socksstate(struct socks_state *sx, struct Curl_easy *data,
                       enum connect_t state
#ifdef DEBUG_AND_VERBOSE
                       , int lineno
#endif
)
{
  enum connect_t oldstate = sx->state;
#ifdef DEBUG_AND_VERBOSE
  /* synced with the state list in urldata.h */
  static const char * const socks_statename[] = {
    "INIT",
    "SOCKS_INIT",
    "SOCKS_SEND",
    "SOCKS_READ_INIT",
    "SOCKS_READ",
    "GSSAPI_INIT",
    "AUTH_INIT",
    "AUTH_SEND",
    "AUTH_READ",
    "REQ_INIT",
    "RESOLVING",
    "RESOLVED",
    "RESOLVE_REMOTE",
    "REQ_SEND",
    "REQ_SENDING",
    "REQ_READ",
    "REQ_READ_MORE",
    "DONE"
  };
#endif

  (void)data;
  if(oldstate == state)
    /* do not bother when the new state is the same as the old state */
    return;

  sx->state = state;

#ifdef DEBUG_AND_VERBOSE
  infof(data,
        "SXSTATE: %s => %s; line %d",
        socks_statename[oldstate], socks_statename[sx->state],
        lineno);
#endif
}

static CURLproxycode socks_state_send(struct Curl_cfilter *cf,
                                      struct socks_state *sx,
                                      struct Curl_easy *data,
                                      CURLproxycode failcode,
                                      const char *description)
{
  size_t nwritten;
  CURLcode result;

  result = Curl_conn_cf_send(cf->next, data, (char *)sx->outp,
                             sx->outstanding, FALSE, &nwritten);
  if(result) {
    if(CURLE_AGAIN == result)
      return CURLPX_OK;

    failf(data, "Failed to send %s: %s", description,
          curl_easy_strerror(result));
    return failcode;
  }
  else if(!nwritten) {
    /* connection closed */
    failf(data, "connection to proxy closed");
    return CURLPX_CLOSED;
  }

  DEBUGASSERT(sx->outstanding >= nwritten);
  /* not done, remain in state */
  sx->outstanding -= nwritten;
  sx->outp += nwritten;
  return CURLPX_OK;
}

static CURLproxycode socks_state_recv(struct Curl_cfilter *cf,
                                      struct socks_state *sx,
                                      struct Curl_easy *data,
                                      CURLproxycode failcode,
                                      const char *description)
{
  size_t nread;
  CURLcode result;

  result = Curl_conn_cf_recv(cf->next, data, (char *)sx->outp,
                            sx->outstanding, &nread);
  if(result) {
    if(CURLE_AGAIN == result)
      return CURLPX_OK;

    failf(data, "SOCKS: Failed receiving %s: %s", description,
          curl_easy_strerror(result));
    return failcode;
  }
  else if(!nread) {
    /* connection closed */
    failf(data, "connection to proxy closed");
    return CURLPX_CLOSED;
  }
  /* remain in reading state */
  DEBUGASSERT(sx->outstanding >= nread);
  sx->outstanding -= nread;
  sx->outp += nread;
  return CURLPX_OK;
}

/* curl-impersonate: set up udp relay
 * Parse the address in reply and store the relay address/port in socks_state.
 * */
static CURLproxycode socks5_set_udp_relay(struct socks_state *sx,
                                          struct Curl_easy *data)
{
  const unsigned char *socksreq = sx->buffer;
  const unsigned char *addrp = &socksreq[4]; /* First 4 bytes are VER, REP, RSV, ATYP */
  size_t addrlen;
  int atyp = socksreq[3]; /* ATYP from SOCKS5 reply */

  if(sx->replylen < 6) { /* minimum: 4-byte header + 2-byte port */
    failf(data, "SOCKS5 UDP associate reply too short");
    return CURLPX_BAD_ADDRESS_TYPE;
  }

  switch(atyp) {
    case SOCKS5_ATYP_IPV4:
      addrlen = 4;
      sx->udp_relay_family = AF_INET;
      break;
#ifdef USE_IPV6
    case SOCKS5_ATYP_IPV6:
      addrlen = 16;
      sx->udp_relay_family = AF_INET6;
      break;
#endif
    case SOCKS5_ATYP_DOMAIN:
    default:
      failf(data, "SOCKS5 UDP associate reply has wrong address type.");
      return CURLPX_BAD_ADDRESS_TYPE;
  }

  if(4 + addrlen + 2 > sx->replylen) { /* header + addr + port */
    failf(data, "SOCKS5 UDP associate reply truncated");
    return CURLPX_BAD_ADDRESS_TYPE;
  }

  memcpy(sx->udp_relay_addr, addrp, addrlen);
  /* Port is in network byte order in the last two bytes. */
  sx->udp_relay_port = (int)((addrp[addrlen] << 8) | addrp[addrlen + 1]);
  {
    char addrstr[MAX_IPADR_LEN] = "";
    if(!curlx_inet_ntop(sx->udp_relay_family, sx->udp_relay_addr,
                        addrstr, sizeof(addrstr)))
      strcpy(addrstr, "unknown");
    infof(data, "SOCKS5 UDP relay reply ATYP=%d BND.ADDR=%s BND.PORT=%d",
          atyp, addrstr, sx->udp_relay_port);
  }
  return CURLPX_OK;
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
static CURLproxycode do_SOCKS4(struct Curl_cfilter *cf,
                               struct socks_state *sx,
                               struct Curl_easy *data)
{
  struct connectdata *conn = cf->conn;
  const bool protocol4a =
    (conn->socks_proxy.proxytype == CURLPROXY_SOCKS4A);
  unsigned char *socksreq = sx->buffer;
  CURLcode result;
  CURLproxycode presult;
  struct Curl_dns_entry *dns = NULL;

  switch(sx->state) {
  case CONNECT_SOCKS_INIT:
    /* SOCKS4 can only do IPv4, insist! */
    conn->ip_version = CURL_IPRESOLVE_V4;
    if(conn->bits.httpproxy)
      infof(data, "SOCKS4%s: connecting to HTTP proxy %s port %d",
            protocol4a ? "a" : "", sx->hostname, sx->remote_port);

    infof(data, "SOCKS4 communication to %s:%d",
          sx->hostname, sx->remote_port);

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

    socksreq[0] = 4; /* version (SOCKS4) */
    socksreq[1] = 1; /* connect */
    socksreq[2] = (unsigned char)((sx->remote_port >> 8) & 0xff); /* MSB */
    socksreq[3] = (unsigned char)(sx->remote_port & 0xff);        /* LSB */

    /* DNS resolve only for SOCKS4, not SOCKS4a */
    if(!protocol4a) {
      result = Curl_resolv(data, sx->hostname, sx->remote_port,
                           cf->conn->ip_version, TRUE, &dns);

      if(result == CURLE_AGAIN) {
        sxstate(sx, data, CONNECT_RESOLVING);
        infof(data, "SOCKS4 non-blocking resolve of %s", sx->hostname);
        return CURLPX_OK;
      }
      else if(result)
        return CURLPX_RESOLVE_HOST;
      sxstate(sx, data, CONNECT_RESOLVED);
      goto CONNECT_RESOLVED;
    }

    /* socks4a does not resolve anything locally */
    sxstate(sx, data, CONNECT_REQ_INIT);
    goto CONNECT_REQ_INIT;

  case CONNECT_RESOLVING:
    /* check if we have the name resolved by now */
    result = Curl_resolv_check(data, &dns);
    if(!dns) {
      if(result)
        return CURLPX_RESOLVE_HOST;
      return CURLPX_OK;
    }
    FALLTHROUGH();
  case CONNECT_RESOLVED:
CONNECT_RESOLVED:
  {
    struct Curl_addrinfo *hp = NULL;
    /*
     * We cannot use 'hostent' as a struct that Curl_resolv() returns. It
     * returns a Curl_addrinfo pointer that may not always look the same.
     */
    if(dns) {
      hp = dns->addr;

      /* scan for the first IPv4 address */
      while(hp && (hp->ai_family != AF_INET))
        hp = hp->ai_next;

      if(hp) {
        struct sockaddr_in *saddr_in;
        char buf[64];
        Curl_printable_address(hp, buf, sizeof(buf));

        saddr_in = (struct sockaddr_in *)(void *)hp->ai_addr;
        socksreq[4] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[0];
        socksreq[5] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[1];
        socksreq[6] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[2];
        socksreq[7] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[3];

        infof(data, "SOCKS4 connect to IPv4 %s (locally resolved)", buf);

        Curl_resolv_unlink(data, &dns); /* not used anymore from now on */
      }
      else
        failf(data, "SOCKS4 connection to %s not supported", sx->hostname);
    }
    else
      failf(data, "Failed to resolve \"%s\" for SOCKS4 connect.",
            sx->hostname);

    if(!hp)
      return CURLPX_RESOLVE_HOST;
  }
    FALLTHROUGH();
  case CONNECT_REQ_INIT:
CONNECT_REQ_INIT:
    /*
     * This is currently not supporting "Identification Protocol (RFC1413)".
     */
    socksreq[8] = 0; /* ensure empty userid is null-terminated */
    if(sx->proxy_user) {
      size_t plen = strlen(sx->proxy_user);
      if(plen > 255) {
        /* there is no real size limit to this field in the protocol, but
           SOCKS5 limits the proxy user field to 255 bytes and it seems likely
           that a longer field is either a mistake or malicious input */
        failf(data, "Too long SOCKS proxy username");
        return CURLPX_LONG_USER;
      }
      /* copy the proxy name WITH trailing zero */
      memcpy(socksreq + 8, sx->proxy_user, plen + 1);
    }

    /*
     * Make connection
     */
    {
      size_t packetsize = 9 +
        strlen((char *)socksreq + 8); /* size including NUL */

      /* If SOCKS4a, set special invalid IP address 0.0.0.x */
      if(protocol4a) {
        size_t hostnamelen = 0;
        socksreq[4] = 0;
        socksreq[5] = 0;
        socksreq[6] = 0;
        socksreq[7] = 1;
        /* append hostname */
        hostnamelen = strlen(sx->hostname) + 1; /* length including NUL */
        if((hostnamelen <= 255) &&
           (packetsize + hostnamelen < sizeof(sx->buffer)))
          strcpy((char *)socksreq + packetsize, sx->hostname);
        else {
          failf(data, "SOCKS4: too long hostname");
          return CURLPX_LONG_HOSTNAME;
        }
        packetsize += hostnamelen;
      }
      sx->outp = socksreq;
      DEBUGASSERT(packetsize <= sizeof(sx->buffer));
      sx->outstanding = packetsize;
      sxstate(sx, data, CONNECT_REQ_SENDING);
    }
    FALLTHROUGH();
  case CONNECT_REQ_SENDING:
    /* Send request */
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_CONNECT,
                               "SOCKS4 connect request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in sending state */
      return CURLPX_OK;
    }
    /* done sending! */
    sx->outstanding = 8; /* receive data size */
    sx->outp = socksreq;
    sxstate(sx, data, CONNECT_SOCKS_READ);

    FALLTHROUGH();
  case CONNECT_SOCKS_READ:
    /* Receive response */
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_CONNECT,
                               "connect request ack");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    sxstate(sx, data, CONNECT_DONE);
    break;
  default: /* lots of unused states in SOCKS4 */
    break;
  }

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
  if(socksreq[0]) {
    failf(data,
          "SOCKS4 reply has wrong version, version should be 0.");
    return CURLPX_BAD_VERSION;
  }

  /* Result */
  switch(socksreq[1]) {
  case 90:
    infof(data, "SOCKS4%s request granted.", protocol4a ? "a" : "");
    break;
  case 91:
    failf(data,
          "cannot complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected or failed.",
          socksreq[4], socksreq[5], socksreq[6], socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLPX_REQUEST_FAILED;
  case 92:
    failf(data,
          "cannot complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected because SOCKS server cannot connect to "
          "identd on the client.",
          socksreq[4], socksreq[5], socksreq[6], socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLPX_IDENTD;
  case 93:
    failf(data,
          "cannot complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", request rejected because the client program and identd "
          "report different user-ids.",
          socksreq[4], socksreq[5], socksreq[6], socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLPX_IDENTD_DIFFER;
  default:
    failf(data,
          "cannot complete SOCKS4 connection to %d.%d.%d.%d:%d. (%d)"
          ", Unknown.",
          socksreq[4], socksreq[5], socksreq[6], socksreq[7],
          (((unsigned char)socksreq[2] << 8) | (unsigned char)socksreq[3]),
          (unsigned char)socksreq[1]);
    return CURLPX_UNKNOWN_FAIL;
  }

  return CURLPX_OK; /* Proxy was successful! */
}

/*
 * This function logs in to a SOCKS5 proxy and sends the specifics to the final
 * destination server.
 */
static CURLproxycode do_SOCKS5(struct Curl_cfilter *cf,
                               struct socks_state *sx,
                               struct Curl_easy *data)
{
  /*
    According to the RFC1928, section "6. Replies". This is what a SOCK5
    replies:

        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

    Where:

    o  VER    protocol version: X'05'
    o  REP    Reply field:
    o  X'00' succeeded
  */
  struct connectdata *conn = cf->conn;
  unsigned char *socksreq = sx->buffer;
  size_t idx;
  CURLcode result;
  CURLproxycode presult;
  bool socks5_resolve_local =
    (conn->socks_proxy.proxytype == CURLPROXY_SOCKS5);
  const size_t hostname_len = strlen(sx->hostname);
  size_t len = 0;
  const unsigned char auth = data->set.socks5auth;
  bool allow_gssapi = FALSE;
  struct Curl_dns_entry *dns = NULL;

  switch(sx->state) {
  case CONNECT_SOCKS_INIT:
    if(conn->bits.httpproxy)
      infof(data, "SOCKS5: connecting to HTTP proxy %s port %d",
            sx->hostname, sx->remote_port);
    /* curl-impersonate */
    if(sx->udp_associate)
      infof(data, "SOCKS5: UDP associate mode enabled for QUIC");

    /* RFC1928 chapter 5 specifies max 255 chars for domain name in packet */
    if(!socks5_resolve_local && hostname_len > 255) {
      failf(data, "SOCKS5: the destination hostname is too long to be "
            "resolved remotely by the proxy.");
      return CURLPX_LONG_HOSTNAME;
    }

    if(auth & ~(CURLAUTH_BASIC | CURLAUTH_GSSAPI))
      infof(data,
            "warning: unsupported value passed to CURLOPT_SOCKS5_AUTH: %u",
            auth);
    if(!(auth & CURLAUTH_BASIC))
      /* disable username/password auth */
      sx->proxy_user = NULL;
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(auth & CURLAUTH_GSSAPI)
      allow_gssapi = TRUE;
#endif

    idx = 0;
    socksreq[idx++] = 5;   /* version */
    idx++;                 /* number of authentication methods */
    socksreq[idx++] = 0;   /* no authentication */
    if(allow_gssapi)
      socksreq[idx++] = 1; /* GSS-API */
    if(sx->proxy_user)
      socksreq[idx++] = 2; /* username/password */
    /* write the number of authentication methods */
    socksreq[1] = (unsigned char) (idx - 2);

    sx->outp = socksreq;
    DEBUGASSERT(idx <= sizeof(sx->buffer));
    sx->outstanding = idx;
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_CONNECT,
                               "initial SOCKS5 request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in sending state */
      return CURLPX_OK;
    }
    sxstate(sx, data, CONNECT_SOCKS_READ);
    goto CONNECT_SOCKS_READ_INIT;
  case CONNECT_SOCKS_SEND:
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_CONNECT,
                               "initial SOCKS5 request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in sending state */
      return CURLPX_OK;
    }
    FALLTHROUGH();
  case CONNECT_SOCKS_READ_INIT:
CONNECT_SOCKS_READ_INIT:
    sx->outstanding = 2; /* expect two bytes */
    sx->outp = socksreq; /* store it here */
    FALLTHROUGH();
  case CONNECT_SOCKS_READ:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_CONNECT,
                               "initial SOCKS5 response");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    else if(socksreq[0] != 5) {
      failf(data, "Received invalid version in initial SOCKS5 response.");
      return CURLPX_BAD_VERSION;
    }
    else if(socksreq[1] == 0) {
      /* DONE! No authentication needed. Send request. */
      sxstate(sx, data, CONNECT_REQ_INIT);
      goto CONNECT_REQ_INIT;
    }
    else if(socksreq[1] == 2) {
      /* regular name + password authentication */
      sxstate(sx, data, CONNECT_AUTH_INIT);
      goto CONNECT_AUTH_INIT;
    }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    else if(allow_gssapi && (socksreq[1] == 1)) {
      sxstate(sx, data, CONNECT_GSSAPI_INIT);
      result = Curl_SOCKS5_gssapi_negotiate(cf, data);
      if(result) {
        failf(data, "Unable to negotiate SOCKS5 GSS-API context.");
        return CURLPX_GSSAPI;
      }
    }
#endif
    else {
      /* error */
      if(!allow_gssapi && (socksreq[1] == 1)) {
        failf(data,
              "SOCKS5 GSSAPI per-message authentication is not supported.");
        return CURLPX_GSSAPI_PERMSG;
      }
      else if(socksreq[1] == 255) {
        failf(data, "No authentication method was acceptable.");
        return CURLPX_NO_AUTH;
      }
    }
    failf(data,
          "Undocumented SOCKS5 mode attempted to be used by server.");
    return CURLPX_UNKNOWN_MODE;
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
  case CONNECT_GSSAPI_INIT:
    /* GSSAPI stuff done non-blocking */
    break;
#endif

  default: /* do nothing! */
    break;

CONNECT_AUTH_INIT:
  case CONNECT_AUTH_INIT: {
    /* Needs username and password */
    size_t proxy_user_len, proxy_password_len;
    if(sx->proxy_user && sx->proxy_password) {
      proxy_user_len = strlen(sx->proxy_user);
      proxy_password_len = strlen(sx->proxy_password);
    }
    else {
      proxy_user_len = 0;
      proxy_password_len = 0;
    }

    /*   username/password request looks like
     * +----+------+----------+------+----------+
     * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     * +----+------+----------+------+----------+
     * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     * +----+------+----------+------+----------+
     */
    len = 0;
    socksreq[len++] = 1;    /* username/pw subnegotiation version */
    socksreq[len++] = (unsigned char) proxy_user_len;
    if(sx->proxy_user && proxy_user_len) {
      /* the length must fit in a single byte */
      if(proxy_user_len > 255) {
        failf(data, "Excessive username length for proxy auth");
        return CURLPX_LONG_USER;
      }
      memcpy(socksreq + len, sx->proxy_user, proxy_user_len);
    }
    len += proxy_user_len;
    socksreq[len++] = (unsigned char) proxy_password_len;
    if(sx->proxy_password && proxy_password_len) {
      /* the length must fit in a single byte */
      if(proxy_password_len > 255) {
        failf(data, "Excessive password length for proxy auth");
        return CURLPX_LONG_PASSWD;
      }
      memcpy(socksreq + len, sx->proxy_password, proxy_password_len);
    }
    len += proxy_password_len;
    sxstate(sx, data, CONNECT_AUTH_SEND);
    DEBUGASSERT(len <= sizeof(sx->buffer));
    sx->outstanding = len;
    sx->outp = socksreq;
  }
    FALLTHROUGH();
  case CONNECT_AUTH_SEND:
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_AUTH,
                               "SOCKS5 sub-negotiation request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in sending state */
      return CURLPX_OK;
    }
    sx->outp = socksreq;
    sx->outstanding = 2;
    sxstate(sx, data, CONNECT_AUTH_READ);
    FALLTHROUGH();
  case CONNECT_AUTH_READ:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_AUTH,
                               "SOCKS5 sub-negotiation response");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    /* ignore the first (VER) byte */
    else if(socksreq[1]) { /* status */
      failf(data, "User was rejected by the SOCKS5 server (%d %d).",
            socksreq[0], socksreq[1]);
      return CURLPX_USER_REJECTED;
    }

    /* Everything is good so far, user was authenticated! */
    sxstate(sx, data, CONNECT_REQ_INIT);
    FALLTHROUGH();
  case CONNECT_REQ_INIT:
CONNECT_REQ_INIT:
    /* curl-impersonate: init the UDP associate req by resolving DNS */
    if(sx->udp_associate) {
      if(!socks5_resolve_local)
        goto CONNECT_RESOLVE_REMOTE;
      result = Curl_resolv(data, sx->hostname, sx->remote_port,
                           cf->conn->ip_version, TRUE, &dns);

      if(result == CURLE_AGAIN) {
        sxstate(sx, data, CONNECT_RESOLVING);
        return CURLPX_OK;
      }
      else if(result)
        return CURLPX_RESOLVE_HOST;
      sxstate(sx, data, CONNECT_RESOLVED);
      goto CONNECT_RESOLVED;
    }
    if(socks5_resolve_local) {
      result = Curl_resolv(data, sx->hostname, sx->remote_port,
                           cf->conn->ip_version, TRUE, &dns);

      if(result == CURLE_AGAIN) {
        sxstate(sx, data, CONNECT_RESOLVING);
        return CURLPX_OK;
      }
      else if(result)
        return CURLPX_RESOLVE_HOST;
      sxstate(sx, data, CONNECT_RESOLVED);
      goto CONNECT_RESOLVED;
    }
    goto CONNECT_RESOLVE_REMOTE;

  case CONNECT_RESOLVING:
    /* check if we have the name resolved by now */
    result = Curl_resolv_check(data, &dns);
    if(!dns) {
      if(result)
        return CURLPX_RESOLVE_HOST;
      return CURLPX_OK;
    }
    FALLTHROUGH();
  case CONNECT_RESOLVED:
CONNECT_RESOLVED:
  {
    char dest[MAX_IPADR_LEN];  /* printable address */
    struct Curl_addrinfo *hp = NULL;
    if(dns)
      hp = dns->addr;
#ifdef USE_IPV6
    if(data->set.ipver != CURL_IPRESOLVE_WHATEVER) {
      int wanted_family = data->set.ipver == CURL_IPRESOLVE_V4 ?
        AF_INET : AF_INET6;
      /* scan for the first proper address */
      while(hp && (hp->ai_family != wanted_family))
        hp = hp->ai_next;
    }
#endif
    if(!hp) {
      failf(data, "Failed to resolve \"%s\" for SOCKS5 connect.",
            sx->hostname);
      return CURLPX_RESOLVE_HOST;
    }

    Curl_printable_address(hp, dest, sizeof(dest));

    len = 0;
    socksreq[len++] = 5; /* version (SOCKS5) */
    socksreq[len++] = sx->udp_associate ? 3 : 1; /* associate: 0x03, connect: 0x01 */
    socksreq[len++] = 0; /* must be zero */
    if(!sx->udp_associate) {
      if(hp->ai_family == AF_INET) {
        int i;
        struct sockaddr_in *saddr_in;
        socksreq[len++] = SOCKS5_ATYP_IPV4;

        saddr_in = (struct sockaddr_in *)(void *)hp->ai_addr;
        for(i = 0; i < 4; i++) {
          socksreq[len++] = ((unsigned char *)&saddr_in->sin_addr.s_addr)[i];
        }

        infof(data, "SOCKS5 connect to %s:%d (locally resolved)", dest,
              sx->remote_port);
      }
#ifdef USE_IPV6
      else if(hp->ai_family == AF_INET6) {
        int i;
        struct sockaddr_in6 *saddr_in6;
        socksreq[len++] = SOCKS5_ATYP_IPV6;

        saddr_in6 = (struct sockaddr_in6 *)(void *)hp->ai_addr;
        for(i = 0; i < 16; i++) {
          socksreq[len++] =
            ((unsigned char *)&saddr_in6->sin6_addr.s6_addr)[i];
        }

        infof(data, "SOCKS5 connect to [%s]:%d (locally resolved)", dest,
              sx->remote_port);
      }
#endif
      else {
        hp = NULL; /* fail! */
        failf(data, "SOCKS5 connection to %s not supported", dest);
      }

      Curl_resolv_unlink(data, &dns); /* not used anymore from now on */
      goto CONNECT_REQ_SEND;
    }

    if(hp->ai_family == AF_INET) {
      struct sockaddr_in *saddr_in;
      saddr_in = (struct sockaddr_in *)(void *)hp->ai_addr;
      memcpy(sx->udp_dest_addr, &saddr_in->sin_addr, sizeof(struct in_addr));
      sx->udp_dest_family = AF_INET;
      sx->udp_dest_atyp = SOCKS5_ATYP_IPV4;
    }
#ifdef USE_IPV6
    else if(hp->ai_family == AF_INET6) {
      struct sockaddr_in6 *saddr_in6;
      saddr_in6 = (struct sockaddr_in6 *)(void *)hp->ai_addr;
      memcpy(sx->udp_dest_addr, &saddr_in6->sin6_addr,
             sizeof(struct in6_addr));
      sx->udp_dest_family = AF_INET6;
      sx->udp_dest_atyp = SOCKS5_ATYP_IPV6;
    }
#endif
    else {
      failf(data, "SOCKS5 UDP associate to %s not supported", dest);
      return CURLPX_BAD_ADDRESS_TYPE;
    }
    sx->udp_dest_port = sx->remote_port;
    sx->udp_dest_set = TRUE;
    if(sx->udp_dest_atyp == SOCKS5_ATYP_IPV4 ||
       sx->udp_dest_atyp == SOCKS5_ATYP_IPV6) {
      memset(&sx->udp_peer_addr, 0, sizeof(sx->udp_peer_addr));
      if(sx->udp_dest_atyp == SOCKS5_ATYP_IPV4) {
        struct sockaddr_in *sa =
          (struct sockaddr_in *)(void *)&sx->udp_peer_addr.curl_sa_addr;
        sa->sin_family = AF_INET;
        memcpy(&sa->sin_addr, sx->udp_dest_addr, sizeof(struct in_addr));
        sa->sin_port = htons((unsigned short)sx->udp_dest_port);
        sx->udp_peer_addr.family = AF_INET;
        sx->udp_peer_addr.socktype = SOCK_DGRAM;
        sx->udp_peer_addr.protocol = IPPROTO_UDP;
        sx->udp_peer_addr.addrlen = sizeof(struct sockaddr_in);
        sx->udp_peer_set = TRUE;
      }
#ifdef USE_IPV6
      else {
        struct sockaddr_in6 *sa6 =
          (struct sockaddr_in6 *)(void *)&sx->udp_peer_addr.curl_sa_addr;
        sa6->sin6_family = AF_INET6;
        memcpy(&sa6->sin6_addr, sx->udp_dest_addr, sizeof(struct in6_addr));
        sa6->sin6_port = htons((unsigned short)sx->udp_dest_port);
        sx->udp_peer_addr.family = AF_INET6;
        sx->udp_peer_addr.socktype = SOCK_DGRAM;
        sx->udp_peer_addr.protocol = IPPROTO_UDP;
        sx->udp_peer_addr.addrlen = sizeof(struct sockaddr_in6);
        sx->udp_peer_set = TRUE;
      }
#endif
    }

    infof(data, "SOCKS5 UDP associate storing target %s:%d for UDP header",
          dest, sx->udp_dest_port);

    if(sx->udp_dest_family == AF_INET6) {
      socksreq[len++] = SOCKS5_ATYP_IPV6;
      memset(&socksreq[len], 0, 16);
      len += 16;
    }
    else {
      socksreq[len++] = SOCKS5_ATYP_IPV4;
      memset(&socksreq[len], 0, 4);
      len += 4;
    }

    infof(data, "SOCKS5 UDP associate to %s:%d (locally resolved)", dest,
          sx->remote_port);
    Curl_resolv_unlink(data, &dns); /* not used anymore from now on */
    goto CONNECT_REQ_SEND;
  }
CONNECT_RESOLVE_REMOTE:
  case CONNECT_RESOLVE_REMOTE:
    /* Authentication is complete, now specify destination to the proxy */
    len = 0;
    socksreq[len++] = 5; /* version (SOCKS5) */
    socksreq[len++] = sx->udp_associate ? 3 : 1; /* associate: 0x03, connect: 0x01 */
    socksreq[len++] = 0; /* must be zero */

    if(sx->udp_associate) {
      unsigned char ip4[4];
#ifdef USE_IPV6
      char ip6[16];
#endif
      if(hostname_len > 255) {
        failf(data, "SOCKS5: the destination hostname is too long to be "
              "resolved remotely by the proxy.");
        return CURLPX_LONG_HOSTNAME;
      }
      /* Cache target port up front so cached peer info uses the right value. */
      sx->udp_dest_port = sx->remote_port;
      if(1 == curlx_inet_pton(AF_INET, sx->hostname, ip4)) {
        memcpy(sx->udp_dest_addr, ip4, sizeof(ip4));
        sx->udp_dest_family = AF_INET;
        sx->udp_dest_atyp = SOCKS5_ATYP_IPV4;
        memset(&sx->udp_peer_addr, 0, sizeof(sx->udp_peer_addr));
        {
          struct sockaddr_in *sa =
            (struct sockaddr_in *)(void *)&sx->udp_peer_addr.curl_sa_addr;
          sa->sin_family = AF_INET;
          memcpy(&sa->sin_addr, sx->udp_dest_addr, sizeof(struct in_addr));
          sa->sin_port = htons((unsigned short)sx->udp_dest_port);
          sx->udp_peer_addr.family = AF_INET;
          sx->udp_peer_addr.socktype = SOCK_DGRAM;
          sx->udp_peer_addr.protocol = IPPROTO_UDP;
          sx->udp_peer_addr.addrlen = sizeof(struct sockaddr_in);
          sx->udp_peer_set = TRUE;
        }
      }
#ifdef USE_IPV6
      else if(1 == curlx_inet_pton(AF_INET6, sx->hostname, ip6)) {
        memcpy(sx->udp_dest_addr, ip6, sizeof(ip6));
        sx->udp_dest_family = AF_INET6;
        sx->udp_dest_atyp = SOCKS5_ATYP_IPV6;
        memset(&sx->udp_peer_addr, 0, sizeof(sx->udp_peer_addr));
        {
          struct sockaddr_in6 *sa6 =
            (struct sockaddr_in6 *)(void *)&sx->udp_peer_addr.curl_sa_addr;
          sa6->sin6_family = AF_INET6;
          memcpy(&sa6->sin6_addr, sx->udp_dest_addr, sizeof(struct in6_addr));
          sa6->sin6_port = htons((unsigned short)sx->udp_dest_port);
          sx->udp_peer_addr.family = AF_INET6;
          sx->udp_peer_addr.socktype = SOCK_DGRAM;
          sx->udp_peer_addr.protocol = IPPROTO_UDP;
          sx->udp_peer_addr.addrlen = sizeof(struct sockaddr_in6);
          sx->udp_peer_set = TRUE;
        }
      }
#endif
      else {
        sx->udp_dest_atyp = SOCKS5_ATYP_DOMAIN;
        memcpy(sx->udp_dest_domain, sx->hostname, hostname_len);
        sx->udp_dest_domain_len = hostname_len;
      }
      sx->udp_dest_set = TRUE;

      if(data->set.ipver == CURL_IPRESOLVE_V6) {
        socksreq[len++] = SOCKS5_ATYP_IPV6;
        memset(&socksreq[len], 0, 16);
        len += 16;
      }
      else {
        socksreq[len++] = SOCKS5_ATYP_IPV4;
        memset(&socksreq[len], 0, 4);
        len += 4;
      }

      infof(data, "SOCKS5 UDP associate to %s:%d (remotely resolved)",
            sx->hostname, sx->remote_port);
      goto CONNECT_REQ_SEND;
    }

    if(!socks5_resolve_local) {
      /* ATYP: domain name = 3,
         IPv6 == 4,
         IPv4 == 1 */
      unsigned char ip4[4];
#ifdef USE_IPV6
      if(conn->bits.ipv6_ip) {
        char ip6[16];
        if(1 != curlx_inet_pton(AF_INET6, sx->hostname, ip6))
          return CURLPX_BAD_ADDRESS_TYPE;
        socksreq[len++] = SOCKS5_ATYP_IPV6;
        memcpy(&socksreq[len], ip6, sizeof(ip6));
        len += sizeof(ip6);
      }
      else
#endif
      if(1 == curlx_inet_pton(AF_INET, sx->hostname, ip4)) {
        socksreq[len++] = SOCKS5_ATYP_IPV4;
        memcpy(&socksreq[len], ip4, sizeof(ip4));
        len += sizeof(ip4);
      }
      else {
        socksreq[len++] = SOCKS5_ATYP_DOMAIN;
        socksreq[len++] = (unsigned char) hostname_len; /* one byte length */
        memcpy(&socksreq[len], sx->hostname, hostname_len); /* w/o NULL */
        len += hostname_len;
      }
      infof(data, "SOCKS5 connect to %s:%d (remotely resolved)",
            sx->hostname, sx->remote_port);
    }
    FALLTHROUGH();

  case CONNECT_REQ_SEND:
CONNECT_REQ_SEND:
    {
      int reqport = sx->udp_associate ? 0 : sx->remote_port;
      if(sx->udp_associate)
        infof(data, "SOCKS5 UDP associate request uses port 0 per RFC");
      /* PORT MSB */
      socksreq[len++] = (unsigned char)((reqport >> 8) & 0xff);
      /* PORT LSB */
      socksreq[len++] = (unsigned char)(reqport & 0xff);
    }

#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(conn->socks5_gssapi_enctype) {
      failf(data, "SOCKS5 GSS-API protection not yet implemented.");
      return CURLPX_GSSAPI_PROTECTION;
    }
#endif
    sx->outp = socksreq;
    DEBUGASSERT(len <= sizeof(sx->buffer));
    sx->outstanding = len;
    sxstate(sx, data, CONNECT_REQ_SENDING);
    FALLTHROUGH();
  case CONNECT_REQ_SENDING:
    presult = socks_state_send(cf, sx, data, CURLPX_SEND_REQUEST,
                               "SOCKS5 connect request");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in send state */
      return CURLPX_OK;
    }
    if(sx->udp_associate)
      infof(data, "SOCKS5 UDP associate request sent");
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(conn->socks5_gssapi_enctype) {
      failf(data, "SOCKS5 GSS-API protection not yet implemented.");
      return CURLPX_GSSAPI_PROTECTION;
    }
#endif
    sx->outstanding = 10; /* minimum packet size is 10 */
    sx->outp = socksreq;
    sxstate(sx, data, CONNECT_REQ_READ);
    FALLTHROUGH();
  case CONNECT_REQ_READ:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_REQACK,
                               "SOCKS5 connect request ack");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    else if(socksreq[0] != 5) { /* version */
      failf(data,
            "SOCKS5 reply has wrong version, version should be 5.");
      return CURLPX_BAD_VERSION;
    }
    else if(socksreq[1]) { /* Anything besides 0 is an error */
      CURLproxycode rc = CURLPX_REPLY_UNASSIGNED;
      int code = socksreq[1];
      failf(data, "cannot complete SOCKS5 connection to %s. (%d)",
            sx->hostname, (unsigned char)socksreq[1]);
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

    /* Fix: in general, returned BND.ADDR is variable length parameter by RFC
       1928, so the reply packet should be read until the end to avoid errors
       at subsequent protocol level.

       +----+-----+-------+------+----------+----------+
       |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
       +----+-----+-------+------+----------+----------+
       | 1  |  1  | X'00' |  1   | Variable |    2     |
       +----+-----+-------+------+----------+----------+

       ATYP:
       o  IP v4 address: X'01', BND.ADDR = 4 byte
       o  domain name:  X'03', BND.ADDR = [ 1 byte length, string ]
       o  IP v6 address: X'04', BND.ADDR = 16 byte
    */

    /* Calculate real packet size */
    if(socksreq[3] == 3) {
      /* domain name */
      int addrlen = (int) socksreq[4];
      len = 5 + addrlen + 2;
    }
    else if(socksreq[3] == 4) {
      /* IPv6 */
      len = 4 + 16 + 2;
    }
    else if(socksreq[3] == 1) {
      len = 4 + 4 + 2;
    }
    else {
      failf(data, "SOCKS5 reply has wrong address type.");
      return CURLPX_BAD_ADDRESS_TYPE;
    }
    sx->replylen = len;

    /* At this point we already read first 10 bytes */
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    if(!conn->socks5_gssapi_enctype) {
      /* decrypt_gssapi_blockread already read the whole packet */
#endif
      if(len > 10) {
        DEBUGASSERT(len <= sizeof(sx->buffer));
        sx->outstanding = len - 10; /* get the rest */
        sx->outp = &socksreq[10];
        sxstate(sx, data, CONNECT_REQ_READ_MORE);
      }
      else {
        sxstate(sx, data, CONNECT_DONE);
        break;
      }
#if defined(HAVE_GSSAPI) || defined(USE_WINDOWS_SSPI)
    }
#endif
    FALLTHROUGH();
  case CONNECT_REQ_READ_MORE:
    presult = socks_state_recv(cf, sx, data, CURLPX_RECV_ADDRESS,
                               "SOCKS5 connect request address");
    if(CURLPX_OK != presult)
      return presult;
    else if(sx->outstanding) {
      /* remain in reading state */
      return CURLPX_OK;
    }
    sxstate(sx, data, CONNECT_DONE);
  }
  if(sx->udp_associate && !sx->udp_relay_family) {
    presult = socks5_set_udp_relay(sx, data);
    if(CURLPX_OK != presult)
      return presult;
    infof(data, "SOCKS5 UDP associate relay established");
  }
  infof(data, "SOCKS5 request granted.");

  return CURLPX_OK; /* Proxy was successful! */
}

static void socks_proxy_discard_tcp(struct socks_state *sx,
                                    struct Curl_easy *data)
{
  if(sx && sx->tcp_cf) {
    sx->tcp_cf->cft->do_close(sx->tcp_cf, data);
    Curl_conn_cf_discard_chain(&sx->tcp_cf, data);
  }
}

static CURLcode socks_proxy_cf_udp_create(struct Curl_cfilter *cf,
                                          struct socks_state *sx,
                                          struct Curl_easy *data)
{
  struct Curl_cfilter *udp_cf = NULL;
  struct Curl_cfilter *tcp_cf = sx->tcp_cf ? sx->tcp_cf : cf->next;
  struct Curl_addrinfo *ai = NULL;
  CURLcode result;
  char addrbuf[MAX_IPADR_LEN];
  /* QUIC needs a connected UDP socket when using UDP ASSOCIATE. */
  int transport = sx->udp_associate ? TRNSPRT_QUIC : TRNSPRT_UDP;
  size_t addrlen;
  bool relay_zero = TRUE;

  if(!sx->udp_relay_family || !sx->udp_relay_port)
    return CURLE_FAILED_INIT;
  infof(data, "SOCKS5 UDP associate relay port=%d family=%s",
        sx->udp_relay_port,
        (sx->udp_relay_family == AF_INET6) ? "IPv6" : "IPv4");
  addrlen = (sx->udp_relay_family == AF_INET6) ? 16 : 4;
  for(size_t i = 0; i < addrlen; ++i) {
    if(sx->udp_relay_addr[i]) {
      relay_zero = FALSE;
      break;
    }
  }
  /* If the relay address is 0.0.0.0/::, reuse the proxy's TCP peer. */
  if(relay_zero && tcp_cf) {
    const struct Curl_sockaddr_ex *peer_addr = NULL;
    if(!Curl_cf_socket_peek(tcp_cf, data, NULL, &peer_addr, NULL) &&
       peer_addr) {
      if(peer_addr->family == AF_INET) {
        struct sockaddr_in *saddr_in =
          (struct sockaddr_in *)(void *)&peer_addr->curl_sa_addr;
        memcpy(sx->udp_relay_addr, &saddr_in->sin_addr,
               sizeof(struct in_addr));
        sx->udp_relay_family = AF_INET;
      }
#ifdef USE_IPV6
      else if(peer_addr->family == AF_INET6) {
        struct sockaddr_in6 *saddr_in6 =
          (struct sockaddr_in6 *)(void *)&peer_addr->curl_sa_addr;
        memcpy(sx->udp_relay_addr, &saddr_in6->sin6_addr,
               sizeof(struct in6_addr));
        sx->udp_relay_family = AF_INET6;
      }
#endif
    }
    infof(data, "SOCKS5 UDP relay address was zero; using proxy host address");
  }
  if(!curlx_inet_ntop(sx->udp_relay_family, sx->udp_relay_addr,
                      addrbuf, sizeof(addrbuf)))
    return CURLE_FAILED_INIT;

  ai = Curl_ip2addr(sx->udp_relay_family, sx->udp_relay_addr,
                    addrbuf, sx->udp_relay_port);
  if(!ai)
    return CURLE_OUT_OF_MEMORY;

  result = Curl_cf_udp_create(&udp_cf, data, cf->conn, ai, transport);
  Curl_freeaddrinfo(ai);
  if(result)
    return result;

  udp_cf->conn = cf->conn;
  udp_cf->sockindex = cf->sockindex;
  sx->udp_cf = udp_cf;
  infof(data, "SOCKS5 UDP relay socket prepared for %s:%d",
        addrbuf, sx->udp_relay_port);
  return CURLE_OK;
}

static CURLcode connect_SOCKS(struct Curl_cfilter *cf,
                              struct socks_state *sxstate,
                              struct Curl_easy *data)
{
  CURLcode result = CURLE_OK;
  CURLproxycode pxresult = CURLPX_OK;
  struct connectdata *conn = cf->conn;

  if(sxstate->udp_associate &&
     conn->socks_proxy.proxytype != CURLPROXY_SOCKS5 &&
     conn->socks_proxy.proxytype != CURLPROXY_SOCKS5_HOSTNAME) {
    failf(data, "SOCKS: UDP associate only supported with SOCKS5");
    data->info.pxcode = CURLPX_REPLY_COMMAND_NOT_SUPPORTED;
    return CURLE_PROXY;
  }

  switch(conn->socks_proxy.proxytype) {
  case CURLPROXY_SOCKS5:
  case CURLPROXY_SOCKS5_HOSTNAME:
    pxresult = do_SOCKS5(cf, sxstate, data);
    break;

  case CURLPROXY_SOCKS4:
  case CURLPROXY_SOCKS4A:
    pxresult = do_SOCKS4(cf, sxstate, data);
    break;

  default:
    failf(data, "unknown proxytype option given");
    result = CURLE_COULDNT_CONNECT;
  } /* switch proxytype */
  if(pxresult) {
    result = CURLE_PROXY;
    data->info.pxcode = pxresult;
  }

  return result;
}

static void socks_proxy_cf_free(struct Curl_cfilter *cf,
                                struct Curl_easy *data)
{
  struct socks_state *sxstate = cf->ctx;
  if(sxstate) {
    socks_proxy_discard_tcp(sxstate, data);
    free(sxstate);
    cf->ctx = NULL;
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
  CURLcode result;
  struct connectdata *conn = cf->conn;
  int sockindex = cf->sockindex;
  struct socks_state *sx = cf->ctx;
  struct Curl_cfilter *tcp_cf = NULL;

  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  if(sx && sx->tcp_cf)
    tcp_cf = sx->tcp_cf;
  else
    tcp_cf = cf->next;

  result = tcp_cf->cft->do_connect(tcp_cf, data, done);
  if(result || !*done)
    return result;

  if(!sx) {
    sx = calloc(1, sizeof(*sx));
    if(!sx)
      return CURLE_OUT_OF_MEMORY;
    cf->ctx = sx;
  }

  if(sx->state == CONNECT_INIT) {
    /* for the secondary socket (FTP), use the "connect to host"
     * but ignore the "connect to port" (use the secondary port)
     */
    sxstate(sx, data, CONNECT_SOCKS_INIT);
    sx->hostname =
      conn->bits.httpproxy ?
      conn->http_proxy.host.name :
      conn->bits.conn_to_host ?
      conn->conn_to_host.name :
      sockindex == SECONDARYSOCKET ?
      conn->secondaryhostname : conn->host.name;
    sx->remote_port =
      conn->bits.httpproxy ? (int)conn->http_proxy.port :
      sockindex == SECONDARYSOCKET ? conn->secondary_port :
      conn->bits.conn_to_port ? conn->conn_to_port :
      conn->remote_port;
    sx->proxy_user = conn->socks_proxy.user;
    sx->proxy_password = conn->socks_proxy.passwd;
    /* Use UDP associate for explicit HTTP/3-only or QUIC transport. */
    sx->udp_associate =
      (conn->transport_wanted == TRNSPRT_QUIC) ||
      (data->state.http_neg.wanted == CURL_HTTP_V3x);
    if(sx->udp_associate)
      infof(data, "SOCKS5 UDP associate starting for HTTP/3 target");
  }

  result = connect_SOCKS(cf, sx, data);
  if(!result && sx->state == CONNECT_DONE) {
    if(sx->udp_associate) {
      if(!sx->udp_cf) {
        result = socks_proxy_cf_udp_create(cf, sx, data);
        if(result)
          return result;
        /* Keep TCP control channel and switch data path to UDP relay. */
        sx->tcp_cf = cf->next;
        cf->next = sx->udp_cf;
        infof(data, "SOCKS5 UDP associate switching to UDP relay socket");
      }
      result = sx->udp_cf->cft->do_connect(sx->udp_cf, data, done);
      if(result || !*done)
        return result;
    }
    cf->connected = TRUE;
    Curl_verboseconnect(data, conn, cf->sockindex);
    if(!sx->udp_associate)
      socks_proxy_cf_free(cf, data);
  }

  *done = cf->connected;
  return result;
}

static CURLcode socks_proxy_cf_send(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    const void *buf, size_t len, bool eos,
                                    size_t *pnwritten)
{
  struct socks_state *sx = cf->ctx;

  if(sx && sx->udp_associate && sx->udp_cf) {
    /* Wrap outgoing QUIC datagrams in SOCKS5 UDP headers. */
    size_t header_len;
    size_t addrlen;
    size_t nwritten = 0;
    unsigned char atyp;
    unsigned char *packet;
    CURLcode result;

    *pnwritten = 0;
    if(!sx->udp_dest_set)
      return CURLE_SEND_ERROR;

    switch(sx->udp_dest_atyp) {
    case SOCKS5_ATYP_IPV6:
      addrlen = 16;
      atyp = SOCKS5_ATYP_IPV6;
      break;
    case SOCKS5_ATYP_DOMAIN:
      if(!sx->udp_dest_domain_len)
        return CURLE_SEND_ERROR;
      addrlen = 1 + sx->udp_dest_domain_len;
      atyp = SOCKS5_ATYP_DOMAIN;
      break;
    case SOCKS5_ATYP_IPV4:
    default:
      addrlen = 4;
      atyp = SOCKS5_ATYP_IPV4;
      break;
    }

    header_len = 4 + addrlen + 2;
    packet = malloc(header_len + len);
    if(!packet)
      return CURLE_OUT_OF_MEMORY;

    packet[0] = 0;
    packet[1] = 0;
    packet[2] = 0;
    packet[3] = atyp;
    if(atyp == SOCKS5_ATYP_DOMAIN) {
      packet[4] = (unsigned char)sx->udp_dest_domain_len;
      memcpy(&packet[5], sx->udp_dest_domain, sx->udp_dest_domain_len);
    }
    else
      memcpy(&packet[4], sx->udp_dest_addr, addrlen);
    packet[4 + addrlen] = (unsigned char)((sx->udp_dest_port >> 8) & 0xff);
    packet[5 + addrlen] = (unsigned char)(sx->udp_dest_port & 0xff);
    memcpy(&packet[header_len], buf, len);

    infof(data, "SOCKS5 UDP send: payload=%zu header=%zu atyp=%d",
          len, header_len, atyp);
    if(atyp == SOCKS5_ATYP_DOMAIN) {
      infof(data, "SOCKS5 UDP header: domain_len=%zu domain=%.*s port=%d",
            sx->udp_dest_domain_len,
            (int)sx->udp_dest_domain_len, sx->udp_dest_domain,
            sx->udp_dest_port);
      /* Debug: print first 30 bytes of header in hex */
      infof(data, "SOCKS5 UDP hex: %02x %02x %02x %02x %02x %02x %02x %02x "
            "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
            "%02x %02x %02x %02x %02x %02x",
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5],
            packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
            packet[12], packet[13], packet[14], packet[15], packet[16],
            packet[17], packet[18], packet[19], packet[20], packet[21],
            packet[22], packet[23], packet[24], packet[25]);
    }
    result = cf->next->cft->do_send(cf->next, data, packet,
                                    header_len + len, eos, &nwritten);
    free(packet);
    if(result) {
      if(result == CURLE_AGAIN)
        *pnwritten = 0;
      return result;
    }

    if(nwritten != (header_len + len))
      return CURLE_SEND_ERROR;

    *pnwritten = len;
    return CURLE_OK;
  }

  return Curl_cf_def_send(cf, data, buf, len, eos, pnwritten);
}

static CURLcode socks_proxy_cf_recv(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    char *buf, size_t len, size_t *pnread)
{
  struct socks_state *sx = cf->ctx;

  if(sx && sx->udp_associate && sx->udp_cf) {
    /* Strip SOCKS5 UDP headers before passing QUIC payload upward. */
    size_t maxhdr = 4 + 1 + 255 + 2;
    size_t pktlen = len + maxhdr;
    unsigned char *packet = malloc(pktlen);
    size_t nread = 0;
    CURLcode result;

    *pnread = 0;
    if(!packet)
      return CURLE_OUT_OF_MEMORY;

    result = cf->next->cft->do_recv(cf->next, data, (char *)packet,
                                    pktlen, &nread);
    if(result) {
      free(packet);
      return result;
    }

    if(nread < 4) {
      free(packet);
      return CURLE_RECV_ERROR;
    }
    if(packet[0] || packet[1] || packet[2]) {
      free(packet);
      return CURLE_RECV_ERROR;
    }
    {
      size_t addrlen;
      size_t off = 4;
      switch(packet[3]) {
      case 1:
        addrlen = 4;
        break;
      case 4:
        addrlen = 16;
        break;
      case 3:
        if(nread < 5) {
          free(packet);
          return CURLE_RECV_ERROR;
        }
        addrlen = 1 + packet[4];
        break;
      default:
        free(packet);
        return CURLE_RECV_ERROR;
      }
    if(nread < off + addrlen + 2) {
      free(packet);
      return CURLE_RECV_ERROR;
    }
    /* For socks5h:// with domain names (udp_dest_atyp == SOCKS5_ATYP_DOMAIN),
     * do NOT set udp_peer_set from received packets. This ensures that
     * CF_QUERY_REMOTE_ADDR consistently returns the relay address throughout
     * the connection. The relay address is what QUIC should use as the "peer"
     * since that's what we're actually communicating with on the network.
     * TLS verification uses the hostname (not IP) for SNI/certificate checks.
     * For socks5:// (local DNS) or IP literals, udp_peer_set is already TRUE
     * from initialization, so we can update udp_peer_addr here. */
    if((packet[3] == SOCKS5_ATYP_IPV4 || packet[3] == SOCKS5_ATYP_IPV6) &&
       sx->udp_dest_atyp != SOCKS5_ATYP_DOMAIN) {
      const unsigned char *addrbytes = &packet[4];
      int port = (int)((packet[4 + addrlen] << 8) |
                       packet[5 + addrlen]);
      memset(&sx->udp_peer_addr, 0, sizeof(sx->udp_peer_addr));
      if(packet[3] == SOCKS5_ATYP_IPV4) {
        struct sockaddr_in *sa =
          (struct sockaddr_in *)(void *)&sx->udp_peer_addr.curl_sa_addr;
        sa->sin_family = AF_INET;
        memcpy(&sa->sin_addr, addrbytes, sizeof(struct in_addr));
        sa->sin_port = htons((unsigned short)port);
        sx->udp_peer_addr.family = AF_INET;
        sx->udp_peer_addr.socktype = SOCK_DGRAM;
        sx->udp_peer_addr.protocol = IPPROTO_UDP;
        sx->udp_peer_addr.addrlen = sizeof(struct sockaddr_in);
        sx->udp_peer_set = TRUE;
      }
#ifdef USE_IPV6
      else {
        struct sockaddr_in6 *sa6 =
          (struct sockaddr_in6 *)(void *)&sx->udp_peer_addr.curl_sa_addr;
        sa6->sin6_family = AF_INET6;
        memcpy(&sa6->sin6_addr, addrbytes, sizeof(struct in6_addr));
        sa6->sin6_port = htons((unsigned short)port);
        sx->udp_peer_addr.family = AF_INET6;
        sx->udp_peer_addr.socktype = SOCK_DGRAM;
        sx->udp_peer_addr.protocol = IPPROTO_UDP;
        sx->udp_peer_addr.addrlen = sizeof(struct sockaddr_in6);
        sx->udp_peer_set = TRUE;
      }
#endif
    }
    off += addrlen + 2;
      if(nread > off) {
        size_t payload = nread - off;
        if(payload > len)
          payload = len;
        memcpy(buf, &packet[off], payload);
        *pnread = payload;
        infof(data, "SOCKS5 UDP recv: payload=%zu header=%zu",
              payload, off);
      }
      else
        *pnread = 0;
    }
    free(packet);
    return CURLE_OK;
  }

  return Curl_cf_def_recv(cf, data, buf, len, pnread);
}

static void socks_cf_adjust_pollset(struct Curl_cfilter *cf,
                                    struct Curl_easy *data,
                                    struct easy_pollset *ps)
{
  struct socks_state *sx = cf->ctx;

  if(!cf->connected && sx) {
    /* If we are not connected, the filter below is and has nothing
     * to wait on, we determine what to wait for. */
    curl_socket_t sock = Curl_conn_cf_get_socket(cf, data);
    switch(sx->state) {
    case CONNECT_RESOLVING:
    case CONNECT_SOCKS_READ:
    case CONNECT_AUTH_READ:
    case CONNECT_REQ_READ:
    case CONNECT_REQ_READ_MORE:
      Curl_pollset_set_in_only(data, ps, sock);
      break;
    default:
      Curl_pollset_set_out_only(data, ps, sock);
      break;
    }
  }
}

static void socks_proxy_cf_close(struct Curl_cfilter *cf,
                                 struct Curl_easy *data)
{

  DEBUGASSERT(cf->next);
  cf->connected = FALSE;
  socks_proxy_cf_free(cf, data);
  cf->next->cft->do_close(cf->next, data);
}

static void socks_proxy_cf_destroy(struct Curl_cfilter *cf,
                                   struct Curl_easy *data)
{
  socks_proxy_cf_free(cf, data);
}

static CURLcode socks_cf_query(struct Curl_cfilter *cf,
                               struct Curl_easy *data,
                               int query, int *pres1, void *pres2)
{
  struct socks_state *sx = cf->ctx;

  if(sx) {
    switch(query) {
    case CF_QUERY_REMOTE_ADDR:
      if(sx->udp_associate && sx->udp_peer_set) {
        *((const struct Curl_sockaddr_ex **)pres2) = &sx->udp_peer_addr;
        return CURLE_OK;
      }
      break;
    case CF_QUERY_HOST_PORT:
      *pres1 = sx->remote_port;
      *((const char **)pres2) = sx->hostname;
      return CURLE_OK;
    default:
      break;
    }
  }
  return cf->next ?
    cf->next->cft->query(cf->next, data, query, pres1, pres2) :
    CURLE_UNKNOWN_OPTION;
}

struct Curl_cftype Curl_cft_socks_proxy = {
  "SOCKS-PROXYY",
  CF_TYPE_IP_CONNECT|CF_TYPE_PROXY,
  0,
  socks_proxy_cf_destroy,
  socks_proxy_cf_connect,
  socks_proxy_cf_close,
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
      struct socks_state *sx = cf->ctx;
      return sx && sx->udp_associate;
    }
  }
  return FALSE;
}

CURLcode Curl_cf_socks_proxy_insert_after(struct Curl_cfilter *cf_at,
                                          struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  (void)data;
  result = Curl_cf_create(&cf, &Curl_cft_socks_proxy, NULL);
  if(!result)
    Curl_conn_cf_insert_after(cf_at, cf);
  return result;
}

#endif /* CURL_DISABLE_PROXY */
