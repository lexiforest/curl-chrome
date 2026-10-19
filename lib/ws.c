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
#include "urldata.h"
#include "ws.h"

#ifndef CURL_DISABLE_WEBSOCKETS

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

/* Include architecture-specific SIMD intrinsics and CPUID headers. MSVC
 * requires <intrin.h>, while GCC and Clang use <cpuid.h>. */
#if defined(__x86_64__) || defined(_M_X64) || \
    defined(__i386__) || defined(_M_IX86)
#include <immintrin.h>
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
#include <arm_neon.h>
#endif

#include "url.h"
#include "bufq.h"
#include "curlx/dynbuf.h"
#include "rand.h"
#include "curlx/base64.h"
#include "cf-recvbuf.h"
#include "connect.h"
#include "sendf.h"
#include "curl_trc.h"
#include "multiif.h"
#include "easyif.h"
#include "transfer.h"
#include "select.h"
#include "curlx/strparse.h"
#include "curlx/strcopy.h"

/* RFC 6455 Section 5.2

    0 1 2 3 4 5 6 7
   +-+-+-+-+-------+
   |F|R|R|R| opcode|
   |I|S|S|S|  (4)  |
   |N|V|V|V|       |
   | |1|2|3|       |
 */
#define WSBIT_FIN          0x80
#define WSBIT_RSV1         0x40
#define WSBIT_RSV2         0x20
#define WSBIT_RSV3         0x10
#define WSBIT_RSV_MASK     (WSBIT_RSV1 | WSBIT_RSV2 | WSBIT_RSV3)
#define WSBIT_OPCODE_CONT  0x0
#define WSBIT_OPCODE_TEXT  0x1
#define WSBIT_OPCODE_BIN   0x2
#define WSBIT_OPCODE_CLOSE 0x8
#define WSBIT_OPCODE_PING  0x9
#define WSBIT_OPCODE_PONG  0xa
#ifdef CURLVERBOSE
#define WSBIT_OPCODE_MASK  0xf
#endif

#define WSBIT_MASK 0x80

/* buffer dimensioning */
#define WS_CHUNK_SIZE  131072
#define WS_CHUNK_COUNT 4
#define WS_DEFLATE_CHUNK 4096
/* Internal encoder flag, never accepted from the public send API. */
#define WS_COMPRESSED (1U << 30)

#ifndef WS_ENC_XBUF_SIZE
#define WS_ENC_XBUF_SIZE 8192
#endif

/* Feature bitmask constants. */
#define WS_CPU_FEAT_INIT   (1 << 0)
#define WS_CPU_FEAT_AVX2   (1 << 1)
#define WS_CPU_FEAT_AVX512 (1 << 2)

/* Determine endianness across supported compilers and operating systems. */
#if (defined(__BYTE_ORDER__) && \
     (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) || \
    defined(_WIN32) || defined(_WIN64) || defined(__LITTLE_ENDIAN__) || \
    defined(__ARMEL__) || defined(__AARCH64EL__) || \
    defined(_M_IX86) || defined(_M_X64) || \
    defined(_M_ARM) || defined(_M_ARM64)
#define WS_IS_LITTLE_ENDIAN 1
#else
#define WS_IS_LITTLE_ENDIAN 0
#endif

/* Identify architectures with native 64-bit scalar operations. */
#if defined(__x86_64__) || defined(_M_X64) || \
    defined(__aarch64__) || defined(_M_ARM64)
#define WS_64BIT_NATIVE 1
#else
#define WS_64BIT_NATIVE 0
#endif

/* SIMD configuration. */
#if WS_IS_LITTLE_ENDIAN

#if defined(__x86_64__) || defined(_M_X64) || \
    defined(__i386__) || defined(_M_IX86)
#define WS_HAVE_X86_SIMD 1
#if defined(__GNUC__) || defined(__clang__)
#if defined(__has_attribute)
#if __has_attribute(target)
#define WS_TARGET_AVX2 __attribute__((target("avx2")))
#if defined(__clang__) && \
    ((defined(__apple_build_version__) && __clang_major__ >= 16) || \
     (!defined(__apple_build_version__) && __clang_major__ >= 18 && \
      __clang_major__ <= 21))
#define WS_TARGET_AVX512 \
  __attribute__((target("avx512f,evex512")))
#else
#define WS_TARGET_AVX512 __attribute__((target("avx512f")))
#endif
#define WS_SUPPORT_AVX_RUNTIME 1
#else
#define WS_TARGET_AVX2
#define WS_TARGET_AVX512
#endif
#else
#define WS_TARGET_AVX2
#define WS_TARGET_AVX512
#endif
#else
#define WS_TARGET_AVX2
#define WS_TARGET_AVX512
#endif

#ifdef _MSC_VER
#define WS_ATOMIC_LOAD(var) \
  (uint32_t)_InterlockedOr((volatile long *)&(var), 0)
#define WS_ATOMIC_STORE(var, val) \
  _InterlockedExchange((volatile long *)&(var), (long)(val))
#else
#define WS_ATOMIC_LOAD(var) \
  __atomic_load_n(&(var), __ATOMIC_RELAXED)
#define WS_ATOMIC_STORE(var, val) \
  __atomic_store_n(&(var), (val), __ATOMIC_RELAXED)
#endif
#endif

/* ARM SIMD configuration. */
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
#define WS_HAVE_ARM_SIMD 1
#endif

#ifdef WS_HAVE_X86_SIMD

/* AVX-512 path: 128 bytes per iteration, unrolled twice. */
#if defined(WS_SUPPORT_AVX_RUNTIME) || defined(__AVX512F__)
WS_TARGET_AVX512
static size_t ws_xor_avx512(const uint8_t *src, uint8_t *dst,
                            size_t len, uint32_t m32)
{
  size_t i = 0;
  __m512i vmask = _mm512_set1_epi32((int)m32);
  for(; i + 128 <= len; i += 128) {
    __m512i v0 = _mm512_loadu_si512((const __m512i *)(const void *)
                                    (src + i));
    __m512i v1 = _mm512_loadu_si512((const __m512i *)(const void *)
                                    (src + i + 64));
    _mm512_storeu_si512((__m512i *)(void *)(dst + i),
                        _mm512_xor_si512(v0, vmask));
    _mm512_storeu_si512((__m512i *)(void *)(dst + i + 64),
                        _mm512_xor_si512(v1, vmask));
  }
  return i;
}
#endif

/* AVX2 path: 64 bytes per iteration, unrolled twice. */
#if defined(WS_SUPPORT_AVX_RUNTIME) || defined(__AVX2__)
WS_TARGET_AVX2
static size_t ws_xor_avx2(const uint8_t *src, uint8_t *dst,
                          size_t len, uint32_t m32)
{
  size_t i = 0;
  __m256i vmask = _mm256_set1_epi32((int)m32);
  for(; i + 64 <= len; i += 64) {
    __m256i v0 = _mm256_loadu_si256((const __m256i *)(const void *)
                                    (src + i));
    __m256i v1 = _mm256_loadu_si256((const __m256i *)(const void *)
                                    (src + i + 32));
    _mm256_storeu_si256((__m256i *)(void *)(dst + i),
                        _mm256_xor_si256(v0, vmask));
    _mm256_storeu_si256((__m256i *)(void *)(dst + i + 32),
                        _mm256_xor_si256(v1, vmask));
  }
  return i;
}
#endif

/* Check both CPU feature bits and operating-system SIMD support. */
static uint32_t ws_get_cpu_features(void)
{
  uint32_t features = WS_CPU_FEAT_INIT;

#ifdef _MSC_VER
  int cpuinfo[4];
  int max_leaf;
  unsigned __int64 xcr0;

  /* Check the maximum supported CPUID leaf. */
  __cpuid(cpuinfo, 0);
  max_leaf = cpuinfo[0];
  if(max_leaf < 1)
    return features;

  __cpuidex(cpuinfo, 1, 0);
  /* Check XSAVE, OSXSAVE and AVX. */
  if((cpuinfo[2] & ((1 << 26) | (1 << 27) | (1 << 28))) !=
     ((1 << 26) | (1 << 27) | (1 << 28)))
    return features;

  xcr0 = _xgetbv(0);
  if((xcr0 & 0x06) != 0x06)
    return features;

  if(max_leaf >= 7) {
    __cpuidex(cpuinfo, 7, 0);
    if(cpuinfo[1] & (1 << 5))
      features |= WS_CPU_FEAT_AVX2;
    if(((xcr0 & 0xe6) == 0xe6) && (cpuinfo[1] & (1 << 16)))
      features |= WS_CPU_FEAT_AVX512;
  }
#elif defined(__GNUC__) || defined(__clang__)
  unsigned int eax = 0;
  unsigned int ebx = 0;
  unsigned int ecx = 0;
  unsigned int edx = 0;
  unsigned int max_leaf;
  uint32_t xcr0_eax;
  uint32_t xcr0_edx;

  /* Check the maximum supported CPUID leaf. */
  max_leaf = __get_cpuid_max(0, NULL);
  if(max_leaf < 1)
    return features;
  if(!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
    return features;
  /* Check XSAVE, OSXSAVE and AVX. */
  if((ecx & ((1 << 26) | (1 << 27) | (1 << 28))) !=
     ((1 << 26) | (1 << 27) | (1 << 28)))
    return features;

  __asm__ volatile("xgetbv" : "=a"(xcr0_eax), "=d"(xcr0_edx) : "c"(0));
  (void)xcr0_edx;
  if((xcr0_eax & 0x06) != 0x06)
    return features;

  if(max_leaf >= 7) {
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    if(ebx & (1 << 5))
      features |= WS_CPU_FEAT_AVX2;
    if(((xcr0_eax & 0xe6) == 0xe6) && (ebx & (1 << 16)))
      features |= WS_CPU_FEAT_AVX512;
  }
#endif

  return features;
}
#endif

#ifdef WS_HAVE_ARM_SIMD
/* NEON path: 32 bytes per iteration, unrolled twice. */
static size_t ws_xor_neon(const uint8_t *src, uint8_t *dst,
                          size_t len, uint32_t m32)
{
  size_t i = 0;
  uint32x4_t vmask = vdupq_n_u32(m32);
  for(; i + 32 <= len; i += 32) {
    uint8x16_t v0 = vld1q_u8(src + i);
    uint8x16_t v1 = vld1q_u8(src + i + 16);
    v0 = veorq_u8(v0, vreinterpretq_u8_u32(vmask));
    v1 = veorq_u8(v1, vreinterpretq_u8_u32(vmask));
    vst1q_u8(dst + i, v0);
    vst1q_u8(dst + i + 16, v1);
  }
  return i;
}
#endif

#endif /* WS_IS_LITTLE_ENDIAN */

/* a client-side WS frame decoder, parsing frame headers and
 * payload, keeping track of current position and stats */
enum ws_dec_state {
  WS_DEC_INIT,
  WS_DEC_HEAD,
  WS_DEC_PAYLOAD
};

struct ws_decoder {
  int frame_age;        /* zero */
  int frame_flags;      /* See the CURLWS_* defines */
  curl_off_t payload_offset;   /* the offset parsing is at */
  curl_off_t payload_len;
  uint8_t head[10];
  int head_len, head_total;
  enum ws_dec_state state;
  int cont_flags;
#ifdef HAVE_LIBZ
  z_stream inflater;
  uint8_t output[WS_DEFLATE_CHUNK];
  size_t output_len, output_pos;
  curl_off_t decoded_offset;
  unsigned int tail_pos;
  BIT(inflate_init);
  BIT(no_context_takeover);
  BIT(compressed_message);
  BIT(compressed_frame);
  BIT(frame_done);
#endif
  BIT(failed);
};

/* a client-side WS frame encoder, generating frame headers and
 * converting payloads, tracking remaining data in current frame */
struct ws_encoder {
  curl_off_t payload_len;  /* payload length of current frame */
  curl_off_t payload_remain;  /* remaining payload of current */
  unsigned int xori; /* xor index */
  uint8_t mask[4]; /* 32-bit mask for this connection */
  uint8_t firstbyte; /* first byte of frame we encode */
  BIT(contfragment); /* set TRUE if the previous fragment sent was not final */
  uint8_t xbuf[WS_ENC_XBUF_SIZE]; /* staging buffer for XOR masking */
};

/* Control frames are allowed up to 125 characters, rfc6455, ch. 5.5 */
#define WS_MAX_CNTRL_LEN    125

struct ws_cntrl_frame {
  unsigned int type;
  size_t payload_len;
  uint8_t payload[WS_MAX_CNTRL_LEN];
};

/* A websocket connection with en- and decoder that treat frames
 * and keep track of boundaries. */
struct websocket {
  struct Curl_easy *data; /* used for write callback handling */
  struct ws_decoder dec;  /* decode of ws frames */
  struct ws_encoder enc;  /* encode of ws frames */
  struct bufq recvbuf;    /* raw data from the server */
  struct bufq sendbuf;    /* raw data to be sent to the server */
  struct curl_ws_frame recvframe;  /* the current WS FRAME received */
  struct ws_cntrl_frame pending; /* a control frame pending to be sent */
  size_t sendbuf_payload; /* number of payload bytes in sendbuf */
  BIT(using_reader);      /* sending WS data is handled via a client reader */
  BIT(pmd_offered);
  BIT(pmd_accepted);
  BIT(client_no_context_takeover);
  BIT(server_no_context_takeover);
  BIT(failed);
  unsigned char client_window_bits;
  unsigned char server_window_bits;
#ifdef HAVE_LIBZ
  z_stream deflater;
  uint8_t compressed[WS_DEFLATE_CHUNK + 4];
  size_t compressed_len;
  curl_off_t input_remain;
  unsigned int input_flags;
  unsigned int message_flags;
  size_t send_credit; /* input consumed, not yet reported to the caller */
  size_t frame_serial; /* explicit frames started by an upload callback */
  BIT(deflate_init);
  BIT(input_active);
  BIT(message_active);
  BIT(message_has_input);
  BIT(wire_started);
  BIT(finishing);
  BIT(flush_done);
  BIT(send_waiting); /* a zero-length send awaiting its final wire output */
#endif
};

#ifdef CURLVERBOSE
static const char *ws_frame_name_of_op(uint8_t firstbyte)
{
  switch(firstbyte & WSBIT_OPCODE_MASK) {
  case WSBIT_OPCODE_CONT:
    return "CONT";
  case WSBIT_OPCODE_TEXT:
    return "TEXT";
  case WSBIT_OPCODE_BIN:
    return "BIN";
  case WSBIT_OPCODE_CLOSE:
    return "CLOSE";
  case WSBIT_OPCODE_PING:
    return "PING";
  case WSBIT_OPCODE_PONG:
    return "PONG";
  default:
    return "???";
  }
}
#endif

static int ws_frame_firstbyte2flags(struct Curl_easy *data,
                                    uint8_t firstbyte, int cont_flags)
{
  switch(firstbyte) {
  /* 0x00 - intermediate TEXT/BINARY fragment */
  case WSBIT_OPCODE_CONT:
    if(!(cont_flags & CURLWS_CONT)) {
      failf(data, "[WS] no ongoing fragmented message to resume");
      return 0;
    }
    return cont_flags | CURLWS_CONT;
  /* 0x80 - final TEXT/BIN fragment */
  case (WSBIT_OPCODE_CONT | WSBIT_FIN):
    if(!(cont_flags & CURLWS_CONT)) {
      failf(data, "[WS] no ongoing fragmented message to resume");
      return 0;
    }
    return cont_flags & ~CURLWS_CONT;
  /* 0x01 - first TEXT fragment */
  case WSBIT_OPCODE_TEXT:
    if(cont_flags & CURLWS_CONT) {
      failf(data, "[WS] fragmented message interrupted by new TEXT msg");
      return 0;
    }
    return CURLWS_TEXT | CURLWS_CONT;
  /* 0x81 - unfragmented TEXT msg */
  case (WSBIT_OPCODE_TEXT | WSBIT_FIN):
    if(cont_flags & CURLWS_CONT) {
      failf(data, "[WS] fragmented message interrupted by new TEXT msg");
      return 0;
    }
    return CURLWS_TEXT;
  /* 0x02 - first BINARY fragment */
  case WSBIT_OPCODE_BIN:
    if(cont_flags & CURLWS_CONT) {
      failf(data, "[WS] fragmented message interrupted by new BINARY msg");
      return 0;
    }
    return CURLWS_BINARY | CURLWS_CONT;
  /* 0x82 - unfragmented BINARY msg */
  case (WSBIT_OPCODE_BIN | WSBIT_FIN):
    if(cont_flags & CURLWS_CONT) {
      failf(data, "[WS] fragmented message interrupted by new BINARY msg");
      return 0;
    }
    return CURLWS_BINARY;
  /* 0x08 - first CLOSE fragment */
  case WSBIT_OPCODE_CLOSE:
    failf(data, "[WS] invalid fragmented CLOSE frame");
    return 0;
  /* 0x88 - unfragmented CLOSE */
  case (WSBIT_OPCODE_CLOSE | WSBIT_FIN):
    return CURLWS_CLOSE;
  /* 0x09 - first PING fragment */
  case WSBIT_OPCODE_PING:
    failf(data, "[WS] invalid fragmented PING frame");
    return 0;
  /* 0x89 - unfragmented PING */
  case (WSBIT_OPCODE_PING | WSBIT_FIN):
    return CURLWS_PING;
  /* 0x0a - first PONG fragment */
  case WSBIT_OPCODE_PONG:
    failf(data, "[WS] invalid fragmented PONG frame");
    return 0;
  /* 0x8a - unfragmented PONG */
  case (WSBIT_OPCODE_PONG | WSBIT_FIN):
    return CURLWS_PONG;
  /* invalid first byte */
  default:
    if(firstbyte & WSBIT_RSV_MASK)
      /* any of the reserved bits 0x40/0x20/0x10 are set */
      failf(data, "[WS] invalid reserved bits: %02x", firstbyte);
    else
      /* any of the reserved opcodes 0x3-0x7 or 0xb-0xf is used */
      failf(data, "[WS] invalid opcode: %02x", firstbyte);
    return 0;
  }
}

static CURLcode ws_frame_flags2firstbyte(struct Curl_easy *data,
                                         unsigned int flags,
                                         bool contfragment,
                                         uint8_t *pfirstbyte)
{
  *pfirstbyte = 0;
  switch(flags & ~CURLWS_OFFSET) {
  case 0:
    if(contfragment) {
      CURL_TRC_WS(data, "no flags given; interpreting as continuation "
                  "fragment for compatibility");
      *pfirstbyte = (WSBIT_OPCODE_CONT | WSBIT_FIN);
      return CURLE_OK;
    }
    failf(data, "[WS] no flags given");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case CURLWS_CONT:
    if(contfragment) {
      infof(data, "[WS] setting CURLWS_CONT flag without message type is "
                  "supported for compatibility but highly discouraged");
      *pfirstbyte = WSBIT_OPCODE_CONT;
      return CURLE_OK;
    }
    failf(data, "[WS] No ongoing fragmented message to continue");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case CURLWS_TEXT:
    *pfirstbyte = contfragment ? (WSBIT_OPCODE_CONT | WSBIT_FIN)
                               : (WSBIT_OPCODE_TEXT | WSBIT_FIN);
    return CURLE_OK;
  case (CURLWS_TEXT | CURLWS_CONT):
    *pfirstbyte = contfragment ? WSBIT_OPCODE_CONT : WSBIT_OPCODE_TEXT;
    return CURLE_OK;
  case CURLWS_BINARY:
    *pfirstbyte = contfragment ? (WSBIT_OPCODE_CONT | WSBIT_FIN)
                               : (WSBIT_OPCODE_BIN | WSBIT_FIN);
    return CURLE_OK;
  case (CURLWS_BINARY | CURLWS_CONT):
    *pfirstbyte = contfragment ? WSBIT_OPCODE_CONT : WSBIT_OPCODE_BIN;
    return CURLE_OK;
  case CURLWS_CLOSE:
    *pfirstbyte = WSBIT_OPCODE_CLOSE | WSBIT_FIN;
    return CURLE_OK;
  case (CURLWS_CLOSE | CURLWS_CONT):
    failf(data, "[WS] CLOSE frame must not be fragmented");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case CURLWS_PING:
    *pfirstbyte = WSBIT_OPCODE_PING | WSBIT_FIN;
    return CURLE_OK;
  case (CURLWS_PING | CURLWS_CONT):
    failf(data, "[WS] PING frame must not be fragmented");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  case CURLWS_PONG:
    *pfirstbyte = WSBIT_OPCODE_PONG | WSBIT_FIN;
    return CURLE_OK;
  case (CURLWS_PONG | CURLWS_CONT):
    failf(data, "[WS] PONG frame must not be fragmented");
    return CURLE_BAD_FUNCTION_ARGUMENT;
  default:
    failf(data, "[WS] unknown flags: %x", flags);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
}

static void ws_dec_info(struct ws_decoder *dec, struct Curl_easy *data,
                        const char *msg)
{
  NOVERBOSE((void)msg);
  switch(dec->head_len) {
  case 0:
    break;
  case 1:
    CURL_TRC_WS(data, "decoded %s [%s%s]", msg,
                ws_frame_name_of_op(dec->head[0]),
                (dec->head[0] & WSBIT_FIN) ? "" : " NON-FINAL");
    break;
  default:
    if(dec->head_len < dec->head_total) {
      CURL_TRC_WS(data, "decoded %s [%s%s](%d/%d)", msg,
                  ws_frame_name_of_op(dec->head[0]),
                  (dec->head[0] & WSBIT_FIN) ? "" : " NON-FINAL",
                  dec->head_len, dec->head_total);
    }
    else {
      CURL_TRC_WS(data, "decoded %s [%s%s payload=%"
                  FMT_OFF_T "/%" FMT_OFF_T "]",
                  msg, ws_frame_name_of_op(dec->head[0]),
                  (dec->head[0] & WSBIT_FIN) ? "" : " NON-FINAL",
                  dec->payload_offset, dec->payload_len);
    }
    break;
  }
}

static CURLcode ws_send_raw_blocking(struct Curl_easy *data,
                                     struct websocket *ws,
                                     const char *buffer, size_t buflen);

typedef CURLcode ws_write_payload(const uint8_t *buf, size_t buflen,
                                  int frame_age, int frame_flags,
                                  curl_off_t payload_offset,
                                  curl_off_t payload_len,
                                  void *userp,
                                  size_t *pnwritten);

static void ws_dec_next_frame(struct ws_decoder *dec)
{
#ifdef HAVE_LIBZ
  dec->output_len = dec->output_pos = 0;
  dec->decoded_offset = 0;
  dec->tail_pos = 0;
  dec->frame_done = FALSE;
  dec->compressed_frame = FALSE;
#endif
  dec->frame_age = 0;
  dec->frame_flags = 0;
  dec->payload_offset = 0;
  dec->payload_len = 0;
  dec->head_len = dec->head_total = 0;
  dec->state = WS_DEC_INIT;
  /* dec->cont_flags must be carried over to next frame */
}

static void ws_dec_reset(struct ws_decoder *dec)
{
  dec->frame_age = 0;
  dec->frame_flags = 0;
  dec->payload_offset = 0;
  dec->payload_len = 0;
  dec->head_len = dec->head_total = 0;
  dec->state = WS_DEC_INIT;
  dec->cont_flags = 0;
}

static void ws_dec_init(struct ws_decoder *dec)
{
  ws_dec_reset(dec);
}

static CURLcode ws_dec_read_head(struct ws_decoder *dec,
                                 struct Curl_easy *data,
                                 struct bufq *inraw)
{
  const uint8_t *inbuf;
  size_t inlen;

  while(Curl_bufq_peek(inraw, &inbuf, &inlen)) {
    if(dec->head_len == 0) {
      uint8_t firstbyte;
      dec->head[0] = *inbuf;
      Curl_bufq_skip(inraw, 1);
      firstbyte = dec->head[0];
#ifdef HAVE_LIBZ
      if(firstbyte & WSBIT_RSV1) {
        if(!dec->inflate_init ||
           ((firstbyte & 0xf) != WSBIT_OPCODE_TEXT &&
            (firstbyte & 0xf) != WSBIT_OPCODE_BIN)) {
          failf(data, "[WS] invalid compressed frame");
          return CURLE_RECV_ERROR;
        }
        firstbyte &= (uint8_t)~WSBIT_RSV1;
      }
#endif
      dec->frame_flags = ws_frame_firstbyte2flags(data, firstbyte,
                                                  dec->cont_flags);
      if(!dec->frame_flags) {
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }

      /* fragmentation only applies to data frames (text/binary);
       * control frames (close/ping/pong) do not affect the CONT status */
      if(dec->frame_flags & (CURLWS_TEXT | CURLWS_BINARY)) {
#ifdef HAVE_LIBZ
        if((firstbyte & 0xf) != WSBIT_OPCODE_CONT)
          dec->compressed_message = !!(dec->head[0] & WSBIT_RSV1);
        dec->compressed_frame = dec->compressed_message;
#endif
        dec->cont_flags = dec->frame_flags;
      }

      dec->head_len = 1;
#if 0
      ws_dec_info(dec, data, "seeing opcode");
#endif
      continue;
    }
    else if(dec->head_len == 1) {
      dec->head[1] = *inbuf;
      Curl_bufq_skip(inraw, 1);
      dec->head_len = 2;

      if(dec->head[1] & WSBIT_MASK) {
        /* A client MUST close a connection if it detects a masked frame. */
        failf(data, "[WS] masked input frame");
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }
      if(dec->frame_flags & CURLWS_PING && dec->head[1] > WS_MAX_CNTRL_LEN) {
        /* The maximum valid size of PING frames is 125 bytes.
           Accepting overlong pings would mean sending equivalent pongs! */
        failf(data, "[WS] received PING frame is too big");
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }
      if(dec->frame_flags & CURLWS_PONG && dec->head[1] > WS_MAX_CNTRL_LEN) {
        /* The maximum valid size of PONG frames is 125 bytes. */
        failf(data, "[WS] received PONG frame is too big");
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }
      if(dec->frame_flags & CURLWS_CLOSE && dec->head[1] > WS_MAX_CNTRL_LEN) {
        failf(data, "[WS] received CLOSE frame is too big");
        ws_dec_reset(dec);
        return CURLE_RECV_ERROR;
      }

      /* How long is the frame head? */
      if(dec->head[1] == 126) {
        dec->head_total = 4;
        continue;
      }
      else if(dec->head[1] == 127) {
        dec->head_total = 10;
        continue;
      }
      else {
        dec->head_total = 2;
      }
    }

    if(dec->head_len < dec->head_total) {
      dec->head[dec->head_len] = *inbuf;
      Curl_bufq_skip(inraw, 1);
      ++dec->head_len;
      if(dec->head_len < dec->head_total) {
#if 0
        ws_dec_info(dec, data, "decoding head");
#endif
        continue;
      }
    }
    /* got the complete frame head */
    DEBUGASSERT(dec->head_len == dec->head_total);
    switch(dec->head_total) {
    case 2:
      dec->payload_len = dec->head[1];
      break;
    case 4:
      dec->payload_len = (dec->head[2] << 8) | dec->head[3];
      break;
    case 10:
      if(dec->head[2] > 127) {
        failf(data, "[WS] frame length longer than 63 bits not supported");
        return CURLE_RECV_ERROR;
      }
      dec->payload_len =
        (curl_off_t)dec->head[2] << 56 |
        (curl_off_t)dec->head[3] << 48 |
        (curl_off_t)dec->head[4] << 40 |
        (curl_off_t)dec->head[5] << 32 |
        (curl_off_t)dec->head[6] << 24 |
        (curl_off_t)dec->head[7] << 16 |
        (curl_off_t)dec->head[8] <<  8 |
        dec->head[9];
      break;
    default:
      /* this should never happen */
      DEBUGASSERT(0);
      failf(data, "[WS] unexpected frame header length");
      return CURLE_RECV_ERROR;
    }

    dec->frame_age = 0;
    dec->payload_offset = 0;
    ws_dec_info(dec, data, "head");
    return CURLE_OK;
  }
  return CURLE_AGAIN;
}

static CURLcode ws_dec_pass_payload(struct ws_decoder *dec,
                                    struct Curl_easy *data,
                                    struct bufq *inraw,
                                    ws_write_payload *write_cb,
                                    void *write_ctx)
{
  const uint8_t *inbuf;
  size_t inlen;
  size_t nwritten;
  CURLcode result;
  size_t remain = curlx_sotouz_range(dec->payload_len - dec->payload_offset,
                                     0, SIZE_MAX);

  while(remain && Curl_bufq_peek(inraw, &inbuf, &inlen) &&
        !Curl_cwriter_is_paused(data)) {
    if(inlen > remain)
      inlen = remain;
    result = write_cb(inbuf, inlen, dec->frame_age, dec->frame_flags,
                      dec->payload_offset, dec->payload_len,
                      write_ctx, &nwritten);
    if(result)
      return result;
    Curl_bufq_skip(inraw, nwritten);
    dec->payload_offset += nwritten;
    remain = curlx_sotouz_range(dec->payload_len - dec->payload_offset,
                                0, SIZE_MAX);
    CURL_TRC_WS(data, "passed %zu bytes payload, %zu remain",
                nwritten, remain);
  }

  return remain ? CURLE_AGAIN : CURLE_OK;
}

#ifdef HAVE_LIBZ
static CURLcode ws_dec_inflate(struct ws_decoder *dec,
                               struct Curl_easy *data,
                               struct bufq *inraw,
                               ws_write_payload *write_cb, void *write_ctx)
{
  static const uint8_t tail[] = { 0, 0, 0xff, 0xff };
  z_stream *z = &dec->inflater;
  bool final = !(dec->frame_flags & CURLWS_CONT);

  while(!Curl_cwriter_is_paused(data)) {
    const uint8_t *input = NULL;
    size_t inlen = 0, used, n;
    bool at_tail;
    int status;
    CURLcode result;

    if(dec->output_pos < dec->output_len || dec->frame_done) {
      size_t len = dec->output_len - dec->output_pos;
      curl_off_t total = dec->frame_done ?
        dec->decoded_offset + (curl_off_t)len : -1;
      result = write_cb(dec->output + dec->output_pos, len,
                        dec->frame_age, dec->frame_flags,
                        dec->decoded_offset, total, write_ctx, &n);
      if(result)
        return result;
      dec->output_pos += n;
      dec->decoded_offset += (curl_off_t)n;
      if(n < len)
        return CURLE_AGAIN;
      dec->output_pos = dec->output_len = 0;
      if(dec->frame_done) {
        if(final && dec->no_context_takeover && inflateReset(z) != Z_OK)
          return CURLE_RECV_ERROR;
        return CURLE_OK;
      }
      continue;
    }

    at_tail = dec->payload_offset == dec->payload_len;
    if(!at_tail) {
      if(!Curl_bufq_peek(inraw, &input, &inlen))
        return CURLE_AGAIN;
      inlen = curlx_sotouz_range(dec->payload_len - dec->payload_offset,
                                 0, CURLMIN(inlen, (size_t)UINT_MAX));
    }
    else if(final && dec->tail_pos < sizeof(tail)) {
      input = tail + dec->tail_pos;
      inlen = sizeof(tail) - dec->tail_pos;
    }
    z->next_in = (Bytef *)input;
    z->avail_in = (uInt)inlen;
    z->next_out = dec->output;
    z->avail_out = sizeof(dec->output);
    status = inflate(z, Z_SYNC_FLUSH);
    used = inlen - z->avail_in;
    dec->output_len = sizeof(dec->output) - z->avail_out;
    /* Never retain a pointer into a queue across calls. */
    z->next_in = NULL;
    z->avail_in = 0;
    if(at_tail)
      dec->tail_pos += (unsigned int)used;
    else {
      Curl_bufq_skip(inraw, used);
      dec->payload_offset += (curl_off_t)used;
    }
    if(status == Z_MEM_ERROR)
      return CURLE_OUT_OF_MEMORY;
    if(status != Z_OK && status != Z_BUF_ERROR && status != Z_STREAM_END) {
      failf(data, "[WS] invalid permessage-deflate payload");
      return CURLE_RECV_ERROR;
    }
    if(dec->decoded_offset > CURL_OFF_T_MAX -
       (curl_off_t)dec->output_len)
      return CURLE_TOO_LARGE;
    if(status == Z_STREAM_END) {
      /* RFC 7692 also permits blocks with BFINAL set. */
      if(inflateReset(z) != Z_OK)
        return CURLE_RECV_ERROR;
    }
    if(dec->payload_offset == dec->payload_len && z->avail_out &&
       (!final || dec->tail_pos == sizeof(tail))) {
      /* Like Chromium, feed the RFC tail and let zlib validate the stream.
       * A permessage-deflate message need not end a DEFLATE stream. */
      dec->frame_done = TRUE;
    }
    else if(!used && !dec->output_len) {
      failf(data, "[WS] stalled permessage-deflate decoder");
      return CURLE_RECV_ERROR;
    }
  }
  return CURLE_AGAIN;
}
#endif

/* Decoded output and the final DEFLATE marker may outlive the raw queue. */
static bool ws_dec_pending(struct ws_decoder *dec)
{
#ifdef HAVE_LIBZ
  return dec->state == WS_DEC_PAYLOAD && dec->compressed_frame;
#else
  (void)dec;
  return FALSE;
#endif
}

static CURLcode ws_dec_pass(struct ws_decoder *dec,
                            struct Curl_easy *data,
                            struct bufq *inraw,
                            ws_write_payload *write_cb,
                            void *write_ctx)
{
  CURLcode result;

  if(dec->failed)
    return CURLE_RECV_ERROR;
  if(Curl_bufq_is_empty(inraw) && !ws_dec_pending(dec))
    return CURLE_AGAIN;

  switch(dec->state) {
  case WS_DEC_INIT:
    ws_dec_next_frame(dec);
    dec->state = WS_DEC_HEAD;
    FALLTHROUGH();
  case WS_DEC_HEAD:
    result = ws_dec_read_head(dec, data, inraw);
    if(result) {
      if(result != CURLE_AGAIN) {
        failf(data, "[WS] decode frame error %d", (int)result);
        break;  /* real error */
      }
      /* incomplete ws frame head */
      DEBUGASSERT(Curl_bufq_is_empty(inraw));
      break;
    }
    /* head parsing done */
    dec->state = WS_DEC_PAYLOAD;
    if(dec->payload_len == 0 && !ws_dec_pending(dec)) {
      size_t nwritten;
      const uint8_t tmp = '\0';
      /* special case of a 0 length frame, need to write once */
      result = write_cb(&tmp, 0, dec->frame_age, dec->frame_flags,
                        0, 0, write_ctx, &nwritten);
      if(result)
        return result;
      dec->state = WS_DEC_INIT;
      break;
    }
    FALLTHROUGH();
  case WS_DEC_PAYLOAD:
#ifdef HAVE_LIBZ
    if(dec->compressed_frame)
      result = ws_dec_inflate(dec, data, inraw, write_cb, write_ctx);
    else
#endif
      result = ws_dec_pass_payload(dec, data, inraw, write_cb, write_ctx);
    ws_dec_info(dec, data, "passing");
    if(result)
      break;
    /* payload parsing done */
    dec->state = WS_DEC_INIT;
    break;
  default:
    /* we covered all enums above, but some code analyzers are wimps */
    result = CURLE_FAILED_INIT;
  }
  if(result && result != CURLE_AGAIN)
    dec->failed = TRUE;
  return result;
}

static void update_meta(struct websocket *ws,
                        int frame_age, int frame_flags,
                        curl_off_t payload_offset,
                        curl_off_t payload_len,
                        size_t cur_len)
{
  curl_off_t bytesleft = payload_len < 0 ? -1 :
    (payload_len - payload_offset - cur_len);

  ws->recvframe.age = frame_age;
  ws->recvframe.flags = frame_flags;
  ws->recvframe.offset = payload_offset;
  ws->recvframe.len = cur_len;
  ws->recvframe.bytesleft = bytesleft;
}

/* WebSocket decoding client writer */
struct ws_cw_ctx {
  struct Curl_cwriter super;
  struct bufq buf;
};

static CURLcode ws_cw_init(struct Curl_easy *data,
                           struct Curl_cwriter *writer)
{
  struct ws_cw_ctx *ctx = writer->ctx;
  (void)data;
  Curl_bufq_init2(&ctx->buf, WS_CHUNK_SIZE, 1, BUFQ_OPT_SOFT_LIMIT);
  return CURLE_OK;
}

static void ws_cw_close(struct Curl_easy *data, struct Curl_cwriter *writer)
{
  struct ws_cw_ctx *ctx = writer->ctx;
  (void)data;
  Curl_bufq_free(&ctx->buf);
}

struct ws_cw_dec_ctx {
  struct Curl_easy *data;
  struct websocket *ws;
  struct Curl_cwriter *next_writer;
  int cw_type;
};

static CURLcode ws_flush(struct Curl_easy *data, struct websocket *ws,
                         bool blocking);
static CURLcode ws_enc_add_pending(struct Curl_easy *data,
                                   struct websocket *ws);

static CURLcode ws_enc_add_cntrl(struct Curl_easy *data,
                                 struct websocket *ws,
                                 const uint8_t *payload,
                                 size_t plen,
                                 unsigned int frame_type)
{
  (void)data;
  DEBUGASSERT(plen <= WS_MAX_CNTRL_LEN);
  if(plen > WS_MAX_CNTRL_LEN)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* Overwrite any pending frame with the new one, we keep
   * only one. */
  ws->pending.type = frame_type;
  ws->pending.payload_len = plen;
  memcpy(ws->pending.payload, payload, plen);
  return CURLE_OK;
}

static curl_off_t ws_payload_remain(curl_off_t payload_total,
                                    curl_off_t payload_offset,
                                    size_t payload_buffered)
{
  curl_off_t buffered, remain = payload_total - payload_offset;
  if((payload_total < 0) || (payload_offset < 0) || (remain < 0))
    return -1;
  buffered = curlx_uztoso(payload_buffered);
  if(remain < buffered)
    return -1;
  return remain - buffered;
}

static CURLcode ws_cw_dec_next(const uint8_t *buf, size_t buflen,
                               int frame_age, int frame_flags,
                               curl_off_t payload_offset,
                               curl_off_t payload_len,
                               void *user_data,
                               size_t *pnwritten)
{
  struct ws_cw_dec_ctx *ctx = user_data;
  struct Curl_easy *data = ctx->data;
  struct websocket *ws = ctx->ws;
  bool auto_pong = !data->set.ws_raw_mode && !data->set.ws_no_auto_pong;
  curl_off_t remain;
  CURLcode result;

  (void)frame_age;
  *pnwritten = 0;
  remain = ws_payload_remain(payload_len, payload_offset, buflen);
  if(remain < 0 && payload_len != -1) {
    DEBUGASSERT(0); /* parameter mismatch */
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(auto_pong && (frame_flags & CURLWS_PING) && !remain) {
    /* auto-respond to PINGs, only works for single-frame payloads atm */
    CURL_TRC_WS(data, "auto PONG to [PING payload=%" FMT_OFF_T
                "/%" FMT_OFF_T "]", payload_offset, payload_len);
    /* send back the exact same content as a PONG */
    result = ws_enc_add_cntrl(data, ws, buf, buflen, CURLWS_PONG);
    if(result)
      return result;
  }
  else if(buflen || !remain) {
    /* forward the decoded frame to the next client writer. */
    update_meta(ws, frame_age, frame_flags, payload_offset,
                payload_len, buflen);

    CURL_TRC_WRITE(data, "[WS] pass %zu decoded bytes", buflen);
    result = Curl_cwriter_write(data, ctx->next_writer,
                                (ctx->cw_type | CLIENTWRITE_0LEN),
                                (const char *)buf, buflen);
    if(result)
      return result;
  }
  *pnwritten = buflen;
  return CURLE_OK;
}

static CURLcode ws_cw_write(struct Curl_easy *data,
                            struct Curl_cwriter *writer, int type,
                            const char *buf, size_t nbytes)
{
  struct ws_cw_ctx *ctx = writer->ctx;
  struct websocket *ws;
  CURLcode result = CURLE_OK;

  CURL_TRC_WRITE(data, "[WS] write(len=%zu, type=%d)", nbytes, type);
  if(!(type & CLIENTWRITE_BODY) || data->set.ws_raw_mode)
    return Curl_cwriter_write(data, writer->next, type, buf, nbytes);

  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] not a websocket transfer");
    return CURLE_FAILED_INIT;
  }

  if(nbytes) {
    size_t nwritten;
    result = Curl_bufq_write(&ctx->buf, (const uint8_t *)buf,
                             nbytes, &nwritten);
    if(result) {
      infof(data, "[WS] error adding data to buffer %d", (int)result);
      return result;
    }
  }

  result = Curl_cwriter_flush(data, writer->next);
  if(result)
    goto out;

  while((!Curl_bufq_is_empty(&ctx->buf) || ws_dec_pending(&ws->dec)) &&
        !Curl_cwriter_is_paused(data)) {
    struct ws_cw_dec_ctx pass_ctx;
    pass_ctx.data = data;
    pass_ctx.ws = ws;
    pass_ctx.next_writer = writer->next;
    pass_ctx.cw_type = type;
    result = ws_dec_pass(&ws->dec, data, &ctx->buf,
                         ws_cw_dec_next, &pass_ctx);
    if(result == CURLE_AGAIN) {
      /* insufficient amount of data, keep it for later.
       * we pretend to have written all since we have a copy */
      result = CURLE_OK;
      goto out;
    }
    else if(result) {
      failf(data, "[WS] decode payload error %d", (int)result);
      Curl_bufq_reset(&ctx->buf);
      goto out;
    }
  }

out:
  if(!result && !ws->using_reader) {
    result = ws_flush(data, ws, Curl_api_is_in_callback(data));
    if(result == CURLE_AGAIN)
      result = CURLE_OK;
  }

  if(!result && (type & CLIENTWRITE_EOS) &&
     (!Curl_bufq_is_empty(&ctx->buf) || (ws->dec.state != WS_DEC_INIT) ||
      (ws->dec.cont_flags & CURLWS_CONT))) {
    failf(data, "[WS] decode ended with incomplete frame");
    ws->dec.failed = TRUE;
    result = CURLE_RECV_ERROR;
  }
  return result;
}

static CURLcode ws_cw_flush(struct Curl_easy *data,
                            struct Curl_cwriter *writer)
{
  CURLcode result = CURLE_OK;

  CURL_TRC_WRITE(data, "[ws] flush");
  if(!data->set.ws_raw_mode) {
    struct ws_cw_ctx *ctx = writer->ctx;
    struct websocket *ws;

    /* Frames should be written one by one, else the meta data does
     * not fit. Flush the next writer first, so it does not aggregate
     * our flushed data with anything it might have buffered. */
    result = Curl_cwriter_flush(data, writer->next);
    if(result)
      goto out;

    ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
    if(!ws) {
      failf(data, "[WS] not a websocket transfer");
      return CURLE_FAILED_INIT;
    }

    while((!Curl_bufq_is_empty(&ctx->buf) || ws_dec_pending(&ws->dec)) &&
        !Curl_cwriter_is_paused(data)) {
      struct ws_cw_dec_ctx pass_ctx;
      pass_ctx.data = data;
      pass_ctx.ws = ws;
      pass_ctx.next_writer = writer->next;
      pass_ctx.cw_type = CLIENTWRITE_BODY;
      result = ws_dec_pass(&ws->dec, data, &ctx->buf,
                           ws_cw_dec_next, &pass_ctx);
      if(result == CURLE_AGAIN) {
        /* insufficient amount of data, keep it for later.
         * we pretend to have written all since we have a copy */
        result = CURLE_OK;
        goto out;
      }
      else if(result) {
        failf(data, "[WS] decode payload error %d", (int)result);
        Curl_bufq_reset(&ctx->buf);
        goto out;
      }
    }
  }

out:
  if(!result)
    result = Curl_cwriter_flush(data, writer->next);
  return result;
}

/* WebSocket payload decoding client writer. */
static const struct Curl_cwtype ws_cw_decode = {
  "ws-decode",
  NULL,
  0,
  ws_cw_init,
  ws_cw_write,
  ws_cw_flush,
  ws_cw_close,
  sizeof(struct ws_cw_ctx)
};

static void ws_enc_info(struct ws_encoder *enc, struct Curl_easy *data,
                        const char *msg)
{
  NOVERBOSE((void)enc);
  NOVERBOSE((void)msg);
  CURL_TRC_WS(data, "WS-ENC: %s [%s%s payload=%"
              FMT_OFF_T "/%" FMT_OFF_T "]",
              msg, ws_frame_name_of_op(enc->firstbyte),
              (enc->firstbyte & WSBIT_FIN) ? "" : " NON-FIN",
              enc->payload_len - enc->payload_remain, enc->payload_len);
}

static void ws_enc_reset(struct ws_encoder *enc)
{
  enc->payload_remain = 0;
  enc->xori = 0;
  enc->contfragment = FALSE;
}

static void ws_enc_init(struct ws_encoder *enc)
{
  ws_enc_reset(enc);
}

/* RFC 6455 Section 5.2

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-------+-+-------------+-------------------------------+
   |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
   |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
   |N|V|V|V|       |S|             |   (if payload len==126/127)   |
   | |1|2|3|       |K|             |                               |
   +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
   |     Extended payload length continued, if payload len == 127  |
   + - - - - - - - - - - - - - - - +-------------------------------+
   |                               |Masking-key, if MASK set to 1  |
   +-------------------------------+-------------------------------+
   | Masking-key (continued)       |          Payload Data         |
   +-------------------------------- - - - - - - - - - - - - - - - +
   :                     Payload Data continued ...                :
   + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
   |                     Payload Data continued ...                |
   +---------------------------------------------------------------+
 */

static CURLcode ws_enc_add_frame(struct Curl_easy *data,
                                 struct ws_encoder *enc,
                                 unsigned int flags,
                                 curl_off_t payload_len,
                                 struct bufq *out)
{
  uint8_t firstb = 0;
  uint8_t head[14];
  CURLcode result;
  size_t hlen, nwritten;

  if(payload_len < 0) {
    failf(data, "[WS] starting new frame with negative payload length %"
                FMT_OFF_T, payload_len);
    return CURLE_SEND_ERROR;
  }

  if(enc->payload_remain > 0) {
    /* trying to write a new frame before the previous one is finished */
    failf(data, "[WS] starting new frame with %" FMT_OFF_T " bytes "
                "from last one remaining to be sent", enc->payload_remain);
    return CURLE_SEND_ERROR;
  }

  result = ws_frame_flags2firstbyte(data, flags & ~WS_COMPRESSED,
                                    (bool)enc->contfragment,
                                    &firstb);
  if(result)
    return result;

  /* fragmentation only applies to data frames (text/binary);
   * control frames (close/ping/pong) do not affect the CONT status */
  if(flags & (CURLWS_TEXT | CURLWS_BINARY)) {
    enc->contfragment = (curl_bit)((flags & CURLWS_CONT) ? TRUE : FALSE);
  }

  if(flags & CURLWS_PING && payload_len > WS_MAX_CNTRL_LEN) {
    failf(data, "[WS] given PING frame is too big");
    return CURLE_TOO_LARGE;
  }
  if(flags & CURLWS_PONG && payload_len > WS_MAX_CNTRL_LEN) {
    failf(data, "[WS] given PONG frame is too big");
    return CURLE_TOO_LARGE;
  }
  if(flags & CURLWS_CLOSE && payload_len > WS_MAX_CNTRL_LEN) {
    failf(data, "[WS] given CLOSE frame is too big");
    return CURLE_TOO_LARGE;
  }

  if(flags & WS_COMPRESSED)
    firstb |= WSBIT_RSV1;
  head[0] = enc->firstbyte = firstb;
  if(payload_len > 65535) {
    head[1] = 127 | WSBIT_MASK;
    head[2] = (uint8_t)((payload_len >> 56) & 0xff);
    head[3] = (uint8_t)((payload_len >> 48) & 0xff);
    head[4] = (uint8_t)((payload_len >> 40) & 0xff);
    head[5] = (uint8_t)((payload_len >> 32) & 0xff);
    head[6] = (uint8_t)((payload_len >> 24) & 0xff);
    head[7] = (uint8_t)((payload_len >> 16) & 0xff);
    head[8] = (uint8_t)((payload_len >> 8) & 0xff);
    head[9] = (uint8_t)(payload_len & 0xff);
    hlen = 10;
  }
  else if(payload_len >= 126) {
    head[1] = 126 | WSBIT_MASK;
    head[2] = (uint8_t)((payload_len >> 8) & 0xff);
    head[3] = (uint8_t)(payload_len & 0xff);
    hlen = 4;
  }
  else {
    head[1] = (uint8_t)payload_len | WSBIT_MASK;
    hlen = 2;
  }

  enc->payload_remain = enc->payload_len = payload_len;
  ws_enc_info(enc, data, "sending");

  /* 4 bytes random */

  result = Curl_rand(data, (uint8_t *)&enc->mask, sizeof(enc->mask));
  if(result)
    return result;

#ifdef DEBUGBUILD
  if(getenv("CURL_WS_FORCE_ZERO_MASK"))
    /* force the bit mask to 0x00000000, effectively disabling masking */
    memset(&enc->mask, 0, sizeof(enc->mask));
#endif

  /* add 4 bytes mask */
  memcpy(&head[hlen], &enc->mask, 4);
  hlen += 4;
  /* reset for payload to come */
  enc->xori = 0;

  result = Curl_bufq_write(out, head, hlen, &nwritten);
  if(result)
    return result;
  if(nwritten != hlen) {
    /* We use a bufq with SOFT_LIMIT, writing should always succeed */
    DEBUGASSERT(0);
    return CURLE_SEND_ERROR;
  }
  return CURLE_OK;
}

static CURLcode ws_enc_write_head(struct Curl_easy *data,
                                  struct websocket *ws,
                                  struct ws_encoder *enc,
                                  unsigned int flags,
                                  curl_off_t payload_len,
                                  struct bufq *out)
{
  /* starting a new frame, we want a clean sendbuf.
   * Any pending control frame we can add now as part of the flush. */
  if(ws->pending.type) {
    CURLcode result = ws_enc_add_pending(data, ws);
    if(result)
      return result;
  }
  return ws_enc_add_frame(data, enc, flags, payload_len, out);
}

static CURLcode ws_enc_write_payload(struct ws_encoder *enc,
                                     struct Curl_easy *data,
                                     const uint8_t *buf, size_t buflen,
                                     struct bufq *out, size_t *pnwritten)
{
  CURLcode result = CURLE_OK;
  size_t i = 0;
  size_t len;
  size_t remain;
#if defined(WS_HAVE_X86_SIMD) && WS_IS_LITTLE_ENDIAN
  static uint32_t cpu_feats;
  uint32_t features;
#endif

  *pnwritten = 0;
  if(Curl_bufq_is_full(out))
    return CURLE_AGAIN;

  /* A completed payload has nothing more to buffer. */
  if(enc->payload_remain <= 0) {
    ws_enc_info(enc, data, "buffered");
    return CURLE_OK;
  }

  len = buflen;
  remain = curlx_sotouz_range(enc->payload_remain, 0, SIZE_MAX);
  if(remain < len)
    len = remain;

#if defined(WS_HAVE_X86_SIMD) && WS_IS_LITTLE_ENDIAN
  /* Evaluate the process-global CPU feature cache once. */
  features = WS_ATOMIC_LOAD(cpu_feats);
  if(!(features & WS_CPU_FEAT_INIT)) {
    features = ws_get_cpu_features();
    WS_ATOMIC_STORE(cpu_feats, features);
  }
  (void)features;
#endif

  while(i < len) {
    uint8_t mask[4];
    size_t chunk = CURLMIN(len - i, (size_t)WS_ENC_XBUF_SIZE);
    size_t j = 0;
    size_t xbuf_idx = 0;
#if WS_IS_LITTLE_ENDIAN
    uint32_t mask32;
#endif

    /* Rotate the four-byte mask to the current frame offset. */
    mask[0] = enc->mask[enc->xori];
    mask[1] = enc->mask[(enc->xori + 1) & 3];
    mask[2] = enc->mask[(enc->xori + 2) & 3];
    mask[3] = enc->mask[(enc->xori + 3) & 3];

#if WS_IS_LITTLE_ENDIAN
    memcpy(&mask32, mask, sizeof(mask32));

    /* SIMD ladder: 128, 64 or 32 bytes per iteration. */
#ifdef WS_HAVE_X86_SIMD
#if defined(WS_SUPPORT_AVX_RUNTIME) || defined(__AVX512F__)
    if((features & WS_CPU_FEAT_AVX512) && chunk >= 128)
      j = ws_xor_avx512(buf + i, enc->xbuf, chunk, mask32);
#endif
#if defined(WS_SUPPORT_AVX_RUNTIME) || defined(__AVX2__)
    if(!j && (features & WS_CPU_FEAT_AVX2) && chunk >= 64)
      j = ws_xor_avx2(buf + i, enc->xbuf, chunk, mask32);
#endif
#elif defined(WS_HAVE_ARM_SIMD)
    if(chunk >= 32)
      j = ws_xor_neon(buf + i, enc->xbuf, chunk, mask32);
#endif

    /* Scalar ladder: eight or four bytes per iteration. */
#if WS_64BIT_NATIVE
    {
      uint64_t mask64 = ((uint64_t)mask32 << 32) | mask32;
      for(; j + 8 <= chunk; j += 8) {
        uint64_t data64;
        memcpy(&data64, buf + i + j, sizeof(data64));
        data64 ^= mask64;
        memcpy(enc->xbuf + j, &data64, sizeof(data64));
      }
    }
#endif
    for(; j + 4 <= chunk; j += 4) {
      uint32_t data32;
      memcpy(&data32, buf + i + j, sizeof(data32));
      data32 ^= mask32;
      memcpy(enc->xbuf + j, &data32, sizeof(data32));
    }
#endif /* WS_IS_LITTLE_ENDIAN */

    /* Final remainder: one byte per iteration. */
    for(; j < chunk; ++j)
      enc->xbuf[j] = buf[i + j] ^ mask[j & 3];

    /* Flush the staging buffer to the connection queue. Short writes and
     * zero-byte stalls leave the remaining data for a later retry. */
    while(xbuf_idx < chunk) {
      size_t n = 0;
      result = Curl_bufq_write(out, enc->xbuf + xbuf_idx,
                               chunk - xbuf_idx, &n);
      if(n) {
        /* Advance for bytes accepted before a later retry or error. */
        xbuf_idx += n;
        i += n;
        enc->xori = (enc->xori + (unsigned int)n) & 3;
      }
      if(result || !n) {
        if(!result)
          result = CURLE_AGAIN;
        goto out;
      }
    }
  }

out:
  *pnwritten = i;
  enc->payload_remain -= (curl_off_t)i;
  ws_enc_info(enc, data, "buffered");
  return result;
}

static CURLcode ws_enc_add_pending(struct Curl_easy *data,
                                   struct websocket *ws)
{
  CURLcode result;
  size_t n;

  if(!ws->pending.type) /* no pending frame here */
    return CURLE_OK;
  if(ws->enc.payload_remain) /* in the middle of another frame */
    return CURLE_AGAIN;

  result = ws_enc_add_frame(data, &ws->enc, ws->pending.type,
                            (curl_off_t)ws->pending.payload_len,
                            &ws->sendbuf);
  if(result) {
    CURL_TRC_WS(data, "ws_enc_cntrl(), error adding head: %d",
                (int)result);
    goto out;
  }
  result = ws_enc_write_payload(&ws->enc, data, ws->pending.payload,
                                ws->pending.payload_len,
                                &ws->sendbuf, &n);
  if(result) {
    CURL_TRC_WS(data, "ws_enc_cntrl(), error adding payload: %d",
                (int)result);
    goto out;
  }
  if(n != ws->pending.payload_len) {
    DEBUGASSERT(0); /* buffer should always be able to take all */
    CURL_TRC_WS(data, "ws_enc_cntrl(), error added only %zu/%zu payload,",
                n, ws->pending.payload_len);
    result = CURLE_SEND_ERROR;
    goto out;
  }
  /* the frame should be complete now */
  DEBUGASSERT(!ws->enc.payload_remain);
  memset(&ws->pending, 0, sizeof(ws->pending));

out:
  return result;
}

#ifdef HAVE_LIBZ
static CURLcode ws_pmd_start(struct Curl_easy *data, struct websocket *ws,
                             unsigned int flags, curl_off_t len)
{
  uint8_t firstbyte;
  CURLcode result;

  if(ws->input_active || ws->finishing || ws->send_credit ||
     ws->send_waiting || len < 0)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  result = ws_frame_flags2firstbyte(data, flags, ws->message_active,
                                    &firstbyte);
  if(result)
    return result;
  if(firstbyte & 8)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(!ws->message_active) {
    ws->message_flags = flags & (CURLWS_TEXT | CURLWS_BINARY);
    ws->message_active = TRUE;
    ws->wire_started = FALSE;
    ws->message_has_input = FALSE;
  }
  ws->input_flags = flags;
  ws->input_remain = len;
  ws->input_active = TRUE;
  return CURLE_OK;
}

static CURLcode ws_pmd_emit(struct Curl_easy *data, struct websocket *ws)
{
  size_t len = CURLMIN(ws->compressed_len, (size_t)WS_DEFLATE_CHUNK);
  size_t n;
  bool final = ws->flush_done && len == ws->compressed_len;
  unsigned int flags = ws->message_flags | (final ? 0 : CURLWS_CONT);
  CURLcode result;

  if(!ws->wire_started)
    flags |= WS_COMPRESSED;
  result = ws_enc_write_head(data, ws, &ws->enc, flags, (curl_off_t)len,
                             &ws->sendbuf);
  if(result)
    return result;
  result = ws_enc_write_payload(&ws->enc, data, ws->compressed, len,
                                &ws->sendbuf, &n);
  if(result)
    return result;
  if(n != len)
    return CURLE_SEND_ERROR;
  ws->compressed_len -= len;
  memmove(ws->compressed, ws->compressed + len, ws->compressed_len);
  ws->wire_started = TRUE;
  if(final) {
    ws->input_active = ws->message_active = FALSE;
    ws->finishing = ws->flush_done = FALSE;
    if(ws->client_no_context_takeover &&
       deflateReset(&ws->deflater) != Z_OK)
      return CURLE_SEND_ERROR;
  }
  return CURLE_OK;
}

/* Produce at most one bounded wire frame. The caller drains sendbuf before
 * calling again. Four trailing octets are retained until Finish, so the
 * message's sync marker can be removed across output-buffer boundaries. */
static CURLcode ws_pmd_encode(struct Curl_easy *data, struct websocket *ws,
                              const uint8_t *buf, size_t len, size_t *used)
{
  z_stream *z = &ws->deflater;

  *used = 0;
  DEBUGASSERT(Curl_bufq_is_empty(&ws->sendbuf));
  while(1) {
    size_t n;
    int status;

    if(ws->input_active && !ws->input_remain) {
      if(ws->input_flags & CURLWS_CONT)
        ws->input_active = FALSE;
      else
        ws->finishing = TRUE;
    }
    if(ws->compressed_len == sizeof(ws->compressed) || ws->flush_done)
      return ws_pmd_emit(data, ws);
    if(!ws->finishing && (!ws->input_active || !len))
      return CURLE_OK;

    if(ws->finishing && !ws->message_has_input) {
      /* Consecutive empty Z_SYNC_FLUSH calls do not produce another marker.
       * A single empty DEFLATE block is Chrome's empty-message encoding. */
      ws->compressed[0] = 0;
      ws->compressed_len = 1;
      ws->flush_done = TRUE;
      continue;
    }

    n = ws->finishing ? 0 :
      curlx_sotouz_range(ws->input_remain, 0,
                         CURLMIN(len, (size_t)WS_DEFLATE_CHUNK));
    z->next_in = (Bytef *)buf;
    z->avail_in = (uInt)n;
    z->next_out = ws->compressed + ws->compressed_len;
    z->avail_out = (uInt)(sizeof(ws->compressed) - ws->compressed_len);
    status = deflate(z, ws->finishing ? Z_SYNC_FLUSH : Z_NO_FLUSH);
    n -= z->avail_in;
    z->next_in = NULL;
    z->avail_in = 0;
    ws->compressed_len = sizeof(ws->compressed) - z->avail_out;
    if(status == Z_MEM_ERROR)
      return CURLE_OUT_OF_MEMORY;
    if(status != Z_OK && status != Z_BUF_ERROR)
      return CURLE_SEND_ERROR;
    if(n) {
      ws->message_has_input = TRUE;
      ws->input_remain -= (curl_off_t)n;
      *used += n;
      buf += n;
      len -= n;
    }
    if(ws->finishing && z->avail_out) {
      static const uint8_t tail[] = { 0, 0, 0xff, 0xff };
      if(ws->compressed_len < sizeof(tail) ||
         memcmp(ws->compressed + ws->compressed_len - sizeof(tail),
                tail, sizeof(tail)))
        return CURLE_SEND_ERROR;
      ws->compressed_len -= sizeof(tail);
      ws->flush_done = TRUE;
    }
  }
}

static CURLcode ws_pmd_send(struct Curl_easy *data, struct websocket *ws,
                            const uint8_t *buf, size_t len,
                            curl_off_t fragsize, unsigned int flags,
                            size_t *sent)
{
  CURLcode result;
  bool started = ws->input_active || ws->finishing || ws->send_credit ||
    ws->send_waiting;

  *sent = 0;
  if(len < ws->send_credit)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(started && !ws->input_active && !ws->finishing &&
     len > ws->send_credit)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(ws->input_active &&
     (curlx_uztoso(len - ws->send_credit) > ws->input_remain))
    return CURLE_BAD_FUNCTION_ARGUMENT;

  while(1) {
    size_t n;
    result = ws_flush(data, ws, Curl_api_is_in_callback(data));
    if(result)
      break;
    if(!ws->finishing) {
      /* Credit is in application bytes, never compressed wire bytes. */
      n = ws->send_credit;
      *sent += n;
      if(n)
        buf += n;
      len -= n;
      ws->send_credit = 0;
      if(started && !len && (!ws->input_active || ws->input_remain)) {
        ws->send_waiting = FALSE;
        return CURLE_OK;
      }
    }
    if(!started) {
      if((flags & CURLWS_OFFSET) &&
         (fragsize < 0 || curlx_uztoso(len) > fragsize))
        return CURLE_BAD_FUNCTION_ARGUMENT;
      result = ws_pmd_start(data, ws, flags,
                            flags & CURLWS_OFFSET ? fragsize :
                            curlx_uztoso(len));
      if(result)
        return result;
      started = TRUE;
      ws->send_waiting = !len;
    }
    result = ws_pmd_encode(data, ws,
                           buf ? buf + ws->send_credit : NULL,
                           len - ws->send_credit, &n);
    ws->send_credit += n;
    if(result)
      break;
  }
  if(result == CURLE_AGAIN)
    return *sent ? CURLE_OK : CURLE_AGAIN;
  ws->failed = TRUE;
  return result;
}
#endif

static CURLcode ws_enc_send(struct Curl_easy *data,
                            struct websocket *ws,
                            const uint8_t *buffer,
                            size_t buflen,
                            curl_off_t fragsize,
                            unsigned int flags,
                            size_t *pnsent)
{
  size_t n;
  CURLcode result = CURLE_OK;

  DEBUGASSERT(!data->set.ws_raw_mode);
  *pnsent = 0;

  if(ws->failed || ws->dec.failed)
    return CURLE_SEND_ERROR;
#ifdef HAVE_LIBZ
  if(ws->deflate_init) {
    if(!(flags & (CURLWS_CLOSE | CURLWS_PING | CURLWS_PONG)))
      return ws_pmd_send(data, ws, buffer, buflen, fragsize, flags, pnsent);
    if(ws->input_active || ws->finishing || ws->send_credit)
      return CURLE_BAD_FUNCTION_ARGUMENT;
  }
#endif

  if(ws->enc.payload_remain || !Curl_bufq_is_empty(&ws->sendbuf)) {
    /* a frame is ongoing with payload buffered or more payload
     * that needs to be encoded into the buffer */
    if(buflen < ws->sendbuf_payload) {
      /* We have been called with LESS buffer data than before. This
       * is not how it is supposed too work. */
      failf(data, "[WS] curl_ws_send() called with smaller 'buflen' than "
            "bytes already buffered in previous call, %zu vs %zu",
            buflen, ws->sendbuf_payload);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    if((curl_off_t)buflen >
       (ws->enc.payload_remain + (curl_off_t)ws->sendbuf_payload)) {
      /* too large buflen beyond payload length of frame */
      failf(data, "[WS] unaligned frame size (sending %zu instead of "
            "%" FMT_OFF_T ")", buflen,
            (curl_off_t)(ws->enc.payload_remain + ws->sendbuf_payload));
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
  }
  else {
    result = ws_flush(data, ws, Curl_api_is_in_callback(data));
    if(result)
      return result;

    result = ws_enc_write_head(data, ws, &ws->enc, flags,
                               (flags & CURLWS_OFFSET) ?
                               fragsize : (curl_off_t)buflen,
                               &ws->sendbuf);
    if(result) {
      CURL_TRC_WS(data, "curl_ws_send(), error writing frame head %d",
                  (int)result);
      return result;
    }
  }

  /* While there is either sendbuf to flush OR more payload to encode... */
  while(!Curl_bufq_is_empty(&ws->sendbuf) || (buflen > ws->sendbuf_payload)) {
    /* Try to add more payload to sendbuf */
    if(buflen > ws->sendbuf_payload) {
      size_t prev_len = Curl_bufq_len(&ws->sendbuf);
      result = ws_enc_write_payload(&ws->enc, data,
                                    buffer + ws->sendbuf_payload,
                                    buflen - ws->sendbuf_payload,
                                    &ws->sendbuf, &n);
      if(result && (result != CURLE_AGAIN))
        return result;
      ws->sendbuf_payload += Curl_bufq_len(&ws->sendbuf) - prev_len;
      if(!ws->sendbuf_payload) {
        return CURLE_AGAIN;
      }
    }

    /* flush, blocking when in callback */
    result = ws_flush(data, ws, Curl_api_is_in_callback(data));
    if(!result && ws->sendbuf_payload > 0) {
      *pnsent += ws->sendbuf_payload;
      buffer += ws->sendbuf_payload;
      buflen -= ws->sendbuf_payload;
      ws->sendbuf_payload = 0;
    }
    else if(result == CURLE_AGAIN) {
      if(ws->sendbuf_payload > Curl_bufq_len(&ws->sendbuf)) {
        /* blocked, part of payload bytes remain, report length
         * that we managed to send. */
        size_t flushed = (ws->sendbuf_payload - Curl_bufq_len(&ws->sendbuf));
        *pnsent += flushed;
        ws->sendbuf_payload -= flushed;
        return CURLE_OK;
      }
      else {
        /* blocked before sending headers or 1st payload byte. We cannot report
         * OK on 0-length send (caller counts only payload) and EAGAIN */
        CURL_TRC_WS(data, "EAGAIN flushing sendbuf, payload_encoded: %zu/%zu",
                    ws->sendbuf_payload, buflen);
        DEBUGASSERT(*pnsent == 0);
        return CURLE_AGAIN;
      }
    }
    else
      return result;  /* real error sending the data */
  }
  return CURLE_OK;
}

struct cr_ws_ctx {
  struct Curl_creader super;
  BIT(read_eos);  /* we read an EOS from the next reader */
  BIT(eos);       /* we have returned an EOS */
#ifdef HAVE_LIBZ
  uint8_t input[WS_DEFLATE_CHUNK];
  size_t input_len, input_pos;
#endif
};

static CURLcode cr_ws_init(struct Curl_easy *data, struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
  return CURLE_OK;
}

static void cr_ws_close(struct Curl_easy *data, struct Curl_creader *reader)
{
  (void)data;
  (void)reader;
}

#ifdef HAVE_LIBZ
static CURLcode cr_ws_read_pmd(struct Curl_easy *data,
                               struct Curl_creader *reader,
                               struct websocket *ws, char *buf, size_t blen,
                               size_t *pnread, bool *peos)
{
  struct cr_ws_ctx *ctx = reader->ctx;
  CURLcode result;

  *pnread = 0;
  *peos = FALSE;
  if(ws->failed || ws->dec.failed)
    return CURLE_SEND_ERROR;
  while(Curl_bufq_is_empty(&ws->sendbuf)) {
    size_t n;
    if(ws->input_active || ws->finishing ||
       ctx->input_pos < ctx->input_len) {
      result = ws_pmd_encode(data, ws, ctx->input + ctx->input_pos,
                             ctx->input_len - ctx->input_pos, &n);
      ctx->input_pos += n;
      if(result)
        goto fail;
      if(!Curl_bufq_is_empty(&ws->sendbuf))
        break;
    }
    if(ctx->input_pos == ctx->input_len) {
      size_t len = sizeof(ctx->input);
      size_t serial = ws->frame_serial;
      bool eos;
      if(ctx->read_eos) {
        if(ws->input_active || ws->message_active ||
           ws->enc.payload_remain) {
          failf(data, "[WS] upload ended with an incomplete message");
          result = CURLE_SEND_ERROR;
          goto fail;
        }
        ctx->eos = TRUE;
        *peos = TRUE;
        return CURLE_OK;
      }
      if(ws->input_active)
        len = curlx_sotouz_range(ws->input_remain, 0, len);
      else if(ws->enc.payload_remain)
        len = curlx_sotouz_range(ws->enc.payload_remain, 0, len);
      ctx->input_pos = ctx->input_len = 0;
      result = Curl_creader_read(data, reader->next, (char *)ctx->input,
                                 len, &ctx->input_len, &eos);
      if(result)
        return result;
      ctx->read_eos = eos;
      if(serial != ws->frame_serial) {
        ctx->read_eos = FALSE;
        Curl_creader_clear_eos(data, reader->next);
      }
      if(ws->enc.payload_remain) {
        if((curl_off_t)ctx->input_len > ws->enc.payload_remain) {
          result = CURLE_SEND_ERROR;
          goto fail;
        }
        result = ws_enc_write_payload(&ws->enc, data, ctx->input,
                                      ctx->input_len, &ws->sendbuf, &n);
        if(result)
          goto fail;
        ctx->input_pos = n;
      }
      else if(ctx->input_len && !ws->input_active) {
        result = ws_pmd_start(data, ws, CURLWS_BINARY,
                              (curl_off_t)ctx->input_len);
        if(result)
          goto fail;
      }
      if(ws->input_active &&
         (curl_off_t)ctx->input_len > ws->input_remain) {
        result = CURLE_SEND_ERROR;
        goto fail;
      }
      if(!ctx->input_len && !ctx->read_eos &&
         (!ws->input_active || ws->input_remain) &&
         Curl_bufq_is_empty(&ws->sendbuf))
        return CURLE_OK; /* a paused upstream reader */
    }
  }
  return Curl_bufq_cread(&ws->sendbuf, buf, blen, pnread);
fail:
  ws->failed = TRUE;
  return result;
}
#endif

static CURLcode cr_ws_read(struct Curl_easy *data,
                           struct Curl_creader *reader,
                           char *buf, size_t blen,
                           size_t *pnread, bool *peos)
{
  struct cr_ws_ctx *ctx = reader->ctx;
  CURLcode result = CURLE_OK;
  size_t nread, n;
  struct websocket *ws;
  bool eos;

  *pnread = 0;
  if(ctx->eos) {
    *peos = TRUE;
    return CURLE_OK;
  }

  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] not a websocket transfer");
    return CURLE_FAILED_INIT;
  }

#ifdef HAVE_LIBZ
  if(ws->deflate_init)
    return cr_ws_read_pmd(data, reader, ws, buf, blen, pnread, peos);
#endif

  if(Curl_bufq_is_empty(&ws->sendbuf)) {
    if(ctx->read_eos) {
      ctx->eos = TRUE;
      *peos = TRUE;
      return CURLE_OK;
    }

    if(ws->enc.payload_remain) {
      CURL_TRC_WS(data, "current frame, %" FMT_OFF_T " remaining",
                  ws->enc.payload_remain);
      blen = curlx_sotouz_range(ws->enc.payload_remain, 0, blen);
    }

    result = Curl_creader_read(data, reader->next, buf, blen, &nread, &eos);
    if(result)
      return result;
    ctx->read_eos = eos;

    if(!Curl_bufq_is_empty(&ws->sendbuf)) {
      /* client_read started a new frame, we disregard any eos reported */
      ctx->read_eos = FALSE;
      Curl_creader_clear_eos(data, reader->next);
    }
    else if(!nread) {
      /* nothing to convert, return this right away */
      if(ctx->read_eos)
        ctx->eos = TRUE;
      *pnread = nread;
      *peos = (bool)ctx->eos;
      goto out;
    }

    if(!ws->enc.payload_remain && Curl_bufq_is_empty(&ws->sendbuf)) {
      /* encode the data as a new BINARY frame */
      result = ws_enc_write_head(data, ws, &ws->enc, CURLWS_BINARY, nread,
                                 &ws->sendbuf);
      if(result)
        goto out;
    }

    result = ws_enc_write_payload(&ws->enc, data, (uint8_t *)buf,
                                  nread, &ws->sendbuf, &n);
    if(result)
      goto out;
    CURL_TRC_READ(data, "cr_ws_read, added %zu payload, len=%zu", nread, n);
  }

  DEBUGASSERT(!Curl_bufq_is_empty(&ws->sendbuf));
  *peos = FALSE;
  result = Curl_bufq_cread(&ws->sendbuf, buf, blen, pnread);
  if(!result && ctx->read_eos && Curl_bufq_is_empty(&ws->sendbuf)) {
    /* no more data, read all, done. */
    ctx->eos = TRUE;
    *peos = TRUE;
  }

out:
  CURL_TRC_READ(data, "cr_ws_read(len=%zu) -> %d, nread=%zu, eos=%d",
                blen, (int)result, *pnread, *peos);
  return result;
}

static curl_off_t cr_ws_total_length(struct Curl_easy *data,
                                     struct Curl_creader *reader)
{
  /* this reader changes length depending on input */
  (void)data;
  (void)reader;
  return -1;
}

static const struct Curl_crtype ws_cr_encode = {
  "ws-encode",
  cr_ws_init,
  cr_ws_read,
  cr_ws_close,
  Curl_creader_def_needs_rewind,
  cr_ws_total_length,
  Curl_creader_def_resume_from,
  Curl_creader_def_cntrl,
  Curl_creader_def_is_paused,
  Curl_creader_def_done,
  sizeof(struct cr_ws_ctx)
};

static void ws_conn_dtor(const void *key, size_t klen, void *entry);

static CURLcode ws_conn_create(struct Curl_easy *data, struct websocket **pws)
{
  struct websocket *ws;
  CURLcode result;

  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    size_t chunk_size = WS_CHUNK_SIZE;
    ws = curlx_calloc(1, sizeof(*ws));
    if(!ws)
      return CURLE_OUT_OF_MEMORY;
#ifdef DEBUGBUILD
    {
      const char *p = getenv("CURL_WS_CHUNK_SIZE");
      if(p) {
        curl_off_t l;
        if(!curlx_str_number(&p, &l, 1 * 1024 * 1024))
          chunk_size = (size_t)l;
      }
    }
#endif
    CURL_TRC_WS(data, "WS, using chunk size %zu", chunk_size);
    Curl_bufq_init2(&ws->recvbuf, chunk_size, WS_CHUNK_COUNT,
                    BUFQ_OPT_SOFT_LIMIT);
    Curl_bufq_init2(&ws->sendbuf, chunk_size, WS_CHUNK_COUNT,
                    BUFQ_OPT_SOFT_LIMIT);
    ws_dec_init(&ws->dec);
    ws_enc_init(&ws->enc);
    result = Curl_conn_meta_set(data->conn, CURL_META_PROTO_WS_CONN,
                                ws, ws_conn_dtor);
    if(result)
      return result;
  }
  *pws = ws;
  return CURLE_OK;
}

static void ws_skip_ows(const char **p)
{
  while(**p == ' ' || **p == '\t')
    ++*p;
}

/* The extension and parameter names are case sensitive. */
static CURLcode ws_parse_pmd(struct websocket *ws, const char *p, bool offer)
{
  unsigned int seen = 0;
  unsigned char client_bits = 15, server_bits = 15;

  ws_skip_ows(&p);
  if(strncmp(p, "permessage-deflate", 18))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  p += 18;
  ws_skip_ows(&p);
  while(*p == ';') {
    const char *name;
    size_t namelen;
    unsigned int bit;
    unsigned char bits = 0;
    bool has_value = FALSE;

    ++p;
    ws_skip_ows(&p);
    name = p;
    while((*p >= 'a' && *p <= 'z') || *p == '_')
      ++p;
    namelen = (size_t)(p - name);
    if(namelen == 26 && !memcmp(name, "server_no_context_takeover", 26))
      bit = 1;
    else if(namelen == 26 && !memcmp(name, "client_no_context_takeover", 26))
      bit = 2;
    else if(namelen == 22 && !memcmp(name, "server_max_window_bits", 22))
      bit = 4;
    else if(namelen == 22 && !memcmp(name, "client_max_window_bits", 22))
      bit = 8;
    else
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(seen & bit)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    seen |= bit;
    ws_skip_ows(&p);
    if(*p == '=') {
      char value[2];
      size_t len = 0;
      bool quoted;
      has_value = TRUE;
      ++p;
      ws_skip_ows(&p);
      quoted = *p == '"';
      if(quoted)
        ++p;
      while(*p && (quoted ? *p != '"' : (*p >= '0' && *p <= '9'))) {
        if(quoted && *p == '\\')
          ++p;
        if(*p < '0' || *p > '9' || len == sizeof(value))
          return CURLE_BAD_FUNCTION_ARGUMENT;
        value[len++] = *p++;
      }
      if(quoted) {
        if(*p != '"')
          return CURLE_BAD_FUNCTION_ARGUMENT;
        ++p;
      }
      if(len == 1 && (value[0] == '8' || value[0] == '9'))
        bits = (unsigned char)(value[0] - '0');
      else if(len == 2 && value[0] == '1' &&
              value[1] >= '0' && value[1] <= '5')
        bits = (unsigned char)(10 + value[1] - '0');
      else
        return CURLE_BAD_FUNCTION_ARGUMENT;
      ws_skip_ows(&p);
    }
    if(offer) {
      if(bit != 8 || has_value)
        return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    else if((bit < 4 && has_value) || (bit >= 4 && !has_value))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(bit == 4)
      server_bits = bits;
    else if(bit == 8)
      client_bits = bits;
  }
  if(*p == '\r')
    ++p;
  if(*p == '\n')
    ++p;
  if(*p || (offer && seen != 8))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(!offer) {
    ws->client_window_bits = client_bits;
    ws->server_window_bits = server_bits;
    ws->server_no_context_takeover = !!(seen & 1);
    ws->client_no_context_takeover = !!(seen & 2);
  }
  return CURLE_OK;
}

CURLcode Curl_ws_header(struct Curl_easy *data, const char *value)
{
  struct websocket *ws;

  if(data->set.ws_raw_mode)
    return CURLE_OK;
  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws || !ws->pmd_offered || ws->pmd_accepted ||
     ws_parse_pmd(ws, value, FALSE)) {
    failf(data, "[WS] invalid Sec-WebSocket-Extensions response");
    return CURLE_WEIRD_SERVER_REPLY;
  }
  ws->pmd_accepted = TRUE;
  return CURLE_OK;
}

struct wsfield {
  const char *name;
  const char *val;
};

CURLcode Curl_ws_request(struct Curl_easy *data, struct dynbuf *req)
{
  unsigned int i;
  CURLcode result = CURLE_OK;
  uint8_t rand[16];
  char *randstr;
  size_t randlen;
  char keyval[40];
  struct websocket *ws;
  struct SingleRequest *k = &data->req;
  struct wsfield heads[] = {
    {
      /* The request MUST contain an |Upgrade| header field whose value
         MUST include the "websocket" keyword. */
      "Upgrade", "websocket"
    },
    {
      /* The request MUST include a header field with the name
         |Sec-WebSocket-Version|. The value of this header field MUST be
         13. */
      "Sec-WebSocket-Version", "13",
    },
    {
      /* The request MUST include a header field with the name
         |Sec-WebSocket-Key|. The value of this header field MUST be a nonce
         consisting of a randomly selected 16-byte value that has been
         base64-encoded (see Section 4 of [RFC4648]). The nonce MUST be
         selected randomly for each connection. */
      "Sec-WebSocket-Key", NULL,
    }
  };
  heads[2].val = &keyval[0];

  /* A retried HTTP handshake must not inherit negotiation or codec state. */
  Curl_conn_meta_remove(data->conn, CURL_META_PROTO_WS_CONN);
  result = ws_conn_create(data, &ws);
  if(result)
    return result;
  ws->pmd_offered = data->set.ws_permessage_deflate;
  ws->pmd_accepted = FALSE;

  /* 16 bytes random */
  result = Curl_rand(data, rand, sizeof(rand));
  if(result)
    return result;
  result = curlx_base64_encode(rand, sizeof(rand), &randstr, &randlen);
  if(result)
    return result;
  DEBUGASSERT(randlen < sizeof(keyval));
  if(randlen >= sizeof(keyval)) {
    curlx_free(randstr);
    return CURLE_FAILED_INIT;
  }
  curlx_strcopy(keyval, sizeof(keyval), randstr, randlen);
  curlx_free(randstr);
  for(i = 0; !result && (i < CURL_ARRAYSIZE(heads)); i++) {
    if(!Curl_checkheaders(data, heads[i].name, strlen(heads[i].name))) {
      result = curlx_dyn_addf(req, "%s: %s\r\n", heads[i].name, heads[i].val);
    }
  }
  if(!result && ws->pmd_offered) {
    const char *custom = Curl_checkheaders(data,
                                         STRCONST("Sec-WebSocket-Extensions"));
    if(custom) {
      const char *value = strchr(custom, ':');
      if(!value || ws_parse_pmd(ws, value + 1, TRUE)) {
        failf(data, "[WS] incompatible custom extension offer");
        return CURLE_BAD_FUNCTION_ARGUMENT;
      }
    }
    else
      result = curlx_dyn_add(req, "Sec-WebSocket-Extensions: "
                            "permessage-deflate; client_max_window_bits\r\n");
  }
  data->state.http_hd_upgrade = TRUE;
  k->upgr101 = UPGR101_WS;
  data->conn->bits.upgrade_in_progress = TRUE;
  return result;
}

static void ws_codec_cleanup(struct websocket *ws)
{
#ifdef HAVE_LIBZ
  if(ws->dec.inflate_init) {
    inflateEnd(&ws->dec.inflater);
    ws->dec.inflate_init = FALSE;
  }
  if(ws->deflate_init) {
    deflateEnd(&ws->deflater);
    ws->deflate_init = FALSE;
  }
#else
  (void)ws;
#endif
}

static void ws_conn_dtor(const void *key, size_t klen, void *entry)
{
  struct websocket *ws = entry;
  (void)key;
  (void)klen;
  ws_codec_cleanup(ws);
  Curl_bufq_free(&ws->recvbuf);
  Curl_bufq_free(&ws->sendbuf);
  curlx_free(ws);
}

/*
 * 'nread' is number of bytes of websocket data already in the buffer at
 * 'mem'.
 */
CURLcode Curl_ws_accept(struct Curl_easy *data,
                        const char *mem, size_t nread)
{
  struct SingleRequest *k = &data->req;
  struct websocket *ws;
  struct Curl_cwriter *ws_dec_writer = NULL;
  struct Curl_creader *ws_enc_reader = NULL;
  CURLcode result;

  DEBUGASSERT(data->conn);
  result = ws_conn_create(data, &ws);
  if(result)
    return result;
#ifdef HAVE_LIBZ
  if(ws->pmd_accepted) {
    int status;
    status = inflateInit2(&ws->dec.inflater, -15);
    if(status != Z_OK) {
      result = status == Z_MEM_ERROR ?
        CURLE_OUT_OF_MEMORY : CURLE_FAILED_INIT;
      goto out;
    }
    ws->dec.inflate_init = TRUE;
    ws->dec.no_context_takeover = ws->server_no_context_takeover;
    /* Like Chromium, use zlib's 9-bit compressor for an 8-bit window.
     * Its maximum match distance is 512 - 262 = 250 bytes. */
    status = deflateInit2(&ws->deflater, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                         -(int)CURLMAX(ws->client_window_bits, 9), 8,
                         Z_DEFAULT_STRATEGY);
    if(status != Z_OK) {
      result = status == Z_MEM_ERROR ?
        CURLE_OUT_OF_MEMORY : CURLE_FAILED_INIT;
      goto out;
    }
    ws->deflate_init = TRUE;
  }
#endif
  /* Verify the Sec-WebSocket-Accept response.

     The sent value is the base64 encoded version of a SHA-1 hash done on the
     |Sec-WebSocket-Key| header field concatenated with
     the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11". */

  /* Extension responses have been validated by Curl_ws_header(). */

  /* If the response includes a |Sec-WebSocket-Protocol| header field
     and this header field indicates the use of a subprotocol that was
     not present in the client's handshake (the server has indicated a
     subprotocol not requested by the client), the client MUST Fail
     the WebSocket Connection. */

  infof(data, "[WS] Received 101, switch to WebSocket");

  /* Install our client writer that decodes WS frames payload */
  result = Curl_cwriter_create(&ws_dec_writer, data, &ws_cw_decode,
                               CURL_CW_CONTENT_DECODE);
  if(result)
    goto out;
  result = Curl_cwriter_add(data, ws_dec_writer);
  if(result)
    goto out;
  ws_dec_writer = NULL; /* owned by transfer now */

  k->header = FALSE; /* we will not get more response headers */

  if(data->set.connect_only) {
    /* In CONNECT_ONLY setup, the payloads from `mem` need to be received
     * when using `curl_ws_recv/curl_easy_recv` later on, after this transfer
     * is already marked as DONE.
     * Since `curl_easy_recv()` is also supposed to work, we need
     * to buffer the data at connection level. See #22107 */
    if(nread) {
      result = Curl_cf_recvbuf_add(data, data->conn, FIRSTSOCKET,
                                   (const uint8_t *)mem, nread);
      if(result)
        goto out;
    }
    CURL_REQ_CLEAR_RECV(data); /* read no more content */
  }
  else { /* !connect_only */
    if(data->set.method == HTTPREQ_PUT) {
      CURL_TRC_WS(data, "UPLOAD set, add ws-encode reader");
      result = Curl_creader_set_fread(data, -1);
      if(result)
        goto out;

      if(!data->set.ws_raw_mode) {
        /* Add our client reader encoding WS BINARY frames */
        result = Curl_creader_create(&ws_enc_reader, data, &ws_cr_encode,
                                     CURL_CR_CONTENT_ENCODE);
        if(result)
          goto out;
        result = Curl_creader_add(data, ws_enc_reader);
        if(result)
          goto out;
        ws_enc_reader = NULL; /* owned by transfer now */
        ws->using_reader = TRUE;
      }

      /* start over with sending */
      data->req.eos_read = FALSE;
      data->req.upload_done = FALSE;
      CURL_REQ_SET_SEND(data);
    }

    /* Then pass any additional data to the writers */
    if(nread) {
      result = Curl_client_write(data, CLIENTWRITE_BODY, mem, nread);
      if(result)
        goto out;
    }
  }

  k->upgr101 = UPGR101_RECEIVED;
  k->header = FALSE; /* we will not get more responses */

out:
  if(ws_dec_writer)
    Curl_cwriter_free(data, ws_dec_writer);
  if(ws_enc_reader)
    Curl_creader_free(data, ws_enc_reader);
  if(result) {
    ws->failed = TRUE;
    ws_codec_cleanup(ws);
    CURL_TRC_WS(data, "Curl_ws_accept() failed -> %d", (int)result);
  }
  else
    CURL_TRC_WS(data, "websocket established, %s mode",
                data->set.connect_only ? "connect-only" : "callback");
  return result;
}

struct ws_collect {
  struct Curl_easy *data;
  struct websocket *ws;
  uint8_t *buffer;
  size_t buflen;
  size_t bufidx;
  int frame_age;
  int frame_flags;
  curl_off_t payload_offset;
  curl_off_t payload_len;
  bool written;
};

static CURLcode ws_client_collect(const uint8_t *buf, size_t buflen,
                                  int frame_age, int frame_flags,
                                  curl_off_t payload_offset,
                                  curl_off_t payload_len,
                                  void *userp,
                                  size_t *pnwritten)
{
  struct ws_collect *ctx = userp;
  struct Curl_easy *data = ctx->data;
  bool auto_pong = !data->set.ws_raw_mode && !data->set.ws_no_auto_pong;
  curl_off_t remain;
  CURLcode result = CURLE_OK;

  *pnwritten = 0;
  remain = ws_payload_remain(payload_len, payload_offset, buflen);
  if(remain < 0 && payload_len != -1) {
    DEBUGASSERT(0); /* parameter mismatch */
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  if(!ctx->bufidx) {
    /* first write */
    ctx->frame_age = frame_age;
    ctx->frame_flags = frame_flags;
    ctx->payload_offset = payload_offset;
  }
  ctx->payload_len = payload_len;

  if(auto_pong && (frame_flags & CURLWS_PING) && !remain) {
    /* auto-respond to PINGs, only works for single-frame payloads atm */
    CURL_TRC_WS(data, "auto PONG to [PING payload=%" FMT_OFF_T
                "/%" FMT_OFF_T "]", payload_offset, payload_len);
    /* send back the exact same content as a PONG */
    result = ws_enc_add_cntrl(ctx->data, ctx->ws, buf, buflen, CURLWS_PONG);
    if(result)
      return result;
    *pnwritten = buflen;
  }
  else {
    size_t write_len;

    ctx->written = TRUE;
    DEBUGASSERT(ctx->buflen >= ctx->bufidx);
    write_len = CURLMIN(buflen, ctx->buflen - ctx->bufidx);
    if(!write_len) {
      if(!buflen)  /* 0 length write, we accept that */
        return CURLE_OK;
      return CURLE_AGAIN;  /* no more space */
    }
    memcpy(ctx->buffer + ctx->bufidx, buf, write_len);
    ctx->bufidx += write_len;
    *pnwritten = write_len;
  }
  return result;
}

static CURLcode nw_in_recv(void *reader_ctx,
                           uint8_t *buf, size_t buflen,
                           size_t *pnread)
{
  struct Curl_easy *data = reader_ctx;
  return Curl_easy_recv(data, buf, buflen, pnread);
}

CURLcode curl_ws_recv(CURL *curl, void *buffer,
                      size_t buflen, size_t *recv,
                      const struct curl_ws_frame **metap)
{
  struct Curl_eapi_guard guard;
  CURLcode result = CURLE_OK;

  if(CURL_EAPI_ENTER(&guard, curl, ws_recv, &result)) {
    struct Curl_easy *data = curl;
    struct connectdata *conn;
    struct websocket *ws;
    struct ws_collect ctx;
    bool receive_more = FALSE;

    if(!recv || !metap || (buflen && !buffer)) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    *recv = 0;
    *metap = NULL;

    conn = data->conn;
    if(!conn) {
      /* Unhappy hack with lifetimes of transfers and connection */
      if(!data->set.connect_only) {
        failf(data, "[WS] CONNECT_ONLY is required");
        result = CURLE_UNSUPPORTED_PROTOCOL;
        goto out;
      }

      Curl_getconnectinfo(data, &conn);
      if(!conn) {
        failf(data, "[WS] connection not found");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
    }
    ws = Curl_conn_meta_get(conn, CURL_META_PROTO_WS_CONN);
    if(!ws) {
      failf(data, "[WS] connection is not setup for websocket");
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
    if(ws->failed || ws->dec.failed) {
      result = CURLE_RECV_ERROR;
      goto out;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.data = data;
    ctx.ws = ws;
    ctx.buffer = buffer;
    ctx.buflen = buflen;

    while(1) {
      /* receive more when our buffer is empty */
      if(Curl_bufq_is_empty(&ws->recvbuf) &&
         (!ws_dec_pending(&ws->dec) || receive_more)) {
        size_t n;
        receive_more = FALSE;
        result = Curl_bufq_slurp(&ws->recvbuf, nw_in_recv, data, &n);
        if(result)
          goto out;
        else if(n == 0) {
          /* connection closed */
          infof(data, "[WS] connection expectedly closed?");
          result = CURLE_GOT_NOTHING;
          if(ws->dec.state != WS_DEC_INIT ||
             (ws->dec.cont_flags & CURLWS_CONT)) {
            ws->dec.failed = TRUE;
            result = CURLE_RECV_ERROR;
          }
          goto out;
        }
        CURL_TRC_WS(data, "curl_ws_recv, added %zu bytes from network",
                    Curl_bufq_len(&ws->recvbuf));
      }

      result = ws_dec_pass(&ws->dec, data, &ws->recvbuf,
                           ws_client_collect, &ctx);
      if(result == CURLE_AGAIN) {
        if(!ctx.written) {
          ws_dec_info(&ws->dec, data, "need more input");
          receive_more = TRUE;
          continue;  /* nothing written, try more input */
        }
        break;
      }
      else if(result) {
        goto out;
      }
      else if(ctx.written) {
        /* The decoded frame is passed back to our caller.
         * There are frames like PING were we auto-respond to and
         * that we do not return. For these `ctx.written` is not set. */
        break;
      }
    }

    /* update frame information to be passed back */
    update_meta(ws, ctx.frame_age, ctx.frame_flags, ctx.payload_offset,
                ctx.payload_len, ctx.bufidx);
    *metap = &ws->recvframe;
    *recv = ws->recvframe.len;
    CURL_TRC_WS(data, "curl_ws_recv(len=%zu) -> %zu bytes (frame at %"
                FMT_OFF_T ", %" FMT_OFF_T " left)",
                buflen, *recv, ws->recvframe.offset,
                ws->recvframe.bytesleft);
    /* all's well, try to send any pending control. we do not know
     * when the application will call `curl_ws_send()` again. */
    if(!data->set.ws_raw_mode && !ws->using_reader && ws->pending.type) {
      CURLcode r2 = ws_enc_add_pending(data, ws);
      if(!r2)
        (void)ws_flush(data, ws, Curl_api_is_in_callback(data));
    }
    result = CURLE_OK;
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

static CURLcode ws_flush(struct Curl_easy *data, struct websocket *ws,
                         bool blocking)
{
  CURLcode result;

  /* If there is space, add any pending control frame */
  if(Curl_bufq_len(&ws->sendbuf) < ws->sendbuf.chunk_size) {
    result = ws_enc_add_pending(data, ws);
    if(result && (result != CURLE_AGAIN))
      return result;
  }

  if(!Curl_bufq_is_empty(&ws->sendbuf)) {
    const uint8_t *out;
    size_t outlen, n;
#ifdef DEBUGBUILD
    /* Simulate a blocking send after this chunk has been sent */
    bool eagain_next = FALSE;
    size_t chunk_egain = 0;
    const char *p = getenv("CURL_WS_CHUNK_EAGAIN");
    if(p) {
      curl_off_t l;
      if(!curlx_str_number(&p, &l, 1 * 1024 * 1024))
        chunk_egain = (size_t)l;
    }
#endif

    while(Curl_bufq_peek(&ws->sendbuf, &out, &outlen)) {
#ifdef DEBUGBUILD
      if(eagain_next)
        return CURLE_AGAIN;
      if(chunk_egain && (outlen > chunk_egain)) {
        outlen = chunk_egain;
        eagain_next = TRUE;
      }
#endif
      if(blocking) {
        result = ws_send_raw_blocking(data, ws, (const char *)out, outlen);
        n = result ? 0 : outlen;
      }
      else if(data->set.connect_only || Curl_api_is_in_callback(data))
        result = Curl_senddata(data, out, outlen, &n);
      else {
        result = Curl_xfer_send(data, out, outlen, FALSE, &n);
        if(!result && !n && outlen)
          result = CURLE_AGAIN;
      }

      /* A send can report an error after writing a partial amount. */
      if(n) {
        CURL_TRC_WS(data, "flushed %zu bytes", n);
        Curl_bufq_skip(&ws->sendbuf, n);
      }

      if(result == CURLE_AGAIN) {
        CURL_TRC_WS(data, "flush EAGAIN, %zu bytes remain in buffer",
                    Curl_bufq_len(&ws->sendbuf));
        return result;
      }
      else if(result) {
        failf(data, "[WS] flush, write error %d", (int)result);
        return result;
      }
    }
  }
  return CURLE_OK;
}

static CURLcode ws_send_raw_blocking(struct Curl_easy *data,
                                     struct websocket *ws,
                                     const char *buffer, size_t buflen)
{
  CURLcode result = CURLE_OK;
  size_t nwritten;

  if(!data)
    return result;

  (void)ws;
  while(buflen) {
    result = Curl_xfer_send(data, buffer, buflen, FALSE, &nwritten);
    if(result)
      return result;
    DEBUGASSERT(nwritten <= buflen);
    buffer += nwritten;
    buflen -= nwritten;
    if(buflen) {
      curl_socket_t sock = data->conn->sock[FIRSTSOCKET];
      timediff_t left_ms;
      int ev;

      CURL_TRC_WS(data, "ws_send_raw_blocking() partial, %zu left to send",
                  buflen);
      left_ms = Curl_timeleft_ms(data);
      if(left_ms < 0) {
        failf(data, "[WS] Timeout waiting for socket becoming writable");
        return CURLE_SEND_ERROR;
      }

      /* POLLOUT socket */
      if(sock == CURL_SOCKET_BAD)
        return CURLE_SEND_ERROR;
      ev = SOCKET_WRITABLE(sock, left_ms ? left_ms : 500);
      if(ev < 0) {
        failf(data, "[WS] Error while waiting for socket becoming writable");
        return CURLE_SEND_ERROR;
      }
    }
  }
  return result;
}

static CURLcode ws_send_raw(struct Curl_easy *data, const void *buffer,
                            size_t buflen, size_t *pnwritten)
{
  struct websocket *ws;
  CURLcode result;

  ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
  if(!ws) {
    failf(data, "[WS] Not a websocket transfer");
    return CURLE_SEND_ERROR;
  }
  if(!buflen)
    return CURLE_OK;

  if(Curl_api_is_in_callback(data)) {
    /* When invoked from inside callbacks, we do a blocking send as the
     * callback will probably not implement partial writes that may then
     * mess up the ws framing subsequently.
     * We need any pending data to be flushed before sending. */
    result = ws_flush(data, ws, TRUE);
    if(result)
      return result;
    result = ws_send_raw_blocking(data, ws, buffer, buflen);
    if(!result)
      *pnwritten = buflen;
  }
  else {
    /* We need any pending data to be sent or EAGAIN this call. */
    result = ws_flush(data, ws, FALSE);
    if(result)
      return result;
    result = Curl_senddata(data, buffer, buflen, pnwritten);
  }

  CURL_TRC_WS(data, "ws_send_raw(len=%zu) -> %d, %zu",
              buflen, (int)result, *pnwritten);
  return result;
}

CURLcode curl_ws_send(CURL *curl, const void *buffer_arg,
                      size_t buflen, size_t *sent,
                      curl_off_t fragsize,
                      unsigned int flags)
{
  struct Curl_eapi_guard guard;
  CURLcode result = CURLE_OK;

  if(CURL_EAPI_ENTER(&guard, curl, ws_send, &result)) {
    struct websocket *ws;
    const uint8_t *buffer = buffer_arg;
    struct Curl_easy *data = curl;
    size_t ndummy;
    size_t *pnsent = sent ? sent : &ndummy;

    CURL_TRC_WS(data, "curl_ws_send(len=%zu, fragsize=%" FMT_OFF_T
                ", flags=%x), raw=%d",
                buflen, fragsize, flags, data->set.ws_raw_mode);

    *pnsent = 0;

    if(flags & WS_COMPRESSED) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    if(!buffer && buflen) {
      failf(data, "[WS] buffer is NULL when buflen is not");
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    if(!data->conn && data->set.connect_only) {
      result = Curl_connect_only_attach(data);
      if(result)
        goto out;
    }
    if(!data->conn) {
      failf(data, "[WS] No associated connection");
      result = CURLE_SEND_ERROR;
      goto out;
    }
    ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
    if(!ws) {
      failf(data, "[WS] Not a websocket transfer");
      result = CURLE_SEND_ERROR;
      goto out;
    }

    if(data->set.ws_raw_mode) {
      /* In raw mode, we write directly to the connection */
      /* try flushing any content still waiting to be sent. */
      result = ws_flush(data, ws, FALSE);
      if(result)
        goto out;

      if(!buffer) {
        failf(data, "[WS] buffer is NULL in raw mode");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      if(!sent) {
        failf(data, "[WS] sent is NULL in raw mode");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      if(fragsize || flags) {
        failf(data, "[WS] fragsize and flags must be zero in raw mode");
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
      result = ws_send_raw(data, buffer, buflen, pnsent);
      goto out;
    }

    /* Not RAW mode, we do the frame encoding */
    result = ws_enc_send(data, ws, buffer, buflen, fragsize, flags, pnsent);
    CURL_TRC_WS(data, "curl_ws_send(len=%zu, fragsize=%" FMT_OFF_T
                ", flags=%x, raw=%d) -> %d, %zu",
                buflen, fragsize, flags, data->set.ws_raw_mode, (int)result,
                *pnsent);
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

static CURLcode ws_setup_conn(struct Curl_easy *data,
                              struct connectdata *conn)
{
  /* WebSocket is 1.1 only (for now) */
  data->state.http_neg.accept_09 = FALSE;
  data->state.http_neg.only_10 = FALSE;
  data->state.http_neg.wanted = CURL_HTTP_V1x;
  data->state.http_neg.allowed = CURL_HTTP_V1x;
  return Curl_http_setup_conn(data, conn);
}

const struct curl_ws_frame *curl_ws_meta(CURL *curl)
{
  /* we only return something for websocket, called from within the callback
     when not using raw mode */
  struct Curl_easy *data = curl;
  if(GOOD_EASY_HANDLE(data) && Curl_api_is_in_callback(data) &&
     data->conn && !data->set.ws_raw_mode) {
    struct websocket *ws;
    ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
    if(ws)
      return &ws->recvframe;
  }
  return NULL;
}

CURL_EXTERN CURLcode curl_ws_start_frame(CURL *curl,
                                         unsigned int flags,
                                         curl_off_t frame_len)
{
  struct Curl_eapi_guard guard;
  CURLcode result = CURLE_OK;

  if(CURL_EAPI_ENTER(&guard, curl, ws_start_frame, &result)) {
    struct Curl_easy *data = curl;
    struct websocket *ws;

    if(flags & WS_COMPRESSED) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }

    if(data->set.ws_raw_mode) {
      failf(data, "cannot curl_ws_start_frame() with CURLWS_RAW_MODE enabled");
      result = CURLE_FAILED_INIT;
      goto out;
    }

    CURL_TRC_WS(data, "curl_ws_start_frame(flags=%x, frame_len=%" FMT_OFF_T,
                flags, frame_len);

    if(!data->conn) {
      failf(data, "[WS] No associated connection");
      result = CURLE_SEND_ERROR;
      goto out;
    }
    ws = Curl_conn_meta_get(data->conn, CURL_META_PROTO_WS_CONN);
    if(!ws) {
      failf(data, "[WS] Not a websocket transfer");
      result = CURLE_SEND_ERROR;
      goto out;
    }

    if(ws->enc.payload_remain) {
      failf(data, "[WS] previous frame not finished");
      result = CURLE_SEND_ERROR;
      goto out;
    }

#ifdef HAVE_LIBZ
    if(ws->deflate_init) {
      if(ws->failed || ws->dec.failed) {
        result = CURLE_SEND_ERROR;
        goto out;
      }
      if(!(flags & (CURLWS_CLOSE | CURLWS_PING | CURLWS_PONG))) {
        result = ws_pmd_start(data, ws, flags, frame_len);
        if(!result)
          ++ws->frame_serial;
        goto out;
      }
      if(ws->input_active || ws->finishing || ws->send_credit) {
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        goto out;
      }
    }
#endif

    result = ws_enc_write_head(data, ws, &ws->enc, flags, frame_len,
                               &ws->sendbuf);
#ifdef HAVE_LIBZ
    if(!result && ws->deflate_init)
      ++ws->frame_serial;
#endif
    if(result)
      CURL_TRC_WS(data, "curl_start_frame(), error adding frame head %d",
                  (int)result);
  }
out:
  CURL_EAPI_LEAVE(&guard);
  return result;
}

const struct Curl_protocol Curl_protocol_ws = {
  ws_setup_conn,                        /* setup_connection */
  Curl_http,                            /* do_it */
  Curl_http_done,                       /* done */
  ZERO_NULL,                            /* do_more */
  ZERO_NULL,                            /* connect_it */
  ZERO_NULL,                            /* connecting */
  ZERO_NULL,                            /* doing */
  ZERO_NULL,                            /* proto_pollset */
  Curl_http_doing_pollset,              /* doing_pollset */
  ZERO_NULL,                            /* domore_pollset */
  Curl_http_perform_pollset,            /* perform_pollset */
  ZERO_NULL,                            /* disconnect */
  Curl_http_write_resp,                 /* write_resp */
  Curl_http_write_resp_hd,              /* write_resp_hd */
  ZERO_NULL,                            /* connection_is_dead */
  ZERO_NULL,                            /* attach connection */
  Curl_http_follow,                     /* follow */
};

#else

CURLcode curl_ws_recv(CURL *curl, void *buffer, size_t buflen,
                      size_t *recv,
                      const struct curl_ws_frame **metap)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)recv;
  (void)metap;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_ws_send(CURL *curl, const void *buffer,
                      size_t buflen, size_t *sent,
                      curl_off_t fragsize,
                      unsigned int flags)
{
  (void)curl;
  (void)buffer;
  (void)buflen;
  (void)sent;
  (void)fragsize;
  (void)flags;
  return CURLE_NOT_BUILT_IN;
}

const struct curl_ws_frame *curl_ws_meta(CURL *data)
{
  (void)data;
  return NULL;
}

CURL_EXTERN CURLcode curl_ws_start_frame(CURL *curl,
                                         unsigned int flags,
                                         curl_off_t frame_len)
{
  (void)curl;
  (void)flags;
  (void)frame_len;
  return CURLE_NOT_BUILT_IN;
}

#endif /* !CURL_DISABLE_WEBSOCKETS */
