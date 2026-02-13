#include "curl_setup.h"

#include <curl/curl.h>

#include "impersonate.h"

const struct impersonate_opts impersonations[] = {
  {
    .target = "chrome100",
    .alias = "chrome100",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \" Not A;Brand\";v=\"99\", \"Chromium\";v=\"100\", \"Google Chrome\";v=\"100\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome101",
    .alias = "chrome101",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \" Not A;Brand\";v=\"99\", \"Chromium\";v=\"101\", \"Google Chrome\";v=\"101\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome104",
    .alias = "chrome104",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Chromium\";v=\"104\", \" Not A;Brand\";v=\"99\", \"Google Chrome\";v=\"104\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome107",
    .alias = "chrome107",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Google Chrome\";v=\"107\", \"Chromium\";v=\"107\", \"Not=A?Brand\";v=\"24\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;2:0;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome110",
    .alias = "chrome110",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Chromium\";v=\"110\", \"Not A(Brand\";v=\"24\", \"Google Chrome\";v=\"110\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;2:0;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome116",
    .alias = "chrome116",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Chromium\";v=\"116\", \"Not)A;Brand\";v=\"24\", \"Google Chrome\";v=\"116\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;2:0;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome119",
    .alias = "chrome119",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Google Chrome\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome120",
    .alias = "chrome120",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome123",
    .alias = "chrome123",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Google Chrome\";v=\"123\", \"Not:A-Brand\";v=\"8\", \"Chromium\";v=\"123\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome124",
    .alias = "chrome124",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .curves = "X25519Kyber768Draft00:X25519:P-256:P-384",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Accept-Language: en-US,en;q=0.9",
      "Priority: u=0, i"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome131",
    .alias = "chrome131",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .curves = "X25519MLKEM768:X25519:P-256:P-384",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Accept-Language: en-US,en;q=0.9",
      "Priority: u=0, i"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome131_android",
    .alias = "chrome131_android",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .curves = "X25519:P-256:P-384",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Android\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Accept-Language: en-US,en;q=0.9",
      "Priority: u=0, i"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome133a",
    .alias = "chrome133a",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .curves = "X25519MLKEM768:X25519:P-256:P-384",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\", \"Chromium\";v=\"133\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Accept-Language: en-US,en;q=0.9",
      "Priority: u=0, i"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = true,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome136",
    .alias = "chrome136",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .curves = "X25519MLKEM768:X25519:P-256:P-384",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Chromium\";v=\"136\", \"Google Chrome\";v=\"136\", \"Not.A/Brand\";v=\"99\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Accept-Language: en-US,en;q=0.9",
      "Priority: u=0, i"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = true,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome142",
    .alias = "chrome142",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .curves = "X25519MLKEM768:X25519:P-256:P-384",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_permute_extensions = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not_A Brand\";v=\"99\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"macOS\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Accept-Language: en-US,en;q=0.9",
      "Priority: u=0, i"
    },
    .http2_settings = "1:65536;2:0;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .ech = "true",
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = true,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome99",
    .alias = "chrome99",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \" Not A;Brand\";v=\"99\", \"Chromium\";v=\"99\", \"Google Chrome\";v=\"99\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "chrome99_android",
    .alias = "chrome99_android",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \" Not A;Brand\";v=\"99\", \"Chromium\";v=\"99\", \"Google Chrome\";v=\"99\"",
      "sec-ch-ua-mobile: ?1",
      "sec-ch-ua-platform: \"Android\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.58 Mobile Safari/537.36",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "edge101",
    .alias = "edge101",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \" Not A;Brand\";v=\"99\", \"Chromium\";v=\"101\", \"Microsoft Edge\";v=\"101\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.47",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "edge99",
    .alias = "edge99",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "ECDHE-ECDSA-AES128-GCM-SHA256:"
      "ECDHE-RSA-AES128-GCM-SHA256:"
      "ECDHE-ECDSA-AES256-GCM-SHA384:"
      "ECDHE-RSA-AES256-GCM-SHA384:"
      "ECDHE-ECDSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-CHACHA20-POLY1305:"
      "ECDHE-RSA-AES128-SHA:"
      "ECDHE-RSA-AES256-SHA:"
      "AES128-GCM-SHA256:"
      "AES256-GCM-SHA384:"
      "AES128-SHA:"
      "AES256-SHA",
    .npn = false,
    .alpn = true,
    .alps = true,
    .tls_session_ticket = true,
    .cert_compression = "brotli",
    .http_headers = {
      "sec-ch-ua: \" Not A;Brand\";v=\"99\", \"Chromium\";v=\"99\", \"Microsoft Edge\";v=\"99\"",
      "sec-ch-ua-mobile: ?0",
      "sec-ch-ua-platform: \"Windows\"",
      "Upgrade-Insecure-Requests: 1",
      "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36 Edg/99.0.1150.30",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-User: ?1",
      "Sec-Fetch-Dest: document",
      "Accept-Encoding: gzip, deflate, br",
      "Accept-Language: en-US,en;q=0.9"
    },
    .http2_settings = "1:65536;3:1000;4:6291456;6:262144",
    .http2_window_update = 15663105,
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 1,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "firefox133",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_CBC_SHA",
    .http_headers = {
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language: en-US,en;q=0.5",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Upgrade-Insecure-Requests: 1",
      "Sec-Fetch-Dest: document",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-User: ?1",
      "Priority: u=0, i",
      "Te: trailers"
    },
    .curves = "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_secp521r1_sha512:"
      "rsa_pss_rsae_sha256:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha256:"
      "rsa_pkcs1_sha384:"
      "rsa_pkcs1_sha512:"
      "ecdsa_sha1:"
      "rsa_pkcs1_sha1",
    .alpn = true,
    .http2_settings = "1:65536;2:0;4:131072;5:16384",
    .http2_window_update = 12517377,
    .http2_pseudo_headers_order = "mpas",
    .http2_stream_exclusive = 0,
    .cert_compression = "zlib,brotli,zstd",
    .ech = "true",
    .tls_session_ticket = true,
    .tls_extension_order = "0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27-65037",
    .tls_delegated_credentials = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1",
    .tls_record_size_limit = 4001,
    .tls_grease = false,
    .tls_signed_cert_timestamps = false,
    .tls_key_shares_limit = 3,
    .split_cookies = true,
  },
  {
    .target = "firefox135",
    .alias = "firefox135",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_CBC_SHA",
    .http_headers = {
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language: en-US,en;q=0.5",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Upgrade-Insecure-Requests: 1",
      "Sec-Fetch-Dest: document",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-User: ?1",
      "Priority: u=0, i",
      "Te: trailers"
    },
    .curves = "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_secp521r1_sha512:"
      "rsa_pss_rsae_sha256:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha256:"
      "rsa_pkcs1_sha384:"
      "rsa_pkcs1_sha512:"
      "ecdsa_sha1:"
      "rsa_pkcs1_sha1",
    .alpn = true,
    .http2_settings = "1:65536;2:0;4:131072;5:16384",
    .http2_window_update = 12517377,
    .http2_pseudo_headers_order = "mpas",
    .http2_stream_exclusive = 0,
    .cert_compression = "zlib,brotli,zstd",
    .ech = "true",
    .tls_session_ticket = true,
    .tls_extension_order = "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037",
    .tls_delegated_credentials = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1",
    .tls_record_size_limit = 4001,
    .tls_grease = false,
    .tls_signed_cert_timestamps = true,
    .tls_key_shares_limit = 3,
    .split_cookies = true,
  },
  {
    .target = "firefox144",
    .alias = "firefox144",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_CBC_SHA",
    .http_headers = {
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/144.0",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language: en-US,en;q=0.5",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Upgrade-Insecure-Requests: 1",
      "Sec-Fetch-Dest: document",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-User: ?1",
      "Priority: u=0, i",
      "Te: trailers"
    },
    .curves = "X25519MLKEM768:X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_secp521r1_sha512:"
      "rsa_pss_rsae_sha256:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha256:"
      "rsa_pkcs1_sha384:"
      "rsa_pkcs1_sha512:"
      "ecdsa_sha1:"
      "rsa_pkcs1_sha1",
    .alpn = true,
    .http2_settings = "1:65536;2:0;4:131072;5:16384",
    .http2_window_update = 12517377,
    .http2_pseudo_headers_order = "mpas",
    .http2_stream_exclusive = 0,
    .http2_stream_weight = 42,
    .cert_compression = "zlib,brotli,zstd",
    .ech = "true",
    .tls_session_ticket = true,
    .tls_extension_order = "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037",
    .tls_delegated_credentials = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1",
    .tls_record_size_limit = 4001,
    .tls_grease = false,
    .tls_signed_cert_timestamps = true,
    .tls_key_shares_limit = 3,
    .split_cookies = true,
  },
  {
    .target = "okhttp4_android",
    .alias = "okhttp4", /* not working */
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_sha1:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Sec-Fetch-Site: none",
      "Accept-Encoding: gzip, deflate, br",
      "Sec-Fetch-Mode: navigate",
      "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
      "Accept-Language: en-US,en;q=0.9",
      "Sec-Fetch-Dest: document"
    },
    .http2_settings = "2:0;4:4194304;3:100",
    .http2_window_update = 10485760,
    .http2_pseudo_headers_order = "mspa",
    .http2_stream_weight = 255,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari153",
    .alias = "safari15_3",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA256:"
      "TLS_RSA_WITH_AES_128_CBC_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA,",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_sha1:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .http_headers = {
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language: en-us",
      "Accept-Encoding: gzip, deflate, br"
    },
    .http2_settings = "4:4194304;3:100",
    .http2_window_update = 10485760,
    .http2_pseudo_headers_order = "mspa",
    .http2_stream_weight = 255,
    .http2_stream_exclusive = 0,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari155",
    .alias = "safari15_5",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_sha1:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language: en-GB,en-US;q=0.9,en;q=0.8",
      "Accept-Encoding: gzip, deflate, br"
    },
    .http2_settings = "4:4194304;3:100",
    .http2_window_update = 10485760,
    .http2_pseudo_headers_order = "mspa",
    .http2_stream_weight = 255,
    .http2_stream_exclusive = 0,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari170",
    .alias = "safari17_0",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_sha1:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Sec-Fetch-Site: none",
      "Accept-Encoding: gzip, deflate, br",
      "Sec-Fetch-Mode: navigate",
      "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
      "Accept-Language: en-US,en;q=0.9",
      "Sec-Fetch-Dest: document"
    },
    .http2_settings = "2:0;4:4194304;3:100",
    .http2_window_update = 10485760,
    .http2_pseudo_headers_order = "mspa",
    .http2_stream_weight = 255,
    .http2_stream_exclusive = 0,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari172_ios",
    .alias = "safari17_2_ios",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_sha1:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Sec-Fetch-Site: none",
      "Accept-Encoding: gzip, deflate, br",
      "Sec-Fetch-Mode: navigate",
      "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
      "Accept-Language: en-US,en;q=0.9",
      "Sec-Fetch-Dest: document"
    },
    .http2_settings = "2:0;4:2097152;3:100",
    .http2_window_update = 10485760,
    .http2_pseudo_headers_order = "mspa",
    .http2_stream_weight = 255,
    .http2_stream_exclusive = 0,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari180",
    .alias = "safari18_0",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "sec-fetch-dest: document",
      "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
      "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "sec-fetch-site: none",
      "sec-fetch-mode: navigate",
      "accept-language: en-US,en;q=0.9",
      "priority: u=0, i",
      "accept-encoding: gzip, deflate, br"
    },
    .http2_settings = "2:0;3:100;4:2097152;8:1;9:1",
    .http2_window_update = 10420225,
    .http2_pseudo_headers_order = "msap",
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 0,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari180_ios",
    .alias = "safari18_0_ios",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "sec-fetch-dest: document",
      "user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
      "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "sec-fetch-site: none",
      "sec-fetch-mode: navigate",
      "accept-language: en-US,en;q=0.9",
      "priority: u=0, i",
      "accept-encoding: gzip, deflate, br"
    },
    .http2_settings = "2:0;3:100;4:2097152;8:1;9:1",
    .http2_window_update = 10420225,
    .http2_pseudo_headers_order = "msap",
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 0,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari184",
    .alias = "safari18_4",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "sec-fetch-dest: document",
      "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
      "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "sec-fetch-site: none",
      "sec-fetch-mode: navigate",
      "accept-language: en-US,en;q=0.9",
      "priority: u=0, i",
      "accept-encoding: gzip, deflate, br"
    },
    .http2_settings = "2:0;3:100;4:2097152;9:1",
    .http2_window_update = 10420225,
    .http2_pseudo_headers_order = "msap",
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 0,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari184_ios",
    .alias = "safari18_4_ios",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_0 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .tls_session_ticket = false,
    .cert_compression = "zlib",
    .http_headers = {
      "sec-fetch-dest: document",
      "user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
      "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "sec-fetch-site: none",
      "sec-fetch-mode: navigate",
      "accept-language: en-US,en;q=0.9",
      "priority: u=0, i",
      "accept-encoding: gzip, deflate, br"
    },
    .http2_settings = "2:0;3:100;4:2097152;9:1",
    .http2_window_update = 10420225,
    .http2_pseudo_headers_order = "msap",
    .http2_stream_weight = 256,
    .http2_stream_exclusive = 0,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari260",
    .alias = "safari26_0",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519MLKEM768:X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .cert_compression = "zlib",
    .http_headers = {
      "sec-fetch-dest: document",
      "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
      "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "sec-fetch-site: none",
      "sec-fetch-mode: navigate",
      "accept-language: en-US,en;q=0.9",
      "priority: u=0, i",
      "accept-encoding: gzip, deflate, br, zstd"
    },
    .http2_settings = "2:0;3:100;4:2097152;9:1",
    .http2_window_update = 10420225,
    .http2_pseudo_headers_order = "msap",
    .http2_no_priority = true,
    .tls_session_ticket = true,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari2601",
    .alias = "safari26_0_1",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519MLKEM768:X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .cert_compression = "zlib",
    .http_headers = {
      "sec-fetch-dest: document",
      "user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15",
      "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "sec-fetch-site: none",
      "sec-fetch-mode: navigate",
      "accept-language: en-US,en;q=0.9",
      "priority: u=0, i",
      "accept-encoding: gzip, deflate, br"
    },
    .http2_settings = "2:0;3:100;4:2097152;9:1",
    .http2_window_update = 10420225,
    .http2_pseudo_headers_order = "msap",
    .http2_no_priority = true,
    .tls_session_ticket = false,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "safari260_ios",
    .alias = "safari26_0_ios",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:"
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    .curves = "X25519:P-256:P-384:P-521",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "rsa_pss_rsae_sha256:"
      "rsa_pkcs1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha384:"
      "rsa_pkcs1_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha512:"
      "rsa_pkcs1_sha1",
    .npn = false,
    .alpn = true,
    .alps = false,
    .cert_compression = "zlib",
    .http_headers = {
      "sec-fetch-dest: document",
      "user-agent: Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
      "accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "sec-fetch-site: none",
      "sec-fetch-mode: navigate",
      "accept-language: en-US,en;q=0.9",
      "priority: u=0, i",
      "accept-encoding: gzip, deflate, br, zstd"
    },
    .http2_settings = "2:0;3:100;4:2097152;9:1",
    .http2_window_update = 10420225,
    .http2_pseudo_headers_order = "msap",
    .http2_no_priority = true,
    .tls_session_ticket = true,
    .tls_extension_order = NULL,
    .tls_use_new_alps_codepoint = false,
    .tls_signed_cert_timestamps = true,
    .tls_grease = true,
    .split_cookies = true,
  },
  {
    .target = "tor145",  // tor 14.5, based on firefox 128
    .alias = "tor145",
    .httpversion = CURL_HTTP_VERSION_2_0,
    .ssl_version = CURL_SSLVERSION_TLSv1_2 | CURL_SSLVERSION_MAX_DEFAULT,
    .ciphers =
      "TLS_AES_128_GCM_SHA256:"
      "TLS_CHACHA20_POLY1305_SHA256:"
      "TLS_AES_256_GCM_SHA384:"
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:"
      "TLS_RSA_WITH_AES_128_GCM_SHA256:"
      "TLS_RSA_WITH_AES_256_GCM_SHA384:"
      "TLS_RSA_WITH_AES_128_CBC_SHA:"
      "TLS_RSA_WITH_AES_256_CBC_SHA",
    .http_headers = {
      "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
      "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language: en-US,en;q=0.5",
      "Accept-Encoding: gzip, deflate, br, zstd",
      "Sec-GPC: 1",
      "Upgrade-Insecure-Requests: 1",
      "Sec-Fetch-Dest: document",
      "Sec-Fetch-Mode: navigate",
      "Sec-Fetch-Site: none",
      "Sec-Fetch-User: ?1",
      "Priority: u=0, i",
      "Te: trailers"
    },
    .curves = "X25519:P-256:P-384:P-521:ffdhe2048:ffdhe3072",
    .sig_hash_algs =
      "ecdsa_secp256r1_sha256:"
      "ecdsa_secp384r1_sha384:"
      "ecdsa_secp521r1_sha512:"
      "rsa_pss_rsae_sha256:"
      "rsa_pss_rsae_sha384:"
      "rsa_pss_rsae_sha512:"
      "rsa_pkcs1_sha256:"
      "rsa_pkcs1_sha384:"
      "rsa_pkcs1_sha512:"
      "ecdsa_sha1:"
      "rsa_pkcs1_sha1",
    .alpn = true,
    .http2_settings = "1:65536;2:0;4:131072;5:16384",
    .http2_window_update = 12517377,
    .http2_pseudo_headers_order = "mpas",
    .http2_stream_exclusive = 0,
    .cert_compression = "zlib,brotli,zstd",
    .ech = "true",
    .tls_session_ticket = true,
    .tls_extension_order = "0-23-65281-10-11-16-5-34-51-43-13-28-65037",
    .tls_delegated_credentials = "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1",
    .tls_record_size_limit = 16385,
    .tls_grease = false,
    .tls_signed_cert_timestamps = true,
    .tls_key_shares_limit = 2,
    .split_cookies = true,
  }
};

const size_t num_impersonations = sizeof(impersonations) / sizeof(impersonations[0]);
