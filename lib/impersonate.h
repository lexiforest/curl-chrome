#ifndef HEADER_CURL_IMPERSONATE_H
#define HEADER_CURL_IMPERSONATE_H

#define IMPERSONATE_MAX_HEADERS 32

struct Curl_easy;
struct curl_slist;

/*
 * curl-impersonate: Options to be set for each supported target browser.
 */
struct impersonate_opts {
  const char *target;
  const char *alias;
  int httpversion;
  int ssl_version;
  const char *ciphers;
  /* Elliptic curves (TLS extension 10).
   * Passed to CURLOPT_SSL_EC_CURVES */
  const char *curves;
  const char *http3_curves;
  /* Signature hash algorithms (TLS extension 13).
   * Passed to CURLOPT_SSL_SIGNATURE_ALGORITHMS */
  const char *sig_hash_algs;
  /* Signature hash algorithms for HTTP/3 (QUIC TLS).
   * If set, used instead of sig_hash_algs for QUIC connections.
   * Chrome applies different verify prefs for TCP vs QUIC:
   * TCP strips SHA-1 (ssl_client_socket_impl.cc), QUIC uses BoringSSL
   * defaults which include rsa_pkcs1_sha1. */
  const char *http3_sig_hash_algs;
  /* Enable TLS NPN extension. */
  bool npn;
  /* Enable TLS ALPN extension. */
  bool alpn;
  /* Enable TLS ALPS extension. */
  bool alps;
  /* Enable TLS session ticket extension. */
  bool tls_session_ticket;
  bool ws_disable_session_ticket;
  /* TLS certificate compression algorithms.
   * (TLS extension 27) */
  const char *cert_compression;
  const char *ws_cert_compression;
  const char *http_headers[IMPERSONATE_MAX_HEADERS];
  const char *http3_headers[IMPERSONATE_MAX_HEADERS];
  const char *ws_headers[IMPERSONATE_MAX_HEADERS];
  const char *http2_pseudo_headers_order;
  const char *http2_settings;
  const char *http_header_order;
  const char *http3_http_header_order;
  const char *ws_http_header_order;
  int http2_window_update;
  const char *http2_streams;
  const char *http3_pseudo_headers_order;
  const char *http3_settings;
  const char *quic_transport_parameters;
  bool tls_permute_extensions;
  bool tls_use_new_alps_codepoint;
  bool tls_signed_cert_timestamps;
  const char *ech;
  const char *tls_extension_order;
  const char *http3_tls_extension_order;
  const char *tls_delegated_credentials;
  int tls_record_size_limit;
  int tls_key_shares_limit;  // for firefox key_shares extension
  bool tls_grease;
  int http2_stream_weight;
  int http2_stream_exclusive;
  bool http2_no_priority;  // disable http2 priority in header frame
  bool proxy_credential_no_reuse;  // do not reuse TLS sessions or connections from different proxy credentials
  bool split_cookies;  // split cookies into one Cookie header per pair
  const char *form_boundary;
  const struct curl_slist *dynamic_http_headers;
  const struct curl_slist *dynamic_http3_headers;
  const struct curl_slist *dynamic_ws_headers;

  /* Other TLS options will come here in the future once they are
   * configurable through curl_easy_setopt() */
};

struct custom_impersonation {
  struct impersonate_opts opts;
  struct curl_slist *owned_strings;
  struct curl_slist *http_headers;
  struct curl_slist *http3_headers;
  struct curl_slist *ws_headers;
};

/*
 * curl-impersonate: Global array of supported browsers and their
 * impersonation options.
 */
extern const struct impersonate_opts impersonations[];
extern const size_t num_impersonations;

CURLcode Curl_impersonate_load_custom(struct Curl_easy *data,
                                      const char *target,
                                      struct custom_impersonation *custom,
                                      bool *found);
void Curl_impersonate_free_custom(struct custom_impersonation *custom);
void Curl_impersonate_cleanup(void);

#endif /* HEADER_CURL_IMPERSONATE_H */
