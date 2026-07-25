/***************************************************************************
 *                                  _   _ ____  _
 *                             ___| | | |  _ \| |
 *                            / __| | | | |_) | |
 *                           | (__| |_| |  _ <| |___
 *                            \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * SPDX-License-Identifier: curl
 ***************************************************************************/
#include "curl_setup.h"

#include <curl/curl.h>
#include <cjson/cJSON.h>

#include "urldata.h"
#include "impersonate.h"
#include "sendf.h"
#include "slist.h"
#include "strcase.h"
#include "curl_printf.h"
#include "curlx/dynbuf.h"
#include "curlx/fopen.h"

#include "memdebug.h"

struct fingerprint_cache {
  bool loaded;
  bool missing;
  CURLcode result;
  char *path;
  cJSON *document;
};

static struct fingerprint_cache fp_cache;

static char *fingerprint_path(void)
{
  char *base = curl_getenv("IMPERSONATE_CONFIG_DIR");
  char *path;
  if(base) {
    path = curl_maprintf("%s%sfingerprints.json", base, DIR_CHAR);
    curlx_free(base);
    return path;
  }

#ifdef _WIN32
  base = curl_getenv("APPDATA");
  if(base) {
    path = curl_maprintf("%s%simpersonate%sfingerprints.json",
                         base, DIR_CHAR, DIR_CHAR);
    curlx_free(base);
    return path;
  }
  base = curl_getenv("USERPROFILE");
  if(base) {
    path = curl_maprintf("%s%sAppData%sRoaming%simpersonate%s"
                         "fingerprints.json", base, DIR_CHAR, DIR_CHAR,
                         DIR_CHAR, DIR_CHAR);
    curlx_free(base);
    return path;
  }
#else
  base = curl_getenv("XDG_CONFIG_HOME");
  if(base) {
    path = curl_maprintf("%s%simpersonate%sfingerprints.json",
                         base, DIR_CHAR, DIR_CHAR);
    curlx_free(base);
    return path;
  }
  base = curl_getenv("HOME");
  if(base) {
    path = curl_maprintf("%s%s.config%simpersonate%sfingerprints.json",
                         base, DIR_CHAR, DIR_CHAR, DIR_CHAR);
    curlx_free(base);
    return path;
  }
#endif
  return NULL;
}

static CURLcode cache_parse_document(const char *data, size_t length)
{
  cJSON *document;

  document = cJSON_ParseWithLengthOpts(data, length + 1, NULL, 1);
  if(!document || !cJSON_IsObject(document)) {
    cJSON_Delete(document);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }
  fp_cache.document = document;
  return CURLE_OK;
}

static CURLcode cache_load(void)
{
  struct dynbuf document;
  FILE *file;
  CURLcode result = CURLE_OK;
  unsigned char buffer[16384];
  size_t nread;

  if(fp_cache.loaded)
    return fp_cache.result;
  fp_cache.loaded = TRUE;
  fp_cache.path = fingerprint_path();
  if(!fp_cache.path) {
    fp_cache.missing = TRUE;
    return CURLE_OK;
  }
  file = curlx_fopen(fp_cache.path, FOPEN_READTEXT);
  if(!file) {
    if(errno == ENOENT) {
      fp_cache.missing = TRUE;
      return CURLE_OK;
    }
    fp_cache.result = CURLE_READ_ERROR;
    return fp_cache.result;
  }

  curlx_dyn_init(&document, CURL_MAX_INPUT_LENGTH);
  do {
    nread = fread(buffer, 1, sizeof(buffer), file);
    if(nread) {
      result = curlx_dyn_addn(&document, buffer, nread);
      if(result)
        break;
    }
  } while(nread == sizeof(buffer));
  if(!result && ferror(file))
    result = CURLE_READ_ERROR;
  curlx_fclose(file);
  if(result == CURLE_TOO_LARGE)
    result = CURLE_FILESIZE_EXCEEDED;
  if(!result) {
    const char *contents = curlx_dyn_ptr(&document);
    if(!contents)
      result = CURLE_BAD_FUNCTION_ARGUMENT;
    else
      result = cache_parse_document(contents, curlx_dyn_len(&document));
  }
  curlx_dyn_free(&document);
  fp_cache.result = result;
  return result;
}

static CURLcode custom_take_string(struct custom_impersonation *custom,
                                   char *value, const char **stored)
{
  struct curl_slist *list;
  if(!value)
    return CURLE_OUT_OF_MEMORY;
  list = Curl_slist_append_nodup(custom->owned_strings, value);
  if(!list) {
    curlx_free(value);
    return CURLE_OUT_OF_MEMORY;
  }
  custom->owned_strings = list;
  *stored = value;
  return CURLE_OK;
}

static CURLcode custom_store_string(struct custom_impersonation *custom,
                                    const char *value, bool empty_is_null,
                                    const char **stored)
{
  char *copy;

  if(empty_is_null && !value[0]) {
    *stored = NULL;
    return CURLE_OK;
  }
  copy = curlx_strdup(value);
  return custom_take_string(custom, copy, stored);
}

static CURLcode append_normalized_group(struct dynbuf *out,
                                        const char *group)
{
  if(!strcmp(group, "X25519Kyber768"))
    group = "X25519Kyber768Draft00";
  return curlx_dyn_add(out, group);
}

static CURLcode value_string_array(const cJSON *value,
                                   struct custom_impersonation *custom,
                                   char separator, bool normalize_groups,
                                   bool empty_is_null,
                                   const char **stored)
{
  struct dynbuf joined;
  const cJSON *item;
  CURLcode result = CURLE_OK;
  bool first = TRUE;

  if(!cJSON_IsArray(value))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  curlx_dyn_init(&joined, CURL_MAX_INPUT_LENGTH);
  cJSON_ArrayForEach(item, value) {
    if(!cJSON_IsString(item)) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      goto out;
    }
    if(!first) {
      result = curlx_dyn_addn(&joined, &separator, 1);
      if(result)
        goto out;
    }
    if(normalize_groups)
      result = append_normalized_group(&joined, item->valuestring);
    else
      result = curlx_dyn_add(&joined, item->valuestring);
    if(result)
      goto out;
    first = FALSE;
  }
  if(first && empty_is_null)
    *stored = NULL;
  else {
    char *joined_value = first ? curlx_strdup("") :
      curlx_dyn_take(&joined, NULL);
    result = custom_take_string(custom, joined_value, stored);
  }
out:
  curlx_dyn_free(&joined);
  return result;
}

static CURLcode value_headers(const cJSON *value,
                              struct curl_slist **headers,
                              bool skip_empty_host)
{
  const cJSON *item;

  if(!cJSON_IsObject(value))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  cJSON_ArrayForEach(item, value) {
    char *line;
    struct curl_slist *list;

    if(!item->string || !item->string[0] || !cJSON_IsString(item))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(skip_empty_host && !item->valuestring[0] &&
       curl_strequal(item->string, "Host"))
      continue;
    line = curl_maprintf("%s: %s", item->string, item->valuestring);
    if(!line)
      return CURLE_OUT_OF_MEMORY;
    list = Curl_slist_append_nodup(*headers, line);
    if(!list) {
      curlx_free(line);
      return CURLE_OUT_OF_MEMORY;
    }
    *headers = list;
  }
  return CURLE_OK;
}

static CURLcode value_plain_string(const cJSON *value,
                                   struct custom_impersonation *custom,
                                   bool empty_is_null,
                                   const char **stored)
{
  if(!cJSON_IsString(value))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  return custom_store_string(custom, value->valuestring, empty_is_null,
                             stored);
}

static CURLcode value_nullable_string(const cJSON *value,
                                      struct custom_impersonation *custom,
                                      const char **stored)
{
  if(cJSON_IsNull(value)) {
    *stored = NULL;
    return CURLE_OK;
  }
  return value_plain_string(value, custom, FALSE, stored);
}

static CURLcode value_bool(const cJSON *value, bool *stored)
{
  if(!cJSON_IsBool(value))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  *stored = cJSON_IsTrue(value) ? TRUE : FALSE;
  return CURLE_OK;
}

static CURLcode value_integer(const cJSON *value, int *stored,
                              bool nullable)
{
  if(nullable && cJSON_IsNull(value))
    return CURLE_OK;
  if(!cJSON_IsNumber(value))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  *stored = value->valueint;
  return CURLE_OK;
}

static CURLcode value_extension_order(const cJSON *value,
                                      struct custom_impersonation *custom,
                                      const char **stored)
{
  char *copy;
  struct dynbuf filtered;
  CURLcode result = CURLE_OK;
  const char *p;
  bool first = TRUE;

  if(!cJSON_IsString(value))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  copy = curlx_strdup(value->valuestring);
  if(!copy)
    return CURLE_OUT_OF_MEMORY;
  curlx_dyn_init(&filtered, CURL_MAX_INPUT_LENGTH);
  p = copy;
  while(*p) {
    const char *dash = strchr(p, '-');
    size_t length = dash ? (size_t)(dash - p) : strlen(p);
    if(!((length == 2) && !memcmp(p, "21", 2))) {
      if(!first) {
        result = curlx_dyn_addn(&filtered, "-", 1);
        if(result)
          goto out;
      }
      result = curlx_dyn_addn(&filtered, p, length);
      if(result)
        goto out;
      first = FALSE;
    }
    if(!dash)
      break;
    p = dash + 1;
  }
  curlx_free(copy);
  copy = first ? curlx_strdup("") : curlx_dyn_take(&filtered, NULL);
  if(!copy) {
    result = CURLE_OUT_OF_MEMORY;
    goto out_no_copy;
  }
  if(!copy[0]) {
    curlx_free(copy);
    *stored = NULL;
    goto out_no_copy;
  }
  result = custom_take_string(custom, copy, stored);
out_no_copy:
  curlx_dyn_free(&filtered);
  return result;
out:
  curlx_free(copy);
  goto out_no_copy;
}

static CURLcode value_pseudo_order(const cJSON *value,
                                   struct custom_impersonation *custom,
                                   const char **stored)
{
  char *copy;
  char *src;
  char *dst;

  if(!cJSON_IsString(value))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  copy = curlx_strdup(value->valuestring);
  if(!copy)
    return CURLE_OUT_OF_MEMORY;
  src = dst = copy;
  while(*src) {
    if(*src != ',')
      *dst++ = *src;
    src++;
  }
  *dst = '\0';
  if(!copy[0]) {
    curlx_free(copy);
    *stored = NULL;
    return CURLE_OK;
  }
  return custom_take_string(custom, copy, stored);
}

static void normalize_tls_version(char *version)
{
  char *start = version;
  char *end;
  while(*start && strchr(" \t\r\n", *start))
    start++;
  end = start + strlen(start);
  while((end > start) && strchr(" \t\r\n", end[-1]))
    end--;
  *end = '\0';
  if(start != version)
    memmove(version, start, (size_t)(end - start) + 1);
}

static CURLcode parse_field(const cJSON *value, const char *name,
                            struct custom_impersonation *custom)
{
  struct impersonate_opts *opts = &custom->opts;

  if(!strcmp(name, "tls_version")) {
    char *version;
    CURLcode result = CURLE_OK;
    if(!cJSON_IsString(value))
      return CURLE_BAD_FUNCTION_ARGUMENT;
    version = curlx_strdup(value->valuestring);
    if(!version)
      return CURLE_OUT_OF_MEMORY;
    normalize_tls_version(version);
    if(!strcmp(version, "1") || curl_strequal(version, "tlsv1"))
      opts->ssl_version = CURL_SSLVERSION_TLSv1 |
        CURL_SSLVERSION_MAX_DEFAULT;
    else if(!strcmp(version, "1.0") ||
            curl_strequal(version, "tlsv1_0"))
      opts->ssl_version = CURL_SSLVERSION_TLSv1_0 |
        CURL_SSLVERSION_MAX_DEFAULT;
    else if(!strcmp(version, "1.1") ||
            curl_strequal(version, "tlsv1_1"))
      opts->ssl_version = CURL_SSLVERSION_TLSv1_1 |
        CURL_SSLVERSION_MAX_DEFAULT;
    else if(!strcmp(version, "1.2") ||
            curl_strequal(version, "tlsv1_2"))
      opts->ssl_version = CURL_SSLVERSION_TLSv1_2 |
        CURL_SSLVERSION_MAX_DEFAULT;
    else if(!strcmp(version, "1.3") ||
            curl_strequal(version, "tlsv1_3"))
      opts->ssl_version = CURL_SSLVERSION_TLSv1_3 |
        CURL_SSLVERSION_MAX_DEFAULT;
    else
      result = CURLE_BAD_FUNCTION_ARGUMENT;
    curlx_free(version);
    return result;
  }
  if(!strcmp(name, "tls_ciphers"))
    return value_string_array(value, custom, ':', FALSE, TRUE,
                              &opts->ciphers);
  if(!strcmp(name, "tls_alpn"))
    return value_bool(value, &opts->alpn);
  if(!strcmp(name, "tls_alps"))
    return value_bool(value, &opts->alps);
  if(!strcmp(name, "tls_session_ticket"))
    return value_bool(value, &opts->tls_session_ticket);
  if(!strcmp(name, "tls_grease"))
    return value_bool(value, &opts->tls_grease);
  if(!strcmp(name, "tls_use_new_alps_codepoint"))
    return value_bool(value, &opts->tls_use_new_alps_codepoint);
  if(!strcmp(name, "tls_permute_extensions"))
    return value_bool(value, &opts->tls_permute_extensions);
  if(!strcmp(name, "tls_signed_cert_timestamps"))
    return value_bool(value, &opts->tls_signed_cert_timestamps);
  if(!strcmp(name, "tls_cert_compression"))
    return value_string_array(value, custom, ',', FALSE, FALSE,
                              &opts->cert_compression);
  if(!strcmp(name, "tls_signature_hashes"))
    return value_string_array(value, custom, ',', FALSE, TRUE,
                              &opts->sig_hash_algs);
  if(!strcmp(name, "tls_supported_groups"))
    return value_string_array(value, custom, ':', TRUE, TRUE,
                              &opts->curves);
  if(!strcmp(name, "tls_delegated_credentials"))
    return value_string_array(value, custom, ':', FALSE, TRUE,
                              &opts->tls_delegated_credentials);
  if(!strcmp(name, "tls_extension_order"))
    return value_extension_order(value, custom, &opts->tls_extension_order);
  if(!strcmp(name, "tls_ech"))
    return value_nullable_string(value, custom, &opts->ech);
  if(!strcmp(name, "tls_key_shares_limit"))
    return value_integer(value, &opts->tls_key_shares_limit, FALSE);
  if(!strcmp(name, "tls_record_size_limit"))
    return value_integer(value, &opts->tls_record_size_limit, TRUE);
  if(!strcmp(name, "headers"))
    return value_headers(value, &custom->http_headers, TRUE);
  if(!strcmp(name, "header_order"))
    return value_plain_string(value, custom, TRUE,
                              &opts->http_header_order);
  if(!strcmp(name, "split_cookies"))
    return value_bool(value, &opts->split_cookies);
  if(!strcmp(name, "form_boundary"))
    return value_plain_string(value, custom, TRUE, &opts->form_boundary);
  if(!strcmp(name, "http2_settings"))
    return value_plain_string(value, custom, TRUE, &opts->http2_settings);
  if(!strcmp(name, "http2_pseudo_headers_order"))
    return value_pseudo_order(value, custom,
                              &opts->http2_pseudo_headers_order);
  if(!strcmp(name, "http2_window_update"))
    return value_integer(value, &opts->http2_window_update, FALSE);
  if(!strcmp(name, "http2_stream_weight"))
    return value_integer(value, &opts->http2_stream_weight, TRUE);
  if(!strcmp(name, "http2_stream_exclusive"))
    return value_integer(value, &opts->http2_stream_exclusive, TRUE);
  if(!strcmp(name, "http2_no_priority"))
    return value_bool(value, &opts->http2_no_priority);
  if(!strcmp(name, "http3_settings"))
    return value_plain_string(value, custom, TRUE, &opts->http3_settings);
  if(!strcmp(name, "http3_pseudo_headers_order"))
    return value_pseudo_order(value, custom,
                              &opts->http3_pseudo_headers_order);
  if(!strcmp(name, "http3_tls_extension_order"))
    return value_plain_string(value, custom, TRUE,
                              &opts->http3_tls_extension_order);
  if(!strcmp(name, "http3_headers"))
    return value_headers(value, &custom->http3_headers, FALSE);
  if(!strcmp(name, "http3_header_order"))
    return value_plain_string(value, custom, TRUE,
                              &opts->http3_http_header_order);
  if(!strcmp(name, "http3_tls_supported_groups"))
    return value_string_array(value, custom, ':', TRUE, TRUE,
                              &opts->http3_curves);
  if(!strcmp(name, "quic_transport_parameters"))
    return value_plain_string(value, custom, TRUE,
                              &opts->quic_transport_parameters);
  if(!strcmp(name, "ws_headers"))
    return value_headers(value, &custom->ws_headers, FALSE);
  if(!strcmp(name, "ws_header_order"))
    return value_plain_string(value, custom, TRUE,
                              &opts->ws_http_header_order);
  if(!strcmp(name, "ws_disable_session_ticket"))
    return value_bool(value, &opts->ws_disable_session_ticket);
  if(!strcmp(name, "ws_tls_cert_compression")) {
    if(cJSON_IsNull(value))
      return CURLE_OK;
    return value_string_array(value, custom, ',', FALSE, FALSE,
                              &opts->ws_cert_compression);
  }
  if(!strcmp(name, "client") || !strcmp(name, "client_version") ||
     !strcmp(name, "os") || !strcmp(name, "os_version") ||
     !strcmp(name, "http_version") || !strcmp(name, "header_lang"))
    return CURLE_OK;

  return CURLE_OK;
}

static CURLcode parse_target(struct Curl_easy *data, const char *target,
                             const cJSON *target_value,
                             struct custom_impersonation *custom)
{
  const cJSON *field;
  CURLcode result;

  memset(custom, 0, sizeof(*custom));
  custom->opts.target = target;
  custom->opts.alias = target;
  custom->opts.httpversion = CURL_HTTP_VERSION_NONE;
  custom->opts.ssl_version = CURL_SSLVERSION_TLSv1_2 |
    CURL_SSLVERSION_MAX_DEFAULT;
  custom->opts.tls_key_shares_limit = 2;
  result = custom_take_string(custom, curlx_strdup(""),
                              &custom->opts.cert_compression);
  if(result) {
    Curl_impersonate_free_custom(custom);
    return result;
  }
  if(!cJSON_IsObject(target_value)) {
    failf(data, "Fingerprint target '%s' must be a JSON object", target);
    Curl_impersonate_free_custom(custom);
    return CURLE_BAD_FUNCTION_ARGUMENT;
  }

  cJSON_ArrayForEach(field, target_value) {
    result = parse_field(field, field->string, custom);
    if(result) {
      failf(data, "Invalid fingerprint target '%s' field '%s'",
            target, field->string);
      Curl_impersonate_free_custom(custom);
      return result;
    }
  }
  if(custom->opts.tls_permute_extensions)
    custom->opts.tls_extension_order = NULL;
  custom->opts.dynamic_http_headers = custom->http_headers;
  custom->opts.dynamic_http3_headers = custom->http3_headers;
  custom->opts.dynamic_ws_headers = custom->ws_headers;
  return CURLE_OK;
}

CURLcode Curl_impersonate_load_custom(struct Curl_easy *data,
                                      const char *target,
                                      struct custom_impersonation *custom,
                                      bool *found)
{
  CURLcode result = cache_load();
  const cJSON *match;

  *found = FALSE;
  memset(custom, 0, sizeof(*custom));
  if(result) {
    failf(data, "Failed loading fingerprints from '%s'",
          fp_cache.path ? fp_cache.path : "(unknown)");
    return result;
  }
  if(fp_cache.missing)
    return CURLE_OK;
  match = cJSON_GetObjectItemCaseSensitive(fp_cache.document, target);
  if(!match)
    return CURLE_OK;
  *found = TRUE;
  return parse_target(data, target, match, custom);
}

void Curl_impersonate_free_custom(struct custom_impersonation *custom)
{
  if(!custom)
    return;
  curl_slist_free_all(custom->owned_strings);
  curl_slist_free_all(custom->http_headers);
  curl_slist_free_all(custom->http3_headers);
  curl_slist_free_all(custom->ws_headers);
  memset(custom, 0, sizeof(*custom));
}

void Curl_impersonate_cleanup(void)
{
  cJSON_Delete(fp_cache.document);
  curlx_free(fp_cache.path);
  memset(&fp_cache, 0, sizeof(fp_cache));
}
