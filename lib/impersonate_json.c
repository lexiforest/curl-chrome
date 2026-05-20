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
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

#include "impersonate.h"
#include "strdup.h"
#include "curlx/dynbuf.h"
#include "curlx/strparse.h"

/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"

#define IMPERSONATE_CONFIG_MAX (4 * 1024 * 1024)
#define IMPERSONATE_PATH "/.config/impersonate/fingerprints.json"

static struct impersonate_opts *loaded_config_targets;
static size_t num_loaded_config_targets;
static struct impersonate_opts *merged_targets;

/* Move past insignificant JSON whitespace. */
static const char *json_ws(const char *p, const char *end)
{
  while(p < end && ISSPACE(*p))
    p++;
  return p;
}

/* Advance over a JSON string without allocating its contents. */
static CURLcode json_skip_string(const char **pp, const char *end)
{
  const char *p = *pp;

  if(p >= end || *p != '"')
    return CURLE_BAD_FUNCTION_ARGUMENT;
  p++;
  while(p < end) {
    if(*p == '\\') {
      p++;
      if(p >= end)
        return CURLE_BAD_FUNCTION_ARGUMENT;
      p++;
    }
    else if(*p == '"') {
      *pp = p + 1;
      return CURLE_OK;
    }
    else
      p++;
  }
  return CURLE_BAD_FUNCTION_ARGUMENT;
}

static CURLcode json_skip_value(const char **pp, const char *end);

/* Advance over a JSON object or array, including nested values. */
static CURLcode json_skip_compound(const char **pp, const char *end,
                                   char open, char close)
{
  CURLcode result;
  const char *p = *pp;
  bool first = TRUE;

  if(p >= end || *p != open)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  p++;
  while(1) {
    p = json_ws(p, end);
    if(p >= end)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(*p == close) {
      *pp = p + 1;
      return CURLE_OK;
    }
    if(!first) {
      if(*p != ',')
        return CURLE_BAD_FUNCTION_ARGUMENT;
      p++;
      p = json_ws(p, end);
    }
    first = FALSE;
    if(open == '{') {
      result = json_skip_string(&p, end);
      if(result)
        return result;
      p = json_ws(p, end);
      if(p >= end || *p != ':')
        return CURLE_BAD_FUNCTION_ARGUMENT;
      p++;
      p = json_ws(p, end);
    }
    result = json_skip_value(&p, end);
    if(result)
      return result;
  }
}

/* Advance over any JSON value supported by the fingerprint schema. */
static CURLcode json_skip_value(const char **pp, const char *end)
{
  const char *p = json_ws(*pp, end);
  CURLcode result;

  if(p >= end)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  if(*p == '"') {
    result = json_skip_string(&p, end);
    *pp = p;
    return result;
  }
  if(*p == '{') {
    result = json_skip_compound(&p, end, '{', '}');
    *pp = p;
    return result;
  }
  if(*p == '[') {
    result = json_skip_compound(&p, end, '[', ']');
    *pp = p;
    return result;
  }
  if(!strncmp(p, "true", 4)) {
    *pp = p + 4;
    return CURLE_OK;
  }
  if(!strncmp(p, "false", 5)) {
    *pp = p + 5;
    return CURLE_OK;
  }
  if(!strncmp(p, "null", 4)) {
    *pp = p + 4;
    return CURLE_OK;
  }
  while(p < end && !ISSPACE(*p) && *p != ',' && *p != '}' && *p != ']')
    p++;
  *pp = p;
  return CURLE_OK;
}

/* Decode a JSON string into a newly allocated C string. */
static CURLcode json_string(const char **pp, const char *end, char **out)
{
  struct dynbuf buf;
  CURLcode result = CURLE_OK;
  const char *p = *pp;
  char c;
  size_t len;

  *out = NULL;
  if(p >= end || *p != '"')
    return CURLE_BAD_FUNCTION_ARGUMENT;
  p++;
  curlx_dyn_init(&buf, DYN_HTTP_REQUEST);
  while(p < end) {
    c = *p++;
    if(c == '"') {
      *out = curlx_dyn_take(&buf, &len);
      if(!*out)
        *out = strdup("");
      curlx_dyn_free(&buf);
      if(!*out)
        return CURLE_OUT_OF_MEMORY;
      *pp = p;
      return CURLE_OK;
    }
    if(c == '\\') {
      if(p >= end) {
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        break;
      }
      c = *p++;
      switch(c) {
      case '"':
      case '\\':
      case '/':
        break;
      case 'b':
        c = '\b';
        break;
      case 'f':
        c = '\f';
        break;
      case 'n':
        c = '\n';
        break;
      case 'r':
        c = '\r';
        break;
      case 't':
        c = '\t';
        break;
      case 'u':
        if(end - p < 4) {
          result = CURLE_BAD_FUNCTION_ARGUMENT;
          break;
        }
        p += 4;
        c = '?';
        break;
      default:
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        break;
      }
      if(result)
        break;
    }
    result = curlx_dyn_addn(&buf, &c, 1);
    if(result)
      break;
  }
  curlx_dyn_free(&buf);
  return result ? result : CURLE_BAD_FUNCTION_ARGUMENT;
}

/* Check whether a JSON value span starts with null. */
static bool json_is_null(const char *p, const char *end)
{
  p = json_ws(p, end);
  return (end - p >= 4) && !strncmp(p, "null", 4);
}

/* Decode a JSON string value, treating null and empty strings as unset. */
static CURLcode json_strdup_if_string(const char *start, const char *end,
                                      char **out)
{
  CURLcode result;
  const char *p = json_ws(start, end);

  *out = NULL;
  if(json_is_null(p, end))
    return CURLE_OK;
  result = json_string(&p, end, out);
  if(result)
    return result;
  if(!**out) {
    free(*out);
    *out = NULL;
  }
  return CURLE_OK;
}

/* Decode a JSON boolean value into a bool. */
static CURLcode json_bool(const char *start, const char *end, bool *out)
{
  const char *p = json_ws(start, end);

  (void)end;
  if(!strncmp(p, "true", 4)) {
    *out = TRUE;
    return CURLE_OK;
  }
  if(!strncmp(p, "false", 5)) {
    *out = FALSE;
    return CURLE_OK;
  }
  return CURLE_BAD_FUNCTION_ARGUMENT;
}

/* Decode a non-negative JSON integer, allowing null as not present. */
static CURLcode json_int(const char *start, const char *end, int *out,
                         bool *present)
{
  const char *p;
  curl_off_t val;

  *present = FALSE;
  p = json_ws(start, end);
  if(json_is_null(p, end))
    return CURLE_OK;
  if(curlx_str_number(&p, &val, INT_MAX))
    return CURLE_BAD_FUNCTION_ARGUMENT;
  p = json_ws(p, end);
  if(p != end)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  *out = (int)val;
  *present = TRUE;
  return CURLE_OK;
}

/* Join a JSON string array into one option string with the given separator. */
static CURLcode json_join_string_array(const char *start, const char *end,
                                       const char *sep, char **out)
{
  struct dynbuf buf;
  CURLcode result = CURLE_OK;
  const char *p = json_ws(start, end);
  bool first = TRUE;
  char *item = NULL;
  size_t len;

  *out = NULL;
  if(p >= end || *p != '[')
    return CURLE_BAD_FUNCTION_ARGUMENT;
  p++;
  curlx_dyn_init(&buf, DYN_HTTP_REQUEST);
  while(1) {
    item = NULL;
    p = json_ws(p, end);
    if(p >= end) {
      result = CURLE_BAD_FUNCTION_ARGUMENT;
      break;
    }
    if(*p == ']') {
      p++;
      break;
    }
    if(!first) {
      if(*p != ',') {
        result = CURLE_BAD_FUNCTION_ARGUMENT;
        break;
      }
      p++;
      p = json_ws(p, end);
    }
    first = FALSE;
    result = json_string(&p, end, &item);
    if(result)
      break;
    if(*item) {
      if(curlx_dyn_len(&buf)) {
        result = curlx_dyn_add(&buf, sep);
        if(result) {
          free(item);
          break;
        }
      }
      result = curlx_dyn_add(&buf, item);
    }
    free(item);
    if(result)
      break;
  }
  if(!result && curlx_dyn_len(&buf)) {
    *out = curlx_dyn_take(&buf, &len);
    if(!*out)
      result = CURLE_OUT_OF_MEMORY;
  }
  curlx_dyn_free(&buf);
  return result;
}

/* Append one HTTP header line to the temporary impersonation options. */
static CURLcode json_add_header(struct impersonate_opts *opts,
                                const char *name, const char *value)
{
  struct dynbuf buf;
  CURLcode result;
  size_t i;
  size_t len;

  if(!value || !*value)
    return CURLE_OK;
  for(i = 0; i < IMPERSONATE_MAX_HEADERS; i++) {
    if(!opts->http_headers[i])
      break;
  }
  if(i == IMPERSONATE_MAX_HEADERS)
    return CURLE_BAD_FUNCTION_ARGUMENT;
  curlx_dyn_init(&buf, DYN_HTTP_REQUEST);
  result = curlx_dyn_add(&buf, name);
  if(!result)
    result = curlx_dyn_add(&buf, ": ");
  if(!result)
    result = curlx_dyn_add(&buf, value);
  if(!result) {
    opts->http_headers[i] = curlx_dyn_take(&buf, &len);
    if(!opts->http_headers[i])
      result = CURLE_OUT_OF_MEMORY;
  }
  curlx_dyn_free(&buf);
  return result;
}

/* Decode the headers object into ordered "name: value" header strings. */
static CURLcode json_headers_object(const char *start, const char *end,
                                    struct impersonate_opts *opts)
{
  CURLcode result;
  const char *p = json_ws(start, end);
  bool first = TRUE;
  char *name = NULL;
  char *value = NULL;

  if(p >= end || *p != '{')
    return CURLE_BAD_FUNCTION_ARGUMENT;
  p++;
  while(1) {
    name = NULL;
    value = NULL;
    p = json_ws(p, end);
    if(p >= end)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(*p == '}')
      return CURLE_OK;
    if(!first) {
      if(*p != ',')
        return CURLE_BAD_FUNCTION_ARGUMENT;
      p++;
      p = json_ws(p, end);
    }
    first = FALSE;
    result = json_string(&p, end, &name);
    if(result)
      return result;
    p = json_ws(p, end);
    if(p >= end || *p != ':') {
      free(name);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    p++;
    result = json_string(&p, end, &value);
    if(!result)
      result = json_add_header(opts, name, value);
    free(name);
    free(value);
    if(result)
      return result;
  }
}

/* Replace an owned string field in the temporary options. */
static CURLcode opts_set_string(char **field, char *value)
{
  free(*field);
  *field = value;
  return CURLE_OK;
}

/* Translate the JSON HTTP version token into a libcurl HTTP version. */
static CURLcode parse_http_version(const char *start, const char *end,
                                   struct impersonate_opts *opts)
{
  CURLcode result;
  char *value = NULL;

  result = json_strdup_if_string(start, end, &value);
  if(result || !value)
    return result;
  if(!strcmp(value, "v1") || !strcmp(value, "1.1"))
    opts->httpversion = CURL_HTTP_VERSION_1_1;
  else if(!strcmp(value, "v2") || !strcmp(value, "2"))
    opts->httpversion = CURL_HTTP_VERSION_2_0;
  else if(!strcmp(value, "v3") || !strcmp(value, "3"))
    opts->httpversion = CURL_HTTP_VERSION_3;
  else
    result = CURLE_BAD_FUNCTION_ARGUMENT;
  free(value);
  return result;
}

/* Translate the JSON TLS version token into a libcurl SSL version. */
static CURLcode parse_tls_version(const char *start, const char *end,
                                  struct impersonate_opts *opts)
{
  CURLcode result;
  char *value = NULL;

  result = json_strdup_if_string(start, end, &value);
  if(result || !value)
    return result;
  if(!strcmp(value, "1.0"))
    opts->ssl_version = CURL_SSLVERSION_TLSv1_0 |
      CURL_SSLVERSION_MAX_DEFAULT;
  else if(!strcmp(value, "1.1"))
    opts->ssl_version = CURL_SSLVERSION_TLSv1_1 |
      CURL_SSLVERSION_MAX_DEFAULT;
  else if(!strcmp(value, "1.2"))
    opts->ssl_version = CURL_SSLVERSION_TLSv1_2 |
      CURL_SSLVERSION_MAX_DEFAULT;
  else if(!strcmp(value, "1.3"))
    opts->ssl_version = CURL_SSLVERSION_TLSv1_3 |
      CURL_SSLVERSION_MAX_DEFAULT;
  else
    result = CURLE_BAD_FUNCTION_ARGUMENT;
  free(value);
  return result;
}

/* Decode and store a JSON string array option field. */
static CURLcode parse_string_array_field(char **field,
                                         const char *start,
                                         const char *end,
                                         const char *sep)
{
  CURLcode result;
  char *value = NULL;

  result = json_join_string_array(start, end, sep, &value);
  if(result)
    return result;
  return opts_set_string(field, value);
}

/* Decode and store a JSON string option field. */
static CURLcode parse_string_field(char **field,
                                   const char *start,
                                   const char *end)
{
  CURLcode result;
  char *value = NULL;

  result = json_strdup_if_string(start, end, &value);
  if(result)
    return result;
  return opts_set_string(field, value);
}

/* Map one fingerprint JSON key/value pair onto struct impersonate_opts. */
static CURLcode parse_impersonate_field(const char *key,
                                        const char *start,
                                        const char *end,
                                        struct impersonate_opts *opts)
{
  CURLcode result = CURLE_OK;
  bool present;
  int value;

  if(!strcmp(key, "http_version"))
    result = parse_http_version(start, end, opts);
  else if(!strcmp(key, "tls_version"))
    result = parse_tls_version(start, end, opts);
  else if(!strcmp(key, "tls_ciphers"))
    result = parse_string_array_field((char **)&opts->ciphers,
                                      start, end, ":");
  else if(!strcmp(key, "tls_supported_groups"))
    result = parse_string_array_field((char **)&opts->curves,
                                      start, end, ":");
  else if(!strcmp(key, "tls_signature_hashes"))
    result = parse_string_array_field((char **)&opts->sig_hash_algs,
                                      start, end, ":");
  else if(!strcmp(key, "tls_cert_compression"))
    result = parse_string_array_field((char **)&opts->cert_compression,
                                      start, end, ",");
  else if(!strcmp(key, "tls_delegated_credentials"))
    result = parse_string_array_field(
      (char **)&opts->tls_delegated_credentials, start, end, ":");
  else if(!strcmp(key, "tls_ech"))
    result = parse_string_field((char **)&opts->ech, start, end);
  else if(!strcmp(key, "tls_extension_order"))
    result = parse_string_field((char **)&opts->tls_extension_order,
                                start, end);
  else if(!strcmp(key, "http3_tls_extension_order"))
    result = parse_string_field((char **)&opts->http3_tls_extension_order,
                                start, end);
  else if(!strcmp(key, "http2_pseudo_headers_order"))
    result = parse_string_field((char **)&opts->http2_pseudo_headers_order,
                                start, end);
  else if(!strcmp(key, "http2_settings"))
    result = parse_string_field((char **)&opts->http2_settings, start, end);
  else if(!strcmp(key, "header_order"))
    result = parse_string_field((char **)&opts->http_header_order,
                                start, end);
  else if(!strcmp(key, "http2_streams"))
    result = parse_string_field((char **)&opts->http2_streams, start, end);
  else if(!strcmp(key, "http3_pseudo_headers_order"))
    result = parse_string_field((char **)&opts->http3_pseudo_headers_order,
                                start, end);
  else if(!strcmp(key, "http3_settings"))
    result = parse_string_field((char **)&opts->http3_settings, start, end);
  else if(!strcmp(key, "quic_transport_parameters"))
    result = parse_string_field((char **)&opts->quic_transport_parameters,
                                start, end);
  else if(!strcmp(key, "form_boundary"))
    result = parse_string_field((char **)&opts->form_boundary, start, end);
  else if(!strcmp(key, "headers"))
    result = json_headers_object(start, end, opts);
  else if(!strcmp(key, "tls_alpn"))
    result = json_bool(start, end, &opts->alpn);
  else if(!strcmp(key, "tls_alps"))
    result = json_bool(start, end, &opts->alps);
  else if(!strcmp(key, "tls_session_ticket"))
    result = json_bool(start, end, &opts->tls_session_ticket);
  else if(!strcmp(key, "tls_grease"))
    result = json_bool(start, end, &opts->tls_grease);
  else if(!strcmp(key, "tls_use_new_alps_codepoint"))
    result = json_bool(start, end, &opts->tls_use_new_alps_codepoint);
  else if(!strcmp(key, "tls_signed_cert_timestamps"))
    result = json_bool(start, end, &opts->tls_signed_cert_timestamps);
  else if(!strcmp(key, "tls_permute_extensions"))
    result = json_bool(start, end, &opts->tls_permute_extensions);
  else if(!strcmp(key, "http2_no_priority"))
    result = json_bool(start, end, &opts->http2_no_priority);
  else if(!strcmp(key, "split_cookies"))
    result = json_bool(start, end, &opts->split_cookies);
  else if(!strcmp(key, "http2_window_update")) {
    result = json_int(start, end, &value, &present);
    if(!result && present)
      opts->http2_window_update = value;
  }
  else if(!strcmp(key, "http2_stream_weight") ||
          !strcmp(key, "http2_priority_weight")) {
    result = json_int(start, end, &value, &present);
    if(!result && present)
      opts->http2_stream_weight = value;
  }
  else if(!strcmp(key, "http2_stream_exclusive") ||
          !strcmp(key, "http2_priority_exclusive")) {
    result = json_int(start, end, &value, &present);
    if(!result && present)
      opts->http2_stream_exclusive = value;
  }
  else if(!strcmp(key, "tls_record_size_limit")) {
    result = json_int(start, end, &value, &present);
    if(!result && present)
      opts->tls_record_size_limit = value;
  }
  else if(!strcmp(key, "tls_key_shares_limit")) {
    result = json_int(start, end, &value, &present);
    if(!result && present)
      opts->tls_key_shares_limit = value;
  }
  return result;
}

/* Decode a target JSON object into temporary impersonation options. */
static CURLcode json_parse_opts(const char *obj, const char *obj_end,
                                const char *target,
                                struct impersonate_opts *opts)
{
  CURLcode result;
  const char *p = obj;
  bool first = TRUE;
  char *key = NULL;
  const char *value_start;
  const char *value_end;

  memset(opts, 0, sizeof(*opts));
  opts->target = strdup(target);
  opts->alias = opts->target;
  opts->ssl_version = CURL_SSLVERSION_DEFAULT;
  if(!opts->target)
    return CURLE_OUT_OF_MEMORY;

  while(1) {
    key = NULL;
    p = json_ws(p, obj_end);
    if(p >= obj_end)
      return CURLE_OK;
    if(!first) {
      if(*p != ',')
        return CURLE_BAD_FUNCTION_ARGUMENT;
      p++;
      p = json_ws(p, obj_end);
    }
    first = FALSE;
    result = json_string(&p, obj_end, &key);
    if(result)
      return result;
    p = json_ws(p, obj_end);
    if(p >= obj_end || *p != ':') {
      free(key);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    p++;
    p = json_ws(p, obj_end);
    value_start = p;
    result = json_skip_value(&p, obj_end);
    value_end = p;
    if(!result)
      result = parse_impersonate_field(key, value_start, value_end, opts);
    free(key);
    if(result)
      return result;
  }
}

/* Store a parsed config target, replacing earlier targets with that name. */
static CURLcode add_config_target(struct impersonate_opts **targets,
                                  size_t *target_count,
                                  const char *name,
                                  const char *obj,
                                  const char *obj_end)
{
  CURLcode result;
  struct impersonate_opts opts;
  struct impersonate_opts *new_targets;
  size_t i;

  result = json_parse_opts(obj, obj_end, name, &opts);
  if(result)
    return result;
  for(i = 0; i < *target_count; i++) {
    if(!strcmp((*targets)[i].target, name)) {
      Curl_impersonate_opts_cleanup(&(*targets)[i]);
      (*targets)[i] = opts;
      return CURLE_OK;
    }
  }
  if(*target_count >= (((size_t)-1) / sizeof(**targets))) {
    Curl_impersonate_opts_cleanup(&opts);
    return CURLE_OUT_OF_MEMORY;
  }
  new_targets = realloc(*targets, (*target_count + 1) * sizeof(**targets));
  if(!new_targets) {
    Curl_impersonate_opts_cleanup(&opts);
    return CURLE_OUT_OF_MEMORY;
  }
  *targets = new_targets;
  (*targets)[*target_count] = opts;
  (*target_count)++;
  return CURLE_OK;
}

/* Decode every top-level JSON object into config impersonation targets. */
static CURLcode json_parse_targets(const char *json,
                                   struct impersonate_opts **targets,
                                   size_t *target_count)
{
  CURLcode result;
  const char *p = json;
  const char *end = json + strlen(json);
  bool first = TRUE;
  char *key = NULL;
  const char *value_start;
  const char *value_end;

  *targets = NULL;
  *target_count = 0;
  p = json_ws(p, end);
  if(p >= end || *p != '{')
    return CURLE_BAD_FUNCTION_ARGUMENT;
  p++;
  while(1) {
    key = NULL;
    p = json_ws(p, end);
    if(p >= end)
      return CURLE_BAD_FUNCTION_ARGUMENT;
    if(*p == '}')
      return CURLE_OK;
    if(!first) {
      if(*p != ',')
        return CURLE_BAD_FUNCTION_ARGUMENT;
      p++;
      p = json_ws(p, end);
    }
    first = FALSE;
    result = json_string(&p, end, &key);
    if(result)
      return result;
    p = json_ws(p, end);
    if(p >= end || *p != ':') {
      free(key);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    p++;
    p = json_ws(p, end);
    value_start = p;
    result = json_skip_value(&p, end);
    value_end = p;
    if(result) {
      free(key);
      return result;
    }
    value_start = json_ws(value_start, value_end);
    if(value_start >= value_end || *value_start != '{') {
      free(key);
      return CURLE_BAD_FUNCTION_ARGUMENT;
    }
    result = add_config_target(targets, target_count, key,
                               value_start + 1, value_end - 1);
    free(key);
    if(result)
      return result;
  }
}

/* Compare impersonation targets by name for qsort and binary search. */
static int compare_targets(const void *a, const void *b)
{
  const struct impersonate_opts *oa = (const struct impersonate_opts *)a;
  const struct impersonate_opts *ob = (const struct impersonate_opts *)b;

  return strcmp(oa->target, ob->target);
}

/* Check whether the config file overrides a built-in target name. */
static bool config_has_target(const struct impersonate_opts *targets,
                              size_t target_count,
                              const char *name)
{
  size_t i;

  for(i = 0; i < target_count; i++) {
    if(!strcmp(targets[i].target, name))
      return TRUE;
  }
  return FALSE;
}

/* Merge built-in and config targets into one sorted lookup table. */
static CURLcode merge_targets(struct impersonate_opts *config_targets,
                              size_t config_count,
                              struct impersonate_opts **targets,
                              size_t *target_count)
{
  struct impersonate_opts *all_targets;
  size_t i;
  size_t count = config_count;
  size_t n = 0;

  for(i = 0; i < num_builtin_impersonations; i++) {
    if(!config_has_target(config_targets, config_count,
                          builtin_impersonations[i].target))
      count++;
  }
  if(count > (((size_t)-1) / sizeof(*all_targets)))
    return CURLE_OUT_OF_MEMORY;
  all_targets = malloc(count * sizeof(*all_targets));
  if(!all_targets)
    return CURLE_OUT_OF_MEMORY;
  for(i = 0; i < num_builtin_impersonations; i++) {
    if(!config_has_target(config_targets, config_count,
                          builtin_impersonations[i].target))
      all_targets[n++] = builtin_impersonations[i];
  }
  for(i = 0; i < config_count; i++)
    all_targets[n++] = config_targets[i];
  qsort(all_targets, count, sizeof(*all_targets), compare_targets);
  *targets = all_targets;
  *target_count = count;
  return CURLE_OK;
}

/* Resolve the fingerprint file path from env or the default home path. */
static CURLcode config_path(char **path)
{
  char *env;
  char *home;
  size_t len;

  *path = NULL;
  env = curl_getenv("CURL_IMPERSONATE_FINGERPRINTS");
  if(env) {
    if(*env) {
      *path = env;
      return CURLE_OK;
    }
    free(env);
  }
  home = curl_getenv("HOME");
  if(!home)
    return CURLE_OK;
  len = strlen(home) + strlen(IMPERSONATE_PATH) + 1;
  *path = malloc(len);
  if(*path)
    msnprintf(*path, len, "%s%s", home, IMPERSONATE_PATH);
  free(home);
  return *path ? CURLE_OK : CURLE_OUT_OF_MEMORY;
}

/* Read a bounded fingerprint file into memory. */
static CURLcode read_file(const char *path, char **contents)
{
  FILE *fp;
  long len;
  size_t nread;

  *contents = NULL;
  fp = fopen(path, FOPEN_READTEXT);
  if(!fp)
    return CURLE_OK;
  if(fseek(fp, 0, SEEK_END)) {
    fclose(fp);
    return CURLE_READ_ERROR;
  }
  len = ftell(fp);
  if(len < 0 || len > IMPERSONATE_CONFIG_MAX) {
    fclose(fp);
    return CURLE_READ_ERROR;
  }
  if(fseek(fp, 0, SEEK_SET)) {
    fclose(fp);
    return CURLE_READ_ERROR;
  }
  *contents = malloc((size_t)len + 1);
  if(!*contents) {
    fclose(fp);
    return CURLE_OUT_OF_MEMORY;
  }
  nread = fread(*contents, 1, (size_t)len, fp);
  fclose(fp);
  if(nread != (size_t)len) {
    free(*contents);
    *contents = NULL;
    return CURLE_READ_ERROR;
  }
  (*contents)[len] = 0;
  return CURLE_OK;
}

/* Release all owned strings in a dynamically loaded impersonation target. */
void Curl_impersonate_opts_cleanup(struct impersonate_opts *opts)
{
  size_t i;

  if(!opts)
    return;
  free((char *)opts->target);
  free((char *)opts->ciphers);
  free((char *)opts->curves);
  free((char *)opts->sig_hash_algs);
  free((char *)opts->http3_sig_hash_algs);
  free((char *)opts->cert_compression);
  for(i = 0; i < IMPERSONATE_MAX_HEADERS; i++)
    free((char *)opts->http_headers[i]);
  free((char *)opts->http2_pseudo_headers_order);
  free((char *)opts->http2_settings);
  free((char *)opts->http_header_order);
  free((char *)opts->http2_streams);
  free((char *)opts->http3_pseudo_headers_order);
  free((char *)opts->http3_settings);
  free((char *)opts->quic_transport_parameters);
  free((char *)opts->ech);
  free((char *)opts->tls_extension_order);
  free((char *)opts->http3_tls_extension_order);
  free((char *)opts->tls_delegated_credentials);
  free((char *)opts->form_boundary);
  memset(opts, 0, sizeof(*opts));
}

/* Free the config targets and restore the built-in target table. */
void free_targets_from_config(void)
{
  size_t i;

  impersonations = builtin_impersonations;
  num_impersonations = num_builtin_impersonations;
  free(merged_targets);
  merged_targets = NULL;
  for(i = 0; i < num_loaded_config_targets; i++)
    Curl_impersonate_opts_cleanup(&loaded_config_targets[i]);
  free(loaded_config_targets);
  loaded_config_targets = NULL;
  num_loaded_config_targets = 0;
}

/* Load every configured target and merge them into the sorted target table. */
CURLcode load_targets_from_config(void)
{
  CURLcode result;
  struct impersonate_opts *config_targets = NULL;
  struct impersonate_opts *all_targets = NULL;
  size_t config_count = 0;
  size_t all_count = 0;
  char *path = NULL;
  char *json = NULL;
  size_t i;

  free_targets_from_config();
  result = config_path(&path);
  if(result || !path)
    return result;
  result = read_file(path, &json);
  free(path);
  if(result || !json)
    return result;
  result = json_parse_targets(json, &config_targets, &config_count);
  free(json);
  if(!result && config_count)
    result = merge_targets(config_targets, config_count,
                           &all_targets, &all_count);
  if(result) {
    for(i = 0; i < config_count; i++)
      Curl_impersonate_opts_cleanup(&config_targets[i]);
    free(config_targets);
    free(all_targets);
    return result;
  }
  if(config_count) {
    loaded_config_targets = config_targets;
    num_loaded_config_targets = config_count;
    merged_targets = all_targets;
    impersonations = merged_targets;
    num_impersonations = all_count;
  }
  return result;
}

/* Export the config loader for the curl tool. */
CURLcode curl_impersonate_load_targets_from_config(void)
{
  return load_targets_from_config();
}

/* Export the config cleanup for the curl tool. */
void curl_impersonate_free_targets_from_config(void)
{
  free_targets_from_config();
}
