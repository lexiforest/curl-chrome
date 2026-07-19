---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_REDIRECT_HISTORY
Section: 3
Source: libcurl
See-also:
  - CURLINFO_EFFECTIVE_URL (3)
  - CURLINFO_REDIRECT_COUNT (3)
  - CURLINFO_RESPONSE_CODE (3)
  - CURLOPT_FOLLOWLOCATION (3)
  - curl_easy_getinfo (3)
  - curl_slist_free_all (3)
Protocol:
  - HTTP
Added-in: 8.21.0
---

# NAME

CURLINFO_REDIRECT_HISTORY - get followed HTTP redirect responses

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_REDIRECT_HISTORY,
                           struct curl_slist **historyp);
~~~

# DESCRIPTION

Pass a pointer to a *struct curl_slist * to receive the HTTP redirect
responses followed during the latest transfer, in request order.

Each list item uses this format, separated by a single ASCII tab:

~~~text
<status-code>\t<url>
~~~

The URL is the request URL that returned the status code. The final response
is not part of the history; retrieve its URL with CURLINFO_EFFECTIVE_URL(3)
and its status with CURLINFO_RESPONSE_CODE(3). Authentication challenges and
automatic transport retries are not included.

The returned list is newly allocated. The application must free it with
curl_slist_free_all(3). If no redirects were followed, the returned list is
NULL.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    result = curl_easy_perform(curl);
    if(result == CURLE_OK) {
      struct curl_slist *history;
      result = curl_easy_getinfo(curl, CURLINFO_REDIRECT_HISTORY, &history);
      if(result == CURLE_OK) {
        struct curl_slist *item;
        for(item = history; item; item = item->next)
          printf("%s\n", item->data);
        curl_slist_free_all(history);
      }
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
