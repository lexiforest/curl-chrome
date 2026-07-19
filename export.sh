#!/bin/bash

# TODO: use cmake to generate mingw makefile, see:
#
# 1. https://github.com/curl/curl/pull/13244/files
# 2. https://everything.curl.dev/build/windows.html

git df curl-8_21_0 -- . ':(exclude)tests/**' > chrome.patch
mv chrome.patch ../curl-impersonate/patches/curl.patch
