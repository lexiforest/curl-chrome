#!/bin/bash

# TODO: use cmake to generate mingw makefile, see:
#
# 1. https://github.com/curl/curl/pull/13244/files
# 2. https://everything.curl.dev/build/windows.html

git df curl-8_7_1 > chrome.patch
mv chrome.patch ../curl-impersonate/chrome/patches/curl-impersonate.patch
