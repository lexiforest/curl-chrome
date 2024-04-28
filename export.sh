#!/bin/bash

git df curl-8_7_1 > chrome.patch
mv chrome.patch ../curl-impersonate/chrome/patches/curl-impersonate.patch
