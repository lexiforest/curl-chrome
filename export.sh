#!/bin/bash

git df curl-8_5_0 > chrome.patch
mv chrome.patch ../curl-impersonate/chrome/patches/curl-impersonate.patch
