---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ca-native
Help: Load CA certs from the OS
Protocols: TLS
Category: tls
Added: 8.2.0
Multi: boolean
See-also:
  - cacert
  - capath
  - dump-ca-embed
  - insecure
  - proxy-ca-native
Example:
  - --ca-native $URL
---

# `--ca-native`

Use the operating system's native CA store for certificate verification.

This option is independent of other CA certificate locations set at run time or
build time. Those locations are searched in addition to the native CA store.

This option works with OpenSSL and its forks (BoringSSL, LibreSSL, etc) on
Windows (Added in 7.71.0) and on Apple OS when libcurl is built with
Apple SecTrust enabled. (Added in 8.17.0)

In this fork, BoringSSL on Windows uses Windows certificate chain verification
when native CA verification is enabled. This enforces Windows' Disallowed
certificate trust list as well as server-authentication policy. Additional CA
files, paths and blobs can extend trust, but cannot override Windows distrust
or other certificate policy failures. Hostname and pinned-key checks still
apply.

This does not enable online CRL or OCSP checks. Explicit --crlfile checks
continue to be performed by BoringSSL alongside Windows native verification.

This option works with wolfSSL on Windows, Linux (Debian, Ubuntu, Gentoo,
Fedora, RHEL), macOS, Android and iOS. (Added in 8.3.0)

This option works with GnuTLS (Added in 8.5.0) and also uses Apple
SecTrust when libcurl is built with it. (Added in 8.17.0)

This option works with Rustls on Windows, macOS, Android and iOS. On Linux it
is equivalent to using the Mozilla CA certificate bundle. When used with Rustls
_only_ the native CA store is consulted, not other locations set at run time or
build time. (Added in 8.13.0)

This option currently has no effect for Schannel. This is the native TLS
library from Microsoft, that by default uses the native CA store for
verification unless overridden by a CA certificate location setting.
