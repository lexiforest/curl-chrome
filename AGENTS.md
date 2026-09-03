# Repository Guidelines

## Project Structure & Module Organization
`curl-chrome` follows curl's upstream layout.

- `lib/`: libcurl core (protocols, connection logic, TLS in `lib/vtls/`, QUIC in `lib/vquic/`).
- `src/`: curl CLI sources.
- `include/curl/`: public headers installed for libcurl users.
- `tests/`: regression and integration suites (`tests/data/`, `tests/libtest/`, `tests/unit/`, `tests/http/`).
- `docs/`: user/developer docs (`docs/internals/` for contributor-facing internals).
- `scripts/`: maintenance and lint helpers.
- `CMake/` and top-level `CMakeLists.txt`: CMake build support.

## Related repos

- Boringssl, ../boringssl
- ngtcp2, ../ngtcp2
- nghttp3, ../nghttp3
- curl-impersonate, ../curl-impersonate

## Fork Delta (vs `curl-8_22_0`)
Baseline check: `git diff --stat curl-8_22_0`.
Current delta: **85 files changed, +8640/-487**.

- Impersonation core: `lib/impersonate.c` + `lib/impersonate.h` with 39 preset targets (Chrome/Edge/Firefox/Safari/Tor/OkHttp variants).
- Public API additions: `curl_easy_impersonate()` and new `CURLOPT_*` for TLS/HTTP2 fingerprints (`CURLOPT_IMPERSONATE`, `CURLOPT_HTTPBASEHEADER`, `CURLOPT_HTTP2_SETTINGS`, `CURLOPT_TLS_EXTENSION_ORDER`, etc.).
- Tooling additions: `curl-impersonate` and tuning flags such as `--impersonate`, `--http2-pseudo-headers-order`, `--tls-permute-extensions`, and `--proxy-credential-no-reuse`.
- Network behavior changes: HTTP/2 priority/pseudo-header ordering, browser-style header merge, WebSocket impersonation, HTTP/3 fingerprint switching, and QUIC-over-SOCKS5 UDP ASSOCIATE (`socks5h` included).
- TLS/QUIC fingerprinting includes signature algorithms, extension order, ALPS codepoint selection, certificate compression, record/key-share limits, transport parameters, and session-cache separation for fingerprint-sensitive settings.
- Build/package rename: artifacts are emitted as `curl-impersonate`, `libcurl-impersonate`, `curl-impersonate-config`, and `libcurl-impersonate.pc`.

## Build, Test, and Development Commands

Do not build unless the user explicitly requests it. The user normally builds
and tests manually.

The packaging build consumes this repository as a generated patch. Always
propagate changes with `./export.sh`; never edit
`../curl-impersonate/build/deps/src/curl` directly.

```sh
./export.sh
cd ../curl-impersonate
make build
```

An existing CMake ExternalProject source tree does not automatically reapply a
changed patch. When a clean patch application is required, clean the generated
outputs after exporting, then rebuild:

```sh
cd ../curl-impersonate
make build CMAKE_BUILD_ARGS="--target clean"
make build
```

## Coding Style & Naming Conventions
- C code style is defined in `docs/internals/CODE_STYLE.md`.
- Use spaces only, 2-space indentation, max 79 columns.
- Keep to C89 style (`/* comments */`, not `//`).
- Prefer clear lower-case names; make file-local helpers `static`.
- Run `make checksrc` before submitting.

## Testing Guidelines

DO NOT TEST unless the user explicitly requests it; the user normally tests
manually.

## Commit & Pull Request Guidelines
- Commit subject format: `[area]: short effect` (imperative, present tense, no trailing period).
- Keep commit body wrapped at 72 columns and explain *why*.
- Use relevant trailers when applicable: `Fixes #...`, `Closes #...`, `Ref: ...`, `Reviewed-by: ...`.
- Keep PRs focused, include tests/docs updates for changed behavior, and ensure CI is green before requesting review.

## Adding new options for impersonating

For libcurl:

- Add the field in `lib/impersonate.h` and preset values in
  `lib/impersonate.c`.
- Add `CURLOPT_XXX` in `include/curl/curl.h`.
- Add storage in `lib/urldata.h`. For strings, also update `struct dupstring`.
- Add the option to `lib/easyoptions.c` in alphabetical order and update the
  option count at the end.
- Implement it in `lib/setopt.c`: use `setopt_long` for integers/booleans and
  `setopt_cptr` for strings.
- Apply preset values in `lib/easy.c` and use `long` values for long options.
- Implement protocol behavior in the appropriate layer, normally
  `lib/vtls/openssl.c`, `lib/http2.c`, `lib/ws.c`, or `lib/vquic/`.
- For TLS-affecting configuration, review copy, completeness, matching, free,
  connection reuse, and session-cache key handling in `lib/vtls/`.

For curl:

- Add storage and cleanup in `src/tool_cfgable.h` and
  `src/tool_cfgable.c`.
- Add the option identifier in `src/tool_getparam.h`.
- Add both the option-table entry and parser case in `src/tool_getparam.c`,
  using the correct argument type such as `ARG_BOOL` or `ARG_STRG`.
- Apply it in `src/config2setopts.c`. Use `my_setopt_long` for long/boolean
  values and `MY_SETOPT_STR` for strings so errors are handled.
- Touch `src/tool_operate.c` only when the option needs transfer-lifecycle
  behavior; ordinary option application belongs in `config2setopts.c`.
- Keep generated/help option lists in their required alphabetical order.
