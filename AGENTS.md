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

## Fork Delta (vs `curl-8_15_0`)
Baseline check: `git diff --stat curl-8_15_0`.
Current delta: **47 files changed, +4834/-183**.

- New impersonation core: `lib/impersonate.c` + `lib/impersonate.h` with 35 preset targets (Chrome/Edge/Firefox/Safari/Tor/OkHttp variants).
- Public API additions: `curl_easy_impersonate()` and new `CURLOPT_*` for TLS/HTTP2 fingerprints (`CURLOPT_IMPERSONATE`, `CURLOPT_HTTPBASEHEADER`, `CURLOPT_HTTP2_SETTINGS`, `CURLOPT_TLS_EXTENSION_ORDER`, etc.).
- Tooling additions: `curl-impersonate` and tuning flags such as `--impersonate`, `--http2-pseudo-headers-order`, `--tls-permute-extensions`, and `--proxy-credential-no-reuse`.
- Network behavior changes: HTTP/2 defaults/priority/pseudo-header ordering, browser-style header merge, and QUIC-over-SOCKS5 UDP ASSOCIATE (`socks5h` included).
- Build/package rename: artifacts are emitted as `curl-impersonate`, `libcurl-impersonate`, `curl-impersonate-config`, and `libcurl-impersonate.pc`.

## Build, Test, and Development Commands

DO NOT BUILD, the user will build manually.

CMake build:

```sh
cmake -S . -B build
cmake --build build
```

## Coding Style & Naming Conventions
- C code style is defined in `docs/internals/CODE_STYLE.md`.
- Use spaces only, 2-space indentation, max 79 columns.
- Keep to C89 style (`/* comments */`, not `//`).
- Prefer clear lower-case names; make file-local helpers `static`.
- Run `make checksrc` before submitting.

## Testing Guidelines

DO NOT TEST, the user will test manually

## Commit & Pull Request Guidelines
- Commit subject format: `[area]: short effect` (imperative, present tense, no trailing period).
- Keep commit body wrapped at 72 columns and explain *why*.
- Use relevant trailers when applicable: `Fixes #...`, `Closes #...`, `Ref: ...`, `Reviewed-by: ...`.
- Keep PRs focused, include tests/docs updates for changed behavior, and ensure CI is green before requesting review.

## Adding new options for impersonating

For libcurl:

- Add options in `impersonate.h`
- Add new browser option in `impersonate.c`
- Add the option `CURLOPT_XXX` in `curl.h`
- Add the option in `urldata.h`. If it's a string option, note the `dupstring` struct.
- Add the option in `easyoptions.c`, the alphabetical order should be kept. Also update the number at the end
- Implement in `setopt.c`. Note, for integer and bool, use `setopt_long`, for string, use `setopt_cptr`
- Implement in `easy.c` for `curl_easy_impersonate`.
- Implement in `vtls/openssl.c` or `http2.c`.

For curl:

- Add the option in `tool_cfgable.c` and `tool_cfgable.h`
- Add the option in `tool_getparam.h`
- Add the option in `tool_getparam.c`, 2 places. note the argument type, like `ARG_BOOL`, etc.
- Implement in `tool_operate.c`, note the difference between my_setopt and my_setopt_str
- Add the option in `config2setopts.c`
