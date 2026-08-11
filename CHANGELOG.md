# Changelog

## 0.3.0 (unreleased)

Implements phases 1 and 2 of
[docs/designs/next](docs/designs/next/08-roadmap.md): the current code, hardened,
with the visible defects fixed. Every v0.1.0 config still loads and behaves the
same way, apart from the behaviour changes listed at the bottom - each of which
is a bug fix.

### Robustness

* Server timeouts on both listeners: `read_header` 10s, `read` 30s, `write` 60s,
  `idle` 120s, `MaxHeaderBytes` 1MiB, all configurable under `timeouts:` and
  `limits:`. v0.1.0 set none of them, so a client that dribbled header bytes
  held a goroutine and a file descriptor indefinitely (R1).
* The write timeout is not applied to connection upgrades (detected from the
  request) or to rules marked `streaming: true`, so websockets, server-sent
  events and long downloads are not cut off (§5.1).
* Request bodies are capped at 32MiB by default; over the limit the client gets
  a `413` (R6).
* Certificates are loaded and parsed at startup. v0.1.0 handed the file names to
  `ServeTLS` in a goroutine whose error was discarded, so a broken certificate
  produced a listening socket that failed every handshake while the process
  reported success (R2).
* Listener errors reach the operator: they are logged, they stop the server (or
  not, with `on_listener_error: continue`), they are returned by `Wait()`, and
  the process exits non-zero (R2, R4).
* `Shutdown` is idempotent and takes a `context.Context`. Calling it twice used
  to panic with `close of closed channel` (R3).
* A panicking rule produces a `500` and a log line through the configured
  logger, instead of a stdlib log line that ignores the configured level (R5).
* An empty rule (`- ` with nothing under it) is a config error instead of a
  nil-pointer panic at startup.

### Security

* Credentials are compared with `crypto/subtle` in constant time, against every
  configured token rather than short-circuiting on the first match (S1).
* A credential a client presented is never logged, at any level. v0.1.0 logged
  every rejected token in plaintext at `info` (S2).
* `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto` and `X-Real-Ip` are
  set from the connection. Inbound values are only believed from a peer listed
  in the new `trusted_proxies:` (S5, S6).
* `tls.min_version` defaults to 1.2 and is set explicitly; `max_version` is
  available too (S7).
* Static file serving is contained with `os.Root`, so a symlink out of the
  served directory is refused rather than followed; dotfiles (`.git`, `.env`)
  are hidden by default (S8, §5.6).
* `proxy_target_accept_self_signed` builds its transport from a clone of the
  standard one instead of replacing it, keeping connection pooling, HTTP/2 and
  the dial and handshake timeouts (S9).

### Correctness

* A `Rule` built in Go code rather than parsed from YAML now matches with its
  regexes. It used to compare the host against the literal text of the regex and
  silently never match (C1).
* `respond_rule` honours `respond_content_type` and `respond_headers`, sets
  `Content-Length`, and no longer appends a newline or forces `text/plain` (C2).
* Path stripping removes the matched prefix and only the matched prefix. It was
  a regex substitution, which removed *every* match in the path (C3).
* `proxy_url` must be an absolute http(s) URL with a host. `proxy_url: garbage`
  passed validation and then failed on every request (C4).
* Token auth no longer answers with `WWW-Authenticate: Bearer` unless the new
  `accept_bearer` option is on, because that told clients to retry in a form
  goproxy did not read (C5).
* A rejected token is no longer forwarded upstream when basic auth rescues the
  request (C6).
* Host matching is case-insensitive and ignores the root-zone trailing dot (C7).
* Validating a config no longer creates the ACME cache directory, which is what
  makes `-check` possible (C8).

### Operability

* `-check` loads, validates and compiles the config, then exits - no port bound,
  no directory created, nothing contacted.
* Unknown config keys are reported as warnings at startup instead of silently
  dropped (A5).
* Rules can be named; the name appears in logs instead of `rules[N]` (A4).
* `SIGHUP` re-reads the TLS certificate files, so a renewal does not need a
  restart.
* `goproxy -version` reports version, commit, build date and Go version, baked
  in by `build.sh` (O5).
* The exported API is `proxy.Server` with `New`, `Start`, `Wait`, `Shutdown`,
  `ReloadCertificates`, `HTTPAddr` and `HTTPSAddr`. `Run` is kept and now
  returns the exported type (A3).
* CI runs build across six platforms, `go vet`, `gofmt`, race-enabled tests,
  both fuzz targets, `staticcheck` and `govulncheck`, weekly as well as on push.
* Dropped the `github.com/lithammer/shortuuid` dependency.

### Behaviour changes

Each is a bug fix; each has an escape hatch unless the old behaviour was simply
wrong.

| Change | Opt-out |
| --- | --- |
| Timeouts now apply | Set them to `0` in `timeouts:` |
| Request bodies are capped at 32MiB | `limits.max_request_body: 0` |
| Host matching is case-insensitive | none - the old behaviour was a bug |
| `respond_body` is sent verbatim, with a detected content type | `respond_content_type: "text/plain; charset=utf-8"` |
| Directory listings are off | `serve_list_directories: true` |
| Dotfiles are not served | `serve_allow_dotfiles: true` |
| `X-Forwarded-Proto`/`-Host`/`X-Real-Ip` are now sent | none |
| Inbound `X-Forwarded-*` is dropped from untrusted peers | list the peer in `trusted_proxies` |
| Failed tokens are no longer logged | none |
| Bad certificates fail at startup | none |
| Token auth sends no `WWW-Authenticate` by default | `accept_bearer: true` |
| `respond_status_code` must be 200-599; a 1xx left the client waiting for a final status | none |
| `Shutdown` takes a `context.Context` (library callers only) | none |

## 0.1.0

Initial release.
