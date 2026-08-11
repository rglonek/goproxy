# 1. Current state — feature inventory and findings

Based on `v0.1.0` (commit `f03b8c0`) plus the config-validation fixes in
`226fb18`. All line references are to the tree as of this document.

## 1.1 Feature inventory

These are the capabilities the redesign must preserve. Nothing in this table is
proposed for removal.

| Area | Capability | Where |
| --- | --- | --- |
| Listeners | HTTP listener on `listen_addr` | `pkg/proxy/server.go:72-94` |
| | HTTPS listener on `tls.listen_addr` | `pkg/proxy/server.go:97-128` |
| | HTTPS-only (omit `listen_addr`) | `pkg/proxy/config.go:143-145` |
| | Automatic HTTP→HTTPS redirect when TLS is configured | `pkg/proxy/server.go:75-84` |
| TLS | Static certificate/key files | `pkg/proxy/config.go:36-39` |
| | Let's Encrypt via `autocert`, with http-01 challenge on the HTTP listener | `pkg/proxy/server.go:61-69,79-81` |
| Routing | Ordered rules, first match wins | `pkg/proxy/rules.go:239-246` |
| | Exact host match, or regex when the value starts with `^` | `pkg/proxy/rules.go:220-237` |
| | Path prefix match, or regex when the value starts with `^` | same |
| | Empty match = matches everything (catch-all) | same |
| Actions | `proxy_rule` — reverse proxy to a single URL | `pkg/proxy/router.go:117-164` |
| | `proxy_append_path` — append or strip the matched path prefix | `pkg/proxy/router.go:140-146` |
| | `proxy_rewrite_host_header` | `pkg/proxy/router.go:119-121` |
| | `proxy_set_headers` / `proxy_remove_headers` (literal or `^`-regex) | `pkg/proxy/router.go:147-161` |
| | `proxy_target_accept_self_signed` | `pkg/proxy/router.go:22-24` |
| | `serve_rule` — static files from a local directory | `pkg/proxy/router.go:87-96` |
| | `redirect_rule` — 3xx to a fixed URL | `pkg/proxy/router.go:81-85` |
| | `respond_rule` — canned status + inline body or file | `pkg/proxy/router.go:98-115` |
| Auth | Basic auth, single user/password per rule | `pkg/proxy/router.go:69-79` |
| | `set_user_header` / `set_user_get_var` to pass identity upstream | `pkg/proxy/router.go:131-138` |
| | Token auth against a list of static tokens, configurable header | `pkg/proxy/router.go:45-66` |
| | `forward_header` — keep or strip the token header upstream | `pkg/proxy/router.go:122-128` |
| | Token auth with basic auth as fallback on the same rule | `pkg/proxy/router.go:55-59,69` |
| Ops | YAML config, validated at startup with rule-indexed errors | `pkg/proxy/config.go:141-172` |
| | Seven log levels, millisecond timestamps | `pkg/proxy/config.go:11-21`, `server.go:53-57` |
| | Graceful shutdown on SIGINT/SIGTERM with a 60s budget | `cli/main.go:45-53` |
| | Cross-platform static binaries (6 targets) | `build.sh` |

Requested but not built, from `FUTURE.md`: third-party auth via handoff to a
separate binary; basic form handling; multiple targets per rule with load
balancing and failover.

## 1.2 What is worth keeping as-is

* **The configuration model.** Ordered rules with first-match-wins is easy to
  reason about and easy to debug. It should survive the redesign unchanged in
  spirit.
* **The action set.** proxy / serve / redirect / respond covers the great
  majority of small-deployment reverse-proxy work.
* **Startup validation with rule indices** (`rules[2]: proxy_rule: proxy_url is
  required`) is genuinely good operator experience and should be extended, not
  replaced.
* **Single static binary, no runtime dependencies.**

## 1.3 Findings

Severity is about production exposure, not code aesthetics. Findings marked
**[verified]** were reproduced against the current tree; the reproduction is
described inline.

### Robustness

**R1 — No server timeouts of any kind. (High)**
`http.Server` is constructed with only `Addr` and `Handler`
(`pkg/proxy/server.go:85-88`, `99-105`, `115-118`). `ReadTimeout`,
`ReadHeaderTimeout`, `WriteTimeout` and `IdleTimeout` all default to zero,
meaning "no timeout". A single client that opens a connection and dribbles
header bytes holds a goroutine and a file descriptor indefinitely; a few
hundred such connections are enough to exhaust the process. This is the
textbook Slowloris exposure and it is the single most important thing to fix.

**R2 — Listener errors are discarded; the process stays up with a dead
listener. (High) [verified]**
`go p.httpServer.Serve(ln)` (`server.go:93`) and `go
p.httpsServer.ServeTLS(ln, certFile, keyFile)` (`server.go:126`) throw away the
returned error. `ServeTLS` is where the certificate and key are actually parsed,
so a malformed or mismatched certificate is not detected at startup.

> Reproduced: a config pointing `tls.certs` at two files containing the text
> `not a cert` / `not a key` passes `Validate()` (which only calls `os.Stat`,
> `config.go:115-120`), `Run()` returns no error and logs "Proxy server
> started", and the process runs happily — while every HTTPS request fails with
> `net/http: TLS handshake timeout`. An operator sees a healthy-looking process
> and a silently broken site.

**R3 — `Shutdown` is not idempotent and panics on a second call. (Medium)
[verified]**
`close(p.shutdown)` at `server.go:163` runs unconditionally. Calling
`Shutdown` twice panics with `close of closed channel`. Reachable in practice:
`cli/main.go:47-53` shuts down from a signal handler goroutine, and any future
path that also shuts down on a fatal error (which is what R2 needs) would
collide with it.

**R4 — `Wait()` cannot report why the server stopped. (Medium)**
`Wait()` (`server.go:167-170`) blocks on a channel closed only by `Shutdown`
and always returns `nil`. There is no way for the process to exit non-zero when
a listener dies, and no way for a supervisor to distinguish "asked to stop" from
"fell over".

**R5 — No panic recovery in the request path. (Medium)**
`net/http` recovers a panicking handler and kills only that connection, but the
panic is written to the standard logger, bypassing the configured logger and log
level entirely, and produces no access-log entry. A rule that panics is
invisible in the operator's log stream.

**R6 — No request size limits.** No `MaxHeaderBytes` override (the 1 MB default
applies), no body cap, no cap on concurrent connections. A `respond_rule` with
`respond_body_file` re-opens and streams the file on **every** request
(`router.go:100-109`) with no caching and no `Content-Length`.

### Security

**S1 — Credential comparison is not constant-time. (Medium)**
Basic auth compares with `user != rule.BasicAuth.User || pass !=
rule.BasicAuth.Pass` (`router.go:72`); token auth uses `slices.Index`
(`router.go:52`), which is `==` under the hood. Both leak length and prefix
information through timing. The fix is `crypto/subtle.ConstantTimeCompare`, and
it is cheap.

**S2 — Failed tokens are written to the log in plaintext. (Medium)**
`router.go:54` logs `ReqToken=%s` with the presented token at `Info` level — the
default level. Any credential a client presents, including one that is valid for
a *different* rule, lands in the log file. Logs are routinely shipped to places
credentials should not go.

**S3 — Passwords and tokens are plaintext in the config file. (Medium)**
`BasicAuth.Pass` (`rules.go:49`) and `TokenAuth.Tokens` (`rules.go:59`) are
literal strings, so the config cannot be committed or templated safely, and
there is no support for hashed passwords or for reading a secret from a file or
environment variable.

**S4 — One user per rule.** `BasicAuth` holds a single `user`/`password` pair.
There is no way to grant two people access to the same rule without sharing a
password.

**S5 — `X-Forwarded-Proto` and `X-Forwarded-Host` are never set. (Medium)**
`NewSingleHostReverseProxy` uses the legacy `Director` API, which appends
`X-Forwarded-For` and nothing else. (`SetXForwarded`, which sets all three, is
only used by the newer `Rewrite` API.) A backend behind goproxy's TLS
termination therefore cannot tell that the original request was HTTPS, and will
generate `http://` absolute URLs and set cookies without `Secure`.

**S6 — Inbound `X-Forwarded-For` is trusted and appended to. (Medium)**
The default director appends the peer address to whatever `X-Forwarded-For` the
client sent, so a direct client can inject arbitrary "original" IPs. There is no
concept of a trusted upstream proxy, and no `X-Real-IP`. Any backend doing
IP-based decisions on the header is spoofable.

**S7 — No TLS policy. (Low/Medium)** No `MinVersion`, cipher suite selection,
curve preference, ALPN configuration or HSTS option. Today's Go default
(TLS 1.2 minimum for servers) is acceptable, but it is inherited rather than
chosen, and it cannot be tightened by an operator who needs TLS 1.3-only.

**S8 — `serve_rule` always exposes directory listings. (Low) [verified]**
`http.FileServer` (`router.go:94`) generates an index page for any directory
without `index.html`, and there is no option to turn it off.

> Reproduced: `path_match: '^/static'` + `serve_local_dir: /tmp/wwwroot` returns
> an HTML listing of the directory tree for `GET /static`.

**S9 — `proxy_target_accept_self_signed` builds a bare `http.Transport`.**
`router.go:23` replaces the transport with `&http.Transport{TLSClientConfig:
&tls.Config{InsecureSkipVerify: true}}` — losing all of `http.DefaultTransport`'s
connection pooling, dial and TLS-handshake timeouts, and HTTP/2 support. Rules
with this flag get materially worse connection behaviour as a side effect. The
option is also all-or-nothing: there is no way to pin a CA instead.

### Correctness

**C1 — Regex matching silently degrades outside the YAML path. (Medium)
[verified]**
`Rule.Compile()` is only ever called from `Rule.UnmarshalYAML`
(`rules.go:118-127`). `pkg/proxy` is an exported, importable package, so a
`Rule` constructed in Go code has `domainRegex == nil`, and `Match` then falls
through to `host != r.DomainMatch` (`rules.go:230`) — comparing the host against
the *literal regex source*.

> Reproduced: `(&Rule{DomainMatch: "^.*\\.example\\.com"}).Match("api.example.com", "/")`
> returns `false`. There is no error; the rule just never matches.

**C2 — `respond_rule` cannot serve anything but plain text. (Medium)
[verified]**
`router.go:112` uses `http.Error`, which forces `Content-Type: text/plain;
charset=utf-8`, adds `X-Content-Type-Options: nosniff`, and appends a newline to
the body. There is no way to set response headers.

> Reproduced: `respond_body: "<h1>hello</h1>"` is served as
> `text/plain; charset=utf-8` with body `"<h1>hello</h1>\n"` — a custom error
> page cannot be rendered as HTML. The `respond_body_file` branch
> (`router.go:108`) has the opposite problem: it writes the status and streams
> the file with *no* `Content-Type` at all.

**C3 — Path stripping uses `ReplaceAllString`. (Low)**
Both the serve and proxy branches strip the matched prefix with
`rule.pathRegex.ReplaceAllString(r.URL.Path, "")` (`router.go:90`, `142`).
`ReplaceAll` removes *every* match, not just the leading one. Today this is
masked because a regex match is only compiled when the pattern starts with `^`,
but the anchoring is enforced by string convention (`strings.HasPrefix(...,
"^")`, `rules.go:197`) rather than by the matcher, and `^` inside an alternation
(`^/a|/b`) is enough to break it. Stripping should be an explicit
"remove this prefix" operation, not a substitution.

**C4 — `proxy_url` validation accepts values that cannot work. (Low)
[verified]**
`rules.go:153` validates with `url.Parse`, which accepts a bare word:
`url.Parse("garbage")` returns no error with an empty scheme and host. That
config passes startup validation and then fails on every request. (A more common
typo, `proxy_url: 127.0.0.1:8081`, *is* caught — but by accident, not by design.)
Validation should require an absolute URL with `http`/`https` scheme and a host.

**C5 — Documented token-auth default does not match the code.** The comment at
`rules.go:60-62` says the token is read from the `Authorization` header when
`token_auth_header` is unset; the code reads `X-TOKEN` (`router.go:50`). The
README repeats the code's behaviour, so the comment is the wrong one — but the
handler also sends `WWW-Authenticate: Bearer` on failure (`router.go:57`), which
tells the client to retry with `Authorization: Bearer …`, a form goproxy does
not accept.

**C6 — A failed token is forwarded upstream when basic auth rescues the
request.** The header-stripping logic at `router.go:122-128` only runs when
`authType == "Token"`. If token auth fails and basic auth then succeeds, the
rejected token header is passed through to the backend.

**C7 — Host matching is case-sensitive and does not handle IDN or trailing
dots.** `Match` (`rules.go:220-237`) strips the port but does not lowercase the
host, so `Example.com` fails to match `domain_match: example.com`. Host headers
are case-insensitive.

**C8 — Validation has side effects.** `TLS.Validate()` creates the Let's Encrypt
cache directory with `os.MkdirAll` (`config.go:132-136`). A `--check`-style
"validate this config" mode cannot exist while validation mutates the
filesystem.

### Structure and API

**A1 — `ServeHTTP` is a 130-line if-chain with stringly-typed state.**
`router.go:34-165` does matching, token auth, basic auth, header rewriting,
path rewriting and all four actions in one function, threading auth state
through an `authType string` compared against `"None"` / `"Token"` / `"Basic"`.
Nothing in it can be tested in isolation, and every new feature widens the same
function.

**A2 — The config struct is also the runtime struct.** `Rule` carries
`domainRegex`, `pathRegex`, `*httputil.ReverseProxy` and
`proxyRemoveHeadersRegex` alongside its YAML tags (`rules.go:18-98`). The
compiled state is built in two different places — `Compile()` during unmarshal
and `setRouter()` after (`router.go:14-28`) — and `proxy_url` is parsed twice,
once in each. This coupling is what makes hot reload and C1 hard.

**A3 — `Run` returns an unexported type.** `func Run(config *Config) (*proxy,
error)` (`server.go:15`) — callers outside the package cannot name the type,
declare a variable of it, or write an interface against it.

**A4 — Rules have no identity.** Logs refer to `Rule=%d` by index, so inserting
a rule renumbers every log line after it. Rules should have optional names.

**A5 — Unknown config keys are silently ignored.** `yaml.Unmarshal`
(`config.go:165`) is called without `KnownFields(true)`. A typo like
`proxy_append_paths` is dropped without a word. This is documented as a known
gotcha in `README.md:206-210` and `examples/README.md`, which is the right
short-term response to a wrong default.

### Operability

**O1 — No metrics, no health endpoint, no readiness signal.** Nothing to scrape,
and no way for a load balancer to ask whether the process is serving.

**O2 — Access logs are unstructured and unparseable.** Every request emits a
hand-formatted `Client=%s Host=%s Path=%s …` line (e.g. `router.go:37`) at
`Info`. There is no request ID, no status code, no response size, no duration,
no method — the three things an operator most wants (what did we return, how
big, how slow) are all absent, and the format cannot be reliably parsed because
values are not quoted.

**O3 — No config reload.** Any change requires a full restart, dropping every
connection.

**O4 — No CI and no tests of the serving path.** There is no `.github/`
directory. `pkg/proxy/config_test.go` covers config parsing and `Rule.Match`
(three test functions, 231 lines) — good as far as it goes — but no test starts
a server, and no test exercises auth, proxying, path rewriting or TLS.

**O5 — Version is a hardcoded string.** `cli/main.go:14` contains `"goproxy
version 0.1.0"`, which `build.sh` does not set, so the binary's reported version
depends on someone remembering to edit the source. No commit or build date is
reported.

**O6 — `test/logwww` is the only integration aid** and is not wired into
anything automatic.

## 1.4 Summary

Nine of the twenty-one findings (R1–R6, S1, S2, S5, S6) are things that would be
fixed in a hardening pass on the existing code without any redesign, and
[08-roadmap.md](08-roadmap.md) proposes exactly that as Phase 1. The rest —
C1, C2, A1, A2, O2, O3 — are consequences of the config struct doubling as the
runtime model and of the monolithic handler, and are what the redesign in
[03-architecture.md](03-architecture.md) is for.
