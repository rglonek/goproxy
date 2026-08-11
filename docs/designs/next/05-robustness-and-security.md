# 5. Robustness and security

Most of this document is Phase 1 of the roadmap: it is achievable against the
*current* code, does not depend on the redesign, and is where the highest-value
change per line sits.

## 5.1 Timeouts and limits (R1, R6)

Proposed defaults, all overridable, all applied to both the HTTP and HTTPS
servers:

| Setting | Default | Rationale |
| --- | --- | --- |
| `ReadHeaderTimeout` | 10s | The Slowloris fix. Nothing legitimate takes longer to send headers. |
| `ReadTimeout` | 30s | Bounds slow request bodies. Must exceed the largest expected upload duration. |
| `WriteTimeout` | 60s | Bounds slow readers. Set high enough for large static files on slow links. |
| `IdleTimeout` | 120s | Reclaims keep-alive connections. |
| `MaxHeaderBytes` | 1 MiB | Go's default, stated explicitly so it is visible. |
| max request body | 32 MiB | Applied with `http.MaxBytesReader`; `0` disables. |
| max concurrent connections | unlimited | Opt-in via a `netutil.LimitListener` wrapper. |
| upstream dial timeout | 10s | |
| upstream TLS handshake timeout | 10s | |
| upstream response header timeout | 30s | |
| shutdown grace | 30s | Then force-close. `cli` currently uses 60s. |

Two caveats worth documenting rather than discovering:

* **`WriteTimeout` and streaming.** A `WriteTimeout` breaks long-lived
  responses — websockets, SSE, large downloads over slow links. The proxy
  action must therefore disable or extend the deadline per request for upgraded
  connections (`Connection: Upgrade`) and for rules explicitly marked
  `streaming: true`. Getting this wrong is the most likely way a timeout
  default breaks a working deployment, so it needs an end-to-end test with a
  websocket and one with an SSE stream.
* **Timeouts interact with `proxy_target_accept_self_signed`'s transport
  replacement** (S9): today that path has *no* dial or handshake timeouts at
  all, because it discards `http.DefaultTransport`. Building transports from a
  tuned base (§3.6) fixes it.

## 5.2 Failure semantics (R2, R3, R4, R5)

**Startup.** Anything that will prevent goproxy serving what the config asked
for is a startup error and a non-zero exit: an unparseable certificate, a port
already bound, an upstream URL with no scheme, an unreadable
`respond_body_file`, a missing serve directory. Certificates are parsed in
`New` with `tls.LoadX509KeyPair`, not passed as filenames to `ServeTLS`, which
is the specific hole in R2.

**Runtime.** A listener returning an error other than `http.ErrServerClosed`
is fatal by default: log at `error`, begin graceful shutdown of the other
listeners, and have `Wait()` return the error so `cli` exits non-zero and the
supervisor restarts. An operator who prefers degraded operation (keep HTTP
serving when HTTPS dies) opts into it with `on_listener_error: continue`.

**Shutdown.** `sync.Once`-guarded, context-driven, and safe to call from a
signal handler and an error path simultaneously (R3). Order: stop accepting →
close idle keep-alives → wait for in-flight → force close at the deadline.

**Panics.** A `Recover` middleware at the head of the chain logs the panic and
the stack through the configured logger at `error`, increments a counter,
returns `500`, and lets the access-log middleware still record the request
(R5). Without it, panics go to the stdlib logger, invisible to whatever the
operator configured.

## 5.3 Authentication (S1, S2, S3, S4)

* **Constant-time comparison.** `subtle.ConstantTimeCompare` for both basic
  auth and tokens (S1). For tokens, compare against every configured token
  rather than short-circuiting on the first match, so timing does not reveal
  *which* token matched. For basic auth, hash both sides to a fixed length
  first (`sha256` then compare) so the comparison does not leak length.
* **Never log credentials** (S2). Tokens are identified in logs by a
  configured `id` (`token=ci`) or, absent one, an index. Presented-but-invalid
  credentials are never logged at any level, including `detail` — a debug level
  that prints secrets is a footgun that eventually ends up enabled in
  production.
* **Hashed passwords** (S3). Accept `password_hash` (bcrypt) alongside the
  existing plaintext `password`, plus `password_file` and `value_env` for
  secrets that should not sit in the config. bcrypt is deliberately slow, so
  successful authentications are cached in a small LRU keyed by
  `hash(user:pass)` with a short TTL, or the proxy becomes a CPU-bound
  bcrypt-per-request machine.
* **Multiple users per rule** (S4) via a `users` list.
* **Auth failures are rate-limited** per source IP, so the proxy is not a free
  password-guessing oracle.
* **Forward-auth** (`FUTURE.md`): a `forward_auth` authenticator that issues a
  subrequest to a URL with the original method, path and headers, treats 2xx as
  success, and copies a configured set of response headers onto the upstream
  request. This is the standard mechanism (nginx `auth_request`, Traefik
  ForwardAuth) and is strictly better than `FUTURE.md`'s "handoff to a separate
  binary", which would mean forking a process per request. If a binary handoff
  is genuinely wanted, the same interface can be satisfied by a long-lived
  subprocess speaking the same protocol over a unix socket.

## 5.4 Forwarded headers and client identity (S5, S6)

The current behaviour — append to whatever `X-Forwarded-For` the client sent,
send nothing else — is both incomplete and spoofable. Proposed:

```yaml
trusted_proxies:
  - 127.0.0.1/32
  - 10.0.0.0/8
```

* If the immediate peer is **not** in `trusted_proxies`, inbound
  `X-Forwarded-*` and `Forwarded` headers are **dropped** and replaced with
  values derived from the actual connection.
* If the peer **is** trusted, inbound values are preserved and appended to, and
  the "real client IP" used for logging, rate limiting and `ip_hash` is taken
  from the rightmost untrusted entry.
* `X-Forwarded-Proto` and `X-Forwarded-Host` are always set (S5), using
  `httputil.ReverseProxy`'s `Rewrite` + `SetXForwarded`.
* Hop-by-hop headers are stripped per RFC 9110 — `ReverseProxy` already does
  this, but the header-rewrite stage must not reintroduce them, so
  `request_headers.set` rejects `Connection`, `Transfer-Encoding`, etc. at
  config-validation time.

## 5.5 TLS (S7)

```yaml
tls:
  min_version: "1.2"        # default; "1.3" for modern-only
  max_version: ""           # unset
  cipher_suites: []         # empty = Go's secure default ordering
  curve_preferences: []
  client_auth:              # new: mutual TLS
    mode: require_and_verify
    ca_file: /etc/ssl/client-ca.pem
  hsts:
    enabled: false          # opt-in: HSTS is hard to undo
    max_age: 31536000
    include_subdomains: false
    preload: false
```

* `MinVersion: tls.VersionTLS12` is set explicitly rather than inherited, so it
  is visible and cannot regress with a Go version change.
* Multiple certificates with SNI selection, replacing the single
  cert/key pair — a host serving two domains with separate certs is currently
  impossible without ACME.
* Certificate reload on `SIGHUP` via `GetCertificate`, so renewals do not need
  a restart.
* OCSP stapling where the certificate supports it.
* HSTS is opt-in and never on by default: a wrong `max_age` is very difficult
  for an operator to recover from.
* The ACME path keeps `autocert` but the http-01 challenge handler is mounted
  explicitly rather than wrapping the whole HTTP handler, so the interaction
  with the HTTP→HTTPS redirect (`server.go:75-84`) is visible instead of
  implicit. tls-alpn-01 becomes available as an alternative that does not
  require port 80 — removing the `listen_addr` must end in `:80` constraint
  (`config.go:153-155`) for operators who cannot bind it.

## 5.6 Static file serving (S8)

* `os.Root`-based containment rather than `http.Dir`. `http.Dir` is safe
  against `..` traversal, but `os.Root` (Go 1.24) also prevents escape through
  symlinks that point outside the root — a real risk when serving a directory
  users can write to.
* Directory listings **off by default**, opt-in per rule.
* Dotfiles (`.git`, `.env`, `.htpasswd`) blocked by default, with an opt-out.
* `Cache-Control` configurable per rule; `ETag`/`If-None-Match` already handled
  by `http.ServeContent`.

## 5.7 New defensive options

Blunt instruments only, per [N2](02-goals.md#23-non-goals):

* **Rate limiting** — token bucket per rule, keyed by client IP or by
  authenticated identity, with a configurable burst and a `429` response
  carrying `Retry-After`.
* **IP allow/deny** — CIDR lists per rule, evaluated before auth.
* **Method allow-lists** — `match.methods`, so a rule can be GET-only.
* **Request body limits** — per rule, overriding the global default.
* **CORS** — a small, explicit preflight handler, because hand-rolling it in
  `proxy_set_headers` is a common source of accidental `Access-Control-Allow-Origin: *`.

## 5.8 Supply chain

* `govulncheck` in CI on every push and on a weekly schedule, so a
  vulnerability in `golang.org/x/crypto` or `yaml.v3` surfaces without a commit.
* Dependabot or Renovate for Go module updates.
* Reproducible builds: `-trimpath` is already used in `build.sh`; add
  `-buildvcs=true` and record the commit in the version string (O5).
* Signed release artefacts and a `checksums.txt`.
* Drop `github.com/lithammer/shortuuid`: it is a direct dependency in `go.mod`
  used only by `test/logwww`, and the request-ID work in
  [06-observability.md](06-observability.md) needs a monotonic, sortable ID
  rather than a random one anyway.
