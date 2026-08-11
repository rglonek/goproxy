# 3. Proposed architecture

## 3.1 Shape of the change

Today there are three files in one package that share mutable state:

```
pkg/proxy/config.go   parse + validate + mkdir
pkg/proxy/rules.go    YAML schema + compiled regexes + matching
pkg/proxy/router.go   transport setup + the whole request path
pkg/proxy/server.go   listeners + lifecycle
```

Proposed layout — each package depends only on those above it:

```
internal/config/      YAML schema, strict decode, validation, v1→v2 adapter
internal/route/       compiled routing table: host index → path matcher → rule
internal/action/      terminal handlers: proxy, serve, redirect, respond
internal/upstream/    target pools, load balancing, health checks, transports
internal/authn/       basic, token, (later) forward-auth; constant-time compare
internal/middleware/  recover, request-id, access-log, limits, rate-limit, cors
internal/observe/     slog setup, access-log schema, metrics registry
internal/listen/      listener construction, TLS config, ACME wiring
pkg/proxy/            public API: Server, New, Run, Reload, Shutdown, Wait
cli/                  flags, signals, process exit codes
```

`internal/` keeps the surface deliberately small: `pkg/proxy` is the supported
API, everything else is free to change. This is a change from today, where
every field of every config struct is public API by accident.

## 3.2 Configuration → runtime, in two steps

The core structural fix (A2, C1). Two distinct type families:

**Schema types** (`internal/config`) are plain data: YAML tags, no methods
except `Validate() error`, no unexported cached state, no behaviour. They can
be marshalled back out losslessly, which is what makes `goproxy config migrate`
and `goproxy config dump` possible.

**Runtime types** (`internal/route`, `internal/action`, …) are built from
schema types by an explicit `Compile` step and are immutable thereafter.

```go
// internal/config
func Load(path string) (*Config, error)          // read + strict decode + validate
func Parse(b []byte) (*Config, error)

// internal/route
func Compile(cfg *config.Config, deps Deps) (*Routes, error)
```

`Compile` is where regexes are compiled, upstream transports are built,
`respond_body_file` contents are read into memory, static-file roots are opened
as `os.Root`, and "this cannot possibly work" is discovered — including the
things that currently blow up at request time or not at all (C4, R2). Because
compilation is a function of config alone, a `--check` mode is simply
`Load` + `Compile` + discard, and validation no longer needs side effects (C8).

Nothing outside `Compile` ever calls `regexp.Compile` or `url.Parse`. There is
no path by which a half-initialised rule reaches the request handler, which is
exactly the failure in C1.

## 3.3 Request pipeline

The 130-line `ServeHTTP` (A1) becomes a chain assembled once, at compile time:

```
                    ┌─ per-server middleware (built once) ─────────────┐
client ──▶ Recover ─▶ RequestID ─▶ AccessLog ─▶ Limits ─▶ Match ──┐
                    └─────────────────────────────────────────────┘  │
                                                                     ▼
                      ┌─ per-rule middleware (built once per rule) ───────┐
                      │  RateLimit ─▶ IPFilter ─▶ Authn ─▶ HeaderRewrite  │
                      └──────────────────────────┬───────────────────────┘
                                                 ▼
                                    Action: proxy | serve | redirect | respond
```

Every stage has the standard shape, so ordering is data and stages compose:

```go
type Middleware func(http.Handler) http.Handler
```

Two consequences worth calling out:

* **Per-rule chains are built at compile time, not per request.** Matching
  produces a `*route.Rule` that already holds a fully assembled
  `http.Handler`. The per-request work is: match, then `rule.Handler.ServeHTTP`.
* **Auth becomes a typed result** instead of the `authType string` compared
  against `"None"`/`"Token"`/`"Basic"` (A1). The authenticated principal is
  attached to the request context, and the header-rewrite stage reads it from
  there. C6 — a rejected token being forwarded upstream when basic auth
  rescues the request — stops being possible, because the "strip the
  credential I consumed" decision is made by the authenticator that consumed
  it.

```go
// internal/authn
type Identity struct {
    Method  string // "basic" | "token" | "forward" | ""
    User    string // authenticated principal, if any
    TokenID string // stable index/label of the matching token — never the token
}

type Authenticator interface {
    // Authenticate consumes credentials from r. It returns the identity on
    // success. On failure it returns the challenge to send and false; the
    // caller decides whether to try the next authenticator or reject.
    Authenticate(r *http.Request) (Identity, Challenge, bool)
    // Strip removes the credentials this authenticator consumed, unless the
    // rule asked for them to be forwarded.
    Strip(r *http.Request)
}
```

Multiple authenticators per rule are tried in order, preserving today's
"token first, basic as fallback" behaviour (`router.go:45-79`) as a
configuration of a general mechanism rather than a special case.

## 3.4 Matching and the routing table

Today matching is a linear scan calling `Rule.Match` per rule, which does
`net.SplitHostPort`, up to two regex evaluations and string comparisons per
rule per request (`rules.go:220-246`). Correct, but O(rules) with allocation,
and case-sensitive (C7).

Proposed `Routes`:

```go
type Routes struct {
    exact    map[string]*hostGroup  // "app.example.com" — lowercased, port-stripped
    suffix   []*hostGroup           // "*.example.com", longest suffix first
    regex    []*hostGroup           // ^-prefixed patterns, in config order
    any      *hostGroup             // rules with no domain_match
}
```

Within a host group, paths are matched by a prefix trie for literal prefixes
plus an ordered regex list, and the winner is resolved back to config order so
that **first-match-wins semantics are preserved exactly**. This is important:
the optimisation must not change which rule wins, or every existing config
becomes a guessing game. The compiler asserts this by construction and a test
fuzzes `Routes.Match` against the naive linear scan.

Improvements that come with it:

* Host is lowercased and the trailing dot stripped once, at request time, into
  a stack buffer — fixing C7.
* `*.example.com` wildcard hosts, without requiring the operator to write a
  regex.
* A `strict_slash`/`match_type` option so `path_match: /api` can mean "the
  `/api` path segment" rather than "any path starting with the characters
  `/api`", which today also matches `/apifoo`.
* Compile-time warnings for unreachable rules — a catch-all in position 2 of 5
  makes rules 3–5 dead, and goproxy can say so at startup instead of leaving
  the operator to discover it.

## 3.5 Actions

```go
// internal/action
type Action interface {
    http.Handler
    Describe() string // for logs and `goproxy config explain`
}
```

Four implementations, each fixing the specific defects found in its current
inline branch:

**`proxy`** — built on `httputil.ReverseProxy` with the modern `Rewrite` hook
instead of `Director`, so `SetXForwarded` sets `X-Forwarded-For`, `-Host` and
`-Proto` correctly (S5), with the inbound value dropped or preserved according
to a `trusted_proxies` setting (S6). Path handling becomes explicit
`strip_prefix` / `add_prefix` operations rather than `ReplaceAllString` (C3).
Targets come from an upstream (§3.6) rather than a single parsed URL.
`ErrorHandler` is set so upstream failures produce a configurable status and a
logged reason instead of the bare 502 with a stdlib log line.

**`serve`** — uses `os.Root` (Go 1.24) rather than `http.Dir`, giving
kernel-enforced containment of the directory root; `index` and `directory
listing` become explicit options, with listings **off by default** (S8); adds
optional `Cache-Control`, precompressed-file support (`.gz`/`.br` siblings) and
a custom 404 hook. One `http.FileServer` is built per rule at compile time
instead of per request (`router.go:94`).

**`redirect`** — gains the ability to interpolate the matched path
(`redirect_url: "https://new.example.com{path}"`), which is the common case
today's fixed-URL redirect cannot express.

**`respond`** — sets `Content-Type` from an explicit option, falling back to
sniffing rather than forcing `text/plain` (C2); supports arbitrary response
headers; reads `respond_body_file` once at compile time into a
`[]byte`, with an optional `reload: true` for files expected to change, and
always sets `Content-Length` (R6).

## 3.6 Upstreams — the FUTURE.md features

A rule's proxy target becomes a reference to a named upstream, or an inline
one-target upstream (so the single-URL form keeps working verbatim):

```go
// internal/upstream
type Pool struct {
    Targets  []*Target
    Policy   Policy      // round-robin | least-conn | ip-hash | first-healthy
    Health   *HealthCheck
    Retry    RetryPolicy
}

type Target struct {
    URL       *url.URL
    Weight    int
    transport http.RoundTripper // shared, tuned, per-target TLS policy
    state     atomic.Pointer[targetState] // healthy, in-flight, EWMA latency
}

type Policy interface{ Pick(*http.Request, []*Target) *Target }
```

This delivers `FUTURE.md`'s "multiple targets for the same rule match: load
balancing, failover" directly. It also fixes S9: transports are built by the
upstream package from a shared, tuned base (`MaxIdleConnsPerHost`,
`DialContext` timeout, `TLSHandshakeTimeout`, `ResponseHeaderTimeout`,
HTTP/2), with the TLS policy — verify, skip verification, or **pin a specific
CA**, which today is impossible — applied on top rather than replacing the
whole transport.

Retries are budgeted (a maximum in-flight retry fraction, not a naive
per-request count) and only ever applied to requests that are safe to replay:
idempotent methods, or requests whose body has been buffered under the
configured limit. Passive health checking (eject a target after N consecutive
failures, re-probe after a cool-off) is the default; active HTTP health checks
are opt-in.

## 3.7 Server lifecycle

```go
// pkg/proxy — the public API
type Server struct { /* ... */ }

func New(cfg *config.Config, opts ...Option) (*Server, error) // compiles; no listeners
func (s *Server) Start(ctx context.Context) error             // binds; returns on bind failure
func (s *Server) Wait() error                                 // blocks; returns why it stopped
func (s *Server) Reload(cfg *config.Config) error             // atomic swap or reject
func (s *Server) Shutdown(ctx context.Context) error          // idempotent
```

Changes against today's `server.go`:

* **`New` binds nothing.** Compilation errors (bad regex, unusable upstream
  URL, unreadable certificate) surface before any port is taken.
* **Certificates are loaded and parsed in `New`, not handed to `ServeTLS` as
  filenames** (R2). `tls.LoadX509KeyPair` at compile time turns the verified
  silent-failure case into a startup error. The loaded certificate is served
  via `GetCertificate`, which also gives a reload path for renewed certs
  without a restart.
* **Every listener goroutine reports.** `Start` runs listeners under an
  `errgroup`; `Serve` returning anything other than `http.ErrServerClosed`
  cancels the group and is the value `Wait` returns (R2, R4). `cli` exits
  non-zero on it.
* **`Shutdown` is idempotent** via `sync.Once` (R3), takes a `context` for the
  deadline instead of a bare `time.Duration`, and drains listeners in order:
  stop accepting, then wait for in-flight requests, then force-close.
* **`Run` is kept** as a thin `New`+`Start` convenience so existing callers
  keep working, but it returns the exported `*Server` (A3).

## 3.8 Reload

```
SIGHUP ──▶ config.Load ──▶ route.Compile ──▶ ok? ──▶ routes.Store(new)
                │                │                └─ no ─▶ log error, keep serving old
                └── error ───────┘
```

The request path reads the table through a single `atomic.Pointer[route.Routes]`
load, so there is no lock and no torn state. A request that started under the
old table finishes under it.

Listener-level changes (bind address, TLS mode) cannot be swapped this way; the
reload compares them and either rebinds that listener specifically or reports
that a restart is required, rather than silently ignoring the change. Resources
held by the old table (idle upstream connections, open file roots) are released
after a grace period once in-flight requests have drained.

## 3.9 Concurrency and shared state

Explicit rules, because the current code has no stated ones:

* The routing table is immutable after compile. The only mutable per-request
  state is in `upstream.Target` (health, in-flight counters), all of it atomic.
* Nothing in the request path takes a mutex.
* `-race` is on in CI for every test, and the end-to-end suite includes a
  concurrent-load test with reload happening underneath it — the exact
  scenario where the current design's shared `*Rule` mutation would show up.

## 3.10 What this buys, mapped to the findings

| Change | Fixes |
| --- | --- |
| Schema/runtime split, explicit `Compile` | C1, C4, C8, A2 |
| Middleware pipeline, typed identity | A1, C6, R5 |
| Compiled routing table | C7, and the `/apifoo` prefix surprise |
| Action types | C2, C3, S8, R6 |
| Upstream package | S9, `FUTURE.md` load balancing/failover |
| Lifecycle rework | R2, R3, R4, A3 |
| Atomic reload | O3 |
| `internal/` + named exports | A3, A4 |
