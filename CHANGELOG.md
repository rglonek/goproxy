# Changelog

## 1.0.0 (unreleased)

The redesign in [docs/designs/next](docs/designs/next), phases 3 to 5: the
schema/runtime split, the request pipeline, observability, reload, and the
capability `FUTURE.md` asked for. **The config schema changed shape**; every
v0.x key has a new home and [docs/MIGRATION.md](docs/MIGRATION.md) maps them.
A v0.x file is detected and refused with a pointer to that page rather than
half-understood.

### Structure

* Config parsing, validation and compilation are separate. `pkg/config` is
  plain data with no behaviour; `pkg/route` compiles it into an immutable
  routing table; the serving path only ever sees compiled objects and never
  re-parses anything per request.
* The request path is a pipeline of small stages - recover, request id, real
  ip, access log, in-flight, then per rule body limit, ip filter, CORS, rate
  limit, authentication - terminating in an action. Every stage is a value that
  can be constructed in a test.
* New importable packages: `pkg/config`, `pkg/route`, `pkg/action`,
  `pkg/upstream`, `pkg/authn`, `pkg/middleware`, `pkg/observe`, `pkg/listen`.
  `pkg/proxy` remains the front door.
* Authentication produces a typed identity rather than a string compared
  against `"None"`. Each authenticator strips the credential it consumed,
  whether or not it accepted it, so a rejected token cannot be forwarded
  upstream when another authenticator rescues the request.

### Configuration (v2)

* `version: 2` is required, and unknown keys are an error: a misspelled option
  stops startup instead of being ignored.
* Errors carry the path to the offending field, and suggest the name you
  probably meant: `rules[2] (api).proxy.upstream: no upstream named "aap" (did
  you mean "app"?)`.
* Listeners are named (`listeners.http`, `listeners.https`), and the HTTP →
  HTTPS redirect is now a flag rather than implied.
* `auth` and `upstreams` are named, reusable blocks that rules reference, so
  six rules can share one auth block.
* Host matching gained wildcards (`*.example.com`); path matching gained
  `path_mode: prefix|exact|segment|regex`, and `segment` is the one people
  usually mean. Rules can match on method.
* Explicit `strip_prefix`/`add_prefix` replace the `proxy_append_path`
  inversion.
* Unreachable rules are reported at startup.

### Capability

* **Several targets per rule**: named upstreams with `round_robin`,
  `least_conn`, `ip_hash` and `first_healthy` policies, weights, passive health
  checking (eject after N failures, re-probe after a cool-off), opt-in active
  health checks, and retries bounded both by attempts and by a budget that caps
  them as a share of live traffic. Only requests that can be replayed are
  retried.
* **Per-upstream TLS**: pin a CA, override the server name, or skip
  verification - built on a clone of the standard transport, so the connection
  pool and timeouts survive.
* **Auth**: several users per rule, bcrypt `password_hash`, secrets from a file
  or the environment, token ids that appear in logs where the token never does,
  and `forward` auth that asks another service (a subrequest, not a process
  fork per request).
* **Defensive options**, per rule: rate limiting, IP allow/deny lists, method
  lists, CORS and a body cap.
* **TLS**: several certificates selected by SNI, mutual TLS, HSTS, and
  certificate reload on `SIGHUP`.

### Observability

* `log/slog` throughout, in JSON or logfmt, replacing the logger dependency.
  goproxy's level names are kept, and `none` silences everything.
* One access-log record per request, written after the response completes, with
  a stable field schema: id, client ip, method, host, path, query, status, sizes,
  duration, rule, action, upstream, target, upstream duration, retries and auth
  identity. It is its own stream, with its own switch, `exclude_paths` and
  `redact_query_params`.
* Request ids: sortable, monotonic, echoed to the client and propagated
  upstream. An inbound id is only believed from a trusted peer.
* Prometheus metrics on the admin listener, with no path, host or client-IP
  labels.
* Admin listener with `/healthz`, `/readyz`, `/metrics`, `/config` (secrets
  redacted) and `POST /reload`; never reachable through the routing table.
* `goproxy -config <file> explain <url>` prints which rule would handle a
  request and why the others were skipped.

### Operations

* **Reload** on `SIGHUP` or `POST /reload`: a new table is compiled and the
  pointer swapped atomically, so there is no lock on the request path and no
  torn state. A config that does not compile is rejected and the old one keeps
  serving. A listener address change is reported as needing a restart rather
  than silently ignored.
* Certificates are re-read on reload.

### Supply chain

* Go 1.25 is the minimum, and go.mod pins `toolchain go1.25.12`: every stdlib
  finding govulncheck reports is "fixed in go1.25.x", so the floor belongs in
  the repo rather than in whichever Go the build machine happens to have.
* `golang.org/x/crypto`, `golang.org/x/net` and `golang.org/x/text` updated to
  current releases, clearing advisories in `x/net/idna` and `x/text/unicode/norm`
  reachable through ACME host matching.
* `govulncheck ./...` reports nothing affecting the code, and CI runs it on
  every push and weekly.

### Release

* `VERSION` at the top of the repository names the release and is embedded in
  the binary, so `goproxy -version` reports what was released without a build
  flag anyone has to remember.
* A manually-triggered **Release** workflow builds `linux/amd64` and
  `linux/arm64` on one runner with `CGO_ENABLED=0`, packages each as a tarball
  and publishes them with a `checksums.txt`. The version comes from the file
  alone, and the run refuses to release over an existing tag.
* Every archive holds a single `goproxy-<version>/` directory, so unpacking one
  leaves that directory behind instead of scattering files over the current one.
  Alongside the binary, `LICENSE` and `README.md` it carries `config-examples/`
  - the `examples/` configs - and `goproxy.service`, a systemd unit to copy into
  `/etc/systemd/system` and edit. The workflow checks that layout before it
  publishes anything.

### Kept from 0.3.0

Everything phases 1 and 2 fixed is still fixed: timeouts and size limits,
certificates parsed at startup, listener errors that reach the operator, an
idempotent context-taking `Shutdown`, panic recovery, constant-time credential
comparison, no credentials in logs, correct `X-Forwarded-*` handling with
`trusted_proxies`, `os.Root`-contained static file serving with listings and
dotfiles off, prefix stripping that strips a prefix, and `-check`.

## 0.3.0

Phases 1 and 2 of the redesign: the v0.1.0 code hardened, with the visible
defects fixed. See the git history for the detail - every finding it addressed
is listed there by identifier.

## 0.1.0

Initial release.
