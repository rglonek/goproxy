# GoProxy

A small reverse proxy: one binary in front of a handful of services on one host,
configured by a file you wrote by hand, run by systemd.

## Features

- **HTTP/HTTPS proxy** with several targets per rule, load balancing, health
  checking and budgeted retries
- **Static files**, redirects and canned responses
- **Authentication**: basic (several users, bcrypt hashes), static tokens, or
  handing the decision to another service
- **Routing** by host (exact, wildcard, regex), path (prefix, exact, segment,
  regex) and method, first match wins
- **TLS termination**: your own certificates with SNI, Let's Encrypt, mutual
  TLS, HSTS
- **Observability**: structured access logs, Prometheus metrics, health and
  readiness endpoints on a separate admin listener
- **Reload** without dropping connections, on `SIGHUP` or an admin endpoint
- **Safe defaults**: timeouts, request size limits, TLS 1.2 minimum, correct
  `X-Forwarded-*` handling, no credentials in logs — without configuring
  anything ([see below](#safe-defaults))

## Quick start

```bash
# check the config without binding anything
./goproxy -config config.yaml -check

# ask which rule would handle a request, and why the others did not
./goproxy -config config.yaml explain https://app.example.com/api/v1

# run it
./goproxy -config config.yaml
```

The smallest config that does something useful — forward every request to a
backend on port 8081:

```yaml
version: 2

listeners:
  http:
    addr: ":8080"

rules:
  - name: everything
    proxy:
      url: "http://127.0.0.1:8081"
```

Route by host and path, with a catch-all last (rules are evaluated in order and
the first match wins):

```yaml
version: 2

listeners:
  http:
    addr: ":8080"

rules:
  - name: api
    match:
      host: "app.example.com"
      path: "/api"
    proxy:
      url: "http://127.0.0.1:8081"
      strip_prefix: "/api"

  - name: static
    match:
      host: "static.example.com"
    serve:
      dir: "/var/www/html"

  - name: catch-all
    respond:
      status: 404
      body: "Not Found"
```

Runnable examples — auth, TLS, Let's Encrypt, load balancing, hardening — are in
[examples/](examples/), one config per topic.

**Upgrading from v0.x?** The schema changed shape; every old key has a new home.
See [docs/MIGRATION.md](docs/MIGRATION.md).

## Safe defaults

goproxy applies these without being asked. Every one can be overridden, and
setting a timeout or a limit to `0` disables it.

| Setting | Default | What it protects against |
| --- | --- | --- |
| `defaults.timeouts.read_header` | `10s` | A client that dribbles headers forever (Slowloris) |
| `defaults.timeouts.read` | `30s` | A slow request body |
| `defaults.timeouts.write` | `60s` | A slow reader holding a connection open |
| `defaults.timeouts.idle` | `120s` | Keep-alive connections piling up |
| `defaults.timeouts.shutdown` | `30s` | A shutdown that never finishes |
| `defaults.limits.max_header_bytes` | `1MiB` | Oversized header blocks |
| `defaults.limits.max_request_body` | `32MiB` | Unbounded uploads (`413` over the limit) |
| `listeners.https.tls.min_version` | `1.2` | Obsolete TLS versions |
| `serve.list_directories` | `false` | Accidentally listing a directory |
| `serve.allow_dotfiles` | `false` | Serving `.git` and `.env` |
| `trusted_proxies` | empty | `X-Forwarded-For` spoofing by direct clients |

The write timeout would cut off a long-lived response, so it is not applied to
connection upgrades (websockets, detected automatically) or to rules marked
`streaming: true` (server-sent events, large downloads over slow links).

`trusted_proxies` decides whether goproxy believes the `X-Forwarded-*` headers a
peer sends. From a peer that is not listed, those headers are dropped and
replaced with values taken from the connection itself, and a warning naming the
peer is logged once. If goproxy runs behind another proxy, list it:

```yaml
trusted_proxies:
  - 127.0.0.1/32
  - 10.0.0.0/8
```

## Configuration reference

Every config file starts with `version: 2`. Unknown keys are an error, so a
misspelled option stops startup instead of being ignored.

### Top level

| Key | Meaning |
| --- | --- |
| `log.level` | `detail`, `debug`, `info` (default), `warn`, `error`, `fatal`, `none` |
| `log.format` | `json` or `text`; text on a terminal, json otherwise |
| `log.access.enabled` | Request logging, on by default |
| `log.access.exclude_paths` | Paths that are not logged, such as a health check |
| `log.access.redact_query_params` | Query parameters whose value is replaced with `REDACTED` |
| `listeners.http.addr` | Address for plain HTTP, e.g. `":80"` |
| `listeners.http.redirect_to_https` | Redirect everything to https; defaults to true when an https listener exists |
| `listeners.https.addr` | Address for HTTPS |
| `listeners.https.tls` | See [TLS](#tls) |
| `admin.addr` | Admin listener; off unless set. Bind it to loopback |
| `admin.metrics` / `admin.reload` / `admin.pprof` | Endpoint switches |
| `defaults.timeouts` / `defaults.limits` | See [Safe defaults](#safe-defaults) |
| `trusted_proxies` | IPs or CIDRs whose `X-Forwarded-*` headers are believed |
| `on_listener_error` | `shutdown` (default) or `continue` |
| `auth` | Named authentication blocks |
| `upstreams` | Named target pools |
| `rules` | The ordered rule list |

### Rules

| Key | Meaning |
| --- | --- |
| `name` | Appears in logs, metrics and `explain`; defaults to `rules[N]` |
| `match.host` | `app.example.com`, `*.example.com` or `^regex$`; empty matches every host. Case-insensitive |
| `match.path` | Matched according to `path_mode`; empty matches every path |
| `match.path_mode` | `prefix` (default), `exact`, `segment` (`/api` matches `/api` and `/api/v1` but not `/apifoo`), `regex` |
| `match.methods` | Allowed methods; a request with another method falls through to the next rule |
| `auth` | The name of an `auth` block |
| `allow_ips` / `deny_ips` | CIDRs, evaluated before auth |
| `rate_limit` | `requests_per_second`, `burst`, `by: ip\|identity` |
| `cors` | `allow_origins`, `allow_methods`, `allow_headers`, `expose_headers`, `allow_credentials`, `max_age` |
| `max_request_body` | Overrides `defaults.limits.max_request_body` |
| `streaming` | The rule's responses are long-lived, so the write timeout is not applied |

Each rule ends in exactly one action:

**`proxy`** — `upstream` (a named pool) or `url` (a single target),
`strip_prefix`, `add_prefix`, `host_header`, `request_headers.{set,remove}`,
`response_headers.{set,remove}`. `remove` entries are header names, or regular
expressions when they start with `^`. The Host the client sent is forwarded
unless `host_header` says otherwise; `X-Forwarded-For`, `-Host`, `-Proto` and
`X-Real-Ip` are set from the connection.

**`serve`** — `dir`, `strip_prefix`, `index`, `list_directories`,
`allow_dotfiles`, `cache_control`. The directory is opened once at startup and
served through that handle, so a symlink out of it is refused by the kernel.

**`redirect`** — `to`, `status`. `{path}` and `{query}` are filled in from the
request.

**`respond`** — `status`, `body` or `body_file`, `content_type` (detected from
the body when unset), `headers`, `reload`. `body_file` is read once at startup
unless `reload: true`.

### Auth

An `auth` block is named and reusable. Within one, the authenticators are tried
in the order token, basic, forward, and the first that accepts the request wins.
The credential goproxy consumed is not passed upstream unless `forward: true`,
and nothing a client presented is ever written to the log.

```yaml
auth:
  staff:
    basic:
      users:
        - { user: alice, password: "wonderland" }
        - { user: bob, password_hash: "$2y$10$..." }   # bcrypt
        - { user: carol, password_file: "/etc/goproxy/carol.pw" }
      realm: "Internal"
      forward_user_header: X-USER
  api:
    token:
      header: X-TOKEN          # default
      accept_bearer: true      # Authorization: Bearer <token>, on by default
      tokens:
        - { id: ci, value: "s3cr3t" }
        - { id: deploy, value_env: DEPLOY_TOKEN }
  sso:
    forward:
      url: "http://127.0.0.1:9000/auth"   # 2xx means allowed
      user_header: X-Auth-User
      copy_headers: [X-Auth-Groups]
```

### Upstreams

```yaml
upstreams:
  app:
    targets:
      - { url: "http://10.0.0.1:8081", weight: 2 }
      - { url: "http://10.0.0.2:8081" }
    policy: round_robin        # least_conn | ip_hash | first_healthy
    health:
      passive: { failures: 3, cooldown: 30s }        # on by default
      active:  { path: /healthz, interval: 10s }     # opt-in
    retry:
      attempts: 2
      on: [connect_error, "503"]
      budget: 10%              # cap retries at a share of live traffic
    tls:
      ca_file: /etc/ssl/certs/internal-ca.pem        # pin a CA
      insecure_skip_verify: false
```

Only requests that can be replayed are retried — a body that has already been
read cannot be, so retries apply to requests without one.

### TLS

```yaml
listeners:
  https:
    addr: ":443"
    tls:
      min_version: "1.2"       # default; "1.3" for modern-only
      max_version: ""
      certs:                   # more than one: the SNI name picks
        - { cert_file: /etc/ssl/site.crt, key_file: /etc/ssl/site.pem }
      # or:
      # acme: { email: ops@example.com, domains: [example.com], cache_dir: /var/lib/goproxy/acme }
      client_auth:             # mutual TLS
        mode: require_and_verify
        ca_file: /etc/ssl/certs/client-ca.pem
      hsts:                    # opt-in: a wrong max_age is hard to undo
        enabled: false
        max_age: 31536000
```

Certificates are loaded and parsed at startup: one that cannot be used is a
startup error, not a listener that fails every handshake. `SIGHUP` re-reads
them, so a renewal does not need a restart.

## Observability

The admin listener is separate from the routed ones, so nothing on it can
collide with a catch-all rule:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Liveness |
| `GET /readyz` | Readiness: 503 while starting, while shutting down, or when an upstream has no healthy target |
| `GET /metrics` | Prometheus |
| `GET /config` | The resolved config, with secrets redacted |
| `POST /reload` | Same as `SIGHUP`, and returns the validation error on rejection |
| `GET /debug/pprof/*` | Opt-in, off by default |

One access-log record is written per request, after the response completes:

```json
{"time":"2026-08-12T10:00:00.123Z","level":"INFO","msg":"request","id":"01KZVE3YNP0018CC",
 "client_ip":"1.2.3.4","method":"GET","host":"example.com","path":"/api/v1/users","query":"page=2",
 "proto":"HTTP/1.1","scheme":"https","status":200,"bytes_in":0,"bytes_out":1732,"duration_ms":12.4,
 "rule":"api","action":"proxy","upstream":"app","target":"http://10.0.0.1:8081","upstream_ms":11.1,
 "retries":0,"auth_method":"token","auth_user":"ci","user_agent":"curl/8.4.0"}
```

The metrics are deliberately small, and every label is a rule name, an upstream
name, a target or a status code — there are no path, host or client-IP labels,
which is how a proxy usually blows up a Prometheus server.

## Signals and exit codes

| Signal | Effect |
| --- | --- |
| `SIGINT`, `SIGTERM` | Graceful shutdown: stop accepting, wait for in-flight requests up to `defaults.timeouts.shutdown`, then close |
| `SIGHUP` | Reload the config file and the certificates. A config that does not compile is rejected and the old one keeps serving |

goproxy exits non-zero when the config cannot be loaded, when a listener cannot
be bound, and when a listener stops on its own. It does not stay alive with a
dead listener.

## Troubleshooting

The config is compiled at startup, and goproxy prints the path to the offending
field:

```
config: config.yaml: rules[2] (api).proxy.upstream: no upstream named "aap" (did you mean "app"?)
```

`-check` does the same without binding a port, creating a directory or
contacting anything. `explain` answers "why is my rule not matching":

```
$ goproxy -config config.yaml explain http://api.example.com/apifoo
GET http://api.example.com/apifoo
  SKIP  api                  path "/apifoo" does not match segment /api
  SKIP  static               path "/apifoo" does not match prefix /site
  MATCH catch-all            matched
        respond 404
```

## Building

Go 1.25 or newer. `go.mod` pins the toolchain to a patched release, so a build
on an older Go fetches that toolchain rather than linking a stdlib with known
advisories in `crypto/tls`, `crypto/x509` and `net/http`:

```bash
go build ./cli          # or ./build.sh for artefacts for every platform
go test ./... -race
govulncheck ./...       # expected to report nothing affecting the code
```

## Releasing

The `VERSION` file at the top of the repository is the single source of truth.
It is embedded in the binary, so `goproxy -version` and the release tag cannot
drift apart, and there is no build flag to forget.

1. Bump `VERSION` (e.g. `1.1.0`) and merge to `main`.
2. Run the **Release** workflow from the Actions tab, typing the same version
   into the prompt. It refuses to run if that does not match the file, or if the
   tag already exists.

The workflow builds `linux/amd64` and `linux/arm64` on one runner with
`CGO_ENABLED=0`, packages each as `goproxy-<version>-linux-<arch>.tar.gz`
containing the binary, `LICENSE` and `README.md`, checks that the binary reports
the version being released, and creates the GitHub release `v<version>` with the
tarballs and a `checksums.txt`.

```bash
tar -xzf goproxy-1.0.0-linux-amd64.tar.gz
./goproxy -version      # goproxy version 1.0.0, commit abc1234, built ..., go1.25.12
```

## Using it as a library

`pkg/proxy` is the front door; the packages under it are importable too and
documented as such:

```go
cfg, err := config.ParseFile("config.yaml")
server, err := proxy.New(cfg)      // compiles; binds nothing
err = server.Start(ctx)            // binds and serves
err = server.Reload(newCfg)        // atomic swap, or rejected
err = server.Shutdown(ctx)         // idempotent
err = server.Wait()                // why it stopped
```

| Package | What it holds |
| --- | --- |
| `pkg/config` | The schema: parsing, validation, no behaviour |
| `pkg/route` | Compiling a config into an immutable routing table |
| `pkg/action` | The four terminal handlers |
| `pkg/upstream` | Target pools, policies, health checking, retries |
| `pkg/authn` | Authenticators and the identity they produce |
| `pkg/middleware` | The request pipeline stages |
| `pkg/observe` | Logging, the access-log schema, metrics |
| `pkg/listen` | TLS configuration, certificates, ACME |
