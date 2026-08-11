# 6. Observability

## 6.1 The problem

Today every request emits one hand-formatted line at `Info`, for example
(`pkg/proxy/router.go:118`):

```
Client=1.2.3.4:5678 Host=example.com Path=/api AuthType=Basic Mod=Proxy Target=http://127.0.0.1:8081 Rule=0
```

It is written *before* the request is handled, so it cannot contain the status
code, the response size, the duration, or whether the upstream was even
reachable. It omits the method. Values are unquoted, so a path containing a
space breaks any parser. Rules are identified by index, so inserting a rule
renumbers everything (A4). And a request that panics or whose upstream fails
produces either nothing or a stdlib log line that bypasses the configured
logger entirely (R5).

The three questions an operator asks — *what did we return, how big, how slow* —
are all unanswerable from the current logs (O2).

## 6.2 Structured logging with `log/slog`

`log/slog` has been in the standard library since Go 1.21 and the project
already requires Go 1.24. Moving to it drops the `github.com/rglonek/logger`
dependency, gains JSON output, and gains levels that map onto the existing
seven-level scheme.

Level mapping, preserving the existing config vocabulary:

| goproxy level | slog level | Meaning |
| --- | --- | --- |
| `detail` | `Debug-4` | Per-request internals: which rule matched and why |
| `debug` | `Debug` | Reload, upstream health transitions, cert rotation |
| `info` | `Info` | Lifecycle: start, listen, reload applied, shutdown |
| `warn` | `Warn` | Recoverable: upstream ejected, auth throttled, unknown config keys |
| `error` | `Error` | Panics, listener failures, config reload rejected |
| `fatal`/`fail` | `Error`+exit | Terminal |
| `none` | silences all | |

**Access logs move off the level system entirely.** They are their own stream
with their own on/off switch, because "I want request logs but not debug noise"
and "I want warnings but no per-request lines" are both reasonable and neither
is expressible today.

## 6.3 Access log schema

One record per request, emitted **after** the response completes, with a stable
field set:

```json
{
  "time": "2026-08-11T10:00:00.123Z",
  "msg": "request",
  "id": "01J8XN4K2P",
  "client_ip": "1.2.3.4",
  "method": "GET",
  "host": "example.com",
  "path": "/api/v1/users",
  "query": "page=2",
  "proto": "HTTP/1.1",
  "scheme": "https",
  "status": 200,
  "bytes_in": 0,
  "bytes_out": 1732,
  "duration_ms": 12.4,
  "rule": "api",
  "action": "proxy",
  "upstream": "app",
  "target": "http://10.0.0.1:8081",
  "upstream_ms": 11.1,
  "retries": 0,
  "auth_method": "token",
  "auth_user": "ci",
  "user_agent": "curl/8.4.0",
  "referer": ""
}
```

Notes on the design:

* **`id`** is a request ID, generated if absent or taken from an inbound
  `X-Request-Id` when the peer is trusted, echoed in the response, and
  propagated upstream. It is what ties an access-log line to the error-log
  lines for the same request. Sortable and monotonic (ULID-style), not random.
* **`rule`** is the rule's name, falling back to `rules[N]` when unnamed (A4).
* **`auth_user`** is the authenticated principal or the token's `id` — never a
  credential (S2).
* **`query`** is included but redactable: `log.access.redact_query_params: [token, key]`
  replaces listed values with `REDACTED`, because secrets in query strings are
  common and end up in log aggregators.
* Fields are stable; adding a field is a minor version, removing or retyping one
  is a breaking change.
* `format: text` produces `logfmt`-style key=value output with proper quoting,
  for people who read logs with their eyes. `format: json` is the default when
  stdout is not a TTY.

Excluding health-check noise is a first-class option
(`access.exclude_paths: ["/healthz"]`), because otherwise a 10s health check
generates 8,640 log lines a day per target.

## 6.4 Metrics

Prometheus text format on the admin listener. Deliberately small — this is a
single-host proxy, not a fleet:

```
goproxy_build_info{version,commit,go_version}                       gauge
goproxy_requests_total{rule,action,method,status}                   counter
goproxy_request_duration_seconds{rule,action}                       histogram
goproxy_request_size_bytes{rule}                                    histogram
goproxy_response_size_bytes{rule}                                   histogram
goproxy_in_flight_requests{rule}                                    gauge
goproxy_upstream_requests_total{upstream,target,status}             counter
goproxy_upstream_duration_seconds{upstream,target}                  histogram
goproxy_upstream_healthy{upstream,target}                           gauge
goproxy_upstream_retries_total{upstream}                            counter
goproxy_auth_failures_total{rule,method}                            counter
goproxy_ratelimit_dropped_total{rule}                               counter
goproxy_tls_handshakes_total{version,result}                        counter
goproxy_tls_cert_expiry_seconds{subject}                            gauge
goproxy_config_reload_total{result}                                 counter
goproxy_config_last_reload_timestamp_seconds                        gauge
goproxy_panics_total                                                counter
```

Cardinality is bounded by construction: labels are rule names, upstream names,
target URLs and status codes — all fixed by the config. **No path, host, or
client-IP labels**, which is how proxies usually blow up a Prometheus server.
`goproxy_tls_cert_expiry_seconds` is included because "the certificate expired"
is the single most common way a small deployment goes down.

## 6.5 Admin listener

A separate listener (`admin.addr`, default off, bound to loopback when on),
never reachable through the routing table:

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Liveness. 200 as long as the process is running. |
| `GET /readyz` | Readiness. 503 while starting, while shutting down, or when every target of a required upstream is unhealthy. |
| `GET /metrics` | Prometheus. |
| `GET /config` | The resolved config with defaults applied and **secrets redacted**. |
| `POST /reload` | Same as `SIGHUP`; returns the validation error on rejection. |
| `GET /debug/pprof/*` | Opt-in, off by default. |

Keeping these off the main listener matters: today there is no way to expose a
health endpoint at all, and putting one on the routed listener means it either
collides with a catch-all rule or has to be special-cased ahead of the rules.

## 6.6 Diagnosing routing

`goproxy config explain --url https://app.example.com/api/v1/users` prints the
match decision:

```
rules[0] "api"      SKIP  host "*.example.com" matched, path "/api" did not match "/api/v1/users"? no — matched
                    MATCH → proxy upstream=app strip_prefix=/api
                            → http://10.0.0.1:8081/v1/users
```

and at `log.level: detail`, the same reasoning is emitted per request. "Why did
my rule not match" is the most common question a rules-in-order proxy generates,
and it currently has no answer short of reading `rules.go:220`.
