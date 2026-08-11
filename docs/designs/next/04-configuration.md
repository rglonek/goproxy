# 4. Configuration

## 4.1 Principles

* **v1 configs keep working forever.** Not deprecated, not warned about.
* **v2 is opt-in**, selected by an explicit `version: 2` key. Absent key = v1.
* Both versions decode into the same internal schema, so there is exactly one
  validator and one compiler. v1 is an adapter, not a parallel implementation.
* **Unknown keys are an error in v2** (`yaml.Decoder.KnownFields(true)`),
  fixing A5. In v1 they stay a warning, because making them fatal would break
  working configs — but they are now *logged* at startup instead of silently
  dropped as they are today.

## 4.2 Why a v2 at all

Three things v1's shape cannot express without becoming contradictory:

1. **Multiple upstream targets.** `proxy_url` is a string. Load balancing needs
   a list, plus a policy, plus health-check settings.
2. **Repetition.** Every rule repeats its auth block, its header rewrites, its
   TLS behaviour. There is no way to say "these six rules share this auth".
3. **Prefix noise.** Inside `proxy_rule:` every key is prefixed `proxy_`
   (`proxy_url`, `proxy_append_path`, `proxy_set_headers`), which is redundant
   once nested and makes the fields longer than they need to be.

If the maintainers would rather not carry two schemas, §4.7 describes a
smaller "v1.5" alternative. This is [open question Q1](09-open-questions.md).

## 4.3 v2 schema — worked example

```yaml
version: 2

log:
  level: info              # detail|debug|info|warn|error|fatal|none (v1 names kept)
  format: json             # json|text
  access:
    enabled: true
    exclude_paths: ["/healthz"]

listeners:
  http:
    addr: ":80"
    redirect_to_https: true          # v1 did this implicitly whenever tls was set
  https:
    addr: ":443"
    tls:
      min_version: "1.2"
      certs:
        - cert_file: /etc/ssl/site.crt
          key_file:  /etc/ssl/site.key
      # or:
      # acme:
      #   email: ops@example.com
      #   domains: [example.com, www.example.com]
      #   cache_dir: /var/lib/goproxy/acme
      hsts:
        enabled: true
        max_age: 31536000

admin:
  addr: "127.0.0.1:9090"     # never routed to; metrics + health + reload live here
  metrics: true

defaults:                     # applied to every rule unless overridden
  timeouts:
    read_header: 10s
    read: 30s
    write: 60s
    idle: 120s
  limits:
    max_request_body: 32MiB
    max_header_bytes: 1MiB

auth:                         # named, reusable — referenced by rules
  staff:
    basic:
      users:
        - user: alice
          password_hash: "$2y$10$..."        # bcrypt
        - user: bob
          password_file: /etc/goproxy/bob.pw # or a literal `password:`
      realm: "Internal"
      forward_user_header: X-User
  api:
    token:
      header: X-TOKEN
      tokens:
        - id: ci               # id is what appears in logs; the token never does
          value_env: CI_TOKEN
        - id: legacy
          value: "s3cr3t"
      forward: false

upstreams:
  app:
    targets:
      - url: http://10.0.0.1:8081
        weight: 2
      - url: http://10.0.0.2:8081
    policy: round_robin        # round_robin|least_conn|ip_hash|first_healthy
    health:
      passive:
        failures: 3
        cooldown: 30s
      active:
        path: /healthz
        interval: 10s
    retry:
      attempts: 2
      on: [connect_error, 502, 503, 504]
      budget: 10%              # cap retries at 10% of live traffic
    tls:
      insecure_skip_verify: false
      ca_file: /etc/ssl/internal-ca.pem   # pinning — impossible in v1

rules:
  - name: api                  # optional; appears in logs and metrics (fixes A4)
    match:
      host: "*.example.com"    # exact | *.wildcard | ^regex
      path: "/api"
      path_mode: prefix        # prefix|exact|segment|regex
      methods: [GET, POST]     # new
    auth: api                  # reference into the `auth:` block
    proxy:
      upstream: app
      strip_prefix: "/api"     # explicit; replaces proxy_append_path's inversion
      host_header: "api.internal"
      request_headers:
        set:    { X-Env: prod }
        remove: ["User-Agent", "^Sec-.*"]
      response_headers:
        set:    { X-Frame-Options: DENY }

  - name: static
    match: { host: "static.example.com" }
    serve:
      dir: /var/www/html
      index: [index.html]
      list_directories: false  # default; v1 always listed (S8)
      cache_control: "public, max-age=3600"

  - name: moved
    match: { path: "/old" }
    redirect:
      to: "https://example.com/new{path}"
      status: 308

  - name: catch-all
    respond:
      status: 404
      body: "<h1>Not found</h1>"
      content_type: "text/html; charset=utf-8"   # v1 forced text/plain (C2)
```

## 4.4 v1 → v2 mapping

The adapter is mechanical. Every v1 key has exactly one v2 home:

| v1 | v2 |
| --- | --- |
| `listen_addr` | `listeners.http.addr` |
| `tls.listen_addr` | `listeners.https.addr` |
| `tls.certs.{cert_file,key_file}` | `listeners.https.tls.certs[0]` |
| `tls.lets_encrypt` | `listeners.https.tls.acme` |
| `log_level` | `log.level` |
| `rules[].domain_match` | `rules[].match.host` |
| `rules[].path_match` | `rules[].match.path` (+ `path_mode: regex` if `^`-prefixed) |
| `rules[].basic_auth` | inline `rules[].auth.basic` with a one-entry `users` list |
| `rules[].token_auth` | inline `rules[].auth.token` |
| `rules[].proxy_rule.proxy_url` | `rules[].proxy.upstream` (inline one-target pool) |
| `proxy_append_path: false` | `strip_prefix: <the rule's path_match>` |
| `proxy_append_path: true` | no `strip_prefix` |
| `proxy_rewrite_host_header` | `proxy.host_header` |
| `proxy_set_headers` / `proxy_remove_headers` | `proxy.request_headers.set` / `.remove` |
| `proxy_target_accept_self_signed` | `upstreams.<x>.tls.insecure_skip_verify` |
| `serve_rule.serve_local_dir` | `serve.dir` (with `list_directories: true` to keep v1 behaviour) |
| `redirect_rule.{redirect_url,redirect_status_code}` | `redirect.{to,status}` |
| `respond_rule.*` | `respond.{status,body,body_file}` |

Shipped as `goproxy config migrate -in old.yaml -out new.yaml`, which emits a
commented v2 file. Because the schema types are pure data (§3.2), this is a
decode-adapt-encode round trip with no special casing.

## 4.5 Validation

Errors get full field paths rather than the current rule-index prefix:

```
config.yaml: rules[2].proxy.upstream: no upstream named "aap" (did you mean "app"?)
config.yaml: rules[4]: unreachable — rules[1] is a catch-all
config.yaml: listeners.https.tls: certs and acme are mutually exclusive
config.yaml: upstreams.app.targets[1].url: must be an absolute http(s) URL, got "garbage"
```

Three validation modes, all built on the same `Load`+`Compile`:

* `goproxy -config c.yaml --check` — parse, validate, compile, exit. No
  listeners bound, no directories created (C8), no ACME contact.
* `goproxy config explain -config c.yaml --url https://host/path` — print
  which rule matches a given request and what it would do. This is the answer
  to "why is my rule not matching", which today requires reading the source.
* `goproxy config dump` — print the fully resolved config with defaults
  applied, so an operator can see what the safe defaults actually set.

## 4.6 Behaviour changes

These are the only cases where an existing config behaves differently. Each is
a bug fix, and each is listed in the release notes with an escape hatch.

| Change | Why | Opt-out |
| --- | --- | --- |
| Timeouts now apply (R1) | A proxy without timeouts is not safe to expose | Set them to `0` explicitly |
| Host matching is case-insensitive (C7) | Host headers are case-insensitive per RFC 9110 | none — the old behaviour is a bug |
| `respond_body` honours `content_type` (C2) | v1 forced `text/plain` and appended `\n` | Set `content_type: text/plain; charset=utf-8` |
| Directory listings off by default (S8) | Accidental disclosure | `list_directories: true` |
| `X-Forwarded-Proto`/`-Host` now sent (S5) | Backends need them behind TLS termination | `forwarded: none` on the rule |
| Inbound `X-Forwarded-For` dropped from untrusted peers (S6) | Spoofable today | list the peer in `trusted_proxies` |
| Failed tokens no longer logged (S2) | Credential leak | none |
| Bad certificates fail at startup (R2) | v1 started with a dead HTTPS listener | none |
| Unknown v1 keys logged as warnings (A5) | v1 dropped them silently | `--no-warn-unknown` |

Everything else — rule ordering, prefix semantics, `proxy_append_path`
inversion, the `X-TOKEN` default header, `WWW-Authenticate` values — is
preserved bit for bit for v1 configs, including the quirks, because configs in
the wild may depend on them. Where a v1 quirk is genuinely wrong (C5's
`WWW-Authenticate: Bearer` for a header goproxy does not read), v2 fixes it and
v1 keeps it.

## 4.7 Alternative: no v2

If two schemas is too much to carry, the minimum viable alternative is to
extend v1 in place, additively:

* `rules[].name`
* `rules[].proxy_rule.proxy_urls` (list) alongside `proxy_url`, plus
  `proxy_policy` and `proxy_health`
* `rules[].basic_auth.users` (list) alongside `user`/`password`
* `rules[].respond_rule.respond_content_type` and `respond_headers`
* `rules[].serve_rule.serve_list_directories`
* top-level `timeouts:`, `limits:`, `admin:`, `trusted_proxies:`

This gets every capability with no migration and no adapter, at the cost of a
config file that reads like it accreted — `proxy_url` and `proxy_urls` side by
side, `user` and `users` side by side. It is a legitimate trade; see
[Q1](09-open-questions.md).

The architecture in [03-architecture.md](03-architecture.md) is unaffected
either way. The schema/runtime split is what matters; the surface syntax is a
separate decision that can be made after the internals land.
