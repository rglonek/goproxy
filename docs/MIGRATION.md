# Migrating a v0.x config to v2

The configuration schema changed shape in v2. A v0.x file is detected and
refused with a pointer to this page rather than half-understood:

```
config: config.yaml: this looks like a goproxy v0.x config file; the schema
changed in v2, see docs/MIGRATION.md
```

Every v0.x capability is still there. The changes are structural: listeners are
named rather than implied, auth and upstreams are defined once and referenced by
name, and each key lives under the section it belongs to instead of carrying a
prefix.

Check your translation before you deploy it:

```bash
goproxy -config config.yaml -check
goproxy -config config.yaml explain https://app.example.com/api/v1
```

## The whole file at a glance

v0.x:

```yaml
log_level: info
listen_addr: ":80"
tls:
  listen_addr: ":443"
  certs:
    cert_file: /etc/ssl/site.crt
    key_file: /etc/ssl/site.pem
rules:
  - domain_match: "app.example.com"
    path_match: "/api"
    token_auth:
      tokens: ["s3cr3t"]
      token_auth_header: "X-TOKEN"
      forward_header: false
    proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
      proxy_append_path: false
      proxy_rewrite_host_header: "app.internal"
      proxy_set_headers:
        X-Env: prod
      proxy_remove_headers: ["User-Agent"]
  - serve_rule:
      serve_local_dir: /var/www/html
  - respond_rule:
      respond_status_code: 404
      respond_body: "Not Found"
```

v2:

```yaml
version: 2

log:
  level: info

listeners:
  http:
    addr: ":80"
  https:
    addr: ":443"
    tls:
      certs:
        - cert_file: /etc/ssl/site.crt
          key_file: /etc/ssl/site.pem

auth:
  api:
    token:
      header: "X-TOKEN"
      forward: false
      tokens:
        - id: legacy
          value: "s3cr3t"

rules:
  - name: api
    match:
      host: "app.example.com"
      path: "/api"
    auth: api
    proxy:
      url: "http://127.0.0.1:8081"
      strip_prefix: "/api"
      host_header: "app.internal"
      request_headers:
        set:
          X-Env: prod
        remove: ["User-Agent"]

  - name: sites
    serve:
      dir: /var/www/html

  - name: catch-all
    respond:
      status: 404
      body: "Not Found"
```

## Key by key

| v0.x | v2 |
| --- | --- |
| *(nothing)* | `version: 2` — required |
| `listen_addr` | `listeners.http.addr` |
| `tls.listen_addr` | `listeners.https.addr` |
| `tls.certs.{cert_file,key_file}` | `listeners.https.tls.certs[0]` (now a list, selected by SNI) |
| `tls.lets_encrypt` | `listeners.https.tls.acme` |
| `log_level` | `log.level` (same names, plus `log.format` and `log.access`) |
| `rules[].domain_match` | `rules[].match.host` |
| `rules[].path_match` | `rules[].match.path` (+ `path_mode: regex` when it started with `^`) |
| `rules[].basic_auth` | a named block under `auth:`, referenced by `rules[].auth` |
| `basic_auth.user` / `.password` | `auth.<name>.basic.users[]` — now a list, so a rule can have several users |
| `basic_auth.set_user_header` | `auth.<name>.basic.forward_user_header` |
| `basic_auth.set_user_get_var` | `auth.<name>.basic.forward_user_query` |
| `rules[].token_auth` | `auth.<name>.token` |
| `token_auth.tokens` | `auth.<name>.token.tokens[].value` (each with an `id` for the logs) |
| `token_auth.token_auth_header` | `auth.<name>.token.header` |
| `token_auth.forward_header` | `auth.<name>.token.forward` |
| `rules[].proxy_rule.proxy_url` | `rules[].proxy.url`, or `rules[].proxy.upstream` for several targets |
| `proxy_append_path: false` | `proxy.strip_prefix: <the rule's path>` |
| `proxy_append_path: true` | nothing — the path is forwarded as it arrived |
| `proxy_rewrite_host_header` | `proxy.host_header` |
| `proxy_set_headers` | `proxy.request_headers.set` |
| `proxy_remove_headers` | `proxy.request_headers.remove` |
| `proxy_target_accept_self_signed` | `upstreams.<name>.tls.insecure_skip_verify` (or pin a CA with `ca_file`) |
| `rules[].serve_rule.serve_local_dir` | `rules[].serve.dir` |
| `rules[].redirect_rule.redirect_url` | `rules[].redirect.to` |
| `rules[].redirect_rule.redirect_status_code` | `rules[].redirect.status` |
| `rules[].respond_rule.respond_status_code` | `rules[].respond.status` |
| `rules[].respond_rule.respond_body` | `rules[].respond.body` |
| `rules[].respond_rule.respond_body_file` | `rules[].respond.body_file` |

## Behaviour that changed with the schema

| Change | What to do about it |
| --- | --- |
| Unknown keys are an error | A typo now stops startup instead of being ignored; `-check` finds them |
| `proxy_append_path` is gone | The path is forwarded unchanged by default; use `strip_prefix` to remove the matched prefix |
| Host matching is case-insensitive and ignores a trailing dot | Nothing; the old behaviour was a bug |
| `path_match` prefix semantics are still the default | `/api` still matches `/apifoo`; use `path_mode: segment` if you did not want that |
| Directory listings are off | `serve.list_directories: true` to keep the old behaviour |
| Dotfiles are not served | `serve.allow_dotfiles: true` to keep the old behaviour |
| `respond.body` is sent verbatim with a detected content type | v0.x forced `text/plain` and appended a newline; set `content_type` if you relied on it |
| Inbound `X-Forwarded-*` is dropped from untrusted peers | List your upstream proxy in `trusted_proxies` |
| `Authorization: Bearer <token>` is accepted for token auth | `accept_bearer: false` to only read the configured header |
| Timeouts and a 32MiB body cap apply | Override or disable them under `defaults` |
| A 1xx `respond.status` is refused | It left the client waiting for a final status that never came |

## Things you could not express before

* **Several targets per rule**, with a load-balancing policy, health checking
  and a retry budget: `upstreams` (see
  [examples/08-load-balancing.yaml](../examples/08-load-balancing.yaml)).
* **Several users per rule**, bcrypt password hashes, and secrets from a file or
  the environment: `auth` (see [examples/04-auth.yaml](../examples/04-auth.yaml)).
* **Handing the auth decision to another service**: `auth.<name>.forward`.
* **An admin listener** with health, metrics, the resolved config and reload.
* **Rate limits, IP allow/deny lists, method lists and CORS**, per rule.
* **Several certificates with SNI, mutual TLS and HSTS.**
* **Reload without dropping connections**: `SIGHUP` or `POST /reload`.
