# GoProxy

A high-performance HTTP/HTTPS proxy server written in Go, designed for reverse proxy, load balancing, and request forwarding scenarios.

## Features

- **HTTP/HTTPS Proxy**: Full support for both HTTP and HTTPS protocols
- **Serving Static Files**: Serve static files from a local directory
- **Redirects**: Redirect certin endpoints to different targets
- **Serve a custom response**: Server a custom response code and message
- **Authentication**: Support for token and user basic auth
- **Header management**: Allow removal, override and forwarding of headers and user names
- **Reverse Proxy**: Route requests to backend services
- **Request Filtering**: Filter requests based on various criteria
- **SSL/TLS Termination**: Handle SSL certificates and termination
- **Logging**: Comprehensive request and error logging
- **Configuration**: YAML-based configuration for easy setup
- **Safe defaults**: Timeouts, request size limits, TLS 1.2 minimum, correct
  `X-Forwarded-*` handling and no credentials in logs, without configuring
  anything ([see below](#safe-defaults))

## Quick Start

### Download Binaries

Download the latest release from the [releases page](https://github.com/yourusername/goproxy/releases) for your platform.

### Basic Usage

1. Create a `config.yaml` file with your configuration
2. Check it without starting anything:
   ```bash
   ./goproxy -config config.yaml -check
   ```
3. Run the proxy server:
   ```bash
   ./goproxy -config config.yaml
   ```

The smallest config that does something useful — forward every request to a
backend on port 8081:

```yaml
listen_addr: ":8080"
rules:
  - proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
      proxy_append_path: true
```

Serve a directory instead:

```yaml
listen_addr: ":8080"
rules:
  - serve_rule:
      serve_local_dir: "/var/www/html"
```

Route by host and path, with a catch-all last (rules are evaluated in order and
the first match wins):

```yaml
listen_addr: ":8080"
rules:
  - domain_match: "app.example.com"
    path_match: "/api"
    proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
      proxy_append_path: true
  - domain_match: "static.example.com"
    serve_rule:
      serve_local_dir: "/var/www/html"
  - respond_rule:
      respond_status_code: 404
      respond_body: "Not Found"
```

More runnable examples — auth, TLS, Let's Encrypt, regex matching — are in
[examples/](examples/), one config per topic.

### Full Example Configuration

```yaml
log_level: info
listen_addr: ":8080" # if using letsencrypt, this must be :80
#tls:
#  listen_addr: ":443"
#  lets_encrypt:
#    email: "glonek@gmail.com"
#    domains:
#      - "localhost"
#      - "home.glonek.io"
#    cache_dir: "/var/lib/goproxy/letsencrypt"
#  certs:
#    cert_file: "snakeoil.crt"
#    key_file: "snakeoil.key"
rules:
  # proxy rule
  - domain_match: 'localhost'
    path_match: "/proxy"
    token_auth:
      tokens:
        - "token1"
        - "token2"
      token_auth_header: "X-TOKEN"
      forward_header: true
    basic_auth:
      user: "admin"
      password: "password"
      set_user_header: "X-USER"
      set_user_get_var: "userget"
    proxy_rule:
      proxy_url: "http://127.0.0.1:8081/service"
      proxy_target_accept_self_signed: false
      # if true, request will be http://127.0.0.1:8081/service/proxy/{path}
      # if false, request will be http://127.0.0.1:8081/service/{path}
      proxy_append_path: true
      proxy_remove_headers:
        - "User-Agent"
        - '^Sec-.*'
      proxy_set_headers:
        "X-BOB": "testcustomheader"
      proxy_rewrite_host_header: "example.com"
  # redirect rule
  - domain_match: 'localhost'
    path_match: "/redirect"
    redirect_rule:
      redirect_url: "http://192.168.4.32/bob"
      redirect_status_code: 301
  # serve rule
  - domain_match: 'localhost'
    path_match: "/serve"
    serve_rule:
      serve_local_dir: "./"
  # catch all, use respond_rule
  - respond_rule:
      respond_status_code: 403
      respond_body: "Forbidden"
```

## Safe defaults

goproxy applies these without being asked. Every one of them can be overridden,
and setting a timeout to `0` disables it.

| Setting | Default | What it protects against |
| --- | --- | --- |
| `timeouts.read_header` | `10s` | A client that dribbles headers forever (Slowloris) |
| `timeouts.read` | `30s` | A slow request body |
| `timeouts.write` | `60s` | A slow reader holding a connection open |
| `timeouts.idle` | `120s` | Keep-alive connections piling up |
| `timeouts.shutdown` | `30s` | A shutdown that never finishes |
| `limits.max_header_bytes` | `1MiB` | Oversized header blocks |
| `limits.max_request_body` | `32MiB` | Unbounded uploads (`413` over the limit) |
| `tls.min_version` | `1.2` | Obsolete TLS versions |
| `serve_rule.serve_list_directories` | `false` | Accidentally listing a directory |
| `trusted_proxies` | empty | `X-Forwarded-For` spoofing by direct clients |

The write timeout would cut off a long-lived response, so it is not applied to
connection upgrades (websockets, detected automatically) or to rules marked
`streaming: true` (server-sent events, large downloads over slow links).

`trusted_proxies` decides whether goproxy believes the `X-Forwarded-*` headers
a peer sends. From a peer that is not listed, those headers are dropped and
replaced with values taken from the connection itself, and a warning naming the
peer is logged once. If goproxy runs behind another proxy, list that proxy's
address there:

```yaml
trusted_proxies:
  - 127.0.0.1/32
  - 10.0.0.0/8
```

## Configuration Reference

The configuration file uses YAML format and supports the following options:

### Top Level Options

- `log_level`: (string) Logging level. Valid values: "detail", "debug", "info", "warn", "error", "fatal" (also accepted as "fail"), "none"
- `listen_addr`: (string) Address and port to listen on for HTTP (e.g. ":8080"); if using letsencrypt in the TLS section, this must be set to ":80". May be omitted to serve HTTPS only, in which case `tls.listen_addr` is required
- `trusted_proxies`: (array) IPs or CIDRs of peers whose `X-Forwarded-*` headers are believed; empty by default
- `on_listener_error`: (string) `shutdown` (default) stops the server when a listener fails; `continue` keeps the other listener serving
- `timeouts`: (object) durations, written as `10s`, `1m30s` or a plain number of seconds
  - `read_header`, `read`, `write`, `idle`, `shutdown`: server timeouts (see [Safe defaults](#safe-defaults))
  - `upstream_dial` (10s), `upstream_tls_handshake` (10s), `upstream_response_header` (30s): applied when proxying
- `limits`: (object) sizes, written as a number of bytes or as `32MiB`, `1MB`, `64KiB`
  - `max_header_bytes`: (size) largest accepted request header block
  - `max_request_body`: (size) largest accepted request body; `0` disables the limit
- `tls`: (object) TLS configuration
  - `listen_addr`: (string) Address and port to listen on for HTTPS (e.g. ":443"); required when a `tls` section is present
  - `min_version` / `max_version`: (string) `1.0`, `1.1`, `1.2` or `1.3`; minimum defaults to `1.2`
  - `lets_encrypt`: (object) Let's Encrypt configuration
    - `email`: (string) Email address for Let's Encrypt registration
    - `domains`: (array) List of domains to obtain certificates for
    - `cache_dir`: (string) Directory to store Let's Encrypt cache/certificates; created at startup
  - `certs`: (object) Manual TLS certificate configuration
    - `cert_file`: (string) Path to certificate file
    - `key_file`: (string) Path to private key file

  The certificate is loaded and parsed at startup: a certificate that cannot be
  used is a startup error, not a listener that fails every handshake. `SIGHUP`
  re-reads it, so a renewal does not need a restart.

### Rules

The `rules` section contains an array of rule objects that define how requests should be handled. Rules are evaluated in order and the first matching rule is used.

Each rule can have the following fields:

- `name`: (string) Optional name for the rule; it appears in log lines instead of `rules[N]`, so inserting a rule does not renumber every line
- `domain_match`: (string) Domain name to match against request Host header; begin with '^' to use regex. Matching is case-insensitive
- `path_match`: (string) Path prefix or regex to match against request URL path; begin with '^' to use regex
- `streaming`: (bool) The rule's responses are long-lived (server-sent events, large downloads); the write timeout is not applied to them
- `token_auth`: (object) Token-based authentication
  - `tokens`: (array) List of valid tokens
  - `token_auth_header`: (string) Header name to check for token (default: "X-TOKEN")
  - `accept_bearer`: (bool) Also accept the token as `Authorization: Bearer <token>`
  - `forward_header`: (bool) Whether to forward auth header to backend (proxy target only). When false, the header is stripped whether the token was accepted or rejected
- `basic_auth`: (object) HTTP Basic authentication
  - `user`: (string) Username
  - `password`: (string) Password  
  - `realm`: (string) Realm sent in the `WWW-Authenticate` challenge (default: "Restricted")
  - `set_user_header`: (string) Optional header to set with authenticated username (proxy target only)
  - `set_user_get_var`: (string) Optional GET parameter to set with authenticated username (proxy or static file hosting targets only)

Credentials are compared in constant time, and a credential a client presented
is never written to the log, at any level.

Rules must specify exactly one of the following actions:

#### proxy_rule
Proxies requests to another server
- `proxy_url`: (string, required) Target URL to proxy requests to
- `proxy_target_accept_self_signed`: (bool) Whether to accept self-signed certificates
- `proxy_append_path`: (bool) Whether to append matched path to target URL
- `proxy_remove_headers`: (array) Headers to remove from request
- `proxy_set_headers`: (object) Headers to add/override in request
- `proxy_rewrite_host_header`: (string) Override Host header sent to target

#### redirect_rule  
Redirects requests to another URL
- `redirect_url`: (string, required) URL to redirect to
- `redirect_status_code`: (int, required) HTTP status code for redirect; must be 3xx (e.g. 301, 302)

The request is proxied with `X-Forwarded-For`, `X-Forwarded-Host`,
`X-Forwarded-Proto` and `X-Real-Ip` set from the connection, subject to
`trusted_proxies`. The Host header the client sent is forwarded unchanged unless
`proxy_rewrite_host_header` says otherwise.

#### serve_rule
Serves files from local directory
- `serve_local_dir`: (string, required) Local directory path to serve files from; must exist at startup
- `serve_index`: (array) File names tried for a directory (default: `["index.html"]`)
- `serve_list_directories`: (bool) Generate an index page for a directory with no index file (default: false)
- `serve_allow_dotfiles`: (bool) Serve names starting with a dot, such as `.git` and `.env` (default: false)
- `serve_cache_control`: (string) Value of the `Cache-Control` response header

The directory is opened once at startup and served through it, so a symlink
pointing outside the directory is refused by the kernel rather than followed.

#### respond_rule
Returns a static response; specify either a body string or file:
- `respond_status_code`: (int, required) HTTP status code to return
- `respond_body`: (string) Response body content
- `respond_body_file`: (string) File to read response body from; read once at startup
- `respond_body_file_reload`: (bool) Re-read `respond_body_file` on every request
- `respond_content_type`: (string) `Content-Type` of the response; detected from the body when unset
- `respond_headers`: (object) Additional response headers

## Troubleshooting

The configuration is validated at startup; goproxy prints the reason and exits
rather than starting with a config it cannot honour. `-check` does the same
without binding a port, creating a directory or contacting anything. Errors in
the `rules` list are prefixed with the index of the rule that caused them,
counting from zero (and its `name`, if it has one):

```
Error parsing config file: rules[2]: proxy_rule: proxy_url is required
```

Unknown keys in the configuration file are reported as warnings at startup and
then ignored, so a misspelled option says so:

```
WARNING unknown config key ignored: line 6: field proxy_append_paths not found in type proxy.ProxyRule
```

A list of the common validation errors and what causes them is in
[examples/README.md](examples/README.md#config-errors).

## Signals and exit codes

| Signal | Effect |
| --- | --- |
| `SIGINT`, `SIGTERM` | Graceful shutdown: stop accepting, wait for in-flight requests up to `timeouts.shutdown`, then close |
| `SIGHUP` | Re-read the TLS certificate files (config reload is not implemented yet) |

goproxy exits non-zero when the config cannot be loaded, when a listener cannot
be bound, and when a listener stops on its own. It does not stay alive with a
dead listener.
