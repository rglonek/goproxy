# Examples

Small, single-purpose configs. Each one runs on its own:

```bash
./goproxy -config examples/01-reverse-proxy.yaml
```

Several examples proxy to `http://127.0.0.1:8081`. The repo ships a test backend
that logs whatever it receives, which is handy for checking headers and GET vars:

```bash
go run ./test/logwww    # listens on :8081
```

| File | What it shows |
| --- | --- |
| [01-reverse-proxy.yaml](01-reverse-proxy.yaml) | Forward everything to one backend |
| [02-serve-static-files.yaml](02-serve-static-files.yaml) | Serve a local directory |
| [03-redirect-and-respond.yaml](03-redirect-and-respond.yaml) | Redirects, canned responses, rule ordering |
| [04-basic-auth.yaml](04-basic-auth.yaml) | HTTP basic auth in front of a backend |
| [05-token-auth.yaml](05-token-auth.yaml) | Static token auth on an API |
| [06-virtual-hosts.yaml](06-virtual-hosts.yaml) | Routing by host and path, exact and regex |
| [07-https-certs.yaml](07-https-certs.yaml) | TLS with your own certificate |
| [08-https-only.yaml](08-https-only.yaml) | HTTPS with no plain HTTP listener |
| [09-lets-encrypt.yaml](09-lets-encrypt.yaml) | Automatic certificates from Let's Encrypt |
| [10-hardening.yaml](10-hardening.yaml) | Timeouts, size limits, trusted proxies, streaming rules |

The full set of options, with every field documented, is the configuration
reference in the [main README](../README.md).

## Things worth knowing

* **Rules are ordered.** The first rule whose `domain_match` and `path_match`
  both match handles the request. A rule with neither matches everything, so
  keep catch-alls last.
* **`^` means regex.** `domain_match` and `path_match` are exact/prefix matches
  unless the value starts with `^`, in which case it is compiled as a regular
  expression.
* **Exactly one action per rule.** `proxy_rule`, `serve_rule`, `redirect_rule`
  and `respond_rule` are mutually exclusive.
* **Unknown keys are reported.** A misspelled option is logged as a warning at
  startup and then ignored:
  `WARNING unknown config key ignored: line 6: field proxy_append_paths not found in type proxy.ProxyRule`.
* **Check before you start.** `./goproxy -config <file> -check` loads, validates
  and compiles the config and exits, without binding a port or creating
  anything.
* **The defaults are safe.** Timeouts, a request body cap, TLS 1.2 minimum, no
  directory listings and no credentials in logs apply whether or not the config
  mentions them; see [10-hardening.yaml](10-hardening.yaml).

## Config errors

The config is validated at startup and goproxy exits with the reason. Rule
errors are reported with the index of the offending rule, counting from zero:

```
Error parsing config file: rules[2]: proxy_rule: proxy_url is required
```

Common ones:

| Message | Cause |
| --- | --- |
| `listen_addr is required (omit it only when tls.listen_addr is set...)` | No listener configured at all |
| `tls: listen_addr is required` | A `tls` section without its own `listen_addr` |
| `lets_encrypt requires listen_addr to end with :80...` | Let's Encrypt needs port 80 for the http-01 challenge |
| `invalid log level: ...` | Valid levels: `detail`, `debug`, `info`, `warn`, `error`, `fatal` (alias `fail`), `none` |
| `rules[N]: serve_rule: serve_local_dir does not exist` | The directory is missing, or the path is relative to a different working directory |
| `rules[N]: proxy_rule: proxy_url: must be an absolute http(s) URL` | `proxy_url` needs a scheme and a host, e.g. `http://127.0.0.1:8081` |
| `rules[N]: rule is empty` | A `-` list item with nothing under it |
| `tls: certs: tls: failed to find any PEM data...` | The certificate or key file is not a usable PEM pair |
| `trusted_proxies[N]: must be an IP address or a CIDR` | Entries are `10.0.0.0/8` or `127.0.0.1`, not host names |
