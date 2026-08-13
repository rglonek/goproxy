# Examples

Small, single-purpose configs. Each one runs on its own (in a release tarball
this directory is `config-examples/`):

```bash
./goproxy -config examples/01-reverse-proxy.yaml -check   # validate it
./goproxy -config examples/01-reverse-proxy.yaml          # run it
```

Several examples proxy to `http://127.0.0.1:8081`. The repository ships a test
backend that logs whatever it receives, which is handy for checking headers and
query parameters:

```bash
go run ./test/logwww    # listens on :8081
```

| File | What it shows |
| --- | --- |
| [01-reverse-proxy.yaml](01-reverse-proxy.yaml) | Forward everything to one backend |
| [02-serve-static-files.yaml](02-serve-static-files.yaml) | Serve a local directory |
| [03-redirect-and-respond.yaml](03-redirect-and-respond.yaml) | Redirects, canned responses, rule ordering |
| [04-auth.yaml](04-auth.yaml) | Basic auth, token auth, and forward auth |
| [05-virtual-hosts.yaml](05-virtual-hosts.yaml) | Routing by host and path: exact, wildcard, regex |
| [06-https.yaml](06-https.yaml) | TLS with your own certificate, mutual TLS, HSTS |
| [07-lets-encrypt.yaml](07-lets-encrypt.yaml) | Automatic certificates from Let's Encrypt |
| [08-load-balancing.yaml](08-load-balancing.yaml) | Several targets, health checking, retries |
| [09-hardening-and-observability.yaml](09-hardening-and-observability.yaml) | Every default written out, plus the admin listener |

The full set of options is the configuration reference in the
[main README](../README.md). Upgrading from v0.x? See
[docs/MIGRATION.md](https://github.com/rglonek/goproxy/blob/main/docs/MIGRATION.md),
which is in the repository rather than the release tarball.

## Things worth knowing

* **Rules are ordered.** The first rule whose `match` applies handles the
  request. A rule with no `match` matches everything, so keep catch-alls last.
  `goproxy -config <file> explain <url>` prints the decision rule by rule.
* **Exactly one action per rule.** `proxy`, `serve`, `redirect` and `respond`
  are mutually exclusive.
* **Unknown keys are an error.** A misspelled option stops startup rather than
  being silently ignored; `-check` finds them without binding a port.
* **The defaults are safe.** Timeouts, a request body cap, TLS 1.2 minimum, no
  directory listings and no credentials in logs apply whether or not the config
  mentions them; see
  [09-hardening-and-observability.yaml](09-hardening-and-observability.yaml).

## Config errors

The config is compiled at startup and goproxy exits with the reason, naming the
field:

```
config: config.yaml: rules[2] (api).proxy.upstream: no upstream named "aap" (did you mean "app"?)
```

Common ones:

| Message | Cause |
| --- | --- |
| `this looks like a goproxy v0.x config file` | The schema changed in v2; see [docs/MIGRATION.md](../docs/MIGRATION.md) |
| `version: must be 2, got N` | Every config file starts with `version: 2` |
| `field <name> not found in type ...` | A misspelled or misplaced key |
| `listeners: at least one of http and https is required` | No listener configured |
| `rules[N].proxy.url: must be an absolute http(s) URL` | `url` needs a scheme and a host, e.g. `http://127.0.0.1:8081` |
| `rules[N].match.path: ... set path_mode: regex to use one` | A `^`-anchored pattern without `path_mode: regex` |
| `rules[N].serve.dir: does not exist` | The directory is missing, or the path is relative to a different working directory |
| `listeners.https.tls.acme: listeners.http.addr must end with :80` | Let's Encrypt needs port 80 for the http-01 challenge |
| `no upstream named "x" (did you mean "y"?)` | A typo in `proxy.upstream`, or a missing `upstreams` entry |
| `trusted_proxies[N]: must be an IP address or a CIDR` | Entries are `10.0.0.0/8` or `127.0.0.1`, not host names |
