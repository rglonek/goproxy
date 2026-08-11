# 2. Goals, non-goals and principles

## 2.1 What goproxy is for

The deployment goproxy is good at, and should stay good at: **one small binary
in front of a handful of services on one host**, configured by a file a person
wrote by hand, run by systemd. Home labs, single-VM side projects, internal
tools, a box that terminates TLS for three containers. That is a real and
underserved niche — the alternatives are either much heavier (nginx, Traefik,
Envoy) or much less capable (a 40-line `httputil` script).

Everything below is chosen to serve that user. Where a decision trades
"scales to a thousand nodes" against "an operator can read the config and the
log and understand what happened", the second wins.

## 2.2 Goals

**G1 — Safe by default.** A config that says "listen on :8080 and proxy to
:8081" should produce a server with timeouts, size limits, sane TLS, no
credential leakage into logs, and correct forwarded headers, without the
operator knowing those things exist.

**G2 — Fails loudly.** Any error that leaves goproxy unable to serve what the
config asked for must reach the operator: at startup, as a non-zero exit; at
runtime, as an error-level log and a non-zero exit unless the operator chose
degraded operation. No more "started successfully" with a dead listener (R2).

**G3 — Testable in pieces.** Every stage of the request path is a value that
can be constructed in a test and exercised with `httptest` in a few lines.
Target: the serving path has meaningful unit tests, plus end-to-end tests
that start a real server on a real port and drive it with a real client.

**G4 — Backwards compatible.** Every `v0.1.0` config file continues to load and
behave the same way, with the exception of behaviour changes that are bug fixes
(see [04-configuration.md](04-configuration.md#46-behaviour-changes)). Operators
upgrade the binary and nothing breaks.

**G5 — Observable.** An operator can answer "is it up", "what is it doing",
"why was that request slow", and "why did that request get a 403" from the
logs and metrics, without adding a debugger.

**G6 — Deliver the FUTURE.md features.** Multiple targets per rule with load
balancing and failover, and a path to external auth. These should fall out of
the new model, not be grafted onto it.

**G7 — Reloadable.** `SIGHUP` (and an admin endpoint) applies a new config
without dropping connections. Bad configs are rejected and the old one stays
live.

## 2.3 Non-goals

**N1 — Not a service mesh.** No xDS, no service discovery integrations, no
distributed tracing backends beyond propagating standard headers, no
clustering. If you need those, you need Envoy.

**N2 — Not a WAF.** Rate limiting and IP allow/deny lists are in scope as blunt
instruments; request inspection, signature matching and bot detection are not.

**N3 — Not a plugin host.** No Lua, no WASM, no Go plugins. The extension story
is "fork it, or hand off to another process" (`FUTURE.md`'s external-auth idea).
Compile-time extensibility for people vendoring the library is enough.

**N4 — Not a caching proxy.** No response cache in v1 of the redesign. It is a
plausible later addition and the architecture should not preclude it, but
caching correctly is a project of its own.

**N5 — No breaking config change forced on anyone.** A `v2` schema may be
offered, but `v1` is supported indefinitely, not deprecated on a timer.

**N6 — No new runtime dependencies.** Single static binary, no sidecar, no
database, no required network egress except ACME when Let's Encrypt is enabled.

## 2.4 Design principles

1. **Parse, don't validate — then compile.** Config parsing produces a
   validated data structure with no behaviour. Compilation turns it into
   runtime objects (regexes, transports, handlers) and is where "this cannot
   work" is discovered. The serving path receives only compiled objects and
   never re-checks or re-parses anything per request.

2. **The hot path allocates nothing it does not have to.** Matching, header
   rewriting and logging are per-request; they get pre-computed structures, not
   string operations over config values.

3. **Immutable routing tables, swapped atomically.** Reload builds a whole new
   table and replaces a pointer. No locks on the request path, no half-applied
   config.

4. **Errors carry context.** `rules[2].proxy_rule.proxy_url: must be an
   absolute http(s) URL, got "garbage"` — the path to the offending field, what
   was expected, and what was found. The existing rule-index prefixes are the
   model; extend them to full field paths.

5. **Explicit over clever.** Prefix stripping is a prefix strip, not a regex
   substitution (C3). Auth outcome is a typed result, not a string compared
   against `"None"` (A1).

6. **The library API is a supported product.** `pkg/proxy` is importable;
   exported types are named, documented and stable. No exported function
   returns an unexported type (A3).

## 2.5 Definition of done

The redesign is complete when:

* Every finding in [01-current-state.md](01-current-state.md) is fixed or
  explicitly accepted with a reason recorded here.
* Every example config in `examples/` runs against the new binary unchanged and
  produces the same observable behaviour, verified by an automated test.
* `go test ./...` covers the serving path end to end, including TLS, auth
  failure modes, path rewriting, and reload.
* CI runs build, vet, staticcheck, race-enabled tests and a govulncheck on
  every push.
* The README documents the safe defaults and how to override them.
