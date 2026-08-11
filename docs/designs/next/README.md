# goproxy "next" — redesign proposal

Status: **partially implemented**. [Phases 1 and 2](08-roadmap.md) — safe
defaults, lifecycle, the visible defects, tests and CI — are implemented; see
[CHANGELOG.md](../../../CHANGELOG.md) for what landed and what changed
behaviour. Phases 3 to 5 (the structural redesign, observability, and the new
capability) are still proposals, and Phase 3 is gated on
[Q2 and Q6](09-open-questions.md); Phase 5 is gated on
[Q1](09-open-questions.md).

The findings in [01-current-state.md](01-current-state.md) describe `v0.1.0` and
are left as written, so that the reasoning behind each change stays readable;
the ones fixed are listed in the changelog by their identifiers (R1, S5, C3 and
so on). Still open after phases 1 and 2: **A1** (the request path is a chain of
small stages now, but still one package and one `ServeHTTP` switch), **A2** (the
config struct still carries the compiled state), **O1**, **O2** and **O3**
(metrics, structured access logs, config reload).

## Why

goproxy today is ~950 lines of Go that does a genuinely useful job: YAML-driven
host/path routing to four terminal actions (proxy, serve, redirect, respond),
with basic and token auth, TLS certificates and Let's Encrypt. The feature set
is well chosen. The implementation, however, has grown as a single
`ServeHTTP` if-chain over a config struct that doubles as the runtime data
structure, and it carries a set of defaults that are unsafe to expose to a
network — most importantly, **no server timeouts at all** and **listener
errors that are discarded, leaving the process alive with a dead listener**.

This proposal takes the features as the requirement, and proposes a
reimplementation of the machinery underneath them: an explicit request
pipeline, a compiled routing table separate from the config schema, real
lifecycle management, and defaults that are safe out of the box. It also
proposes the features `FUTURE.md` already asks for (multiple targets per rule,
load balancing, failover) as first-class parts of the new model rather than
bolt-ons.

## How to read this

| Document | What it covers |
| --- | --- |
| [01-current-state.md](01-current-state.md) | Feature inventory of v0.1.0, and 21 findings with evidence from the running code |
| [02-goals.md](02-goals.md) | Goals, non-goals, design principles, and what "done" means |
| [03-architecture.md](03-architecture.md) | Proposed package layout, request pipeline, core interfaces, lifecycle and reload |
| [04-configuration.md](04-configuration.md) | Config v2 schema, worked examples, and v1 compatibility/migration |
| [05-robustness-and-security.md](05-robustness-and-security.md) | Timeouts, limits, TLS policy, auth, forwarded headers, failure semantics |
| [06-observability.md](06-observability.md) | Structured access logs, metrics, health endpoints, admin listener |
| [07-testing-and-release.md](07-testing-and-release.md) | Test strategy, CI, versioning, release process |
| [08-roadmap.md](08-roadmap.md) | Phased delivery plan — each phase independently shippable |
| [09-open-questions.md](09-open-questions.md) | Decisions that need a maintainer call before Phase 2 starts |

## The proposal in one page

**Keep**: the YAML-first, single-binary, zero-dependency-at-runtime model. The
ordered-rules mental model ("first match wins") is simple and worth preserving.
Every v0.1.0 config keeps working.

**Change**:

1. **Split the config schema from the runtime model.** Today `Rule` is both the
   YAML shape and the live matcher, with compiled regexes cached in unexported
   fields populated from `UnmarshalYAML`. Proposed: `config` parses and
   validates a pure data schema; `router` compiles it into an immutable
   `*Routes`; the serving path only ever sees the compiled form.

2. **Make the request path a pipeline.** A chain of small, individually
   testable middlewares (recover → request ID → access log → limits → match →
   authn → header rewrite) terminating in an `Action`. Replaces the 130-line
   `ServeHTTP` where auth state is tracked in a `string` variable.

3. **Own the lifecycle properly.** Listener errors propagate to the caller and
   to process exit; `Shutdown` is idempotent; `Wait` returns the reason the
   server stopped; `SIGHUP` reloads config by atomically swapping the compiled
   routes.

4. **Safe defaults.** Read/write/idle/header timeouts, request body and header
   caps, TLS 1.2 minimum with modern suites, constant-time credential
   comparison, hashed passwords accepted, no credentials in logs, correct
   `X-Forwarded-*` handling with a trusted-proxy list.

5. **Upstreams as a first-class concept.** A named upstream is a set of
   targets plus a load-balancing policy, health checking, and retry budget —
   which is what `FUTURE.md` asks for and what a single `proxy_url` string
   cannot express.

6. **Observability that an operator can use.** `log/slog` structured access
   logs with a stable field schema, Prometheus metrics, and `/healthz`
   `/readyz` on a separate admin listener that is never routed to.

**Cost**: roughly 5 phases (see [08-roadmap.md](08-roadmap.md)), of which
Phase 1 (safe defaults and lifecycle) is a small, high-value change that does
not depend on the rest.
