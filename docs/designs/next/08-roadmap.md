# 8. Roadmap

Five phases. Each is independently shippable and independently useful — if the
project stops after Phase 1, goproxy is meaningfully better and nothing is left
half-migrated. Phases 1 and 2 do not depend on the redesign at all and could be
merged next week.

## Phase 1 — Harden what exists (no redesign) — **implemented**

**Goal:** make the current code safe to expose to the internet.

* Server timeouts and `MaxHeaderBytes` on both listeners (R1).
* Load and parse certificates at startup; propagate `Serve`/`ServeTLS` errors
  to `Wait()` and to the process exit code (R2, R4).
* `sync.Once` on `Shutdown`; take a `context` (R3).
* `Recover` middleware (R5).
* `subtle.ConstantTimeCompare` for basic auth and tokens (S1).
* Stop logging presented tokens (S2).
* Switch to the `Rewrite` API and `SetXForwarded`; add `trusted_proxies`
  (S5, S6).
* Explicit `tls.MinVersion` (S7).
* Build the self-signed transport from a clone of `http.DefaultTransport`
  instead of a bare one (S9).
* Require an absolute http(s) URL in `proxy_url` validation (C4).
* Lowercase the host before matching (C7).
* Fix the `token_auth` doc/code mismatch and the misleading
  `WWW-Authenticate: Bearer` (C5).
* Add the integration harness and the tests for each of the above (§7.2).
* Add CI (§7.3).

**Size:** small — most of these are a few lines each. **Risk:** low, except for
timeouts, which need the streaming exception (§5.1) and a release note.
**Ships as:** v0.2.0.

*As built:* phases 1 and 2 shipped together as v0.3.0. Q3 was answered (a) —
timeouts on by default, with the streaming exception auto-detected from
`Connection: Upgrade` and an explicit `streaming: true` for server-sent events.
Q4 was answered as recommended: `trusted_proxies` is empty by default and a
warning naming the peer is logged the first time an inbound `X-Forwarded-*` is
dropped. Q7's `Authorization: Bearer` question is answered additively with an
opt-in `accept_bearer`; `X-TOKEN` remains the default and prefix semantics are
unchanged.

## Phase 2 — Fix the visible defects — **implemented**

**Goal:** the things users notice.

* `respond_rule`: `content_type` and response headers; read the body file once
  at compile time; set `Content-Length` (C2, R6).
* `serve_rule`: `os.Root`, directory listings off by default, dotfile
  blocking, `Cache-Control` (S8, §5.6).
* Explicit prefix stripping instead of `ReplaceAllString` (C3).
* Optional `name` on rules, used in logs (A4).
* `--check` mode; move the ACME `MkdirAll` out of `Validate` (C8).
* Warn on unknown config keys instead of dropping them silently (A5).
* Version/commit/date from build info (O5).

**Size:** small–medium. **Risk:** low; three behaviour changes need release
notes (listings, content type, unknown keys). **Ships as:** v0.3.0.

## Phase 3 — The structural redesign — **implemented**

**Goal:** the schema/runtime split and the pipeline
([03-architecture.md](03-architecture.md)). This is the phase that costs real
effort, and it is the enabler for everything after it.

* `internal/config`: schema types with no behaviour, strict decode, field-path
  errors.
* `internal/route`: `Compile` + the routing table, with the differential fuzz
  test against the linear scan.
* `internal/action`: the four actions behind the `Action` interface.
* `internal/authn`: typed `Identity`, ordered authenticators, per-authenticator
  strip (fixes C6 by construction).
* `internal/middleware`: the chain from §3.3.
* `pkg/proxy`: the new `Server` API with exported types (A3), `Run` kept as a
  compatibility shim.
* The compatibility suite over `examples/` gates the merge (§7.2).

**Size:** large — this is the bulk of the work. **Risk:** medium. It is a
rewrite of the request path, and the mitigation is that the config surface does
not change at all in this phase, so the compatibility suite is a complete
specification of correct behaviour.

**Explicitly not in this phase:** any new config syntax. Phase 3 is
"same behaviour, new internals", which keeps the diff reviewable and the
regression surface bounded. **Ships as:** v0.4.0.

## Phase 4 — Observability and operations — **implemented**

**Goal:** [G5](02-goals.md#22-goals) and [G7](02-goals.md#22-goals).

* `log/slog` migration and the structured access log (§6.2, §6.3).
* Request IDs, propagated and echoed.
* Admin listener: `/healthz`, `/readyz`, `/metrics`, `/config`, `/reload`
  (§6.5).
* Prometheus metrics (§6.4).
* `SIGHUP` reload via the atomic table swap (§3.8) — cheap now that Phase 3
  made the routing table immutable and rebuildable, and effectively impossible
  before it.
* `goproxy config explain` (§6.6).

**Size:** medium. **Risk:** low — mostly additive. The one behaviour change is
the log format, which is why it is gated behind `log.format` with the old
human-readable style available. **Ships as:** v0.5.0.

## Phase 5 — New capability — **implemented**

**Goal:** `FUTURE.md`, and the features the new model makes cheap.

* `internal/upstream`: multi-target pools, load-balancing policies, passive and
  active health checks, retry budgets (§3.6) — `FUTURE.md`'s headline request.
* Forward-auth (§5.3) — `FUTURE.md`'s third-party auth, done as a subrequest
  rather than a per-request process fork.
* Hashed passwords, multiple users, secrets from env/file (S3, S4).
* Rate limiting, IP allow/deny, method matching, CORS (§5.7).
* Multiple certificates with SNI; mutual TLS; tls-alpn-01 (§5.5).
* Config v2 and `goproxy config migrate`, if [Q1](09-open-questions.md) is
  answered that way ([04-configuration.md](04-configuration.md)).

**Size:** medium, and highly divisible — every bullet is independent and can
ship on its own. **Ships as:** v0.6.0 … v1.0.0.

`FUTURE.md`'s "basic form handling (like contact us forms)" is deliberately
absent. It is the one item on that list that does not fit a proxy: it means
owning form parsing, validation, spam handling and email delivery, which is an
application, not a routing concern. Recommendation is to drop it, or to satisfy
it with a `respond` action that can POST to a webhook — worth a decision, see
[Q5](09-open-questions.md).

## Sequencing notes

* **Phases 1 and 2 are worth doing regardless** of whether the redesign is
  approved. They are small, they fix real exposure, and they do not constrain
  the redesign.
* **Phase 3 is the commitment point.** Everything after it is much cheaper
  because of it; without it, Phases 4 and 5 mean adding more branches to a
  handler that is already the longest function in the codebase.
* **Reload (Phase 4) genuinely depends on Phase 3.** Swapping config atomically
  requires the runtime state to be rebuildable from config alone, which is
  precisely what today's `Rule`-carries-its-own-compiled-state design prevents.
* Test infrastructure lands in Phase 1 and is what makes Phase 3 safe to
  attempt. Doing the rewrite first and the tests after would be the wrong
  order.

## Rough shape of the diff

| Phase | New code | Changed | Risk |
| --- | --- | --- | --- |
| 1 | ~400 (mostly tests) | ~150 | Low |
| 2 | ~300 | ~200 | Low |
| 3 | ~2,000 | most of `pkg/proxy` | Medium |
| 4 | ~800 | ~200 | Low |
| 5 | ~1,500 | ~100 | Low–medium |

Estimated end state: roughly 3–4k lines of implementation plus a comparable
amount of test, against today's ~950 including tests. That is a real increase,
and it should be weighed honestly — see [Q6](09-open-questions.md) on whether
the project wants to be that size.

## What was actually built

Phases 1 and 2 shipped as v0.3.0; phases 3, 4 and 5 shipped together as v1.0.0,
once the open questions were answered:

* **Q1 — config v2, no backwards compatibility.** There is one schema, not two.
  A v0.x file is detected and refused with a pointer to `docs/MIGRATION.md`,
  which maps every old key to its new home. No `config migrate` command: a
  migrator only pays for itself if v1 has to keep working.
* **Q2 — everything importable under `pkg/`.** No `internal/`. Each package is
  documented as a supported surface.
* **Q3 — timeouts on by default**, with the streaming exception detected from
  `Connection: Upgrade` and an explicit `streaming: true` for server-sent
  events.
* **Q4 — `trusted_proxies` empty by default**, with a warning naming the peer
  the first time an inbound `X-Forwarded-*` is dropped.
* **Q5 — form handling reshaped as a `webhook` action and left unbuilt.**
  `FUTURE.md` describes the shape it would take.
* **Q6 — yes to the size.** The original was a proof of concept.
* **Q7 — as proposed.** Character-based prefixes stay the default with
  `path_mode: segment` available and recommended; the HTTP → HTTPS redirect
  stays automatic with `redirect_to_https` to turn it off; `X-TOKEN` stays the
  default token header and `Authorization: Bearer` is accepted as well.
