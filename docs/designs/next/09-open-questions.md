# 9. Open questions

Decisions that need a maintainer call. Phases 1 and 2 of
[the roadmap](08-roadmap.md) are unblocked by all of them; Phase 3 needs Q2 and
Q6 answered, and Phase 5 needs Q1.

---

**Q1 — Config v2, or additive v1?**

[04-configuration.md](04-configuration.md) proposes a v2 schema with a v1
adapter and a `config migrate` command; §4.7 proposes instead extending v1
additively (`proxy_urls` next to `proxy_url`, `users` next to `user`, …).

*v2* gives a coherent file that can express upstreams, reusable auth blocks and
defaults, at the cost of two schemas to maintain and document forever.
*Additive v1* gives every capability with zero migration, at the cost of a
config surface that visibly accreted.

Recommendation: **additive v1 through Phase 5, and revisit v2 only if the
accretion actually becomes a problem.** The user this project serves reads the
config by hand; a stable file they already understand is worth more than an
elegant one they have to relearn. But this is a taste call about the project's
identity, not a technical one.

---

**Q2 — `internal/` or keep everything importable?**

§3.1 proposes moving most packages under `internal/`, leaving `pkg/proxy` as the
supported API. That is the right call if goproxy is a binary that happens to be
written in Go. It is the wrong call if people are embedding it as a library and
reaching into `Rule` and `Config` directly — today every field of every config
struct is public, so anyone doing that would break.

Are there known library consumers? If yes, which types do they touch? Absent an
answer the plan assumes there are none, since the module is `goproxy` (not a
resolvable import path) and there is no published `pkg.go.dev` entry, which
strongly suggests binary-only use.

---

**Q3 — Should timeouts be on by default in a patch release?**

Adding `ReadTimeout`/`WriteTimeout` (R1) is the single highest-value fix in this
document and also the only Phase 1 change that can break a working deployment —
specifically, long downloads over slow links, websockets, and SSE (§5.1).

Options: (a) on by default with the streaming exception auto-detected from
`Connection: Upgrade`, generous defaults, and a release note; (b) on by default
but only `ReadHeaderTimeout` (which fixes Slowloris and breaks nothing), with
the rest opt-in; (c) all opt-in.

Recommendation: **(a)**, because (b) and (c) leave a proxy that can be held open
indefinitely by a slow reader, and the whole point is to be safe without the
operator knowing the setting exists. Worth an explicit sign-off, though, since
it is the one change most likely to generate an issue report.

---

**Q4 — What is the compatibility promise for the `X-Forwarded-For` change?**

Dropping inbound `X-Forwarded-For` from untrusted peers (S6) is correct, but if
someone is running goproxy behind another proxy today and has *not* configured
`trusted_proxies` (which does not exist yet), their backend will start seeing
the intermediate proxy's IP instead of the client's.

Options: default `trusted_proxies` to empty (secure, may change behaviour for
chained deployments) or to loopback + RFC1918 (friendlier, still spoofable from
inside a private network).

Recommendation: **empty by default, with a startup warning when an inbound
`X-Forwarded-For` is dropped**, so the operator is told exactly what to add.

---

**Q5 — `FUTURE.md`'s "basic form handling" — keep, reshape, or drop?**

As written it means goproxy parses `application/x-www-form-urlencoded` bodies,
validates fields, and does something with them (email? webhook? file?). That is
an application concern, and it brings in SMTP, spam handling and templating.

Options: drop it; or reshape it as a `webhook` action that forwards a form POST
as JSON to a configured URL with a shared secret, which is a routing concern and
maybe 100 lines.

Recommendation: **reshape as a `webhook` action, or drop.** Either way, out of
scope until Phase 5. What was the original need — a contact form on a static
site served by `serve_rule`? If so, the webhook shape covers it.

---

**Q6 — Is the project willing to be 4× its current size?**

The honest accounting from [08-roadmap.md](08-roadmap.md#rough-shape-of-the-diff):
~950 lines today, ~3–4k implementation plus similar test after Phase 5. Some of
that is unavoidable (tests, safe defaults, error messages with field paths), and
some is optional capability (load balancing, health checks, rate limiting,
metrics).

A legitimate alternative reading of this document is: **do Phases 1 and 2, stop,
and stay small.** That fixes every security and robustness finding, costs a few
hundred lines, and leaves goproxy the ~1,200-line binary it is today — which for
the single-host use case in [02-goals.md](02-goals.md#21-what-goproxy-is-for) may
be exactly right. The findings in [01-current-state.md](01-current-state.md) that
would remain unfixed under that plan are A1, A2, O2 and O3 — internal structure
and operability, not exposure.

This is the decision that determines whether the rest of the plan is worth
executing, and it should be made before Phase 3 starts rather than discovered
halfway through it.

---

**Q7 — Minor, but they affect the schema, so they are cheaper to settle early:**

* Should `path_match` prefix semantics stay character-based (`/api` matches
  `/apifoo`) or become segment-based? Segment-based is what people expect;
  character-based is what exists. Proposed: keep the current behaviour as the
  default, add `path_mode: segment`, and recommend it in the docs.
* Should HTTP→HTTPS redirect remain automatic whenever `tls` is set
  (`server.go:75-84`), or become an explicit `redirect_to_https` flag? Automatic
  means an HTTP-only rule is impossible to express while TLS is configured.
  Proposed: keep automatic as the default, add the flag to turn it off.
* Should the default token header stay `X-TOKEN`, or should
  `Authorization: Bearer` also be accepted (which is what the current
  `WWW-Authenticate: Bearer` response already tells clients to send — C5)?
  Proposed: accept both, keep `X-TOKEN` as the default.
