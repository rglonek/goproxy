# 7. Testing, CI and release

## 7.1 Where the tests are today

`pkg/proxy/config_test.go` — 231 lines, three functions: `TestParseConfigValid`,
`TestParseConfigInvalid`, `TestRuleMatch`. They cover config parsing and rule
matching well. Nothing else is tested: no test starts a server, and there is no
coverage of auth, proxying, path rewriting, header manipulation, TLS, or
shutdown (O4). There is no CI.

The findings in [01-current-state.md](01-current-state.md) are the evidence for
what that costs — R2 (a dead HTTPS listener that reports success), R3 (a panic
on the second `Shutdown`), C1 (regexes silently not compiled) and C2 (responses
forced to `text/plain`) are all things a single end-to-end test would have
caught.

## 7.2 Test strategy

**Unit — config.** Table-driven over `testdata/*.yaml`, one file per case, each
paired with an expected error string or expected resolved config. Golden files
for the resolved output so defaults changing is visible in a diff. Extend the
existing tests rather than replacing them.

**Unit — routing.** Table of (config, host, path, method) → expected rule name.
Plus a differential fuzz test: `Routes.Match` (the compiled index) against a
naive linear scan over the same rules, asserting they always pick the same rule.
This is the safety net for the §3.4 optimisation, which must not change which
rule wins.

**Unit — middleware and actions.** Each stage constructed directly and driven
with `httptest.NewRecorder`. Auth gets explicit cases for: no credentials,
wrong password, right password, wrong token, right token, token-fails-then-basic-
succeeds (C6), and credentials never appearing in captured log output (S2).

**Integration — one process, real ports.** A harness that writes a config to a
temp dir, starts a real `Server`, and drives it with `http.Client`:

* every action type end to end;
* TLS with a generated self-signed cert, including the verified R2 case: a
  deliberately corrupt cert must make startup fail, not succeed silently;
* HTTP→HTTPS redirect;
* the `X-Forwarded-*` matrix — trusted peer, untrusted peer, inbound spoof
  attempt (S5, S6);
* websocket and SSE through the proxy, to prove `WriteTimeout` does not break
  streaming (§5.1);
* upstream failure modes: connection refused, slow response, half-closed,
  502 → retry → success;
* `SIGHUP` reload under concurrent load, with `-race`, asserting no dropped
  requests and no torn config;
* double `Shutdown` (R3) and shutdown with in-flight requests.

**Compatibility suite.** Every file in `examples/` is loaded by the new binary
and asserted to produce the same routing decisions as v0.1.0. This is the
mechanical guarantee behind [G4](02-goals.md#22-goals). The v1→v2 migrator is
tested by round trip: `migrate(v1)` → load → compare resolved config against
loading the v1 file directly. They must be identical.

**Fuzzing.** `FuzzParseConfig` (never panic, always either a config or an
error) and `FuzzMatch` (arbitrary host/path never panics, never allocates
unboundedly). Both are cheap to write and run in CI on a short budget, with a
seed corpus grown from any bug found.

**Benchmarks.** `BenchmarkMatch` over 10 / 100 / 1000 rules to demonstrate the
routing table's value and catch regressions, and an allocation budget on the
hot path (`-benchmem`, asserted with `testing.AllocsPerRun`).

**`test/logwww`** stays, but is wrapped as a reusable test fixture rather than a
manually started binary, so the header/GET-var assertions it exists to support
can be made automatically (O6).

## 7.3 CI

There is no `.github/` today. Proposed, on push and PR:

```
build      go build ./... on linux/darwin/windows × amd64/arm64 (compile only)
vet        go vet ./...
lint       staticcheck; gofumpt -l (fails on diff)
test       go test -race -count=1 ./...
cover      go test -coverprofile; report, and fail if total drops below the ratchet
fuzz       go test -fuzz -fuzztime=60s on the two fuzz targets
vuln       govulncheck ./...
examples   compatibility suite against examples/
```

Coverage as a **ratchet** (may not go down) rather than a fixed threshold —
a fixed number either blocks work early or is meaningless later.

Weekly scheduled run of `govulncheck` and the dependency update job, so a CVE in
a dependency surfaces without waiting for a commit.

## 7.4 Release

Current state: `build.sh` cross-compiles six targets and tars them, and the
version is a hardcoded string in `cli/main.go:14` that `build.sh` does not set
(O5). Proposed:

* Version, commit and build date injected with `-ldflags -X`, or read from
  `runtime/debug.ReadBuildInfo()` with `-buildvcs=true`. `goproxy -version`
  prints all three plus the Go version.
* A tag-triggered GitHub Actions workflow replacing manual `build.sh` runs,
  producing the same six artefacts plus `checksums.txt` and a signature.
* `CHANGELOG.md` with the behaviour-change table from
  [04-configuration.md](04-configuration.md#46-behaviour-changes) reproduced in
  the release notes of whichever release ships it.
* Semantic versioning taken seriously now that `pkg/proxy` is a supported
  import: the `internal/` split in §3.1 exists so that most of the redesign is
  not a breaking change for library users.
* Optionally a container image and a `goproxy.service` systemd unit with
  `NoNewPrivileges`, `ProtectSystem=strict`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  — the last one being what lets goproxy bind :80 and :443 without running as
  root, which the README does not currently address.
