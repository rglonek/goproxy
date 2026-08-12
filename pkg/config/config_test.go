package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const minimal = `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - respond: { status: 200, body: "ok" }
`

func TestParseMinimal(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("minimal config does not load: %v", err)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(cfg.Rules))
	}
	// what is not set gets the safe default
	if got := cfg.Defaults.Timeouts.ReadHeader.Or(DefaultReadHeaderTimeout); got != DefaultReadHeaderTimeout {
		t.Errorf("read_header = %s", got)
	}
	if got := cfg.Defaults.Limits.MaxRequestBody.Or(DefaultMaxRequestBody); got != int64(DefaultMaxRequestBody) {
		t.Errorf("max_request_body = %d", got)
	}
}

func TestParseFull(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 2
log:
  level: debug
  format: json
  access:
    enabled: true
    exclude_paths: ["/healthz"]
    redact_query_params: [token]
listeners:
  http:
    addr: ":80"
    redirect_to_https: false
admin:
  addr: "127.0.0.1:9090"
defaults:
  timeouts:
    read_header: 5s
    read: 1m30s
    write: 0
    idle: 90
  limits:
    max_header_bytes: 64KiB
    max_request_body: 0
trusted_proxies: ["127.0.0.1/32", "10.0.0.0/8"]
on_listener_error: continue
auth:
  api:
    token:
      tokens: [{ id: ci, value: "x" }]
upstreams:
  app:
    targets:
      - { url: "http://10.0.0.1:8081", weight: 2 }
      - { url: "http://10.0.0.2:8081" }
    policy: least_conn
    health:
      passive: { failures: 3, cooldown: 30s }
      active: { path: /healthz, interval: 10s }
    retry:
      attempts: 2
      on: [connect_error, "503"]
      budget: 10%
rules:
  - name: api
    match: { host: "*.example.com", path: "/api", path_mode: segment, methods: [GET] }
    auth: api
    rate_limit: { requests_per_second: 10, burst: 20 }
    proxy:
      upstream: app
      strip_prefix: /api
`))
	if err != nil {
		t.Fatalf("full config does not load: %v", err)
	}
	if got := cfg.Log.Level; got != LevelDebug {
		t.Errorf("level = %v", got)
	}
	if got := cfg.Defaults.Timeouts.Read.Or(0); got != 90*time.Second {
		t.Errorf("read = %s", got)
	}
	if got := cfg.Defaults.Timeouts.Write.Or(DefaultWriteTimeout); got != 0 {
		t.Errorf("write = %s, want an explicit 0", got)
	}
	if got := cfg.Defaults.Timeouts.Idle.Or(0); got != 90*time.Second {
		t.Errorf("idle = %s, want a bare number to mean seconds", got)
	}
	if got := cfg.Defaults.Limits.MaxHeaderBytes.Or(0); got != 64<<10 {
		t.Errorf("max_header_bytes = %d", got)
	}
	if got := cfg.Upstreams["app"].Retry.Budget.Or(0); got != 0.1 {
		t.Errorf("budget = %v, want 0.1", got)
	}
}

// The schema changed shape in v2, so a v0.x file has to be diagnosed rather
// than half-understood.
func TestLegacyConfigIsDiagnosed(t *testing.T) {
	legacy := []string{
		`
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`,
		`
log_level: info
listen_addr: ":8080"
rules:
  - proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
`,
	}
	for _, text := range legacy {
		_, err := Parse([]byte(text))
		if !errors.Is(err, ErrLegacyConfig) {
			t.Fatalf("error = %v, want the legacy-config hint", err)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		errContains string
	}{
		{"no version", `
listeners:
  http: { addr: ":8080" }
rules:
  - respond: { status: 200, body: ok }
`, "version"},
		{"unknown key", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - respnod: { status: 200 }
`, "field respnod not found"},
		{"no listener", `
version: 2
rules:
  - respond: { status: 200, body: ok }
`, "listeners: at least one"},
		{"redirect to a listener that does not exist", `
version: 2
listeners:
  http: { addr: ":8080", redirect_to_https: true }
rules:
  - respond: { status: 200, body: ok }
`, "no https listener to redirect to"},
		{"no rules", `
version: 2
listeners:
  http: { addr: ":8080" }
`, "rules: at least one"},
		{"two actions", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - respond: { status: 200, body: ok }
    redirect: { to: "https://x", status: 301 }
`, "only one of proxy, serve, redirect or respond"},
		{"unknown upstream", `
version: 2
listeners:
  http: { addr: ":8080" }
upstreams:
  app:
    targets: [{ url: "http://127.0.0.1:8081" }]
rules:
  - proxy: { upstream: aap }
`, `did you mean "app"?`},
		{"unknown auth", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: a, password: b }]
rules:
  - auth: staf
    respond: { status: 200, body: ok }
`, `did you mean "staff"?`},
		{"bad proxy url", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - proxy: { url: "garbage" }
`, "absolute http(s) URL"},
		{"regex path without the mode", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - match: { path: "^/api" }
    respond: { status: 200, body: ok }
`, "set path_mode: regex"},
		{"bad wildcard host", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - match: { host: "app.*.com" }
    respond: { status: 200, body: ok }
`, "wildcard host"},
		{"hop-by-hop header", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - proxy:
      url: "http://127.0.0.1:8081"
      request_headers:
        set: { Connection: keep-alive }
`, "hop-by-hop"},
		{"interim respond status", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - respond: { status: 100, body: wait }
`, "between 200 and 599"},
		{"duplicate rule name", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - { name: a, respond: { status: 200, body: ok } }
  - { name: a, respond: { status: 200, body: ok } }
`, "already used by rules[0]"},
		{"user with no password", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice }]
rules:
  - respond: { status: 200, body: ok }
`, "one of password, password_hash or password_file"},
		{"token with two values", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  api:
    token:
      tokens: [{ id: a, value: x, value_env: Y }]
rules:
  - respond: { status: 200, body: ok }
`, "mutually exclusive"},
		{"acme without port 80", `
version: 2
listeners:
  http: { addr: ":8080" }
  https:
    addr: ":443"
    tls:
      acme: { email: a@example.com, domains: [example.com], cache_dir: /tmp/acme }
rules:
  - respond: { status: 200, body: ok }
`, ":80"},
		{"certs and acme together", `
version: 2
listeners:
  https:
    addr: ":443"
    tls:
      certs: [{ cert_file: /dev/null, key_file: /dev/null }]
      acme: { email: a@example.com, domains: [example.com], cache_dir: /tmp/acme }
rules:
  - respond: { status: 200, body: ok }
`, "mutually exclusive"},
		{"bad trusted proxy", `
version: 2
listeners:
  http: { addr: ":8080" }
trusted_proxies: ["not-a-cidr"]
rules:
  - respond: { status: 200, body: ok }
`, "trusted_proxies[0]"},
		{"bad duration", `
version: 2
listeners:
  http: { addr: ":8080" }
defaults:
  timeouts: { read: "ten seconds" }
rules:
  - respond: { status: 200, body: ok }
`, "invalid duration"},
		{"bad size", `
version: 2
listeners:
  http: { addr: ":8080" }
defaults:
  limits: { max_request_body: "lots" }
rules:
  - respond: { status: 200, body: ok }
`, "invalid size"},
		{"empty rule", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  -
`, "rule is empty"},
		{"rule name in the error", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - name: api
    proxy: {}
`, "(api)"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.yaml))
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", test.errContains)
			}
			if !strings.Contains(err.Error(), test.errContains) {
				t.Fatalf("error = %v, want it to contain %q", err, test.errContains)
			}
		})
	}
}

func TestUnreachableRules(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - { name: catch-all, respond: { status: 200, body: ok } }
  - { name: never, match: { path: "/api" }, respond: { status: 200, body: ok } }
`))
	if err != nil {
		t.Fatal(err)
	}
	warnings := cfg.Unreachable()
	if len(warnings) != 1 {
		t.Fatalf("warnings = %v, want one", warnings)
	}
	if !strings.Contains(warnings[0], "never") {
		t.Errorf("warning = %q", warnings[0])
	}
}

func TestRedactedRemovesSecrets(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  api:
    token:
      tokens: [{ id: ci, value: "supersecret" }]
    basic:
      users: [{ user: alice, password: "hunter2" }]
rules:
  - { auth: api, respond: { status: 200, body: ok } }
`))
	if err != nil {
		t.Fatal(err)
	}
	redacted := Redacted(cfg)
	if got := redacted.Auth["api"].Token.Tokens[0].Value; got != "REDACTED" {
		t.Errorf("token value = %q", got)
	}
	if got := redacted.Auth["api"].Basic.Users[0].Password; got != "REDACTED" {
		t.Errorf("password = %q", got)
	}
	// the original is untouched
	if got := cfg.Auth["api"].Token.Tokens[0].Value; got != "supersecret" {
		t.Errorf("redacting modified the original config: %q", got)
	}
}

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in   string
		want ByteSize
		bad  bool
	}{
		{"1024", 1024, false},
		{"1KiB", 1024, false},
		{"1kb", 1000, false},
		{"32MiB", 32 << 20, false},
		{"1.5MiB", 1536 << 10, false},
		{"0", 0, false},
		{"", 0, true},
		{"-1", 0, true},
		{"lots", 0, true},
	}
	for _, test := range tests {
		got, err := ParseByteSize(test.in)
		switch {
		case test.bad && err == nil:
			t.Errorf("ParseByteSize(%q) = %d, want an error", test.in, got)
		case !test.bad && err != nil:
			t.Errorf("ParseByteSize(%q): %v", test.in, err)
		case !test.bad && got != test.want:
			t.Errorf("ParseByteSize(%q) = %d, want %d", test.in, got, test.want)
		}
	}
}

func TestParseLevel(t *testing.T) {
	for _, name := range []string{"detail", "debug", "info", "warn", "error", "fatal", "fail", "none"} {
		if _, err := ParseLevel(name); err != nil {
			t.Errorf("ParseLevel(%q): %v", name, err)
		}
	}
	if _, err := ParseLevel("chatty"); err == nil {
		t.Error("ParseLevel accepted an unknown level")
	}
}

// FuzzParse asserts the property the parser has to have: whatever the bytes, it
// returns either a usable config or an error - never a panic.
func FuzzParse(f *testing.F) {
	f.Add(minimal)
	f.Add("version: 2\nrules: []\n")
	f.Add("]] not yaml [[")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		cfg, err := Parse([]byte(in))
		if err != nil {
			if cfg != nil {
				t.Fatal("Parse returned both a config and an error")
			}
			return
		}
		if len(cfg.Rules) == 0 {
			t.Fatal("a config with no rules got through validation")
		}
		if cfg.Listeners.HTTP == nil && cfg.Listeners.HTTPS == nil {
			t.Fatal("a config with no listener got through validation")
		}
		_ = Redacted(cfg)
		_ = cfg.Unreachable()
	})
}
