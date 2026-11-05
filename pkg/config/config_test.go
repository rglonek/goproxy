package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
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
		{"allow without auth", `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - name: open
    allow: { users: [alice] }
    respond: { status: 200, body: ok }
`, "rules[0] (open).allow: requires auth"},
		{"allow with neither list", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x }]
rules:
  - auth: staff
    allow: {}
    respond: { status: 200, body: ok }
`, "allow: at least one of users or groups is required"},
		// commenting out every entry leaves a null allow, which the decoder
		// would otherwise read as no allow at all: everyone through
		{"allow with nothing under it", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x }]
rules:
  - name: admin
    auth: staff
    allow:
      # groups: [admin]
    respond: { status: 200, body: ok }
`, "rules[0] (admin).allow: is empty"},
		{"allow with an empty user list", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x, groups: [admin] }]
rules:
  - auth: staff
    allow: { users: [], groups: [admin] }
    respond: { status: 200, body: ok }
`, "allow.users: is empty"},
		{"allow with an empty group list", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x }]
rules:
  - auth: staff
    allow: { users: [alice], groups: [] }
    respond: { status: 200, body: ok }
`, "allow.groups: is empty"},
		{"allow naming a user the auth block does not have", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x }]
rules:
  - auth: staff
    allow: { users: [alcie] }
    respond: { status: 200, body: ok }
`, `allow.users[0]: auth block "staff" has no user or token named "alcie" (did you mean "alice"?)`},
		{"allow naming a group nobody has", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x, groups: [owner] }]
rules:
  - auth: staff
    allow: { groups: [onwer] }
    respond: { status: 200, body: ok }
`, `allow.groups[0]: no user or token in auth block "staff" has group "onwer" (did you mean "owner"?)`},
		{"group with a comma", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x, groups: ["owner,guest"] }]
rules:
  - respond: { status: 200, body: ok }
`, "basic.users[0].groups[0]: \"owner,guest\" must be printable ASCII with no comma or space"},
		{"empty group", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  api:
    token:
      tokens: [{ id: ci, value: x, groups: [""] }]
rules:
  - respond: { status: 200, body: ok }
`, "token.tokens[0].groups[0]: must not be empty"},
		{"group listed twice", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x, groups: [owner, owner] }]
rules:
  - respond: { status: 200, body: ok }
`, `"owner" appears twice`},
		{"user and groups in one header", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x }]
      forward_user_header: X-User
      forward_groups_header: x-user
rules:
  - respond: { status: 200, body: ok }
`, "basic.forward_groups_header: \"x-user\" is already forward_user_header"},
		// the client's copy of an identity header is removed before
		// authentication, so one that carries a credential would lock
		// everyone out
		{"identity header that carries the basic credential", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x }]
      forward_user_header: Authorization
rules:
  - respond: { status: 200, body: ok }
`, "basic.forward_user_header: \"Authorization\" is where basic reads a credential from"},
		{"identity header that carries the token", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    token:
      tokens: [{ value: x }]
    basic:
      users: [{ user: alice, password: x }]
      forward_groups_header: X_Token
rules:
  - respond: { status: 200, body: ok }
`, "is where token reads a credential from"},
		{"identity header the auth service is sent", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  sso:
    forward:
      url: "http://127.0.0.1:9000/auth"
      request_headers: [Cookie, X-Auth-User]
      user_header: X-Auth-User
rules:
  - respond: { status: 200, body: ok }
`, "forward.user_header: \"X-Auth-User\" is where forward.request_headers reads a credential from"},
		{"hop-by-hop identity header", `
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  staff:
    basic:
      users: [{ user: alice, password: x }]
      forward_groups_header: Connection
rules:
  - respond: { status: 200, body: ok }
`, "hop-by-hop"},
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

func TestParseGroupsAndAllow(t *testing.T) {
	cfg, err := Parse([]byte(`
version: 2
listeners:
  http: { addr: ":8080" }
auth:
  people:
    token:
      tokens: [{ id: ci, value: x, groups: [deploy] }]
    basic:
      users:
        - { user: robert, password: x, groups: [owner] }
        - { user: gina, password: y, groups: [guest] }
      forward_user_header: X-Alice-User
      forward_groups_header: X-Alice-Role
  sso:
    forward:
      url: "http://127.0.0.1:9000/auth"
      user_header: X-Auth-User
      groups_header: X-Auth-Groups
rules:
  - name: owner
    auth: people
    allow: { groups: [owner] }
    respond: { status: 200, body: ok }
  - name: named
    auth: people
    allow: { users: [gina, ci], groups: [guest, deploy] }
    respond: { status: 200, body: ok }
  # a forward-auth service can name any user and any group
  - name: sso
    auth: sso
    allow: { users: [whoever], groups: [anything] }
    respond: { status: 200, body: ok }
`))
	if err != nil {
		t.Fatalf("config does not load: %v", err)
	}
	if got := cfg.Auth["people"].Basic.Users[0].Groups; len(got) != 1 || got[0] != "owner" {
		t.Errorf("groups = %v", got)
	}
	if got := cfg.Auth["people"].Basic.ForwardGroupsHeader; got != "X-Alice-Role" {
		t.Errorf("forward_groups_header = %q", got)
	}
	if got := cfg.Auth["sso"].Forward.GroupsHeader; got != "X-Auth-Groups" {
		t.Errorf("groups_header = %q", got)
	}
	if allow := cfg.Rules[1].Allow; allow == nil || len(allow.Users) != 2 || len(allow.Groups) != 2 {
		t.Errorf("allow = %+v", allow)
	}
	if cfg.Rules[0].Allow.Users != nil {
		t.Errorf("users = %v, want none", cfg.Rules[0].Allow.Users)
	}
}

func TestIdentityHeaderKey(t *testing.T) {
	for _, name := range []string{"X-Alice-User", "x-alice-user", "X_ALICE_USER", "x_Alice-user"} {
		if got := IdentityHeaderKey(name); got != "x-alice-user" {
			t.Errorf("IdentityHeaderKey(%q) = %q", name, got)
		}
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

func TestRedactedHeaderValues(t *testing.T) {
	t.Setenv("GOPROXY_TEST_UPSTREAM_KEY", "from-the-environment")
	cfg, err := Parse([]byte(`
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - name: api
    match: { path: /api }
    proxy:
      url: "http://127.0.0.1:8081"
      request_headers:
        set:
          X-Env: prod
          Authorization: "Bearer literal-key"
          X-Api-Key: { value: "literal-api-key" }
          X-Upstream-Auth: { prefix: "Bearer ", value_env: GOPROXY_TEST_UPSTREAM_KEY }
      response_headers:
        set: { Set-Cookie: "session=abc123", X-Frame-Options: DENY }
  - respond:
      status: 200
      headers: { X-Auth-Token: "respond-secret", X-Custom: yes }
`))
	if err != nil {
		t.Fatal(err)
	}
	redacted := Redacted(cfg)
	set := redacted.Rules[0].Proxy.RequestHeaders.Set
	for name, want := range map[string]string{
		"X-Env":         "prod",
		"Authorization": "REDACTED",
		"X-Api-Key":     "REDACTED",
	} {
		if got := set[name].Value; got != want {
			t.Errorf("request_headers.set.%s = %q, want %q", name, got, want)
		}
	}
	// a value from the environment is not in the config to begin with: only
	// where it comes from is, and that is no secret
	if got := set["X-Upstream-Auth"]; got.ValueEnv != "GOPROXY_TEST_UPSTREAM_KEY" || got.Prefix != "Bearer " || got.Value != "" {
		t.Errorf("request_headers.set.X-Upstream-Auth = %+v", got)
	}
	response := redacted.Rules[0].Proxy.ResponseHeaders.Set
	if got := response["Set-Cookie"].Value; got != "REDACTED" {
		t.Errorf("response_headers.set.Set-Cookie = %q", got)
	}
	if got := response["X-Frame-Options"].Value; got != "DENY" {
		t.Errorf("response_headers.set.X-Frame-Options = %q", got)
	}
	if got := redacted.Rules[1].Respond.Headers; got["X-Auth-Token"] != "REDACTED" || got["X-Custom"] != "yes" {
		t.Errorf("respond.headers = %v", got)
	}

	encoded, err := yaml.Marshal(redacted)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"literal-key", "literal-api-key", "from-the-environment", "abc123", "respond-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("the redacted config still contains %q:\n%s", secret, encoded)
		}
	}
	// a plain value is written back as the string it was written as
	if !strings.Contains(string(encoded), "X-Env: prod") {
		t.Errorf("X-Env was not written back as a plain string:\n%s", encoded)
	}

	// the original is untouched
	if got := cfg.Rules[0].Proxy.RequestHeaders.Set["Authorization"].Value; got != "Bearer literal-key" {
		t.Errorf("redacting modified the original config: %q", got)
	}
	if got := cfg.Rules[1].Respond.Headers["X-Auth-Token"]; got != "respond-secret" {
		t.Errorf("redacting modified the original respond headers: %q", got)
	}
}

func TestSensitiveHeader(t *testing.T) {
	for name, want := range map[string]bool{
		"Authorization":        true,
		"proxy-authorization":  true,
		"Cookie":               true,
		"Set-Cookie":           true,
		"X-Api-Key":            true,
		"X-Auth-Token":         true,
		"X-Amz-Security-Token": true,
		"X-Session-Id":         true,
		"X-Client-Secret":      true,
		"X-Env":                false,
		"X-Frame-Options":      false,
		"Cache-Control":        false,
		"X-Forwarded-Proto":    false,
	} {
		if got := SensitiveHeader(name); got != want {
			t.Errorf("SensitiveHeader(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestHeaderValueForms(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte(`
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - proxy:
      url: "http://127.0.0.1:8081"
      request_headers:
        set:
          X-Plain: prod
          X-Number: 5
          X-Empty: ""
          X-Literal: { value: "lit" }
          Authorization: { prefix: "Bearer ", value_env: GOPROXY_TEST_UPSTREAM_KEY }
          X-From-File: { value_file: "` + keyFile + `" }
`))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPROXY_TEST_UPSTREAM_KEY", "from-the-environment")
	set := cfg.Rules[0].Proxy.RequestHeaders.Set
	for name, want := range map[string]string{
		"X-Plain":       "prod",
		"X-Number":      "5",
		"X-Empty":       "",
		"X-Literal":     "lit",
		"Authorization": "Bearer from-the-environment",
		"X-From-File":   "from-a-file", // the editor's trailing newline is dropped
	} {
		got, err := set[name].Resolve()
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if set["X-Plain"].External() || !set["Authorization"].External() || !set["X-From-File"].External() {
		t.Error("External() does not tell the literal values from the external ones")
	}
}

func TestHeaderValueResolveErrors(t *testing.T) {
	dir := t.TempDir()
	twoLines := filepath.Join(dir, "two-lines")
	if err := os.WriteFile(twoLines, []byte("first-secret\nsecond-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPROXY_TEST_EMPTY", "")
	t.Setenv("GOPROXY_TEST_NEWLINE", "a-secret\r\nInjected: yes")

	tests := []struct {
		value HeaderValue
		want  string
	}{
		{HeaderValue{ValueEnv: "GOPROXY_TEST_UNSET"}, "environment variable GOPROXY_TEST_UNSET is not set"},
		{HeaderValue{ValueEnv: "GOPROXY_TEST_EMPTY"}, "environment variable GOPROXY_TEST_EMPTY is empty"},
		{HeaderValue{ValueEnv: "GOPROXY_TEST_NEWLINE"}, "environment variable GOPROXY_TEST_NEWLINE contains a line break"},
		{HeaderValue{ValueFile: twoLines}, twoLines + " contains a line break"},
		{HeaderValue{ValueFile: empty}, empty + " is empty"},
		{HeaderValue{ValueFile: filepath.Join(dir, "missing")}, "no such file"},
	}
	for _, test := range tests {
		_, err := test.value.Resolve()
		if err == nil {
			t.Errorf("%+v resolved, want an error containing %q", test.value, test.want)
			continue
		}
		if !strings.Contains(err.Error(), test.want) {
			t.Errorf("%+v: error = %q, want it to contain %q", test.value, err, test.want)
		}
		// the error says where to look, never what was found
		for _, secret := range []string{"a-secret", "first-secret", "second-secret"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%+v: error %q gives the secret away", test.value, err)
			}
		}
	}
}

func TestHeaderValueErrors(t *testing.T) {
	tests := []struct{ name, set, want string }{
		{"unknown key", `{ X-Key: { value_evn: KEY } }`, "field value_evn not found in type config.HeaderValue"},
		{"repeated key", `{ X-Key: { value_env: A, value_env: B } }`, `mapping key "value_env" already defined`},
		{"two sources", `{ X-Key: { value_env: A, value_file: /etc/hostname } }`,
			"rules[0] (api).proxy.request_headers.set.X-Key: value, value_env and value_file are mutually exclusive"},
		{"no source", `{ X-Key: { prefix: "Bearer " } }`,
			"rules[0] (api).proxy.request_headers.set.X-Key: one of value, value_env or value_file is required"},
		{"missing file", `{ X-Key: { value_file: /does/not/exist } }`,
			"rules[0] (api).proxy.request_headers.set.X-Key.value_file: does not exist: /does/not/exist"},
		{"a list", `{ X-Key: [a, b] }`, "a header value must be a string, or a mapping"},
		{"a source of the wrong type", `{ X-Key: { value_env: [A] } }`, "cannot unmarshal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(`
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - name: api
    proxy:
      url: "http://127.0.0.1:8081"
      request_headers:
        set: ` + test.set + `
`))
			if err == nil {
				t.Fatalf("accepted, want an error containing %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("error = %q, want it to contain %q", err, test.want)
			}
		})
	}

	// response headers take the same forms
	_, err := Parse([]byte(`
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - proxy:
      url: "http://127.0.0.1:8081"
      response_headers:
        set: { X-Key: { value_file: /does/not/exist } }
`))
	if err == nil || !strings.Contains(err.Error(), "rules[0].proxy.response_headers.set.X-Key.value_file: does not exist") {
		t.Errorf("response_headers error = %v", err)
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
	f.Add(`
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - proxy:
      url: "http://127.0.0.1:8081"
      request_headers:
        set: { X-Env: prod, Authorization: { prefix: "Bearer ", value_env: KEY } }
`)
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
