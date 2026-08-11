package proxy

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseTimeoutsAndLimits(t *testing.T) {
	config, err := ParseConfig([]byte(`
listen_addr: ":8080"
timeouts:
  read_header: 5s
  read: 1m30s
  write: 0
  idle: 90
  shutdown: 15s
limits:
  max_header_bytes: 64KiB
  max_request_body: 0
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := config.readHeaderTimeout(); got != 5*time.Second {
		t.Errorf("read_header = %s", got)
	}
	if got := config.readTimeout(); got != 90*time.Second {
		t.Errorf("read = %s", got)
	}
	if got := config.writeTimeout(); got != 0 {
		t.Errorf("write = %s, want an explicit 0", got)
	}
	if got := config.idleTimeout(); got != 90*time.Second {
		t.Errorf("idle = %s, want a bare number to mean seconds", got)
	}
	if got := config.ShutdownTimeout(); got != 15*time.Second {
		t.Errorf("shutdown = %s", got)
	}
	if got := config.maxHeaderBytes(); got != 64<<10 {
		t.Errorf("max_header_bytes = %d", got)
	}
	if got := config.maxRequestBody(); got != 0 {
		t.Errorf("max_request_body = %d, want an explicit 0", got)
	}
	// what is not set gets the safe default
	if got := config.upstreamDialTimeout(); got != DefaultUpstreamDialTimeout {
		t.Errorf("upstream_dial = %s", got)
	}
}

func TestDefaultsWhenNothingIsSet(t *testing.T) {
	config, err := ParseConfig([]byte(`
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"read_header", config.readHeaderTimeout(), DefaultReadHeaderTimeout},
		{"read", config.readTimeout(), DefaultReadTimeout},
		{"write", config.writeTimeout(), DefaultWriteTimeout},
		{"idle", config.idleTimeout(), DefaultIdleTimeout},
		{"shutdown", config.ShutdownTimeout(), DefaultShutdownTimeout},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %s, want the default %s", check.name, check.got, check.want)
		}
	}
	if config.maxRequestBody() != int64(DefaultMaxRequestBody) {
		t.Errorf("max_request_body = %d", config.maxRequestBody())
	}
}

// A5: v0.1.0 dropped an unknown key without a word, so `proxy_append_paths`
// silently did nothing.
func TestUnknownKeysAreReportedAsWarnings(t *testing.T) {
	config, err := ParseConfig([]byte(`
listen_addr: ":8080"
listen_addrs: ":9090"
rules:
  - proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
      proxy_append_paths: true
`))
	if err != nil {
		t.Fatalf("an unknown key must not be fatal for a v1 config: %v", err)
	}
	warnings := strings.Join(config.Warnings(), "\n")
	contains(t, warnings, "listen_addrs")
	contains(t, warnings, "proxy_append_paths")
}

func TestConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		errContains string
	}{
		// C4: url.Parse accepts a bare word, and the rule then failed on every
		// request instead of at startup
		{"proxy_url without a scheme", `
listen_addr: ":8080"
rules:
  - proxy_rule:
      proxy_url: "garbage"
`, "absolute http(s) URL"},
		{"proxy_url without a host", `
listen_addr: ":8080"
rules:
  - proxy_rule:
      proxy_url: "http://"
`, "must include a host"},
		{"bad domain regex", `
listen_addr: ":8080"
rules:
  - domain_match: "^[unclosed"
    respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "invalid regex"},
		{"hop-by-hop header", `
listen_addr: ":8080"
rules:
  - proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
      proxy_set_headers:
        Connection: keep-alive
`, "hop-by-hop"},
		{"bad trusted proxy", `
listen_addr: ":8080"
trusted_proxies: ["not-a-cidr"]
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "trusted_proxies[0]"},
		{"bad on_listener_error", `
listen_addr: ":8080"
on_listener_error: maybe
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "on_listener_error"},
		{"bad tls min_version", `
listen_addr: ":8080"
tls:
  listen_addr: ":8443"
  min_version: "0.9"
  lets_encrypt:
    email: "a@example.com"
    domains: ["example.com"]
    cache_dir: "/tmp"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "min_version"},
		{"bad duration", `
listen_addr: ":8080"
timeouts:
  read: "ten seconds"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "invalid duration"},
		{"bad size", `
listen_addr: ":8080"
limits:
  max_request_body: "lots"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "invalid size"},
		{"interim respond status", `
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 100
      respond_body: "wait"
`, "between 200 and 599"},
		{"named rule reports its name", `
listen_addr: ":8080"
rules:
  - name: api
    proxy_rule: {}
`, "(api)"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(test.yaml))
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", test.errContains)
			}
			contains(t, err.Error(), test.errContains)
		})
	}
}

// C8: validating a config must not touch the filesystem, so that a --check mode
// can exist.
func TestValidateDoesNotCreateTheACMECacheDir(t *testing.T) {
	dir := t.TempDir() + "/does-not-exist-yet"
	config, err := ParseConfig([]byte(`
listen_addr: ":80"
tls:
  listen_addr: ":443"
  lets_encrypt:
    email: "a@example.com"
    domains: ["example.com"]
    cache_dir: "` + dir + `"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("validating the config created the ACME cache directory")
	}
}

func TestCompileIsSafeToCallTwice(t *testing.T) {
	config, err := ParseConfig([]byte(`
listen_addr: ":8080"
rules:
  - proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
      proxy_remove_headers: ["^X-.*", "User-Agent"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Compile(); err != nil {
		t.Fatal(err)
	}
	if got := len(config.Rules[0].ProxyRule.proxyRemoveHeadersRegex); got != 2 {
		t.Fatalf("compiled %d header matchers, want 2", got)
	}
}
