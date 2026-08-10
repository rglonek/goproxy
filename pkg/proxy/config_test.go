package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigValid(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "snakeoil.crt")
	keyFile := filepath.Join(dir, "snakeoil.key")
	for _, f := range []string{certFile, keyFile} {
		if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name string
		yaml string
	}{
		{"minimal respond", `
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 403
      respond_body: "Forbidden"
`},
		{"log level fatal", `
log_level: fatal
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`},
		// "fail" is the spelling used by the README; it is accepted as an alias of "fatal"
		{"log level fail", `
log_level: fail
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`},
		{"https only, no plain http listener", `
tls:
  listen_addr: ":8443"
  certs:
    cert_file: "` + certFile + `"
    key_file: "` + keyFile + `"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`},
		{"http and https", `
listen_addr: ":8080"
tls:
  listen_addr: ":8443"
  certs:
    cert_file: "` + certFile + `"
    key_file: "` + keyFile + `"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`},
		{"lets encrypt on port 80", `
listen_addr: ":80"
tls:
  listen_addr: ":443"
  lets_encrypt:
    email: "someone@example.com"
    domains: ["example.com"]
    cache_dir: "` + filepath.Join(dir, "acme") + `"
rules:
  - proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(test.yaml)); err != nil {
				t.Fatalf("expected config to be valid, got: %v", err)
			}
		})
	}
}

func TestParseConfigInvalid(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		errContains string
	}{
		{"no listener at all", `
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "listen_addr is required"},
		{"no rules", `
listen_addr: ":8080"
`, "rules is required"},
		{"tls without listen_addr", `
listen_addr: ":8080"
tls:
  lets_encrypt:
    email: "someone@example.com"
    domains: ["example.com"]
    cache_dir: "/tmp"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "tls: listen_addr is required"},
		{"lets encrypt not on port 80", `
listen_addr: ":8080"
tls:
  listen_addr: ":443"
  lets_encrypt:
    email: "someone@example.com"
    domains: ["example.com"]
    cache_dir: "/tmp"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, ":80"},
		{"unknown log level", `
log_level: chatty
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, "invalid log level"},
		{"rule with no action", `
listen_addr: ":8080"
rules:
  - path_match: "/nowhere"
`, "rules[0]"},
		{"proxy rule without url", `
listen_addr: ":8080"
rules:
  - proxy_rule: {}
`, "proxy_url is required"},
		{"redirect rule without url", `
listen_addr: ":8080"
rules:
  - redirect_rule:
      redirect_status_code: 301
`, "redirect_url is required"},
		{"redirect rule with non 3xx code", `
listen_addr: ":8080"
rules:
  - redirect_rule:
      redirect_url: "https://example.com"
      redirect_status_code: 200
`, "3xx"},
		{"serve rule without dir", `
listen_addr: ":8080"
rules:
  - serve_rule: {}
`, "serve_local_dir is required"},
		{"respond rule without status code", `
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_body: "ok"
`, "respond_status_code"},
		{"second rule reported with its index", `
listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
  - proxy_rule: {}
`, "rules[1]"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(test.yaml))
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", test.errContains)
			}
			if !strings.Contains(err.Error(), test.errContains) {
				t.Fatalf("expected error containing %q, got: %v", test.errContains, err)
			}
		})
	}
}

func TestRuleMatch(t *testing.T) {
	config, err := ParseConfig([]byte(`
listen_addr: ":8080"
rules:
  - domain_match: '^.*\.example\.com$'
    path_match: "/api"
    respond_rule:
      respond_status_code: 200
      respond_body: "api"
  - respond_rule:
      respond_status_code: 403
      respond_body: "Forbidden"
`))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host  string
		path  string
		index int
	}{
		{"api.example.com", "/api/v1/users", 0},
		{"api.example.com:8080", "/api", 0},
		{"api.example.com", "/other", 1},
		{"example.com", "/api", 1},
	}
	for _, test := range tests {
		if _, index := config.Rules.Match(test.host, test.path); index != test.index {
			t.Errorf("Match(%q, %q) = rule %d, want rule %d", test.host, test.path, index, test.index)
		}
	}
}
