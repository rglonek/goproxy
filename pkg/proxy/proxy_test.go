package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestProxyAppendPath(t *testing.T) {
	backend := newEchoBackend(t)

	tests := []struct {
		name       string
		pathMatch  string
		appendPath bool
		request    string
		wantPath   string
	}{
		{"append keeps the whole path", "/api", true, "/api/v1/users", "/api/v1/users"},
		{"no append strips the literal prefix", "/api", false, "/api/v1/users", "/v1/users"},
		{"no append with a regex prefix", `^/api`, false, "/api/v1/users", "/v1/users"},
		// ReplaceAllString used to remove every match, not just the leading one
		{"strip removes only the leading match", `^/api`, false, "/api/x/api/y", "/x/api/y"},
		{"no path match, nothing to strip", "", false, "/anything", "/anything"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
log_level: detail
rules:
  - path_match: %q
    proxy_rule:
      proxy_url: %q
      proxy_append_path: %t
`, test.pathMatch, backend.URL, test.appendPath))

			resp, body := get(t, server.url(test.request))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
			}
			if got := decodeEcho(t, body).Path; got != test.wantPath {
				t.Errorf("backend saw path %q, want %q", got, test.wantPath)
			}
		})
	}
}

func TestProxyForwardsHostAndQuery(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	req := mustRequest(t, http.MethodGet, server.url("/x?a=1&b=2"), nil)
	req.Host = "app.example.com"
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	got := decodeEcho(t, body)
	if got.Host != "app.example.com" {
		t.Errorf("backend saw Host %q, want the host the client sent", got.Host)
	}
	if got.RawQuery != "a=1&b=2" {
		t.Errorf("backend saw query %q", got.RawQuery)
	}
}

func TestProxyRewriteHostHeader(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - proxy_rule:
      proxy_url: %q
      proxy_append_path: true
      proxy_rewrite_host_header: "internal.example.com"
`, backend.URL))

	req := mustRequest(t, http.MethodGet, server.url("/x"), nil)
	req.Host = "public.example.com"
	_, body := do(t, req)
	got := decodeEcho(t, body)
	if got.Host != "internal.example.com" {
		t.Errorf("backend saw Host %q, want the rewritten host", got.Host)
	}
	// the original host is still visible to the backend through X-Forwarded-Host
	if got.Header.Get("X-Forwarded-Host") != "public.example.com" {
		t.Errorf("X-Forwarded-Host = %q, want the original host", got.Header.Get("X-Forwarded-Host"))
	}
}

func TestProxySetAndRemoveHeaders(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - proxy_rule:
      proxy_url: %q
      proxy_append_path: true
      proxy_set_headers:
        X-Env: prod
      proxy_remove_headers:
        - "User-Agent"
        - "^X-Secret-.*"
`, backend.URL))

	req := mustRequest(t, http.MethodGet, server.url("/x"), nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Set("X-Secret-One", "a")
	req.Header.Set("X-Secret-Two", "b")
	req.Header.Set("X-Kept", "yes")
	_, body := do(t, req)
	got := decodeEcho(t, body)

	if got.Header.Get("X-Env") != "prod" {
		t.Errorf("X-Env = %q, want prod", got.Header.Get("X-Env"))
	}
	if got.Header.Get("User-Agent") != "" {
		t.Errorf("User-Agent was forwarded: %q", got.Header.Get("User-Agent"))
	}
	if got.Header.Get("X-Secret-One") != "" || got.Header.Get("X-Secret-Two") != "" {
		t.Errorf("regex header removal did not apply: %v", got.Header)
	}
	if got.Header.Get("X-Kept") != "yes" {
		t.Errorf("X-Kept = %q, want yes", got.Header.Get("X-Kept"))
	}
}

// S5: a backend behind TLS termination has to be able to tell that the original
// request was HTTPS, and which host it was for.
func TestProxySetsForwardedHeaders(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	_, body := get(t, server.url("/x"))
	got := decodeEcho(t, body)
	if got.Header.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("X-Forwarded-Proto = %q, want http", got.Header.Get("X-Forwarded-Proto"))
	}
	if got.Header.Get("X-Forwarded-Host") == "" {
		t.Error("X-Forwarded-Host was not set")
	}
	if got.Header.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %q, want the peer address", got.Header.Get("X-Forwarded-For"))
	}
	if got.Header.Get("X-Real-Ip") != "127.0.0.1" {
		t.Errorf("X-Real-Ip = %q", got.Header.Get("X-Real-Ip"))
	}
}

// S6: a client that is not a trusted proxy must not be able to claim it is
// speaking for somebody else.
func TestProxyForwardedForSpoofing(t *testing.T) {
	backend := newEchoBackend(t)

	tests := []struct {
		name           string
		trustedProxies string
		wantForwarded  string
		wantRealIP     string
	}{
		{"untrusted peer: the claim is dropped", "", "127.0.0.1", "127.0.0.1"},
		{"trusted peer: the claim is kept and appended to", `trusted_proxies: ["127.0.0.0/8"]`, "1.2.3.4, 127.0.0.1", "1.2.3.4"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
%s
rules:
  - proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, test.trustedProxies, backend.URL))

			req := mustRequest(t, http.MethodGet, server.url("/x"), nil)
			req.Header.Set("X-Forwarded-For", "1.2.3.4")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Real-Ip", "1.2.3.4")
			_, body := do(t, req)
			got := decodeEcho(t, body)

			if got.Header.Get("X-Forwarded-For") != test.wantForwarded {
				t.Errorf("X-Forwarded-For = %q, want %q", got.Header.Get("X-Forwarded-For"), test.wantForwarded)
			}
			if got.Header.Get("X-Real-Ip") != test.wantRealIP {
				t.Errorf("X-Real-Ip = %q, want %q", got.Header.Get("X-Real-Ip"), test.wantRealIP)
			}
			if test.trustedProxies == "" && got.Header.Get("X-Forwarded-Proto") != "http" {
				t.Errorf("X-Forwarded-Proto = %q, want the real scheme", got.Header.Get("X-Forwarded-Proto"))
			}
		})
	}
}

func TestProxyUpstreamDownIs502(t *testing.T) {
	dead := freePort(t) // nothing is listening there
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - proxy_rule:
      proxy_url: "http://%s"
      proxy_append_path: true
`, dead))

	resp, _ := get(t, server.url("/x"))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	contains(t, server.logs(), "Mod=Proxy")
}

func TestBasicAuth(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - path_match: "/app"
    basic_auth:
      user: "admin"
      password: "s3cret"
      set_user_header: "X-USER"
      set_user_get_var: "user"
    proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	t.Run("no credentials", func(t *testing.T) {
		resp, _ := get(t, server.url("/app"))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
			t.Errorf("WWW-Authenticate = %q", got)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		req := mustRequest(t, http.MethodGet, server.url("/app"), nil)
		req.SetBasicAuth("admin", "wrong")
		resp, _ := do(t, req)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("right password", func(t *testing.T) {
		req := mustRequest(t, http.MethodGet, server.url("/app/page"), nil)
		req.SetBasicAuth("admin", "s3cret")
		resp, body := do(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
		}
		got := decodeEcho(t, body)
		if got.Header.Get("X-USER") != "admin" {
			t.Errorf("X-USER = %q, want admin", got.Header.Get("X-USER"))
		}
		if got.RawQuery != "user=admin" {
			t.Errorf("query = %q, want user=admin", got.RawQuery)
		}
		if got.Header.Get("Authorization") != "" {
			t.Error("the Authorization header goproxy consumed was forwarded upstream")
		}
	})

	t.Run("credentials never reach the log", func(t *testing.T) {
		notContains(t, server.logs(), "s3cret")
	})
}

func TestTokenAuth(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
log_level: detail
rules:
  - path_match: "/api"
    token_auth:
      tokens: ["token1", "token2"]
      token_auth_header: "X-TOKEN"
      forward_header: false
    proxy_rule:
      proxy_url: %q
      proxy_append_path: true
  - path_match: "/keep"
    token_auth:
      tokens: ["token1"]
      forward_header: true
    proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL, backend.URL))

	t.Run("no token", func(t *testing.T) {
		resp, _ := get(t, server.url("/api"))
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		// v0.1.0 answered `WWW-Authenticate: Bearer`, telling the client to
		// retry in a form goproxy does not read
		if got := resp.Header.Get("WWW-Authenticate"); got != "" {
			t.Errorf("WWW-Authenticate = %q, want no challenge", got)
		}
	})

	t.Run("wrong token is rejected and never logged", func(t *testing.T) {
		req := mustRequest(t, http.MethodGet, server.url("/api"), nil)
		req.Header.Set("X-TOKEN", "hunter2-is-valid-elsewhere")
		resp, _ := do(t, req)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
		notContains(t, server.logs(), "hunter2-is-valid-elsewhere")
	})

	t.Run("valid token is accepted and stripped", func(t *testing.T) {
		req := mustRequest(t, http.MethodGet, server.url("/api/v1"), nil)
		req.Header.Set("X-TOKEN", "token2")
		resp, body := do(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
		}
		if got := decodeEcho(t, body).Header.Get("X-TOKEN"); got != "" {
			t.Errorf("X-TOKEN was forwarded upstream: %q", got)
		}
		notContains(t, server.logs(), "token2")
	})

	t.Run("forward_header keeps the token", func(t *testing.T) {
		req := mustRequest(t, http.MethodGet, server.url("/keep"), nil)
		req.Header.Set("X-TOKEN", "token1")
		_, body := do(t, req)
		if got := decodeEcho(t, body).Header.Get("X-TOKEN"); got != "token1" {
			t.Errorf("X-TOKEN = %q, want it forwarded", got)
		}
	})
}

// C6: when token auth fails and basic auth rescues the request, the rejected
// token must not be handed to the backend.
func TestTokenFailureThenBasicSuccessStripsToken(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - token_auth:
      tokens: ["good-token"]
      forward_header: false
    basic_auth:
      user: "admin"
      password: "s3cret"
    proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	req := mustRequest(t, http.MethodGet, server.url("/x"), nil)
	req.Header.Set("X-TOKEN", "rejected-token")
	req.SetBasicAuth("admin", "s3cret")
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if got := decodeEcho(t, body).Header.Get("X-TOKEN"); got != "" {
		t.Errorf("rejected token was forwarded upstream: %q", got)
	}
}

func TestTokenAuthAcceptBearer(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - token_auth:
      tokens: ["token1"]
      accept_bearer: true
    proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	req := mustRequest(t, http.MethodGet, server.url("/x"), nil)
	req.Header.Set("Authorization", "Bearer token1")
	resp, body := do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if got := decodeEcho(t, body).Header.Get("Authorization"); got != "" {
		t.Errorf("the bearer token goproxy consumed was forwarded: %q", got)
	}

	resp, _ = get(t, server.url("/x"))
	if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer when accept_bearer is on", got)
	}
}

func TestSelfSignedUpstreamKeepsTunedTransport(t *testing.T) {
	config, err := ParseConfig([]byte(`
listen_addr: "127.0.0.1:0"
rules:
  - proxy_rule:
      proxy_url: "https://127.0.0.1:9"
      proxy_target_accept_self_signed: true
`))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	transport := server.insecureTransport
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify was not set")
	}
	// S9: v0.1.0 replaced the transport with a bare one, losing every timeout
	// and the connection pool
	if transport.TLSHandshakeTimeout == 0 || transport.ResponseHeaderTimeout == 0 {
		t.Error("the self-signed transport has no timeouts")
	}
	if transport.MaxIdleConns == 0 {
		t.Error("the self-signed transport has no connection pool")
	}
}
