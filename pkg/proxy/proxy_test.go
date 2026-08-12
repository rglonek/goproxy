package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestActionsEndToEnd(t *testing.T) {
	backend := newEchoBackend(t, "app")
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<h1>root</h1>")
	writeFile(t, dir, "hello.txt", "hello")
	writeFile(t, dir, ".env", "SECRET=1")
	writeFile(t, dir, "listing/a.txt", "a")

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: api
    match: { path: "/api" }
    proxy:
      url: %q
      strip_prefix: "/api"
      host_header: "internal.example.com"
      request_headers:
        set: { X-Env: prod }
        remove: ["User-Agent", "^X-Secret-.*"]
      response_headers:
        set: { X-Frame-Options: DENY }
  - name: keep-path
    match: { path: "/keep" }
    proxy: { url: %q }
  - name: static
    match: { path: "/site" }
    serve:
      dir: %q
      strip_prefix: "/site"
      cache_control: "public, max-age=60"
  - name: moved
    match: { path: "/old" }
    redirect: { to: "https://example.com/new{path}{query}", status: 308 }
  - name: catch-all
    respond:
      status: 404
      body: "<h1>not found</h1>"
      content_type: "text/html; charset=utf-8"
      headers: { X-Custom: yes }
`, backend.URL, backend.URL, dir))

	t.Run("proxy strips the prefix and rewrites headers", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/api/v1/users?page=2"), nil)
		req.Header.Set("User-Agent", "test-agent")
		req.Header.Set("X-Secret-One", "a")
		resp, body := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusOK)
		got := decodeEcho(t, body)
		equal(t, "path", got.Path, "/v1/users")
		equal(t, "query", got.RawQuery, "page=2")
		equal(t, "host", got.Host, "internal.example.com")
		equal(t, "X-Env", got.Header.Get("X-Env"), "prod")
		equal(t, "User-Agent", got.Header.Get("User-Agent"), "")
		equal(t, "X-Secret-One", got.Header.Get("X-Secret-One"), "")
		equal(t, "X-Forwarded-Proto", got.Header.Get("X-Forwarded-Proto"), "http")
		equal(t, "X-Forwarded-For", got.Header.Get("X-Forwarded-For"), "127.0.0.1")
		equal(t, "X-Frame-Options", resp.Header.Get("X-Frame-Options"), "DENY")
		if resp.Header.Get("X-Request-Id") == "" {
			t.Error("no request id was echoed to the client")
		}
	})

	t.Run("proxy without strip_prefix keeps the path", func(t *testing.T) {
		_, body := get(t, server.url("/keep/a/b"))
		equal(t, "path", decodeEcho(t, body).Path, "/keep/a/b")
	})

	t.Run("serve", func(t *testing.T) {
		resp, body := get(t, server.url("/site/hello.txt"))
		equal(t, "status", resp.StatusCode, http.StatusOK)
		equal(t, "body", body, "hello")
		equal(t, "Cache-Control", resp.Header.Get("Cache-Control"), "public, max-age=60")

		resp, body = get(t, server.url("/site/"))
		equal(t, "index status", resp.StatusCode, http.StatusOK)
		equal(t, "index body", body, "<h1>root</h1>")

		resp, _ = get(t, server.url("/site/.env"))
		equal(t, "dotfile status", resp.StatusCode, http.StatusNotFound)

		resp, _ = get(t, server.url("/site/listing/"))
		equal(t, "listing status", resp.StatusCode, http.StatusNotFound)

		resp, _ = get(t, server.url("/site/listing"))
		equal(t, "redirect status", resp.StatusCode, http.StatusMovedPermanently)
		equal(t, "Location", resp.Header.Get("Location"), "/site/listing/")
	})

	t.Run("redirect interpolates the path", func(t *testing.T) {
		resp, _ := get(t, server.url("/old/page?a=1"))
		equal(t, "status", resp.StatusCode, http.StatusPermanentRedirect)
		equal(t, "Location", resp.Header.Get("Location"), "https://example.com/new/old/page?a=1")
	})

	t.Run("respond", func(t *testing.T) {
		resp, body := get(t, server.url("/nothing"))
		equal(t, "status", resp.StatusCode, http.StatusNotFound)
		equal(t, "body", body, "<h1>not found</h1>")
		equal(t, "Content-Type", resp.Header.Get("Content-Type"), "text/html; charset=utf-8")
		equal(t, "Content-Length", resp.Header.Get("Content-Length"), "18")
		equal(t, "X-Custom", resp.Header.Get("X-Custom"), "yes")
	})
}

func TestMatching(t *testing.T) {
	server := newTestServer(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: exact-host
    match: { host: "app.example.com", path: "/api" }
    respond: { status: 200, body: "exact" }
  - name: wildcard-host
    match: { host: "*.example.com" }
    respond: { status: 200, body: "wildcard" }
  - name: regex-host
    match: { host: '^(alpha|beta)\.test$' }
    respond: { status: 200, body: "regex" }
  - name: segment
    match: { path: "/seg", path_mode: segment }
    respond: { status: 200, body: "segment" }
  - name: exact-path
    match: { path: "/exact", path_mode: exact }
    respond: { status: 200, body: "exactpath" }
  - name: regex-path
    match: { path: '^/re/[0-9]+$', path_mode: regex }
    respond: { status: 200, body: "regexpath" }
  - name: get-only
    match: { path: "/getonly", methods: [GET] }
    respond: { status: 200, body: "getonly" }
`)

	tests := []struct {
		host, path, method string
		want               string
		status             int
	}{
		{"app.example.com", "/api/v1", "GET", "exact", 200},
		{"APP.example.com:8080", "/api", "GET", "exact", 200},
		{"app.example.com.", "/other", "GET", "wildcard", 200},
		{"other.example.com", "/x", "GET", "wildcard", 200},
		{"example.com", "/x", "GET", "", 404},
		{"alpha.test", "/x", "GET", "regex", 200},
		{"gamma.test", "/x", "GET", "", 404},
		{"h", "/seg", "GET", "segment", 200},
		{"h", "/seg/deep", "GET", "segment", 200},
		{"h", "/segfoo", "GET", "", 404},
		{"h", "/exact", "GET", "exactpath", 200},
		{"h", "/exact/more", "GET", "", 404},
		{"h", "/re/123", "GET", "regexpath", 200},
		{"h", "/re/abc", "GET", "", 404},
		{"h", "/getonly", "GET", "getonly", 200},
		{"h", "/getonly", "POST", "", 405},
	}
	for _, test := range tests {
		name := test.method + " " + test.host + test.path
		t.Run(name, func(t *testing.T) {
			req := request(t, test.method, server.url(test.path), nil)
			req.Host = test.host
			resp, body := do(t, req)
			equal(t, "status", resp.StatusCode, test.status)
			if test.want != "" {
				equal(t, "body", body, test.want)
			}
		})
	}
}

func TestAuth(t *testing.T) {
	backend := newEchoBackend(t, "app")
	dir := t.TempDir()
	writeFile(t, dir, "token.txt", "file-token\n")
	t.Setenv("GOPROXY_TEST_TOKEN", "env-token")

	hashed, err := bcrypt.GenerateFromPassword([]byte("bobs-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
auth:
  api:
    token:
      header: X-TOKEN
      tokens:
        - { id: ci, value: "t0ken" }
        - { id: fromenv, value_env: GOPROXY_TEST_TOKEN }
        - { id: fromfile, value_file: %q }
    basic:
      users:
        - { user: alice, password: "wonderland" }
        - { user: bob, password_hash: %q }
      realm: "Internal"
      forward_user_header: X-User
      forward_user_query: user
rules:
  - name: api
    auth: api
    proxy: { url: %q }
`, writeFile(t, dir, "token.txt", "file-token\n"), string(hashed), backend.URL))

	t.Run("no credentials", func(t *testing.T) {
		resp, _ := get(t, server.url("/x"))
		equal(t, "status", resp.StatusCode, http.StatusUnauthorized)
		challenges := resp.Header.Values("WWW-Authenticate")
		if len(challenges) != 2 {
			t.Fatalf("challenges = %v, want a bearer and a basic one", challenges)
		}
		contains(t, strings.Join(challenges, " "), `Basic realm="Internal"`)
	})

	t.Run("token from the config", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.Header.Set("X-TOKEN", "t0ken")
		resp, body := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusOK)
		equal(t, "forwarded token", decodeEcho(t, body).Header.Get("X-Token"), "")
	})

	t.Run("token from the environment", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.Header.Set("X-TOKEN", "env-token")
		resp, _ := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusOK)
	})

	t.Run("token from a file, with the trailing newline trimmed", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.Header.Set("X-TOKEN", "file-token")
		resp, _ := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusOK)
	})

	t.Run("bearer token", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.Header.Set("Authorization", "Bearer t0ken")
		resp, body := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusOK)
		equal(t, "forwarded authorization", decodeEcho(t, body).Header.Get("Authorization"), "")
	})

	t.Run("basic auth with a plain password", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.SetBasicAuth("alice", "wonderland")
		resp, body := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusOK)
		got := decodeEcho(t, body)
		equal(t, "X-User", got.Header.Get("X-User"), "alice")
		equal(t, "query", got.RawQuery, "user=alice")
		equal(t, "forwarded authorization", got.Header.Get("Authorization"), "")
	})

	t.Run("basic auth with a bcrypt hash", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.SetBasicAuth("bob", "bobs-password")
		resp, _ := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusOK)
	})

	t.Run("wrong password", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.SetBasicAuth("alice", "wrong")
		resp, _ := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusUnauthorized)
	})

	// a rejected token must not reach the backend when basic auth rescues the
	// request
	t.Run("rejected token is not forwarded", func(t *testing.T) {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.Header.Set("X-TOKEN", "rejected-token")
		req.SetBasicAuth("alice", "wonderland")
		resp, body := do(t, req)
		equal(t, "status", resp.StatusCode, http.StatusOK)
		equal(t, "forwarded token", decodeEcho(t, body).Header.Get("X-Token"), "")
	})

	t.Run("credentials never reach the log", func(t *testing.T) {
		logs := server.log()
		for _, secret := range []string{"t0ken", "env-token", "file-token", "wonderland", "rejected-token"} {
			notContains(t, logs, secret)
		}
		contains(t, logs, "authentication failed")
	})
}

func TestForwardAuth(t *testing.T) {
	backend := newEchoBackend(t, "app")
	authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Session") != "good" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("X-Auth-User", "carol")
		w.Header().Set("X-Groups", "staff")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(authService.Close)

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
auth:
  sso:
    forward:
      url: %q
      user_header: X-Auth-User
      copy_headers: [X-Groups]
rules:
  - name: app
    auth: sso
    proxy: { url: %q }
`, authService.URL, backend.URL))

	resp, _ := get(t, server.url("/x"))
	equal(t, "unauthenticated status", resp.StatusCode, http.StatusUnauthorized)

	req := request(t, http.MethodGet, server.url("/x"), nil)
	req.Header.Set("X-Session", "good")
	resp, body := do(t, req)
	equal(t, "status", resp.StatusCode, http.StatusOK)
	equal(t, "copied header", decodeEcho(t, body).Header.Get("X-Groups"), "staff")
	contains(t, server.log(), "")
}

func TestLoadBalancingAndFailover(t *testing.T) {
	first := newEchoBackend(t, "first")
	second := newEchoBackend(t, "second")

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
upstreams:
  app:
    targets:
      - url: %q
      - url: %q
    policy: round_robin
rules:
  - name: app
    proxy: { upstream: app }
`, first.URL, second.URL))

	seen := map[string]int{}
	for range 6 {
		_, body := get(t, server.url("/x"))
		seen[decodeEcho(t, body).Backend]++
	}
	if seen["first"] != 3 || seen["second"] != 3 {
		t.Fatalf("round robin spread = %v, want an even split", seen)
	}
}

func TestFailoverToHealthyTarget(t *testing.T) {
	dead := freePort(t) // nothing is listening there
	alive := newEchoBackend(t, "alive")

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
upstreams:
  app:
    targets:
      - url: "http://%s"
      - url: %q
    policy: round_robin
    health:
      passive: { failures: 1, cooldown: 30s }
    retry:
      attempts: 2
      on: [connect_error]
rules:
  - name: app
    proxy: { upstream: app }
`, dead, alive.URL))

	// the first request may start on the dead target, and has to be retried
	// onto the live one rather than failing
	for i := range 5 {
		resp, body := get(t, server.url("/x"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, body = %s", i, resp.StatusCode, body)
		}
		equal(t, "backend", decodeEcho(t, body).Backend, "alive")
	}
	contains(t, server.log(), "upstream target ejected")
}

func TestRetryIsNotAppliedToRequestsWithABody(t *testing.T) {
	dead := freePort(t)
	alive := newEchoBackend(t, "alive")
	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
upstreams:
  app:
    targets:
      - url: "http://%s"
      - url: %q
    policy: first_healthy
    health:
      passive: { enabled: false }
    retry: { attempts: 2, on: [connect_error] }
rules:
  - name: app
    proxy: { upstream: app }
`, dead, alive.URL))

	// a body that has already been read cannot be replayed, so this must fail
	// rather than be silently sent twice
	resp, _ := do(t, request(t, http.MethodPost, server.url("/x"), strings.NewReader("payload")))
	equal(t, "status", resp.StatusCode, http.StatusBadGateway)
}

func TestRateLimit(t *testing.T) {
	server := newTestServer(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: limited
    rate_limit: { requests_per_second: 1, burst: 2 }
    respond: { status: 200, body: "ok" }
`)

	statuses := []int{}
	for range 4 {
		resp, _ := get(t, server.url("/x"))
		statuses = append(statuses, resp.StatusCode)
	}
	equal(t, "first", statuses[0], http.StatusOK)
	equal(t, "second", statuses[1], http.StatusOK)
	equal(t, "third", statuses[2], http.StatusTooManyRequests)
	if statuses[3] != http.StatusTooManyRequests {
		t.Errorf("fourth = %d, want 429", statuses[3])
	}
	resp, _ := get(t, server.url("/x"))
	if resp.Header.Get("Retry-After") == "" && resp.StatusCode == http.StatusTooManyRequests {
		t.Error("no Retry-After on a rate-limited response")
	}
}

func TestIPFilterAndCORS(t *testing.T) {
	server := newTestServer(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: denied
    match: { path: "/denied" }
    deny_ips: ["127.0.0.0/8"]
    respond: { status: 200, body: "ok" }
  - name: allowed
    match: { path: "/allowed" }
    allow_ips: ["10.0.0.0/8"]
    respond: { status: 200, body: "ok" }
  - name: cors
    match: { path: "/cors" }
    cors:
      allow_origins: ["https://app.example.com"]
      allow_methods: [GET, POST]
      max_age: 600
    respond: { status: 200, body: "ok" }
`)

	resp, _ := get(t, server.url("/denied"))
	equal(t, "denied", resp.StatusCode, http.StatusForbidden)

	resp, _ = get(t, server.url("/allowed"))
	equal(t, "not in the allow list", resp.StatusCode, http.StatusForbidden)

	req := request(t, http.MethodOptions, server.url("/cors"), nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, _ = do(t, req)
	equal(t, "preflight status", resp.StatusCode, http.StatusNoContent)
	equal(t, "allow-origin", resp.Header.Get("Access-Control-Allow-Origin"), "https://app.example.com")
	equal(t, "allow-methods", resp.Header.Get("Access-Control-Allow-Methods"), "GET, POST")
	equal(t, "max-age", resp.Header.Get("Access-Control-Max-Age"), "600")

	req = request(t, http.MethodOptions, server.url("/cors"), nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, _ = do(t, req)
	equal(t, "other origin", resp.Header.Get("Access-Control-Allow-Origin"), "")
}

func TestTrustedProxies(t *testing.T) {
	backend := newEchoBackend(t, "app")
	for _, test := range []struct {
		name          string
		trusted       string
		wantForwarded string
		wantRealIP    string
	}{
		{"untrusted peer: the claim is dropped", "", "127.0.0.1", "127.0.0.1"},
		{"trusted peer: the claim is kept and appended to", `trusted_proxies: ["127.0.0.0/8"]`, "1.2.3.4, 127.0.0.1", "1.2.3.4"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
%s
rules:
  - name: app
    proxy: { url: %q }
`, test.trusted, backend.URL))

			req := request(t, http.MethodGet, server.url("/x"), nil)
			req.Header.Set("X-Forwarded-For", "1.2.3.4")
			req.Header.Set("X-Forwarded-Proto", "https")
			_, body := do(t, req)
			got := decodeEcho(t, body)
			equal(t, "X-Forwarded-For", got.Header.Get("X-Forwarded-For"), test.wantForwarded)
			equal(t, "X-Real-Ip", got.Header.Get("X-Real-Ip"), test.wantRealIP)
			if test.trusted == "" {
				equal(t, "X-Forwarded-Proto", got.Header.Get("X-Forwarded-Proto"), "http")
				contains(t, server.log(), "dropped inbound X-Forwarded-*")
			}
		})
	}
}

func TestAdminEndpoints(t *testing.T) {
	server := newTestServer(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
admin: { addr: "127.0.0.1:0" }
auth:
  api:
    token:
      tokens: [{ id: ci, value: "supersecret" }]
rules:
  - name: catch-all
    auth: api
    respond: { status: 200, body: "ok" }
`)

	resp, body := get(t, server.adminURL("/healthz"))
	equal(t, "healthz", resp.StatusCode, http.StatusOK)
	equal(t, "healthz body", strings.TrimSpace(body), "ok")

	resp, _ = get(t, server.adminURL("/readyz"))
	equal(t, "readyz", resp.StatusCode, http.StatusOK)

	// generate a request so there is something to count
	get(t, server.url("/x"))
	resp, body = get(t, server.adminURL("/metrics"))
	equal(t, "metrics", resp.StatusCode, http.StatusOK)
	contains(t, body, "goproxy_requests_total{")
	contains(t, body, "goproxy_build_info{")
	contains(t, body, "goproxy_auth_failures_total{")

	resp, body = get(t, server.adminURL("/config"))
	equal(t, "config", resp.StatusCode, http.StatusOK)
	contains(t, body, "REDACTED")
	notContains(t, body, "supersecret")

	// the admin listener is not the routed one
	resp, _ = get(t, server.url("/healthz"))
	equal(t, "healthz is not routed", resp.StatusCode, http.StatusUnauthorized)
}

func TestReloadUnderLoad(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: catch-all
    respond: { status: 200, body: "first" }
`)
	cfg := parseFile(t, path)
	server := startTestServer(t, cfg)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	bodies := map[string]int{}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, body := get(t, server.url("/x"))
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status during reload = %d", resp.StatusCode)
					return
				}
				mu.Lock()
				bodies[body]++
				mu.Unlock()
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	writeFileAt(t, path, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: catch-all
    respond: { status: 200, body: "second" }
`)
	if err := server.ReloadFile(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	if bodies["first"] == 0 || bodies["second"] == 0 {
		t.Fatalf("responses = %v, want both configs to have served", bodies)
	}
	_, body := get(t, server.url("/x"))
	equal(t, "after reload", body, "second")
}

func TestReloadRejectsABadConfig(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: catch-all
    respond: { status: 200, body: "first" }
`)
	server := startTestServer(t, parseFile(t, path))

	writeFileAt(t, path, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: broken
    proxy: { url: "garbage" }
`)
	if err := server.ReloadFile(); err == nil {
		t.Fatal("a config that cannot compile was accepted")
	}
	_, body := get(t, server.url("/x"))
	equal(t, "still serving the old config", body, "first")
}

func TestReloadRejectsAListenerChange(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "config.yaml", `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: catch-all
    respond: { status: 200, body: "first" }
`)
	server := startTestServer(t, parseFile(t, path))

	writeFileAt(t, path, `
version: 2
listeners:
  http: { addr: "127.0.0.1:1" }
rules:
  - name: catch-all
    respond: { status: 200, body: "first" }
`)
	err := server.ReloadFile()
	if err == nil {
		t.Fatal("a listener address change was accepted by reload")
	}
	contains(t, err.Error(), "restart is required")
}

func TestShutdownIsIdempotent(t *testing.T) {
	server := startTestServer(t, parse(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - respond: { status: 200, body: "ok" }
`))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("Wait = %v, want nil", err)
	}
}

func TestWaitReportsListenerFailure(t *testing.T) {
	server := startTestServer(t, parse(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - respond: { status: 200, body: "ok" }
`))
	server.httpLn.Close() // pull the listener out from under the serving goroutine

	waited := make(chan error, 1)
	go func() { waited <- server.Wait() }()
	select {
	case err := <-waited:
		if err == nil {
			t.Fatal("Wait returned nil after the listener died")
		}
		contains(t, err.Error(), "http listener")
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the listener died")
	}
}

func TestPanicIsRecovered(t *testing.T) {
	server := startTestServer(t, parse(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - respond: { status: 200, body: "ok" }
`))
	// replace the routing table's handler with one that panics
	panicking := httptest.NewServer(nil)
	panicking.Close()

	server.routes.Load().Rules()[0].Handler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("rule exploded")
	})
	resp, _ := get(t, server.url("/x"))
	equal(t, "status", resp.StatusCode, http.StatusInternalServerError)
	contains(t, server.log(), "panic serving request")
	contains(t, server.log(), "rule exploded")
}

// A metric registered with an empty label name renders as {=""}, which no
// Prometheus parser accepts, and an arbitrary method token would give the
// request counter unbounded cardinality.
func TestMetricsExpositionIsValid(t *testing.T) {
	server := newTestServer(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
admin: { addr: "127.0.0.1:0" }
rules:
  - name: catch-all
    respond: { status: 200, body: "ok" }
`)
	get(t, server.url("/x"))
	// a method token a client made up
	weird := request(t, "FOOBAR", server.url("/x"), nil)
	do(t, weird)

	_, body := get(t, server.adminURL("/metrics"))
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.Contains(line, `{=`) || strings.Contains(line, `,=`) {
			t.Errorf("metric line has an empty label name: %q", line)
		}
	}
	contains(t, body, "goproxy_panics_total 0")
	contains(t, body, `method="other"`)
	notContains(t, body, `method="FOOBAR"`)
}

// A rate limit keyed by identity has to run after authentication, or the
// identity is not known yet and every client shares the anonymous bucket.
func TestRateLimitByIdentity(t *testing.T) {
	server := newTestServer(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
auth:
  api:
    token:
      tokens:
        - { id: alice, value: "alice-token" }
        - { id: bob, value: "bob-token" }
rules:
  - name: limited
    auth: api
    rate_limit: { requests_per_second: 1, burst: 1, by: identity }
    respond: { status: 200, body: "ok" }
`)
	call := func(token string) int {
		req := request(t, http.MethodGet, server.url("/x"), nil)
		req.Header.Set("X-TOKEN", token)
		resp, _ := do(t, req)
		return resp.StatusCode
	}
	equal(t, "alice first", call("alice-token"), http.StatusOK)
	equal(t, "alice second", call("alice-token"), http.StatusTooManyRequests)
	// bob has his own bucket: without the ordering fix he would share alice's
	equal(t, "bob first", call("bob-token"), http.StatusOK)
}

// trusted_proxies and log.level are server-level rather than part of the
// routing table, so a reload has to apply them deliberately; without that a
// change would be accepted and then quietly ignored.
func TestReloadAppliesServerLevelSettings(t *testing.T) {
	backend := newEchoBackend(t, "app")
	dir := t.TempDir()
	before := fmt.Sprintf(`
version: 2
log: { level: info }
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - name: app
    proxy: { url: %q }
`, backend.URL)
	path := writeFile(t, dir, "config.yaml", before)
	server := startTestServer(t, parseFile(t, path))

	req := request(t, http.MethodGet, server.url("/x"), nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	_, body := do(t, req)
	equal(t, "before reload", decodeEcho(t, body).Header.Get("X-Real-Ip"), "127.0.0.1")

	writeFileAt(t, path, strings.Replace(before,
		"log: { level: info }",
		"log: { level: detail }\ntrusted_proxies: [\"127.0.0.0/8\"]", 1))
	if err := server.ReloadFile(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	req = request(t, http.MethodGet, server.url("/x"), nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	_, body = do(t, req)
	equal(t, "after reload", decodeEcho(t, body).Header.Get("X-Real-Ip"), "1.2.3.4")
	// the level change took effect too: detail logs which rule matched
	contains(t, server.log(), "rule matched")
}

// Settings that are baked into the logger or the listeners at startup cannot be
// swapped, so a reload says so rather than leaving the operator to find out.
func TestReloadWarnsAboutSettingsItCannotApply(t *testing.T) {
	dir := t.TempDir()
	before := `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
defaults:
  timeouts: { read: 30s }
rules:
  - name: app
    respond: { status: 200, body: ok }
`
	path := writeFile(t, dir, "config.yaml", before)
	server := startTestServer(t, parseFile(t, path))

	writeFileAt(t, path, strings.Replace(before, "read: 30s", "read: 5s", 1))
	if err := server.ReloadFile(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	contains(t, server.log(), "needs a restart")
	contains(t, server.log(), "defaults.timeouts")
}
