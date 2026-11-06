package proxy

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goproxy/pkg/config"
)

// TestExampleConfigs loads and compiles every config in examples/ with the
// current binary, so a documented option that no longer exists cannot go
// unnoticed. The examples point at paths that only exist on a real deployment
// (/var/www/html, /etc/ssl/...), so those are redirected into the test's temp
// directory; nothing else about the files is changed.
func TestExampleConfigs(t *testing.T) {
	certFile, keyFile, _ := testCert(t)
	dir := t.TempDir()
	webroot := filepath.Join(dir, "www")
	if err := os.MkdirAll(webroot, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPROXY_DEPLOY_TOKEN", "deploy-token")
	t.Setenv("GOPROXY_APP_KEY", "app-key")
	aliceDir := alicePasswords(t)

	replacements := strings.NewReplacer(
		"/var/www/html", webroot,
		"/etc/goproxy/alice", aliceDir,
		`dir: "./"`, `dir: "`+webroot+`"`,
		"snakeoil.crt", certFile,
		"snakeoil.pem", keyFile,
		"/var/lib/goproxy/letsencrypt", filepath.Join(dir, "acme"),
		// bind to a port the test can actually take
		`addr: ":8080"`, `addr: "127.0.0.1:0"`,
		`addr: ":8443"`, `addr: "127.0.0.1:0"`,
		`addr: ":80"`, `addr: "127.0.0.1:80"`, // acme needs the :80 suffix; nothing is bound here
		`addr: ":443"`, `addr: "127.0.0.1:0"`,
		`addr: "127.0.0.1:9090"`, `addr: "127.0.0.1:0"`,
	)

	files, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example configs found")
	}

	for _, file := range files {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			text := replacements.Replace(string(raw))
			cfg, err := config.Parse([]byte(text))
			if err != nil {
				t.Fatalf("example does not load: %v", err)
			}
			// compiling is what proves the rules can run: upstream URLs, static
			// directories, certificates, secrets and response bodies are all
			// resolved here
			server, err := New(cfg)
			if err != nil {
				t.Fatalf("example does not compile: %v", err)
			}
			server.Routes().Close()
		})
	}
}

// The examples are also the routing documentation, so a few of their documented
// decisions are asserted directly.
func TestVirtualHostExampleRoutes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "05-virtual-hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	text := strings.ReplaceAll(string(raw), "/var/www/html", dir)
	text = strings.ReplaceAll(text, `addr: ":8080"`, `addr: "127.0.0.1:0"`)
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Routes().Close()

	tests := []struct {
		host, path, method, want string
	}{
		{"app.example.com", "/api/v1", "GET", "api"},
		// the method list only makes this rule skip; the wildcard host rule below
		// still matches
		{"app.example.com", "/api", "DELETE", "sites"},
		{"static.example.com", "/index.html", "GET", "sites"},
		{"alpha.example.net", "/x", "GET", "legacy"},
		{"somewhere.else", "/", "GET", "catch-all"},
	}
	for _, test := range tests {
		rule, _ := server.Routes().Match(test.host, test.path, test.method)
		if rule == nil {
			t.Errorf("%s %s%s matched nothing, want %s", test.method, test.host, test.path, test.want)
			continue
		}
		if rule.Name != test.want {
			t.Errorf("%s %s%s = %s, want %s", test.method, test.host, test.path, rule.Name, test.want)
		}
	}
}

// alicePasswords writes the password files examples/10-alice.yaml reads, each
// user's password being "<user>-pw".
func alicePasswords(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, user := range []string{"robert", "gina", "vic"} {
		writeFile(t, dir, user+".pw", user+"-pw")
	}
	return dir
}

// examples/10-alice.yaml is the documentation for running Alice behind
// goproxy, so which role reaches which route is asserted against the file
// itself, along with what Alice is told about who is calling.
func TestAliceExampleRoles(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "10-alice.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	backend := newEchoBackend(t, "alice")
	text := strings.NewReplacer(
		"/etc/goproxy/alice", alicePasswords(t),
		`"http://127.0.0.1:8000"`, `"`+backend.URL+`"`,
		`addr: ":8080"`, `addr: "127.0.0.1:0"`,
	).Replace(string(raw))
	server := newTestServer(t, text)

	const (
		all       = "robert gina vic"
		talkers   = "robert gina"
		ownerOnly = "robert"
	)
	routes := []struct {
		method, path, allowed string
	}{
		{"GET", "/api/events", all},
		{"POST", "/api/chat/stream", talkers},
		{"POST", "/v1/chat/completions", talkers},
		{"POST", "/api/chat", talkers},
		{"GET", "/api/conversation", talkers},
		{"POST", "/api/session/rotate", talkers},
		{"POST", "/api/voice/speak", talkers},
		{"GET", "/api/voice/engines", talkers},
		{"POST", "/api/voice/select", ownerOnly}, // before voice/.* matches it
		{"POST", "/api/approvals/decide", ownerOnly},
		{"POST", "/api/stop", ownerOnly},
		{"POST", "/api/restart", ownerOnly},
		{"POST", "/api/reset", ownerOnly},
		{"POST", "/api/identity/confirm", ownerOnly},
		{"POST", "/api/sleep", ownerOnly},
		{"GET", "/", all},
		{"GET", "/ui/", all},
		{"GET", "/api/state", all},
		{"GET", "/api/thoughts", all},
		{"GET", "/api/dreams", all},
		{"GET", "/api/goals", all},
		{"GET", "/api/health", all},
		{"GET", "/v1/models", all},
	}
	roles := map[string]string{"robert": "owner", "gina": "guest", "vic": "viewer"}
	for _, route := range routes {
		for _, user := range []string{"robert", "gina", "vic"} {
			req := request(t, route.method, server.url(route.path), nil)
			req.SetBasicAuth(user, user+"-pw")
			// a guest claiming to be the owner changes nothing
			req.Header.Set("X-Alice-User", "robert")
			req.Header.Set("X-Alice-Role", "owner")
			resp, body := do(t, req)
			want := http.StatusForbidden
			if strings.Contains(" "+route.allowed+" ", " "+user+" ") {
				want = http.StatusOK
			}
			if resp.StatusCode != want {
				t.Errorf("%s %s as %s = %d, want %d", route.method, route.path, user, resp.StatusCode, want)
				continue
			}
			if want != http.StatusOK {
				continue
			}
			got := decodeEcho(t, body)
			equal(t, route.path+" X-Alice-User", strings.Join(got.Header.Values("X-Alice-User"), "|"), user)
			equal(t, route.path+" X-Alice-Role", strings.Join(got.Header.Values("X-Alice-Role"), "|"), roles[user])
			equal(t, route.path+" Authorization", got.Header.Get("Authorization"), "Bearer CHANGE-ME")
		}
	}

	resp, _ := get(t, server.url("/api/state"))
	equal(t, "no credentials", resp.StatusCode, http.StatusUnauthorized)
	// reading is all the catch-all is for
	req := request(t, http.MethodPost, server.url("/api/state"), nil)
	req.SetBasicAuth("robert", "robert-pw")
	resp, _ = do(t, req)
	equal(t, "POST to a read route", resp.StatusCode, http.StatusMethodNotAllowed)
}
