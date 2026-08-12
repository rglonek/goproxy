package proxy

import (
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

	replacements := strings.NewReplacer(
		"/var/www/html", webroot,
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
