package proxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExampleConfigs loads every config in examples/ with the current binary.
// The examples point at paths that only exist on a real deployment
// (/var/www/html, /etc/ssl/...), so those are redirected into the test's temp
// directory; nothing else about the files is changed.
func TestExampleConfigs(t *testing.T) {
	certFile, keyFile, _ := testCert(t)
	dir := t.TempDir()
	webroot := filepath.Join(dir, "www")
	if err := os.MkdirAll(webroot, 0o755); err != nil {
		t.Fatal(err)
	}
	replacements := strings.NewReplacer(
		"/var/www/html", webroot,
		`serve_local_dir: "./"`, `serve_local_dir: "`+webroot+`"`,
		"/etc/ssl/certs/example.com.crt", certFile,
		"/etc/ssl/private/example.com.key", keyFile,
		"snakeoil.crt", certFile,
		"snakeoil.key", keyFile,
		"/var/lib/goproxy/letsencrypt", filepath.Join(dir, "acme"),
	)

	files, err := filepath.Glob(filepath.Join("..", "..", "examples", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example configs found")
	}

	// what each example is documented to do, as (host, path) -> rule index
	routes := map[string][]struct {
		host  string
		path  string
		index int
	}{
		"01-reverse-proxy.yaml": {{"localhost", "/anything", 0}},
		"03-redirect-and-respond.yaml": {
			{"localhost", "/old-docs", 0},
			{"localhost", "/old-docs/page", 0},
			{"localhost", "/anything-else", 1},
		},
		"04-basic-auth.yaml": {{"localhost", "/app/page", 0}},
		"05-token-auth.yaml": {{"localhost", "/api/v1", 0}},
		"06-virtual-hosts.yaml": {
			{"app.example.com", "/api/v1/x", 0},
			{"app.example.com:8080", "/api", 0},
			{"APP.example.com", "/api", 0},
			{"app.example.com", "/other", 1},
			{"static.example.com", "/index.html", 1},
			{"somewhere.else", "/", 2},
		},
	}

	for _, file := range files {
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			config, err := ParseConfig([]byte(replacements.Replace(string(raw))))
			if err != nil {
				t.Fatalf("example does not load: %v", err)
			}
			if warnings := config.Warnings(); len(warnings) > 0 {
				t.Errorf("example has unknown keys: %v", warnings)
			}
			// compiling is what proves the rules can actually run: upstream
			// URLs, static directories, certificates and response bodies are
			// all resolved here
			server, err := New(config)
			if err != nil {
				t.Fatalf("example does not compile: %v", err)
			}
			defer func() { _ = server.Shutdown(context.Background()) }()

			for _, route := range routes[name] {
				rule, index := config.Rules.Match(route.host, route.path)
				if rule == nil {
					t.Errorf("Match(%q, %q) matched no rule, want rules[%d]", route.host, route.path, route.index)
					continue
				}
				if index != route.index {
					t.Errorf("Match(%q, %q) = rules[%d], want rules[%d]", route.host, route.path, index, route.index)
				}
			}
		})
	}
}
