package proxy

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The routing table and the rules' compiled state are shared by every request.
// Run the actions concurrently so -race has something to look at.
func TestConcurrentLoadAcrossRules(t *testing.T) {
	backend := newEchoBackend(t)
	dir := serveDir(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
log_level: warn
rules:
  - name: api
    path_match: "/api"
    token_auth:
      tokens: ["token1"]
    proxy_rule:
      proxy_url: %q
      proxy_append_path: false
  - name: static
    path_match: "/static"
    serve_rule:
      serve_local_dir: %q
  - name: catch-all
    respond_rule:
      respond_status_code: 404
      respond_body: "nope"
`, backend.URL, dir))

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 25 {
				request := mustRequest(t, http.MethodGet, server.url("/api/v"+strconv.Itoa(i)), nil)
				request.Header.Set("X-TOKEN", "token1")
				if resp, body := do(t, request); resp.StatusCode != http.StatusOK {
					t.Errorf("worker %d: proxy status = %d, body = %s", worker, resp.StatusCode, body)
					return
				} else if got := decodeEcho(t, body).Path; got != "/v"+strconv.Itoa(i) {
					t.Errorf("worker %d: backend saw %q", worker, got)
					return
				}

				if resp, body := get(t, server.url("/static/hello.txt")); resp.StatusCode != http.StatusOK || body != "hello" {
					t.Errorf("worker %d: serve status = %d, body = %q", worker, resp.StatusCode, body)
					return
				}

				if resp, _ := get(t, server.url("/nothing-here")); resp.StatusCode != http.StatusNotFound {
					t.Errorf("worker %d: respond status = %d", worker, resp.StatusCode)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestHeadRequestOnRespondRule(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "0123456789"
`)
	resp, body := do(t, mustRequest(t, http.MethodHead, server.url("/"), nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body != "" {
		t.Errorf("HEAD returned a body: %q", body)
	}
	if got := resp.Header.Get("Content-Length"); got != "10" {
		t.Errorf("Content-Length = %q, want 10", got)
	}
}

// With proxy_append_path the URL is forwarded untouched, so an escaped
// separator in the path survives.
func TestProxyPreservesEscapedPath(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	_, body := get(t, server.url("/a%2Fb/c"))
	got := decodeEcho(t, body)
	if got.RawPath != "/a%2Fb/c" {
		t.Errorf("backend saw raw path %q, want the escaping preserved", got.RawPath)
	}
	if got.Path != "/a/b/c" {
		t.Errorf("backend saw decoded path %q", got.Path)
	}
}

func TestServeDirectoryRedirectKeepsQuery(t *testing.T) {
	dir := serveDir(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - serve_rule:
      serve_local_dir: %q
`, dir))

	resp, _ := get(t, server.url("/sub?a=1"))
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "/sub/?a=1" {
		t.Errorf("Location = %q, want /sub/?a=1", got)
	}

}

// A Location starting with "//" is read by a browser as another host. With
// `path_match: "/"` the stripped prefix is "/" and the remaining path starts
// with one too, so concatenating them would send the client to "//sub/" - a
// different site. A relative reference is used instead.
func TestDirectoryRedirectIsNeverProtocolRelative(t *testing.T) {
	tests := []struct {
		urlPrefix string
		name      string
		want      string
	}{
		{"", "/sub", "/sub/"},
		{"/static", "/sub", "/static/sub/"},
		{"/", "/sub", "sub/"},
		{"//evil.example.com", "/sub", "sub/"},
	}
	handler := &serveHandler{}
	for _, test := range tests {
		if got := handler.directoryLocation(test.urlPrefix, test.name); got != test.want {
			t.Errorf("directoryLocation(%q, %q) = %q, want %q", test.urlPrefix, test.name, got, test.want)
		}
	}
}

func TestServeDirectoryRedirectUnderRootPathMatch(t *testing.T) {
	dir := serveDir(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - path_match: "/"
    serve_rule:
      serve_local_dir: %q
`, dir))

	resp, _ := get(t, server.url("/sub"))
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if strings.HasPrefix(location, "//") {
		t.Fatalf("Location = %q: a browser would read that as another host", location)
	}
	// following it has to land on the directory index
	resp, body := get(t, server.url("/sub/"))
	if resp.StatusCode != http.StatusOK || body != "<h1>sub index</h1>" {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}
