package proxy

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func serveDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<h1>root index</h1>")
	writeFile(t, dir, "hello.txt", "hello")
	writeFile(t, dir, "sub/index.html", "<h1>sub index</h1>")
	writeFile(t, dir, "listing/a.txt", "a")
	writeFile(t, dir, "listing/b.txt", "b")
	writeFile(t, dir, ".env", "SECRET=1")
	return dir
}

func TestServeStaticFiles(t *testing.T) {
	dir := serveDir(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - serve_rule:
      serve_local_dir: %q
      serve_cache_control: "public, max-age=60"
`, dir))

	t.Run("index file", func(t *testing.T) {
		resp, body := get(t, server.url("/"))
		if resp.StatusCode != http.StatusOK || body != "<h1>root index</h1>" {
			t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
		}
		if resp.Header.Get("Cache-Control") != "public, max-age=60" {
			t.Errorf("Cache-Control = %q", resp.Header.Get("Cache-Control"))
		}
	})

	t.Run("regular file", func(t *testing.T) {
		resp, body := get(t, server.url("/hello.txt"))
		if resp.StatusCode != http.StatusOK || body != "hello" {
			t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		resp, _ := get(t, server.url("/nope.txt"))
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})

	// S8: v0.1.0 generated an index page for any directory without an
	// index.html, with no way to turn it off
	t.Run("directory listings are off by default", func(t *testing.T) {
		resp, body := get(t, server.url("/listing/"))
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404, body = %q", resp.StatusCode, body)
		}
		notContains(t, body, "a.txt")
	})

	t.Run("dotfiles are hidden", func(t *testing.T) {
		resp, _ := get(t, server.url("/.env"))
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("directory without a trailing slash redirects", func(t *testing.T) {
		resp, _ := get(t, server.url("/sub"))
		if resp.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("status = %d, want 301", resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); got != "/sub/" {
			t.Errorf("Location = %q, want /sub/", got)
		}
	})

	t.Run("traversal out of the root", func(t *testing.T) {
		// the client cannot even express this: net/http cleans the path. Ask
		// the handler directly instead.
		resp, _ := get(t, server.url("/../../etc/passwd"))
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})
}

func TestServeDirectoryListingOptIn(t *testing.T) {
	dir := serveDir(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - serve_rule:
      serve_local_dir: %q
      serve_list_directories: true
`, dir))

	resp, body := get(t, server.url("/listing/"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	contains(t, body, "a.txt")
	contains(t, body, "b.txt")

	t.Run("dotfiles stay hidden in listings", func(t *testing.T) {
		_, body := get(t, server.url("/"))
		notContains(t, body, ".env")
	})
}

// os.Root refuses to follow a symlink that leaves the served directory;
// http.Dir, which v0.1.0 used, follows it.
func TestServeDoesNotFollowEscapingSymlink(t *testing.T) {
	dir := t.TempDir()
	secretDir := t.TempDir()
	writeFile(t, secretDir, "secret.txt", "top secret")
	writeFile(t, dir, "public.txt", "public")
	if err := os.Symlink(filepath.Join(secretDir, "secret.txt"), filepath.Join(dir, "escape.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - serve_rule:
      serve_local_dir: %q
`, dir))

	resp, body := get(t, server.url("/escape.txt"))
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("symlink out of the root was served: %q", body)
	}
	notContains(t, body, "top secret")
}

func TestServeStripsMatchedPrefix(t *testing.T) {
	dir := serveDir(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - path_match: "/static"
    serve_rule:
      serve_local_dir: %q
`, dir))

	resp, body := get(t, server.url("/static/hello.txt"))
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}

	t.Run("redirects keep the matched prefix", func(t *testing.T) {
		resp, _ := get(t, server.url("/static/sub"))
		if resp.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("status = %d, want 301", resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); got != "/static/sub/" {
			t.Errorf("Location = %q, want /static/sub/", got)
		}
	})
}

// C2: v0.1.0 forced text/plain, appended a newline and added nosniff, so a
// custom HTML error page was impossible.
func TestRespondContentType(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
rules:
  - path_match: "/html"
    respond_rule:
      respond_status_code: 404
      respond_body: "<h1>Not here</h1>"
      respond_content_type: "text/html; charset=utf-8"
      respond_headers:
        X-Frame-Options: DENY
  - path_match: "/sniffed"
    respond_rule:
      respond_status_code: 200
      respond_body: "<html><body>hi</body></html>"
  - path_match: "/empty"
    respond_rule:
      respond_status_code: 204
  - respond_rule:
      respond_status_code: 403
      respond_body: "Forbidden"
`)

	t.Run("explicit content type", func(t *testing.T) {
		resp, body := get(t, server.url("/html"))
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		if body != "<h1>Not here</h1>" {
			t.Errorf("body = %q, want it verbatim with no trailing newline", body)
		}
		if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("Content-Type = %q", got)
		}
		if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options = %q", got)
		}
		if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
			t.Errorf("Content-Length = %q, want %d", got, len(body))
		}
	})

	t.Run("sniffed content type", func(t *testing.T) {
		resp, _ := get(t, server.url("/sniffed"))
		if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("Content-Type = %q, want the sniffed type", got)
		}
	})

	t.Run("no body allowed", func(t *testing.T) {
		resp, body := get(t, server.url("/empty"))
		if resp.StatusCode != http.StatusNoContent || body != "" {
			t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
		}
	})

	t.Run("plain text body", func(t *testing.T) {
		resp, body := get(t, server.url("/other"))
		if resp.StatusCode != http.StatusForbidden || body != "Forbidden" {
			t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
		}
	})
}

func TestRespondBodyFile(t *testing.T) {
	dir := t.TempDir()
	page := writeFile(t, dir, "page.html", "<h1>from a file</h1>")

	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
rules:
  - path_match: "/reload"
    respond_rule:
      respond_status_code: 200
      respond_body_file: %q
      respond_body_file_reload: true
  - respond_rule:
      respond_status_code: 200
      respond_body_file: %q
`, page, page))

	resp, body := get(t, server.url("/"))
	if resp.StatusCode != http.StatusOK || body != "<h1>from a file</h1>" {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if resp.Header.Get("Content-Length") == "" {
		t.Error("Content-Length was not set")
	}

	// the file is read once at startup, so changing it does not change the
	// response ...
	writeFile(t, dir, "page.html", "<h1>changed</h1>")
	if _, body := get(t, server.url("/")); body != "<h1>from a file</h1>" {
		t.Errorf("body = %q, want the copy read at startup", body)
	}
	// ... unless the rule asked for a reload
	if _, body := get(t, server.url("/reload")); body != "<h1>changed</h1>" {
		t.Errorf("body = %q, want the reloaded file", body)
	}
}

func TestRedirect(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
rules:
  - path_match: "/old-docs"
    redirect_rule:
      redirect_url: "https://example.com/docs"
      redirect_status_code: 301
  - respond_rule:
      respond_status_code: 404
      respond_body: "nope"
`)

	resp, _ := get(t, server.url("/old-docs/anything"))
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "https://example.com/docs" {
		t.Errorf("Location = %q", got)
	}
}

// A4: rules can be named, and the name is what shows up in the log.
func TestRuleNameInLogs(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
rules:
  - name: catch-all
    respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`)
	get(t, server.url("/x"))
	contains(t, server.logs(), "Rule=catch-all")
}

func TestUnnamedRuleLogsItsIndex(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
rules:
  - path_match: "/a"
    respond_rule:
      respond_status_code: 200
      respond_body: "a"
  - respond_rule:
      respond_status_code: 200
      respond_body: "b"
`)
	get(t, server.url("/b"))
	contains(t, server.logs(), "Rule=rules[1]")
}
