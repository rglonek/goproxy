package action

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"goproxy/pkg/config"
	"goproxy/pkg/observe"
)

func TestStripPrefix(t *testing.T) {
	tests := []struct{ path, prefix, want string }{
		{"/api/v1", "/api", "/v1"},
		{"/api", "/api", "/"},
		{"/api/v1/api", "/api", "/v1/api"}, // only the leading one goes
		// a character prefix is what was asked for, and what is left is still
		// a rooted path
		{"/apifoo", "/api", "/foo"},
		{"/other", "/api", "/other"},
		{"/x", "", "/x"},
	}
	for _, test := range tests {
		if got := stripPrefix(test.path, test.prefix); got != test.want {
			t.Errorf("stripPrefix(%q, %q) = %q, want %q", test.path, test.prefix, got, test.want)
		}
	}
}

func TestJoinPath(t *testing.T) {
	tests := []struct{ base, rest, want string }{
		{"/api", "/v1", "/api/v1"},
		{"/api/", "/v1", "/api/v1"},
		{"/api", "v1", "/api/v1"},
		{"", "/v1", "/v1"},
		{"/", "/v1", "/v1"},
		{"/api", "/", "/api"},
	}
	for _, test := range tests {
		if got := joinPath(test.base, test.rest); got != test.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", test.base, test.rest, got, test.want)
		}
	}
}

func TestRespondContentTypeAndBody(t *testing.T) {
	dir := t.TempDir()
	page := filepath.Join(dir, "page.html")
	if err := os.WriteFile(page, []byte("<h1>from a file</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name            string
		cfg             config.Respond
		wantBody        string
		wantContentType string
	}{
		{"explicit type", config.Respond{Status: 200, Body: "x", ContentType: "text/plain"}, "x", "text/plain"},
		{"sniffed html", config.Respond{Status: 200, Body: "<html><body>hi</body></html>"}, "<html><body>hi</body></html>", "text/html; charset=utf-8"},
		{"from a file", config.Respond{Status: 200, BodyFile: page}, "<h1>from a file</h1>", "text/html; charset=utf-8"},
		{"no content", config.Respond{Status: 204}, "", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := test.cfg
			action, err := NewRespond(&cfg, observe.Discard())
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			action.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))

			if recorder.Body.String() != test.wantBody {
				t.Errorf("body = %q, want %q", recorder.Body.String(), test.wantBody)
			}
			if got := recorder.Header().Get("Content-Type"); got != test.wantContentType {
				t.Errorf("Content-Type = %q, want %q", got, test.wantContentType)
			}
			if test.wantBody != "" && recorder.Header().Get("Content-Length") == "" {
				t.Error("no Content-Length")
			}
			// a status that cannot carry a body must not declare one
			if cfg.Status == http.StatusNoContent && recorder.Header().Get("Content-Length") != "" {
				t.Error("204 declared a Content-Length")
			}
		})
	}
}

func TestRespondReloadsWhenAsked(t *testing.T) {
	dir := t.TempDir()
	page := filepath.Join(dir, "page.html")
	if err := os.WriteFile(page, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixed, err := NewRespond(&config.Respond{Status: 200, BodyFile: page}, observe.Discard())
	if err != nil {
		t.Fatal(err)
	}
	reloading, err := NewRespond(&config.Respond{Status: 200, BodyFile: page, Reload: true}, observe.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(page, []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	fixed.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if recorder.Body.String() != "first" {
		t.Errorf("body = %q, want the copy read at startup", recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	reloading.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if recorder.Body.String() != "second" {
		t.Errorf("body = %q, want the reloaded file", recorder.Body.String())
	}
}

func TestRedirectInterpolation(t *testing.T) {
	action := NewRedirect(&config.Redirect{To: "https://new.example.com{path}{query}", Status: 308})
	recorder := httptest.NewRecorder()
	action.ServeHTTP(recorder, httptest.NewRequest("GET", "/old/page?a=1", nil))

	if got := recorder.Header().Get("Location"); got != "https://new.example.com/old/page?a=1" {
		t.Errorf("Location = %q", got)
	}
	if recorder.Code != 308 {
		t.Errorf("status = %d", recorder.Code)
	}
}

// os.Root refuses to follow a symlink that leaves the served directory;
// http.Dir, which v0.1.0 used, follows it.
func TestServeDoesNotFollowEscapingSymlink(t *testing.T) {
	dir := t.TempDir()
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "secret.txt"), []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(secret, "secret.txt"), filepath.Join(dir, "escape.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	action, err := NewServe(&config.Serve{Dir: dir}, observe.Discard())
	if err != nil {
		t.Fatal(err)
	}
	defer action.Close()

	recorder := httptest.NewRecorder()
	action.ServeHTTP(recorder, httptest.NewRequest("GET", "/escape.txt", nil))
	if recorder.Code == http.StatusOK {
		t.Fatalf("a symlink out of the root was served: %q", recorder.Body.String())
	}
}

// A Location starting with "//" is read by a browser as another host, which
// with strip_prefix: "/" is otherwise reachable.
func TestDirectoryLocationIsNeverProtocolRelative(t *testing.T) {
	tests := []struct{ prefix, name, want string }{
		{"", "/sub", "/sub/"},
		{"/static", "/sub", "/static/sub/"},
		{"/", "/sub", "sub/"},
		{"//evil.example.com", "/sub", "sub/"},
	}
	for _, test := range tests {
		if got := directoryLocation(test.prefix, test.name); got != test.want {
			t.Errorf("directoryLocation(%q, %q) = %q, want %q", test.prefix, test.name, got, test.want)
		}
	}
}

func TestContainsDotFile(t *testing.T) {
	for path, want := range map[string]bool{
		"/.env":            true,
		"/a/.git/config":   true,
		"/a/b.txt":         false,
		"/":                false,
		"/a/..":            false,
		"/normal.file.txt": false,
	} {
		if got := containsDotFile(path); got != want {
			t.Errorf("containsDotFile(%q) = %v, want %v", path, got, want)
		}
	}
}
