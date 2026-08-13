package route

import (
	"net/http/httptest"
	"strings"
	"testing"

	"goproxy/pkg/config"
)

func compile(t *testing.T, yamlText string) *Routes {
	t.Helper()
	cfg, err := config.Parse([]byte(yamlText))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	routes, err := Compile(cfg, Deps{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Cleanup(routes.Close)
	return routes
}

const matchingRules = `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - name: exact
    match: { host: "app.example.com", path: "/api" }
    respond: { status: 200, body: exact }
  - name: wildcard
    match: { host: "*.example.com" }
    respond: { status: 200, body: wildcard }
  - name: regex-host
    match: { host: '^(alpha|beta)\.test$' }
    respond: { status: 200, body: regex }
  - name: segment
    match: { path: "/seg", path_mode: segment }
    respond: { status: 200, body: segment }
  - name: exact-path
    match: { path: "/exact", path_mode: exact }
    respond: { status: 200, body: exactpath }
  - name: regex-path
    match: { path: '^/re/[0-9]+$', path_mode: regex }
    respond: { status: 200, body: regexpath }
  - name: get-only
    match: { path: "/getonly", methods: [GET, HEAD] }
    respond: { status: 200, body: getonly }
  - name: catch-all
    respond: { status: 200, body: catchall }
`

func TestMatch(t *testing.T) {
	routes := compile(t, matchingRules)
	tests := []struct {
		host, path, method string
		want               string
	}{
		{"app.example.com", "/api/v1", "GET", "exact"},
		{"APP.EXAMPLE.COM:8080", "/api", "GET", "exact"},
		{"app.example.com.", "/other", "GET", "wildcard"},
		{"deep.sub.example.com", "/x", "GET", "wildcard"},
		{"example.com", "/x", "GET", "catch-all"},
		{"alpha.test", "/x", "GET", "regex-host"},
		{"gamma.test", "/x", "GET", "catch-all"},
		{"h", "/seg", "GET", "segment"},
		{"h", "/seg/deep", "GET", "segment"},
		{"h", "/segfoo", "GET", "catch-all"},
		{"h", "/exact", "GET", "exact-path"},
		{"h", "/exact/more", "GET", "catch-all"},
		{"h", "/re/42", "GET", "regex-path"},
		{"h", "/re/x", "GET", "catch-all"},
		{"h", "/getonly", "HEAD", "get-only"},
		{"h", "/getonly", "POST", "catch-all"},
	}
	for _, test := range tests {
		rule, _ := routes.Match(test.host, test.path, test.method)
		if rule == nil {
			t.Errorf("Match(%q, %q, %s) matched nothing, want %s", test.host, test.path, test.method, test.want)
			continue
		}
		if rule.Name != test.want {
			t.Errorf("Match(%q, %q, %s) = %s, want %s", test.host, test.path, test.method, rule.Name, test.want)
		}
	}
}

// The host index must not change which rule wins: it is an optimisation, not a
// semantic. This is the differential test against a naive scan.
func TestMatchAgreesWithLinearScan(t *testing.T) {
	routes := compile(t, matchingRules)
	hosts := []string{"app.example.com", "other.example.com", "alpha.test", "nothing", "", "APP.example.com:1"}
	paths := []string{"/api", "/api/v1", "/seg", "/segfoo", "/exact", "/re/1", "/getonly", "/", "/x"}
	methods := []string{"GET", "POST"}
	for _, host := range hosts {
		for _, path := range paths {
			for _, method := range methods {
				got, _ := routes.Match(host, path, method)
				want := linearScan(routes, host, path, method)
				if got != want {
					t.Fatalf("Match(%q, %q, %s) = %v, linear scan = %v", host, path, method, name(got), name(want))
				}
			}
		}
	}
}

// linearScan is the specification: the first rule, in config order, that
// matches on host, path and method.
func linearScan(routes *Routes, host, path, method string) *Rule {
	normalized := NormalizeHost(host)
	for _, rule := range routes.Rules() {
		if rule.host != nil && !rule.host.match(normalized) {
			continue
		}
		if !rule.path.match(path) {
			continue
		}
		if !rule.methodAllowed(method) {
			continue
		}
		return rule
	}
	return nil
}

func name(rule *Rule) string {
	if rule == nil {
		return "<none>"
	}
	return rule.Name
}

func TestMethodMismatchIs405(t *testing.T) {
	routes := compile(t, `
version: 2
listeners:
  http: { addr: ":8080" }
rules:
  - name: get-only
    match: { path: "/x", methods: [GET] }
    respond: { status: 200, body: ok }
`)
	rule, methodMismatch := routes.Match("h", "/x", "DELETE")
	if rule != nil {
		t.Fatalf("matched %s, want nothing", rule.Name)
	}
	if !methodMismatch {
		t.Error("a rule matched but for the method: that is a 405, not a 404")
	}

	recorder := httptest.NewRecorder()
	routes.ServeHTTP(recorder, httptest.NewRequest("DELETE", "/x", nil))
	if recorder.Code != 405 {
		t.Errorf("status = %d, want 405", recorder.Code)
	}
}

func TestExplain(t *testing.T) {
	routes := compile(t, matchingRules)
	decisions := routes.Explain("unrelated.test", "/nope", "GET")
	if len(decisions) == 0 {
		t.Fatal("no decisions")
	}
	last := decisions[len(decisions)-1]
	if !last.Matched || last.Rule != "catch-all" {
		t.Fatalf("last decision = %+v, want the catch-all to match", last)
	}
	if !strings.Contains(decisions[0].Reason, "does not match") {
		t.Errorf("first reason = %q, want it to say why the rule was skipped", decisions[0].Reason)
	}
	contains := false
	for _, decision := range decisions {
		if strings.Contains(decision.Action, "respond 200") {
			contains = true
		}
	}
	if !contains {
		t.Error("no decision described its action")
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := map[string]string{
		"Example.COM":      "example.com",
		"example.com.":     "example.com",
		"example.com:8080": "example.com",
		"[::1]:8080":       "[::1]",
		"[::1]":            "[::1]",
		"":                 "",
		"host":             "host",
	}
	for in, want := range tests {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzMatch asserts that matching never panics and always agrees with the
// linear scan, whatever the request looks like.
func FuzzMatch(f *testing.F) {
	cfg, err := config.Parse([]byte(matchingRules))
	if err != nil {
		f.Fatal(err)
	}
	routes, err := Compile(cfg, Deps{})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(routes.Close)

	f.Add("app.example.com", "/api/v1", "GET")
	f.Add("", "", "")
	f.Add("[::1]:8080", "/%2f/..", "POST")
	f.Fuzz(func(t *testing.T, host, path, method string) {
		got, _ := routes.Match(host, path, method)
		want := linearScan(routes, host, path, method)
		if got != want {
			t.Fatalf("Match(%q, %q, %q) = %v, linear scan = %v", host, path, method, name(got), name(want))
		}
	})
}
