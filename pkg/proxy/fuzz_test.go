package proxy

import (
	"testing"
)

// FuzzParseConfig asserts the property the parser has to have: whatever the
// bytes, it returns either a usable config or an error - never a panic, and
// never a config that has not been compiled.
func FuzzParseConfig(f *testing.F) {
	f.Add(`listen_addr: ":8080"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`)
	f.Add(`listen_addr: ":8080"
rules:
  - domain_match: "^.*"
    path_match: "^/api"
    proxy_rule:
      proxy_url: "http://127.0.0.1:8081"
`)
	f.Add("listen_addr: 8080\nrules: []\n")
	f.Add("]] not yaml [[")
	f.Add("")

	f.Fuzz(func(t *testing.T, in string) {
		config, err := ParseConfig([]byte(in))
		if err != nil {
			if config != nil {
				t.Fatal("ParseConfig returned both a config and an error")
			}
			return
		}
		if len(config.Rules) == 0 {
			t.Fatal("a valid config with no rules got through validation")
		}
		// a config that parsed is compiled, so matching must not panic
		config.Rules.Match("example.com", "/")
	})
}

// FuzzMatch asserts that matching never panics on arbitrary input, and that the
// compiled matcher agrees with a naive scan of the same rules.
func FuzzMatch(f *testing.F) {
	f.Add("example.com", "/api/v1")
	f.Add("", "")
	f.Add("[::1]:8080", "/%2f/..")
	f.Add("EXAMPLE.COM.", "/API")

	rules := Rules{
		{DomainMatch: "app.example.com", PathMatch: "/api"},
		{DomainMatch: `^.*\.example\.com$`},
		{PathMatch: `^/static`},
		{},
	}
	for _, rule := range rules {
		if err := rule.Compile(); err != nil {
			f.Fatal(err)
		}
	}

	f.Fuzz(func(t *testing.T, host, path string) {
		rule, index := rules.Match(host, path)
		if (rule == nil) != (index < 0) {
			t.Fatalf("Match(%q, %q) = (%v, %d): rule and index disagree", host, path, rule, index)
		}
		// the naive scan every rules-in-order proxy is specified by
		want := -1
		for i, candidate := range rules {
			if candidate.Match(host, path) {
				want = i
				break
			}
		}
		if index != want {
			t.Fatalf("Match(%q, %q) = %d, naive scan = %d", host, path, index, want)
		}
	})
}
