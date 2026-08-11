package proxy

import (
	"testing"
)

// C1: Compile used to run only from UnmarshalYAML, so a Rule built in Go code
// compared the host against the literal text of its own regex and never
// matched.
func TestRuleBuiltInGoCodeMatchesWithItsRegex(t *testing.T) {
	rule := &Rule{DomainMatch: `^.*\.example\.com$`}
	if !rule.Match("api.example.com", "/") {
		t.Error(`Match("api.example.com") = false, want true`)
	}
	if rule.Match("example.com", "/") {
		t.Error(`Match("example.com") = true, want false`)
	}
}

// C7: host names are case-insensitive, and a trailing dot is the same host.
func TestRuleMatchNormalisesHost(t *testing.T) {
	tests := []struct {
		domainMatch string
		host        string
		want        bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "Example.COM", true},
		{"example.com", "example.com.", true},
		{"example.com", "example.com:8080", true},
		{"Example.com", "example.com", true},
		{"example.com", "other.com", false},
		{`^.*\.example\.com$`, "API.Example.com", true},
		{"", "anything", true},
	}
	for _, test := range tests {
		rule := &Rule{DomainMatch: test.domainMatch}
		if got := rule.Match(test.host, "/"); got != test.want {
			t.Errorf("Rule{domain_match: %q}.Match(%q) = %v, want %v", test.domainMatch, test.host, got, test.want)
		}
	}
}

// C3: stripping the matched prefix is a prefix strip, not a substitution.
func TestStripPathPrefix(t *testing.T) {
	tests := []struct {
		pathMatch string
		path      string
		want      string
	}{
		{"/api", "/api/v1", "/v1"},
		{"/api", "/api/v1/api", "/v1/api"},
		{`^/api`, "/api/v1", "/v1"},
		{`^/api`, "/api/x/api/y", "/x/api/y"},
		// the alternation matches, but not at the start: there is no prefix to
		// remove. ReplaceAllString would have cut "/b" out of the middle.
		{`^/a|/b`, "/x/b/thing", "/x/b/thing"},
		{`^/a|/b`, "/b/thing", "/thing"},
		{"", "/untouched", "/untouched"},
		{"/api", "/other", "/other"},
	}
	for _, test := range tests {
		rule := &Rule{PathMatch: test.pathMatch}
		if err := rule.Compile(); err != nil {
			t.Fatalf("compile %q: %v", test.pathMatch, err)
		}
		if got := rule.stripPathPrefix(test.path); got != test.want {
			t.Errorf("Rule{path_match: %q}.stripPathPrefix(%q) = %q, want %q", test.pathMatch, test.path, got, test.want)
		}
	}
}

func TestRulesMatchFirstWins(t *testing.T) {
	rules := Rules{
		{DomainMatch: "app.example.com", PathMatch: "/api"},
		{DomainMatch: `^.*\.example\.com$`},
		{},
	}
	tests := []struct {
		host  string
		path  string
		index int
	}{
		{"app.example.com", "/api/v1", 0},
		{"app.example.com", "/other", 1},
		{"elsewhere.net", "/api", 2},
	}
	for _, test := range tests {
		if _, index := rules.Match(test.host, test.path); index != test.index {
			t.Errorf("Match(%q, %q) = %d, want %d", test.host, test.path, index, test.index)
		}
	}
}

func TestTrustedProxies(t *testing.T) {
	trusted, err := newTrustedProxies([]string{"127.0.0.0/8", "10.1.2.3", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:1234", true},
		{"127.9.9.9", true},
		{"10.1.2.3:80", true},
		{"10.1.2.4:80", false},
		{"[::1]:443", true},
		{"::ffff:127.0.0.1", true},
		{"8.8.8.8:53", false},
		{"not-an-address", false},
	}
	for _, test := range tests {
		if got := trusted.trusts(test.addr); got != test.want {
			t.Errorf("trusts(%q) = %v, want %v", test.addr, got, test.want)
		}
	}
}

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in   string
		want ByteSize
		bad  bool
	}{
		{"1024", 1024, false},
		{"1KiB", 1024, false},
		{"1kb", 1000, false},
		{"32MiB", 32 << 20, false},
		{"1.5MiB", 1536 << 10, false},
		{"0", 0, false},
		{"", 0, true},
		{"-1", 0, true},
		{"lots", 0, true},
	}
	for _, test := range tests {
		got, err := ParseByteSize(test.in)
		if test.bad {
			if err == nil {
				t.Errorf("ParseByteSize(%q) = %d, want an error", test.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseByteSize(%q): %v", test.in, err)
			continue
		}
		if got != test.want {
			t.Errorf("ParseByteSize(%q) = %d, want %d", test.in, got, test.want)
		}
	}
}
