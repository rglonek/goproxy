package route

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"goproxy/pkg/config"
)

// hostMatcher decides whether a request host belongs to a rule. There are
// three kinds - exact, wildcard and regex - and exact ones are indexed, so a
// config with many virtual hosts does not scan them all.
type hostMatcher interface {
	match(host string) bool
	String() string
}

type exactHost string

func (h exactHost) match(host string) bool { return string(h) == host }
func (h exactHost) String() string         { return string(h) }

type wildcardHost string // stores ".example.com" for "*.example.com"

func (h wildcardHost) match(host string) bool {
	// *.example.com covers any subdomain, but not example.com itself
	return strings.HasSuffix(host, string(h)) && len(host) > len(h)
}
func (h wildcardHost) String() string { return "*" + string(h) }

type regexHost struct{ re *regexp.Regexp }

func (h regexHost) match(host string) bool { return h.re.MatchString(host) }
func (h regexHost) String() string         { return h.re.String() }

func newHostMatcher(pattern string) (hostMatcher, error) {
	switch {
	case pattern == "":
		return nil, nil
	case strings.HasPrefix(pattern, "^"):
		expression, err := regexp.Compile(strings.ToLower(pattern))
		if err != nil {
			return nil, err
		}
		return regexHost{re: expression}, nil
	case strings.HasPrefix(pattern, "*."):
		return wildcardHost(strings.ToLower(pattern[1:])), nil
	default:
		return exactHost(NormalizeHost(pattern)), nil
	}
}

// pathMatcher decides whether a request path belongs to a rule.
type pathMatcher interface {
	match(path string) bool
	String() string
}

type anyPath struct{}

func (anyPath) match(string) bool { return true }
func (anyPath) String() string    { return "any path" }

type prefixPath string

func (p prefixPath) match(path string) bool { return strings.HasPrefix(path, string(p)) }
func (p prefixPath) String() string         { return "prefix " + string(p) }

type exactPath string

func (p exactPath) match(path string) bool { return path == string(p) }
func (p exactPath) String() string         { return "exactly " + string(p) }

// segmentPath matches whole path segments: /api matches /api and /api/v1 but
// not /apifoo, which is what people usually mean by a path prefix.
type segmentPath string

func (p segmentPath) match(path string) bool {
	if !strings.HasPrefix(path, string(p)) {
		return false
	}
	rest := path[len(p):]
	return rest == "" || rest[0] == '/' || strings.HasSuffix(string(p), "/")
}
func (p segmentPath) String() string { return "segment " + string(p) }

type regexPath struct{ re *regexp.Regexp }

func (p regexPath) match(path string) bool { return p.re.MatchString(path) }
func (p regexPath) String() string         { return "regex " + p.re.String() }

func newPathMatcher(pattern, mode string) (pathMatcher, error) {
	if pattern == "" {
		return anyPath{}, nil
	}
	switch mode {
	case "", config.PathModePrefix:
		return prefixPath(pattern), nil
	case config.PathModeExact:
		return exactPath(pattern), nil
	case config.PathModeSegment:
		return segmentPath(pattern), nil
	case config.PathModeRegex:
		expression, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		return regexPath{re: expression}, nil
	}
	return nil, fmt.Errorf("unknown path_mode %q", mode)
}

// Decision is why a rule did or did not match, for `goproxy config explain`.
type Decision struct {
	Rule    string
	Matched bool
	Reason  string
	Action  string
}

// Explain reports what would happen to a request, rule by rule. "Why is my
// rule not matching" is the question a rules-in-order proxy generates most,
// and it should not need a debugger.
func (r *Routes) Explain(host, path, method string) []Decision {
	normalized := NormalizeHost(host)
	decisions := make([]Decision, 0, len(r.rules))
	for _, rule := range r.rules {
		decision := Decision{Rule: rule.Name, Action: rule.Describe()}
		switch {
		case rule.host != nil && !rule.host.match(normalized):
			decision.Reason = fmt.Sprintf("host %q does not match %s", normalized, rule.host)
		case !rule.path.match(path):
			decision.Reason = fmt.Sprintf("path %q does not match %s", path, rule.path)
		case !rule.methodAllowed(method):
			decision.Reason = fmt.Sprintf("method %s is not in %v", method, rule.methods)
		default:
			decision.Matched = true
			decision.Reason = "matched"
			if !rule.auth.Empty() {
				decision.Reason += fmt.Sprintf(" (requires auth: %s)", strings.Join(rule.auth.Methods(), ", "))
			}
		}
		decisions = append(decisions, decision)
		if decision.Matched {
			break
		}
	}
	return decisions
}

// contextFrom turns a stop channel into a context, so that background work
// started by the table stops with it.
func contextFrom(stop <-chan struct{}) context.Context {
	if stop == nil {
		return context.Background()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-stop
		cancel()
	}()
	return ctx
}
