package proxy

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
)

type Rules []*Rule

// note for each rule, only the Redirect*, Proxy* or ServeLocalDir fields can be set, not all of them
// the Match must be set with at least Domain or Path, or both
// the Match can be .* for an everything match, or empty (which also matches everything)
type Rule struct {
	// name: optional name for the rule, used in log lines instead of the rule
	// index so that inserting a rule does not renumber every log line
	Name string `yaml:"name"`
	// basic_auth: basic auth credentials
	// example: 'user:password'
	BasicAuth *BasicAuth `yaml:"basic_auth"`
	// token_auth: token-based auth credentials
	TokenAuth *TokenAuth `yaml:"token_auth"`
	// domain_match: match the domain name of the request, if using regex, the domain must start with '^'
	// matching is case-insensitive: the request host is lowercased first
	// example: 'example.com', '^.*\.example\.com'
	DomainMatch string `yaml:"domain_match"`
	// path_match: match the path of the request, if using regex, the path must start with '^'
	// example: '/api/v1/users', '/api/v1/users/.*', '^/api/v1/users'
	PathMatch string `yaml:"path_match"`
	// streaming: the responses of this rule are long-lived (server-sent events,
	// long downloads). The write timeout is not applied to them.
	// Connection upgrades (websockets) are detected automatically and do not
	// need this flag.
	Streaming bool `yaml:"streaming"`
	// redirect_rule: redirect the request to the given url
	// example: 'https://example.com/redirected'
	RedirectRule *RedirectRule `yaml:"redirect_rule"`
	// proxy_rule: proxy the request to the given url
	// example: 'http://127.0.0.1:8080/myservice'
	ProxyRule *ProxyRule `yaml:"proxy_rule"`
	// serve_rule: serve the local directory as the response
	// example: '/var/www/html'
	ServeRule *ServeRule `yaml:"serve_rule"`
	// respond_rule: respond with the given status code and body
	// example: 404, 'Not Found'
	RespondRule *RespondRule `yaml:"respond_rule"`
	// unexported fields
	domainRegex  *regexp.Regexp
	domainLower  string
	pathRegex    *regexp.Regexp
	compileOnce  sync.Once
	compileErr   error
	index        int
	serveHandler *serveHandler
	respondBody  []byte
}

type BasicAuth struct {
	User string `yaml:"user"`
	Pass string `yaml:"password"`
	// when proxying, set header with this given name on target (ex X-USER) and set it to the authenticated user
	SetUserHeader *string `yaml:"set_user_header"`
	// when proxying or serving static files, set GET var with this given name on target (ex user) and set it to the authenticated user
	SetUserGETVar *string `yaml:"set_user_get_var"`
	// realm: the realm sent in the WWW-Authenticate challenge, defaults to "Restricted"
	Realm string `yaml:"realm"`
	// unexported fields: credentials are compared as fixed-length hashes so
	// that neither their value nor their length leaks through timing
	userHash [sha256.Size]byte
	passHash [sha256.Size]byte
}

type TokenAuth struct {
	// token: the token to use for authentication
	// example: 'token'
	Tokens []string `yaml:"tokens"`
	// token_auth_header: the header to read the token from
	// example: 'X-TOKEN', 'X-Api-Key'
	// if not set, the token is read from the X-TOKEN header
	TokenAuthHeader string `yaml:"token_auth_header"`
	// accept_bearer: also accept the token in 'Authorization: Bearer <token>'
	AcceptBearer bool `yaml:"accept_bearer"`
	// when proxying, set header on target
	ForwardHeader bool `yaml:"forward_header"`
	// unexported fields
	tokenHashes [][sha256.Size]byte
}

type RedirectRule struct {
	// redirect_url: redirect the request to the given url
	// example: 'https://example.com/redirected'
	RedirectURL string `yaml:"redirect_url"`
	// redirect_status_code: the status code to return when redirecting
	// example: 301
	RedirectStatusCode int `yaml:"redirect_status_code"`
}

type ProxyRule struct {
	// proxy_url: proxy the request to the given url
	// example: 'http://127.0.0.1:8080/myservice'
	ProxyURL string `yaml:"proxy_url"`
	// proxy_target_accept_self_signed: accept self-signed certificates from the proxy target (only works for https ProxyURLs)
	ProxyTargetAcceptSelfSigned bool `yaml:"proxy_target_accept_self_signed"`
	// append_path: append the path of the request to the proxy_url
	// example: true, '/api/v1/users' will be proxied to 'http://127.0.0.1:8080/myservice/api/v1/users'
	// example: false, '/api/v1/users' will be proxied to 'http://127.0.0.1:8080/myservice'
	ProxyAppendPath bool `yaml:"proxy_append_path"`
	// rewrite_host_header: rewrite the host header to the given value if set
	// example: 'example.com' will set the host header to 'example.com' when proxying to 'http://127.0.0.1:8080/myservice'
	ProxyRewriteHostHeader string `yaml:"proxy_rewrite_host_header"`
	// proxy_remove_headers: remove the given headers from the request
	// can use regex, if starting with ^
	ProxyRemoveHeaders []string `yaml:"proxy_remove_headers"`
	// proxy_set_headers: set the given headers on the request
	ProxySetHeaders map[string]string `yaml:"proxy_set_headers"`
	// unexported fields
	proxy                   *httputil.ReverseProxy
	proxyURL                *url.URL
	proxyRemoveHeadersRegex []*regexp.Regexp
}

type ServeRule struct {
	// serve_local_dir: serve the local directory as the response
	// example: '/var/www/html'
	ServeLocalDir string `yaml:"serve_local_dir"`
	// serve_index: file names tried when a directory is requested
	// defaults to ['index.html']
	ServeIndex []string `yaml:"serve_index"`
	// serve_list_directories: generate an index page for directories that have
	// no index file. Off by default.
	ServeListDirectories bool `yaml:"serve_list_directories"`
	// serve_allow_dotfiles: serve files and directories whose name starts with
	// a dot. Off by default, so .git and .env are not exposed.
	ServeAllowDotfiles bool `yaml:"serve_allow_dotfiles"`
	// serve_cache_control: value of the Cache-Control response header
	ServeCacheControl string `yaml:"serve_cache_control"`
}

type RespondRule struct {
	// respond_status_code: the status code to return when responding
	// example: 404
	RespondStatusCode int `yaml:"respond_status_code"`
	// respond_body: the body to return when responding
	// example: 'Not Found'
	RespondBody string `yaml:"respond_body"`
	// respond_body_file: the file to return when responding
	// example: '/var/www/html/index.html'
	RespondBodyFile string `yaml:"respond_body_file"`
	// respond_body_file_reload: re-read respond_body_file on every request
	// instead of loading it once at startup
	RespondBodyFileReload bool `yaml:"respond_body_file_reload"`
	// respond_content_type: the Content-Type of the response. If unset, the
	// type is detected from the body.
	RespondContentType string `yaml:"respond_content_type"`
	// respond_headers: additional response headers
	RespondHeaders map[string]string `yaml:"respond_headers"`
}

// hopByHopHeaders must not be set on a proxied request: they describe a single
// transport hop, not the message (RFC 9110 section 7.6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func (r *Rule) Validate() error {
	notNil := 0
	if r.ProxyRule != nil {
		notNil++
	}
	if r.ServeRule != nil {
		notNil++
	}
	if r.RedirectRule != nil {
		notNil++
	}
	if r.RespondRule != nil {
		notNil++
	}
	if notNil == 0 {
		return fmt.Errorf("one of proxy_rule, serve_rule, redirect_rule or respond_rule must be set")
	}
	if notNil > 1 {
		return fmt.Errorf("only one of proxy_rule, serve_rule, redirect_rule or respond_rule can be set")
	}
	if r.ProxyRule != nil {
		if err := r.ProxyRule.validate(); err != nil {
			return fmt.Errorf("proxy_rule: %w", err)
		}
	}
	if r.RedirectRule != nil {
		if r.RedirectRule.RedirectURL == "" {
			return fmt.Errorf("redirect_rule: redirect_url is required")
		}
		if r.RedirectRule.RedirectStatusCode < 300 || r.RedirectRule.RedirectStatusCode > 399 {
			return fmt.Errorf("redirect_rule: redirect_status_code must be a 3xx status code, got %d", r.RedirectRule.RedirectStatusCode)
		}
	}
	if r.ServeRule != nil {
		if r.ServeRule.ServeLocalDir == "" {
			return fmt.Errorf("serve_rule: serve_local_dir is required")
		}
		info, err := os.Stat(r.ServeRule.ServeLocalDir)
		if os.IsNotExist(err) {
			return fmt.Errorf("serve_rule: serve_local_dir does not exist: %s", r.ServeRule.ServeLocalDir)
		}
		if err == nil && !info.IsDir() {
			return fmt.Errorf("serve_rule: serve_local_dir is not a directory: %s", r.ServeRule.ServeLocalDir)
		}
	}
	if r.RespondRule != nil {
		// 1xx is an interim response: the client would wait for a final status
		// that a respond_rule never sends
		if r.RespondRule.RespondStatusCode < 200 || r.RespondRule.RespondStatusCode > 599 {
			return fmt.Errorf("respond_rule: respond_status_code must be a valid http status code between 200 and 599, got %d", r.RespondRule.RespondStatusCode)
		}
		if r.RespondRule.RespondBody != "" && r.RespondRule.RespondBodyFile != "" {
			return fmt.Errorf("respond_rule: respond_body and respond_body_file cannot be set at the same time")
		}
		if r.RespondRule.RespondBodyFile != "" {
			if _, err := os.Stat(r.RespondRule.RespondBodyFile); os.IsNotExist(err) {
				return fmt.Errorf("respond_rule: respond_body_file does not exist: %s", r.RespondRule.RespondBodyFile)
			}
		}
	}
	if r.DomainMatch != "" && strings.HasPrefix(r.DomainMatch, "^") {
		if _, err := regexp.Compile(r.DomainMatch); err != nil {
			return fmt.Errorf("domain_match: invalid regex: %w", err)
		}
	}
	if r.PathMatch != "" && strings.HasPrefix(r.PathMatch, "^") {
		if _, err := regexp.Compile(r.PathMatch); err != nil {
			return fmt.Errorf("path_match: invalid regex: %w", err)
		}
	}
	return nil
}

func (p *ProxyRule) validate() error {
	if p.ProxyURL == "" {
		return fmt.Errorf("proxy_url is required")
	}
	target, err := url.Parse(p.ProxyURL)
	if err != nil {
		return fmt.Errorf("proxy_url is not a valid url: %w", err)
	}
	// url.Parse accepts a bare word such as "garbage": it returns a URL with no
	// scheme and no host, which cannot be proxied to.
	if target.Scheme != "http" && target.Scheme != "https" {
		return fmt.Errorf("proxy_url: must be an absolute http(s) URL, got %q", p.ProxyURL)
	}
	if target.Host == "" {
		return fmt.Errorf("proxy_url: must include a host, got %q", p.ProxyURL)
	}
	for _, header := range p.ProxyRemoveHeaders {
		if strings.HasPrefix(header, "^") {
			if _, err := regexp.Compile(header); err != nil {
				return fmt.Errorf("proxy_remove_headers: invalid regex %q: %w", header, err)
			}
		}
	}
	for name := range p.ProxySetHeaders {
		for _, hop := range hopByHopHeaders {
			if strings.EqualFold(name, hop) {
				return fmt.Errorf("proxy_set_headers: %q is a hop-by-hop header and cannot be forwarded", name)
			}
		}
	}
	return nil
}

// Compile builds the rule's matching state. It is safe to call from several
// goroutines and only ever runs once per rule.
func (r *Rule) Compile() error {
	r.compileOnce.Do(func() { r.compileErr = r.compile() })
	return r.compileErr
}

func (r *Rule) compile() error {
	if strings.HasPrefix(r.DomainMatch, "^") {
		domainRegex, err := regexp.Compile(r.DomainMatch)
		if err != nil {
			return fmt.Errorf("domain_match: %w", err)
		}
		r.domainRegex = domainRegex
	}
	r.domainLower = strings.ToLower(strings.TrimSuffix(r.DomainMatch, "."))
	if strings.HasPrefix(r.PathMatch, "^") {
		pathRegex, err := regexp.Compile(r.PathMatch)
		if err != nil {
			return fmt.Errorf("path_match: %w", err)
		}
		r.pathRegex = pathRegex
	}
	if r.TokenAuth != nil {
		r.TokenAuth.tokenHashes = nil
		for _, token := range r.TokenAuth.Tokens {
			r.TokenAuth.tokenHashes = append(r.TokenAuth.tokenHashes, sha256.Sum256([]byte(token)))
		}
	}
	if r.BasicAuth != nil {
		r.BasicAuth.userHash = sha256.Sum256([]byte(r.BasicAuth.User))
		r.BasicAuth.passHash = sha256.Sum256([]byte(r.BasicAuth.Pass))
	}
	if r.ProxyRule != nil {
		target, err := url.Parse(r.ProxyRule.ProxyURL)
		if err != nil {
			return fmt.Errorf("proxy_rule: proxy_url: %w", err)
		}
		r.ProxyRule.proxyURL = target
		r.ProxyRule.proxyRemoveHeadersRegex = nil
		for _, header := range r.ProxyRule.ProxyRemoveHeaders {
			if strings.HasPrefix(header, "^") {
				rx, err := regexp.Compile(header)
				if err != nil {
					return fmt.Errorf("proxy_rule: proxy_remove_headers: %w", err)
				}
				r.ProxyRule.proxyRemoveHeadersRegex = append(r.ProxyRule.proxyRemoveHeadersRegex, rx)
			} else {
				r.ProxyRule.proxyRemoveHeadersRegex = append(r.ProxyRule.proxyRemoveHeadersRegex, nil) // nil means no regex
			}
		}
	}
	return nil
}

// String identifies the rule in log lines: its name if it has one, its index
// otherwise.
func (r *Rule) String() string {
	if r.Name != "" {
		return r.Name
	}
	return fmt.Sprintf("rules[%d]", r.index)
}

// normalizeHost strips the port and the root-zone trailing dot, and lowercases
// what is left: host names are case-insensitive (RFC 9110 section 4.2.3).
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (r *Rule) Match(host, path string) bool {
	return r.matchNormalized(normalizeHost(host), path)
}

func (r *Rule) matchNormalized(host, path string) bool {
	// Compile is a no-op once the rule has been compiled; calling it here means
	// a Rule built in Go code (rather than parsed from YAML) still matches with
	// its regexes, instead of silently comparing the host against the regex
	// source.
	if err := r.Compile(); err != nil {
		return false
	}
	if r.DomainMatch != "" {
		if r.domainRegex != nil {
			if !r.domainRegex.MatchString(host) {
				return false
			}
		} else if host != r.domainLower {
			return false
		}
	}
	if r.PathMatch != "" {
		if r.pathRegex != nil {
			if !r.pathRegex.MatchString(path) {
				return false
			}
		} else if !strings.HasPrefix(path, r.PathMatch) {
			return false
		}
	}
	return true
}

// stripPathPrefix removes the part of the path the rule matched on, and only
// that part: a leading literal prefix, or a leading regex match. It is a prefix
// strip, not a substitution, so a pattern that also matches later in the path
// leaves the rest of the path alone.
func (r *Rule) stripPathPrefix(path string) string {
	if r.PathMatch == "" {
		return path
	}
	if r.pathRegex != nil {
		if loc := r.pathRegex.FindStringIndex(path); loc != nil && loc[0] == 0 {
			return path[loc[1]:]
		}
		return path
	}
	return strings.TrimPrefix(path, r.PathMatch)
}

func (r *Rules) Match(host, path string) (*Rule, int) {
	host = normalizeHost(host)
	for i, rule := range *r {
		if rule == nil {
			continue
		}
		if rule.matchNormalized(host, path) {
			return rule, i
		}
	}
	return nil, -1
}

func (r *Rules) Validate() error {
	for i, rule := range *r {
		if rule == nil {
			// an empty list item ("- " with nothing under it) decodes to a nil
			// rule; without this it panics on the next line
			return fmt.Errorf("rules[%d]: rule is empty", i)
		}
		rule.index = i
		if err := rule.Validate(); err != nil {
			if rule.Name != "" {
				return fmt.Errorf("rules[%d] (%s): %w", i, rule.Name, err)
			}
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}
