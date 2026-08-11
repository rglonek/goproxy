package proxy

import (
	"fmt"
	"net"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type Rules []*Rule

// note for each rule, only the Redirect*, Proxy* or ServeLocalDir fields can be set, not all of them
// the Match must be set with at least Domain or Path, or both
// the Match can be .* for an everything match, or empty (which also matches everything)
type Rule struct {
	// basic_auth: basic auth credentials
	// example: 'user:password'
	BasicAuth *BasicAuth `yaml:"basic_auth"`
	// token_auth: token-based auth credentials
	TokenAuth *TokenAuth `yaml:"token_auth"`
	// domain_match: match the domain name of the request, if using regex, the domain must start with '^'
	// example: 'example.com', '^.*\.example\.com'
	DomainMatch string `yaml:"domain_match"`
	// path_match: match the path of the request, if using regex, the path must start with '^'
	// example: '/api/v1/users', '/api/v1/users/.*', '^/api/v1/users'
	PathMatch string `yaml:"path_match"`
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
	domainRegex *regexp.Regexp
	pathRegex   *regexp.Regexp
}

type BasicAuth struct {
	User string `yaml:"user"`
	Pass string `yaml:"password"`
	// when proxying, set header with this given name on target (ex X-USER) and set it to the authenticated user
	SetUserHeader *string `yaml:"set_user_header"`
	// when proxying or serving static files, set GET var with this given name on target (ex user) and set it to the authenticated user
	SetUserGETVar *string `yaml:"set_user_get_var"`
}

type TokenAuth struct {
	// token: the token to use for authentication
	// example: 'token'
	Tokens []string `yaml:"tokens"`
	// token_auth_header: the header to read the token from
	// example: 'Authorization', 'X-Token'
	// if not set, the token will be read from the Authorization header
	TokenAuthHeader string `yaml:"token_auth_header"`
	// when proxying, set header on target
	ForwardHeader bool `yaml:"forward_header"`
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
	proxyRemoveHeadersRegex []*regexp.Regexp
}

type ServeRule struct {
	// serve_local_dir: serve the local directory as the response
	// example: '/var/www/html'
	ServeLocalDir string `yaml:"serve_local_dir"`
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
}

func (r *Rule) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawProxyRule Rule
	if err := unmarshal((*rawProxyRule)(r)); err != nil {
		return err
	}
	if err := r.Compile(); err != nil {
		return err
	}
	return nil
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
		if r.ProxyRule.ProxyURL == "" {
			return fmt.Errorf("proxy_rule: proxy_url is required")
		}
		if _, err := url.Parse(r.ProxyRule.ProxyURL); err != nil {
			return fmt.Errorf("proxy_rule: proxy_url is not a valid url: %w", err)
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
		if _, err := os.Stat(r.ServeRule.ServeLocalDir); os.IsNotExist(err) {
			return fmt.Errorf("serve_rule: serve_local_dir does not exist: %s", r.ServeRule.ServeLocalDir)
		}
	}
	if r.RespondRule != nil {
		if r.RespondRule.RespondStatusCode < 100 || r.RespondRule.RespondStatusCode > 999 {
			return fmt.Errorf("respond_rule: respond_status_code must be a valid http status code, got %d", r.RespondRule.RespondStatusCode)
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
	return nil
}

func (r *Rule) Compile() error {
	if strings.HasPrefix(r.DomainMatch, "^") {
		domainRegex, err := regexp.Compile(r.DomainMatch)
		if err != nil {
			return err
		}
		r.domainRegex = domainRegex
	}
	if strings.HasPrefix(r.PathMatch, "^") {
		pathRegex, err := regexp.Compile(r.PathMatch)
		if err != nil {
			return err
		}
		r.pathRegex = pathRegex
	}
	if r.ProxyRule != nil {
		for _, header := range r.ProxyRule.ProxyRemoveHeaders {
			if strings.HasPrefix(header, "^") {
				rx, err := regexp.Compile(header)
				if err != nil {
					return err
				}
				r.ProxyRule.proxyRemoveHeadersRegex = append(r.ProxyRule.proxyRemoveHeadersRegex, rx)
			} else {
				r.ProxyRule.proxyRemoveHeadersRegex = append(r.ProxyRule.proxyRemoveHeadersRegex, nil) // nil means no regex
			}
		}
	}
	return nil
}

func (r *Rule) Match(host, path string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if r.DomainMatch != "" && r.domainRegex != nil && !r.domainRegex.MatchString(host) {
		return false
	}
	if r.PathMatch != "" && r.pathRegex != nil && !r.pathRegex.MatchString(path) {
		return false
	}
	if r.DomainMatch != "" && r.domainRegex == nil && host != r.DomainMatch {
		return false
	}
	if r.PathMatch != "" && r.pathRegex == nil && !strings.HasPrefix(path, r.PathMatch) {
		return false
	}
	return true
}

func (r *Rules) Match(host, path string) (*Rule, int) {
	for i, rule := range *r {
		if rule.Match(host, path) {
			return rule, i
		}
	}
	return nil, -1
}

func (r *Rules) Validate() error {
	for i, rule := range *r {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}
