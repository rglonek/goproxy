package config

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// hopByHopHeaders describe a single transport hop, not the message, so they
// must not be set on a proxied request (RFC 9110 section 7.6.1).
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Validate checks the whole config. Errors carry the path to the offending
// field, so the message says where to look as well as what is wrong.
func (c *Config) Validate() error {
	if c.Listeners.HTTP == nil && c.Listeners.HTTPS == nil {
		return fmt.Errorf("listeners: at least one of http and https is required")
	}
	if c.Listeners.HTTP != nil {
		if c.Listeners.HTTP.Addr == "" {
			return fmt.Errorf("listeners.http.addr: is required")
		}
		if c.Listeners.HTTPS == nil && c.Listeners.HTTP.RedirectToHTTPS != nil && *c.Listeners.HTTP.RedirectToHTTPS {
			return fmt.Errorf("listeners.http.redirect_to_https: there is no https listener to redirect to")
		}
	}
	if c.Listeners.HTTPS != nil {
		if c.Listeners.HTTPS.Addr == "" {
			return fmt.Errorf("listeners.https.addr: is required")
		}
		if err := c.Listeners.HTTPS.TLS.validate(); err != nil {
			return fmt.Errorf("listeners.https.tls.%w", err)
		}
		if c.Listeners.HTTPS.TLS.ACME != nil {
			if c.Listeners.HTTP == nil {
				return fmt.Errorf("listeners.https.tls.acme: an http listener on :80 is required for the http-01 challenge")
			}
			if !strings.HasSuffix(c.Listeners.HTTP.Addr, ":80") {
				return fmt.Errorf("listeners.https.tls.acme: listeners.http.addr must end with :80 for the http-01 challenge, got %q", c.Listeners.HTTP.Addr)
			}
		}
	}
	if err := c.Log.validate(); err != nil {
		return fmt.Errorf("log.%w", err)
	}
	if c.Admin != nil && c.Admin.Addr == "" {
		return fmt.Errorf("admin.addr: is required")
	}
	switch c.OnListenerError {
	case "", OnListenerErrorShutdown, OnListenerErrorContinue:
	default:
		return fmt.Errorf("on_listener_error: must be %q or %q, got %q", OnListenerErrorShutdown, OnListenerErrorContinue, c.OnListenerError)
	}
	for i, proxy := range c.TrustedProxies {
		if _, err := ParsePrefix(proxy); err != nil {
			return fmt.Errorf("trusted_proxies[%d]: %w", i, err)
		}
	}

	for _, name := range sortedKeys(c.Auth) {
		if err := c.Auth[name].validate(); err != nil {
			return fmt.Errorf("auth.%s.%w", name, err)
		}
	}
	for _, name := range sortedKeys(c.Upstreams) {
		if err := c.Upstreams[name].validate(); err != nil {
			return fmt.Errorf("upstreams.%s.%w", name, err)
		}
	}

	if len(c.Rules) == 0 {
		return fmt.Errorf("rules: at least one rule is required")
	}
	seenNames := map[string]int{}
	for i, rule := range c.Rules {
		if rule == nil {
			return fmt.Errorf("rules[%d]: rule is empty", i)
		}
		if rule.Name != "" {
			if first, ok := seenNames[rule.Name]; ok {
				return fmt.Errorf("rules[%d].name: %q is already used by rules[%d]", i, rule.Name, first)
			}
			seenNames[rule.Name] = i
		}
		if err := rule.validate(c); err != nil {
			return fmt.Errorf("rules[%d]%s.%w", i, nameSuffix(rule.Name), err)
		}
	}
	return nil
}

// Unreachable reports rules that can never match because an earlier rule
// matches everything they do. It is a warning, not an error: an unreachable
// rule is usually a mistake but never a danger.
func (c *Config) Unreachable() []string {
	var warnings []string
	for i, rule := range c.Rules {
		for j := 0; j < i; j++ {
			earlier := c.Rules[j]
			if earlier.Match.Host == "" && earlier.Match.Path == "" && len(earlier.Match.Methods) == 0 {
				warnings = append(warnings, fmt.Sprintf("rules[%d]%s is unreachable: rules[%d]%s matches everything", i, nameSuffix(rule.Name), j, nameSuffix(earlier.Name)))
				break
			}
		}
	}
	return warnings
}

func nameSuffix(name string) string {
	if name == "" {
		return ""
	}
	return " (" + name + ")"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (l *Log) validate() error {
	switch l.Format {
	case "", FormatJSON, FormatText:
	default:
		return fmt.Errorf("format: must be %q or %q, got %q", FormatJSON, FormatText, l.Format)
	}
	return nil
}

func (t *TLS) validate() error {
	if len(t.Certs) == 0 && t.ACME == nil {
		return fmt.Errorf("certs or acme is required")
	}
	if len(t.Certs) > 0 && t.ACME != nil {
		return fmt.Errorf("certs and acme are mutually exclusive")
	}
	for i, cert := range t.Certs {
		if cert.CertFile == "" {
			return fmt.Errorf("certs[%d].cert_file: is required", i)
		}
		if cert.KeyFile == "" {
			return fmt.Errorf("certs[%d].key_file: is required", i)
		}
		if err := mustExist(cert.CertFile); err != nil {
			return fmt.Errorf("certs[%d].cert_file: %w", i, err)
		}
		if err := mustExist(cert.KeyFile); err != nil {
			return fmt.Errorf("certs[%d].key_file: %w", i, err)
		}
	}
	if t.ACME != nil {
		if t.ACME.Email == "" {
			return fmt.Errorf("acme.email: is required")
		}
		if len(t.ACME.Domains) == 0 {
			return fmt.Errorf("acme.domains: at least one domain is required")
		}
		if t.ACME.CacheDir == "" {
			return fmt.Errorf("acme.cache_dir: is required")
		}
		// the directory is created when the server starts, not here:
		// validating a config must not touch the filesystem
	}
	minVersion, err := ParseTLSVersion(t.MinVersion, tls.VersionTLS12)
	if err != nil {
		return fmt.Errorf("min_version: %w", err)
	}
	maxVersion, err := ParseTLSVersion(t.MaxVersion, 0)
	if err != nil {
		return fmt.Errorf("max_version: %w", err)
	}
	if maxVersion != 0 && maxVersion < minVersion {
		return fmt.Errorf("max_version: must not be lower than min_version")
	}
	if t.ClientAuth != nil {
		if _, err := ParseClientAuth(t.ClientAuth.Mode); err != nil {
			return fmt.Errorf("client_auth.mode: %w", err)
		}
		needsCA := t.ClientAuth.Mode == ClientAuthVerifyIfGiven || t.ClientAuth.Mode == ClientAuthRequireAndVerfy
		if needsCA && t.ClientAuth.CAFile == "" {
			return fmt.Errorf("client_auth.ca_file: is required for mode %q", t.ClientAuth.Mode)
		}
		if t.ClientAuth.CAFile != "" {
			if err := mustExist(t.ClientAuth.CAFile); err != nil {
				return fmt.Errorf("client_auth.ca_file: %w", err)
			}
		}
	}
	return nil
}

// ParseTLSVersion turns "1.2" into the crypto/tls constant.
func ParseTLSVersion(s string, fallback uint16) (uint16, error) {
	switch strings.TrimSpace(s) {
	case "":
		return fallback, nil
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("must be one of 1.0, 1.1, 1.2, 1.3, got %q", s)
}

// ParseClientAuth turns a client_auth mode into the crypto/tls constant.
func ParseClientAuth(s string) (tls.ClientAuthType, error) {
	switch strings.TrimSpace(s) {
	case "", ClientAuthNone:
		return tls.NoClientCert, nil
	case ClientAuthRequest:
		return tls.RequestClientCert, nil
	case ClientAuthRequire:
		return tls.RequireAnyClientCert, nil
	case ClientAuthVerifyIfGiven:
		return tls.VerifyClientCertIfGiven, nil
	case ClientAuthRequireAndVerfy:
		return tls.RequireAndVerifyClientCert, nil
	}
	return 0, fmt.Errorf("must be one of none, request, require, verify_if_given, require_and_verify, got %q", s)
}

// ParsePrefix accepts a CIDR or a bare address and returns the network it
// describes.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if prefix, err := netip.ParsePrefix(s); err == nil {
		prefix = prefix.Masked()
		// compare v4-mapped v6 prefixes in their v4 form
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			if unmapped, err := prefix.Addr().Unmap().Prefix(prefix.Bits() - 96); err == nil {
				return unmapped, nil
			}
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("must be an IP address or a CIDR, got %q", s)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func (a *Auth) validate() error {
	if a == nil {
		return fmt.Errorf("auth block is empty")
	}
	if a.Basic == nil && a.Token == nil && a.Forward == nil {
		return fmt.Errorf("one of basic, token or forward is required")
	}
	if a.Basic != nil {
		if len(a.Basic.Users) == 0 {
			return fmt.Errorf("basic.users: at least one user is required")
		}
		seen := map[string]bool{}
		for i, user := range a.Basic.Users {
			if user.User == "" {
				return fmt.Errorf("basic.users[%d].user: is required", i)
			}
			if seen[user.User] {
				return fmt.Errorf("basic.users[%d].user: %q appears twice", i, user.User)
			}
			seen[user.User] = true
			set := 0
			for _, value := range []string{user.Password, user.PasswordHash, user.PasswordFile} {
				if value != "" {
					set++
				}
			}
			if set == 0 {
				return fmt.Errorf("basic.users[%d]: one of password, password_hash or password_file is required", i)
			}
			if set > 1 {
				return fmt.Errorf("basic.users[%d]: password, password_hash and password_file are mutually exclusive", i)
			}
			if user.PasswordFile != "" {
				if err := mustExist(user.PasswordFile); err != nil {
					return fmt.Errorf("basic.users[%d].password_file: %w", i, err)
				}
			}
		}
	}
	if a.Token != nil {
		if len(a.Token.Tokens) == 0 {
			return fmt.Errorf("token.tokens: at least one token is required")
		}
		seen := map[string]bool{}
		for i, token := range a.Token.Tokens {
			if token.ID != "" {
				if seen[token.ID] {
					return fmt.Errorf("token.tokens[%d].id: %q appears twice", i, token.ID)
				}
				seen[token.ID] = true
			}
			set := 0
			for _, value := range []string{token.Value, token.ValueEnv, token.ValueFile} {
				if value != "" {
					set++
				}
			}
			if set == 0 {
				return fmt.Errorf("token.tokens[%d]: one of value, value_env or value_file is required", i)
			}
			if set > 1 {
				return fmt.Errorf("token.tokens[%d]: value, value_env and value_file are mutually exclusive", i)
			}
			if token.ValueFile != "" {
				if err := mustExist(token.ValueFile); err != nil {
					return fmt.Errorf("token.tokens[%d].value_file: %w", i, err)
				}
			}
		}
	}
	if a.Forward != nil {
		if err := absoluteURL(a.Forward.URL); err != nil {
			return fmt.Errorf("forward.url: %w", err)
		}
	}
	return nil
}

func (u *Upstream) validate() error {
	if len(u.Targets) == 0 {
		return fmt.Errorf("targets: at least one target is required")
	}
	for i, target := range u.Targets {
		if err := absoluteURL(target.URL); err != nil {
			return fmt.Errorf("targets[%d].url: %w", i, err)
		}
		if target.Weight < 0 {
			return fmt.Errorf("targets[%d].weight: must not be negative, got %d", i, target.Weight)
		}
	}
	switch u.Policy {
	case "", PolicyRoundRobin, PolicyLeastConn, PolicyIPHash, PolicyFirstHealthy:
	default:
		return fmt.Errorf("policy: must be one of %s, %s, %s, %s, got %q",
			PolicyRoundRobin, PolicyLeastConn, PolicyIPHash, PolicyFirstHealthy, u.Policy)
	}
	if u.Health != nil {
		if u.Health.Passive != nil && u.Health.Passive.Failures < 0 {
			return fmt.Errorf("health.passive.failures: must not be negative")
		}
		if u.Health.Active != nil {
			if u.Health.Active.Path == "" {
				return fmt.Errorf("health.active.path: is required")
			}
			if !strings.HasPrefix(u.Health.Active.Path, "/") {
				return fmt.Errorf("health.active.path: must start with /, got %q", u.Health.Active.Path)
			}
			for i, status := range u.Health.Active.ExpectStatus {
				if status < 100 || status > 599 {
					return fmt.Errorf("health.active.expect_status[%d]: must be a status code, got %d", i, status)
				}
			}
		}
	}
	if u.Retry != nil {
		if u.Retry.Attempts < 0 {
			return fmt.Errorf("retry.attempts: must not be negative, got %d", u.Retry.Attempts)
		}
		for i, on := range u.Retry.On {
			if on == "connect_error" {
				continue
			}
			status, err := strconv.Atoi(on)
			if err != nil || status < 100 || status > 599 {
				return fmt.Errorf("retry.on[%d]: must be \"connect_error\" or a status code, got %q", i, on)
			}
		}
		if u.Retry.Budget != nil && *u.Retry.Budget > 1 {
			return fmt.Errorf("retry.budget: must not exceed 100%%")
		}
	}
	if u.TLS != nil {
		if u.TLS.InsecureSkipVerify && u.TLS.CAFile != "" {
			return fmt.Errorf("tls: insecure_skip_verify and ca_file are mutually exclusive")
		}
		if u.TLS.CAFile != "" {
			if err := mustExist(u.TLS.CAFile); err != nil {
				return fmt.Errorf("tls.ca_file: %w", err)
			}
		}
	}
	return nil
}

func (r *Rule) validate(c *Config) error {
	actions := 0
	for _, set := range []bool{r.Proxy != nil, r.Serve != nil, r.Redirect != nil, r.Respond != nil} {
		if set {
			actions++
		}
	}
	if actions == 0 {
		return fmt.Errorf(": one of proxy, serve, redirect or respond is required")
	}
	if actions > 1 {
		return fmt.Errorf(": only one of proxy, serve, redirect or respond can be set")
	}
	if err := r.Match.validate(); err != nil {
		return fmt.Errorf("match.%w", err)
	}
	if r.Auth != "" {
		if _, ok := c.Auth[r.Auth]; !ok {
			return fmt.Errorf("auth: no auth block named %q%s", r.Auth, didYouMean(r.Auth, sortedKeys(c.Auth)))
		}
	}
	for i, cidr := range r.AllowIPs {
		if _, err := ParsePrefix(cidr); err != nil {
			return fmt.Errorf("allow_ips[%d]: %w", i, err)
		}
	}
	for i, cidr := range r.DenyIPs {
		if _, err := ParsePrefix(cidr); err != nil {
			return fmt.Errorf("deny_ips[%d]: %w", i, err)
		}
	}
	if r.RateLimit != nil {
		if r.RateLimit.RequestsPerSecond <= 0 {
			return fmt.Errorf("rate_limit.requests_per_second: must be greater than zero")
		}
		if r.RateLimit.Burst < 0 {
			return fmt.Errorf("rate_limit.burst: must not be negative")
		}
		switch r.RateLimit.By {
		case "", "ip", "identity":
		default:
			return fmt.Errorf("rate_limit.by: must be \"ip\" or \"identity\", got %q", r.RateLimit.By)
		}
	}
	if r.CORS != nil && len(r.CORS.AllowOrigins) == 0 {
		return fmt.Errorf("cors.allow_origins: at least one origin is required")
	}

	switch {
	case r.Proxy != nil:
		return r.Proxy.validate(c)
	case r.Serve != nil:
		return r.Serve.validate()
	case r.Redirect != nil:
		return r.Redirect.validate()
	case r.Respond != nil:
		return r.Respond.validate()
	}
	return nil
}

func (m *Match) validate() error {
	switch m.PathMode {
	case "", PathModePrefix, PathModeExact, PathModeSegment:
		if strings.HasPrefix(m.Path, "^") {
			return fmt.Errorf("path: %q looks like a regular expression; set path_mode: regex to use one", m.Path)
		}
		if m.Path != "" && !strings.HasPrefix(m.Path, "/") {
			return fmt.Errorf("path: must start with /, got %q", m.Path)
		}
	case PathModeRegex:
		if _, err := regexp.Compile(m.Path); err != nil {
			return fmt.Errorf("path: invalid regular expression: %w", err)
		}
	default:
		return fmt.Errorf("path_mode: must be one of %s, %s, %s, %s, got %q",
			PathModePrefix, PathModeExact, PathModeSegment, PathModeRegex, m.PathMode)
	}
	if strings.HasPrefix(m.Host, "^") {
		if _, err := regexp.Compile(m.Host); err != nil {
			return fmt.Errorf("host: invalid regular expression: %w", err)
		}
	} else if strings.Contains(m.Host, "*") && !strings.HasPrefix(m.Host, "*.") {
		return fmt.Errorf("host: a wildcard host must look like *.example.com, got %q", m.Host)
	}
	for i, method := range m.Methods {
		if method != strings.ToUpper(method) {
			return fmt.Errorf("methods[%d]: must be upper case, got %q", i, method)
		}
	}
	return nil
}

func (p *Proxy) validate(c *Config) error {
	if p.Upstream == "" && p.URL == "" {
		return fmt.Errorf("proxy: one of upstream or url is required")
	}
	if p.Upstream != "" && p.URL != "" {
		return fmt.Errorf("proxy: upstream and url are mutually exclusive")
	}
	if p.Upstream != "" {
		if _, ok := c.Upstreams[p.Upstream]; !ok {
			return fmt.Errorf("proxy.upstream: no upstream named %q%s", p.Upstream, didYouMean(p.Upstream, sortedKeys(c.Upstreams)))
		}
	}
	if p.URL != "" {
		if err := absoluteURL(p.URL); err != nil {
			return fmt.Errorf("proxy.url: %w", err)
		}
	}
	if p.StripPrefix != "" && !strings.HasPrefix(p.StripPrefix, "/") {
		return fmt.Errorf("proxy.strip_prefix: must start with /, got %q", p.StripPrefix)
	}
	if p.AddPrefix != "" && !strings.HasPrefix(p.AddPrefix, "/") {
		return fmt.Errorf("proxy.add_prefix: must start with /, got %q", p.AddPrefix)
	}
	if err := p.RequestHeaders.validate(); err != nil {
		return fmt.Errorf("proxy.request_headers.%w", err)
	}
	if err := p.ResponseHeaders.validate(); err != nil {
		return fmt.Errorf("proxy.response_headers.%w", err)
	}
	return nil
}

func (h *Headers) validate() error {
	if h == nil {
		return nil
	}
	for name := range h.Set {
		if slices.ContainsFunc(hopByHopHeaders, func(hop string) bool { return strings.EqualFold(hop, name) }) {
			return fmt.Errorf("set: %q is a hop-by-hop header and cannot be forwarded", name)
		}
		if name != http.CanonicalHeaderKey(name) && strings.ContainsAny(name, " \t\r\n") {
			return fmt.Errorf("set: %q is not a valid header name", name)
		}
	}
	for i, name := range h.Remove {
		if strings.HasPrefix(name, "^") {
			if _, err := regexp.Compile(name); err != nil {
				return fmt.Errorf("remove[%d]: invalid regular expression: %w", i, err)
			}
		}
	}
	return nil
}

func (s *Serve) validate() error {
	if s.Dir == "" {
		return fmt.Errorf("serve.dir: is required")
	}
	info, err := os.Stat(s.Dir)
	if os.IsNotExist(err) {
		return fmt.Errorf("serve.dir: does not exist: %s", s.Dir)
	}
	if err == nil && !info.IsDir() {
		return fmt.Errorf("serve.dir: is not a directory: %s", s.Dir)
	}
	if s.StripPrefix != "" && !strings.HasPrefix(s.StripPrefix, "/") {
		return fmt.Errorf("serve.strip_prefix: must start with /, got %q", s.StripPrefix)
	}
	return nil
}

func (r *Redirect) validate() error {
	if r.To == "" {
		return fmt.Errorf("redirect.to: is required")
	}
	if r.Status == 0 {
		return fmt.Errorf("redirect.status: is required")
	}
	if r.Status < 300 || r.Status > 399 {
		return fmt.Errorf("redirect.status: must be a 3xx status code, got %d", r.Status)
	}
	return nil
}

func (r *Respond) validate() error {
	// 1xx is an interim response: the client would wait for a final status
	// that a respond rule never sends
	if r.Status < 200 || r.Status > 599 {
		return fmt.Errorf("respond.status: must be a status code between 200 and 599, got %d", r.Status)
	}
	if r.Body != "" && r.BodyFile != "" {
		return fmt.Errorf("respond: body and body_file are mutually exclusive")
	}
	if r.BodyFile != "" {
		if err := mustExist(r.BodyFile); err != nil {
			return fmt.Errorf("respond.body_file: %w", err)
		}
	}
	if r.Reload && r.BodyFile == "" {
		return fmt.Errorf("respond.reload: only means something with body_file")
	}
	return nil
}

func absoluteURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a valid URL: %w", err)
	}
	// url.Parse accepts a bare word such as "garbage": it returns a URL with
	// no scheme and no host, which cannot be reached
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("must be an absolute http(s) URL, got %q", raw)
	}
	if parsed.Host == "" {
		return fmt.Errorf("must include a host, got %q", raw)
	}
	return nil
}

func mustExist(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("does not exist: %s", path)
		}
		return err
	}
	return nil
}

// didYouMean suggests the closest known name, which is usually the typo the
// operator just made.
func didYouMean(got string, known []string) string {
	best, bestDistance := "", len(got)/2+2
	for _, candidate := range known {
		if distance := editDistance(got, candidate); distance < bestDistance {
			best, bestDistance = candidate, distance
		}
	}
	if best == "" {
		if len(known) == 0 {
			return ""
		}
		return " (known names: " + strings.Join(known, ", ") + ")"
	}
	return fmt.Sprintf(" (did you mean %q?)", best)
}

func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, min(current[j-1]+1, previous[j-1]+cost))
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}
