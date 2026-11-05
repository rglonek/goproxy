// Package authn authenticates requests. An authenticator either produces an
// Identity or refuses; a Chain tries several in order. Every authenticator
// removes the credential it consumed, so a credential goproxy checked is never
// also handed to the backend - including one it rejected. And the headers that
// say who the client is are goproxy's alone: a client's copy of one is removed
// before anything reads it.
package authn

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"goproxy/pkg/config"
)

// Authentication methods, as they appear in logs and metrics.
const (
	MethodBasic   = "basic"
	MethodToken   = "token"
	MethodForward = "forward"
)

// Identity is who the request turned out to be. It never carries a credential:
// TokenID is a label from the config, not the token.
type Identity struct {
	Method  string
	User    string
	TokenID string
	// Groups are what a rule's allow.groups is matched against.
	Groups []string
	// Headers are added to the upstream request: the authenticated user, and
	// anything a forward-auth service asked to pass along.
	Headers http.Header
	// Query is added to the upstream request's query string.
	Query map[string]string
}

// Authenticated reports whether any authenticator accepted the request.
func (i Identity) Authenticated() bool {
	return i.Method != ""
}

// Subject is the name to log: the user, or the token id.
func (i Identity) Subject() string {
	if i.User != "" {
		return i.User
	}
	return i.TokenID
}

func (i *Identity) addHeader(name, value string) {
	if i.Headers == nil {
		i.Headers = http.Header{}
	}
	i.Headers.Set(name, value)
}

func (i *Identity) addQuery(name, value string) {
	if i.Query == nil {
		i.Query = map[string]string{}
	}
	i.Query[name] = value
}

// Authenticator consumes credentials from a request.
type Authenticator interface {
	// Method names the mechanism, for logs and metrics.
	Method() string
	// Authenticate returns the identity on success. It must not write to the
	// response.
	Authenticate(r *http.Request) (Identity, bool)
	// Challenge is the WWW-Authenticate value to offer when every
	// authenticator refused, or "" for none.
	Challenge() string
	// Strip removes the credentials this authenticator read, unless the rule
	// asked for them to be forwarded.
	Strip(r *http.Request)
}

// Chain tries authenticators in order and is what a rule actually holds.
type Chain struct {
	authenticators []Authenticator
	// identityHeaders are the headers goproxy fills in from the identity, keyed
	// by config.IdentityHeaderKey; identityQuery the query parameters. A
	// client's copy of either is removed before authentication.
	identityHeaders map[string]bool
	identityQuery   []string
}

// New builds the authenticator chain described by an auth block. Secrets are
// resolved here, at compile time, so an unreadable password file is a startup
// error rather than a 500 in production.
func New(cfg *config.Auth) (*Chain, error) {
	if cfg == nil {
		return nil, nil
	}
	chain := &Chain{}
	if cfg.Token != nil {
		token, err := newToken(cfg.Token)
		if err != nil {
			return nil, fmt.Errorf("token: %w", err)
		}
		chain.authenticators = append(chain.authenticators, token)
	}
	if cfg.Basic != nil {
		basic, err := newBasic(cfg.Basic)
		if err != nil {
			return nil, fmt.Errorf("basic: %w", err)
		}
		chain.authenticators = append(chain.authenticators, basic)
	}
	if cfg.Forward != nil {
		forward, err := newForward(cfg.Forward)
		if err != nil {
			return nil, fmt.Errorf("forward: %w", err)
		}
		chain.authenticators = append(chain.authenticators, forward)
	}

	// every authenticator's identity headers, not only the one that will
	// accept the request: when a token wins, the X-User that basic would have
	// set must not arrive from the client instead
	var names []string
	if cfg.Basic != nil {
		names = append(names, cfg.Basic.ForwardUserHeader, cfg.Basic.ForwardGroupsHeader)
		if cfg.Basic.ForwardUserQuery != "" {
			chain.identityQuery = append(chain.identityQuery, cfg.Basic.ForwardUserQuery)
		}
	}
	if cfg.Forward != nil {
		// copy_headers are not here: one may be a credential the auth service
		// reads, so the forward authenticator removes those in Strip, once the
		// service has answered
		names = append(names, cfg.Forward.UserHeader, cfg.Forward.GroupsHeader)
	}
	chain.identityHeaders = headerKeys(names)
	return chain, nil
}

// headerKeys is the set of header names to remove, folded so that a client
// cannot slip one past in another case or spelled with underscores.
func headerKeys(names []string) map[string]bool {
	keys := map[string]bool{}
	for _, name := range names {
		if name != "" {
			keys[config.IdentityHeaderKey(name)] = true
		}
	}
	return keys
}

// removeHeaders deletes every header whose folded name is in keys, however
// many times and in whatever spelling the client sent it.
func removeHeaders(header http.Header, keys map[string]bool) {
	if len(keys) == 0 {
		return
	}
	for name := range header {
		if keys[config.IdentityHeaderKey(name)] {
			delete(header, name)
		}
	}
}

// Authenticate runs the chain. On success it returns the identity; on failure
// it returns the challenges to offer, and the caller answers 401.
func (c *Chain) Authenticate(r *http.Request) (Identity, bool) {
	if c == nil || len(c.authenticators) == 0 {
		return Identity{}, true
	}
	for _, authenticator := range c.authenticators {
		if identity, ok := authenticator.Authenticate(r); ok {
			identity.Method = authenticator.Method()
			return identity, true
		}
	}
	return Identity{}, false
}

// Challenges are the WWW-Authenticate values to send with a 401.
func (c *Chain) Challenges() []string {
	if c == nil {
		return nil
	}
	var challenges []string
	for _, authenticator := range c.authenticators {
		if challenge := authenticator.Challenge(); challenge != "" {
			challenges = append(challenges, challenge)
		}
	}
	return challenges
}

// Strip removes every credential the chain consumed. It runs whether or not
// authentication succeeded, so a rejected token is not forwarded upstream when
// another authenticator rescues the request.
func (c *Chain) Strip(r *http.Request) {
	if c == nil {
		return
	}
	for _, authenticator := range c.authenticators {
		authenticator.Strip(r)
	}
}

// StripIdentity removes what a client sent in the headers and query parameters
// that goproxy fills in from the identity - forward_user_header,
// forward_groups_header, forward_user_query, and a forward-auth service's
// user_header and groups_header. It runs before authentication, so no
// authenticator sees a client's claim either, and whether or not
// authentication then sets the header: when the authenticator that accepted
// the request does not, the backend gets none rather than the client's.
func (c *Chain) StripIdentity(r *http.Request) {
	if c == nil {
		return
	}
	removeHeaders(r.Header, c.identityHeaders)
	if len(c.identityQuery) > 0 && r.URL.RawQuery != "" {
		r.URL.RawQuery = removeQuery(r.URL.RawQuery, c.identityQuery)
	}
}

// removeQuery drops the named parameters from a raw query string. It works on
// the string rather than through url.Values so that the parameters it keeps
// stay in the order and the encoding the client sent.
func removeQuery(raw string, names []string) string {
	parts := strings.Split(raw, "&")
	kept := parts[:0]
	for _, part := range parts {
		key, _, _ := strings.Cut(part, "=")
		if unescaped, err := url.QueryUnescape(key); err == nil {
			key = unescaped
		}
		drop := false
		for _, name := range names {
			if key == name {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "&")
}

// Empty reports whether the chain would let everything through.
func (c *Chain) Empty() bool {
	return c == nil || len(c.authenticators) == 0
}

// Methods names the mechanisms in the chain, for `config explain`.
func (c *Chain) Methods() []string {
	if c == nil {
		return nil
	}
	methods := make([]string, 0, len(c.authenticators))
	for _, authenticator := range c.authenticators {
		methods = append(methods, authenticator.Method())
	}
	return methods
}
