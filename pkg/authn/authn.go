// Package authn authenticates requests. An authenticator either produces an
// Identity or refuses; a Chain tries several in order. Every authenticator
// removes the credential it consumed, so a credential goproxy checked is never
// also handed to the backend - including one it rejected.
package authn

import (
	"fmt"
	"net/http"
	"os"
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
	return chain, nil
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

// resolveSecret reads a secret from the config, an environment variable or a
// file. Reading it here means the config file itself does not have to hold it.
func resolveSecret(literal, fromEnv, fromFile string) (string, error) {
	switch {
	case literal != "":
		return literal, nil
	case fromEnv != "":
		value, ok := os.LookupEnv(fromEnv)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", fromEnv)
		}
		if value == "" {
			return "", fmt.Errorf("environment variable %s is empty", fromEnv)
		}
		return value, nil
	case fromFile != "":
		content, err := os.ReadFile(fromFile)
		if err != nil {
			return "", err
		}
		value := strings.TrimRight(string(content), "\r\n")
		if value == "" {
			return "", fmt.Errorf("%s is empty", fromFile)
		}
		return value, nil
	}
	return "", fmt.Errorf("no value configured")
}
