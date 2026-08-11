package proxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"
)

// authentication methods, as reported in log lines
const (
	authNone  = "None"
	authToken = "Token"
	authBasic = "Basic"
)

// identity is the outcome of authenticating a request. It replaces the
// stringly-typed auth state the request path used to thread through itself, and
// it never carries a credential: tokenID is a label, not the token.
type identity struct {
	method string
	user   string
	// tokenID identifies which configured token matched, for logs
	tokenID string
	// tokenAttempted records that a token authenticator ran, whether or not it
	// succeeded. The credential it consumed is stripped either way, so a
	// rejected token is never forwarded upstream.
	tokenAttempted bool
	// basicAttempted records that basic auth ran and succeeded.
	basicAttempted bool
}

func (i identity) authType() string {
	if i.method == "" {
		return authNone
	}
	return i.method
}

// tokenHeaderName is the header a rule reads its token from.
func (t *TokenAuth) tokenHeaderName() string {
	if t.TokenAuthHeader != "" {
		return t.TokenAuthHeader
	}
	return "X-TOKEN"
}

func (t *TokenAuth) presentedToken(r *http.Request) string {
	if token := r.Header.Get(t.tokenHeaderName()); token != "" {
		return token
	}
	if t.AcceptBearer {
		if value := r.Header.Get("Authorization"); value != "" {
			if token, ok := strings.CutPrefix(value, "Bearer "); ok {
				return strings.TrimSpace(token)
			}
		}
	}
	return ""
}

// match returns the index of the configured token equal to presented, or -1.
// Every token is compared, in constant time, so neither the value nor the
// length of a token leaks through how long the comparison took, and a failure
// does not reveal which token nearly matched.
func (t *TokenAuth) match(presented string) int {
	if presented == "" {
		return -1
	}
	sum := sha256.Sum256([]byte(presented))
	index := -1
	for i, want := range t.tokenHashes {
		if subtle.ConstantTimeCompare(sum[:], want[:]) == 1 && index == -1 {
			index = i
		}
	}
	return index
}

func (b *BasicAuth) match(user, pass string) bool {
	userSum := sha256.Sum256([]byte(user))
	passSum := sha256.Sum256([]byte(pass))
	ok := subtle.ConstantTimeCompare(userSum[:], b.userHash[:])
	ok &= subtle.ConstantTimeCompare(passSum[:], b.passHash[:])
	return ok == 1
}

func (b *BasicAuth) realm() string {
	if b.Realm != "" {
		return b.Realm
	}
	return "Restricted"
}

// authenticate runs the rule's authenticators in order - token first, basic as
// a fallback - and writes the challenge itself when every one of them failed.
// It returns false when the request must not be handled.
func (h *handler) authenticate(w http.ResponseWriter, r *http.Request, rule *Rule) (identity, bool) {
	var id identity

	if rule.TokenAuth != nil {
		id.tokenAttempted = true
		presented := rule.TokenAuth.presentedToken(r)
		index := rule.TokenAuth.match(presented)
		if index == -1 {
			// the presented token is a credential: it is never logged, at any
			// level, because it may well be valid somewhere else
			h.log.Info("Client=%s Host=%s Path=%s Mod=TokenAuth Rule=%s Failed", h.clientIP(r), r.Host, r.URL.Path, rule)
			if rule.BasicAuth == nil {
				// v0.1.0 answered with `WWW-Authenticate: Bearer`, telling the
				// client to retry with a header goproxy does not read unless
				// accept_bearer is set. Only send the challenge when it is true.
				if rule.TokenAuth.AcceptBearer {
					w.Header().Set("WWW-Authenticate", "Bearer")
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return id, false
			}
		} else {
			id.method = authToken
			id.tokenID = strconv.Itoa(index)
			h.log.Info("Client=%s Host=%s Path=%s Mod=TokenAuth Rule=%s Success TokenIdx=%s", h.clientIP(r), r.Host, r.URL.Path, rule, id.tokenID)
		}
	}

	if id.method == "" && rule.BasicAuth != nil {
		user, pass, ok := r.BasicAuth()
		if !ok || !rule.BasicAuth.match(user, pass) {
			h.log.Info("Client=%s Host=%s Path=%s Mod=BasicAuth User=%s Rule=%s Failed", h.clientIP(r), r.Host, r.URL.Path, user, rule)
			w.Header().Set("WWW-Authenticate", `Basic realm="`+strings.ReplaceAll(rule.BasicAuth.realm(), `"`, "")+`"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return id, false
		}
		id.method = authBasic
		id.user = user
		id.basicAttempted = true
		h.log.Info("Client=%s Host=%s Path=%s Mod=BasicAuth User=%s Rule=%s Success", h.clientIP(r), r.Host, r.URL.Path, user, rule)
	}

	return id, true
}

// stripConsumedCredentials removes the credentials goproxy itself consumed, so
// they are not forwarded to the backend. The token header is removed whenever a
// token authenticator ran, including when it rejected the token and basic auth
// rescued the request.
func (id identity) stripConsumedCredentials(r *http.Request, rule *Rule) {
	if id.tokenAttempted && !rule.TokenAuth.ForwardHeader {
		r.Header.Del(rule.TokenAuth.tokenHeaderName())
		if rule.TokenAuth.AcceptBearer {
			if value := r.Header.Get("Authorization"); strings.HasPrefix(value, "Bearer ") {
				r.Header.Del("Authorization")
			}
		}
	}
	if id.basicAttempted {
		r.Header.Del("Authorization")
	}
}
