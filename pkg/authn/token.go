package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"goproxy/pkg/config"
)

// DefaultTokenHeader is where a token is read from when the rule does not say.
const DefaultTokenHeader = "X-TOKEN"

type tokenAuth struct {
	header       string
	acceptBearer bool
	forward      bool
	ids          []string
	hashes       [][sha256.Size]byte
}

func newToken(cfg *config.TokenAuth) (*tokenAuth, error) {
	auth := &tokenAuth{
		header:       cfg.Header,
		acceptBearer: cfg.AcceptBearer == nil || *cfg.AcceptBearer,
		forward:      cfg.Forward,
	}
	if auth.header == "" {
		auth.header = DefaultTokenHeader
	}
	for i, token := range cfg.Tokens {
		value, err := resolveSecret(token.Value, token.ValueEnv, token.ValueFile)
		if err != nil {
			return nil, fmt.Errorf("tokens[%d]: %w", i, err)
		}
		id := token.ID
		if id == "" {
			id = strconv.Itoa(i)
		}
		auth.ids = append(auth.ids, id)
		auth.hashes = append(auth.hashes, sha256.Sum256([]byte(value)))
	}
	return auth, nil
}

func (t *tokenAuth) Method() string { return MethodToken }

func (t *tokenAuth) Authenticate(r *http.Request) (Identity, bool) {
	presented := t.presented(r)
	if presented == "" {
		return Identity{}, false
	}
	// every token is compared, so how long the comparison took reveals neither
	// which token nearly matched nor how long it is
	sum := sha256.Sum256([]byte(presented))
	index := -1
	for i, expected := range t.hashes {
		if subtle.ConstantTimeCompare(sum[:], expected[:]) == 1 && index == -1 {
			index = i
		}
	}
	if index == -1 {
		return Identity{}, false
	}
	return Identity{TokenID: t.ids[index]}, true
}

func (t *tokenAuth) presented(r *http.Request) string {
	if token := r.Header.Get(t.header); token != "" {
		return token
	}
	if t.acceptBearer {
		if value := r.Header.Get("Authorization"); value != "" {
			if token, ok := strings.CutPrefix(value, "Bearer "); ok {
				return strings.TrimSpace(token)
			}
		}
	}
	return ""
}

func (t *tokenAuth) Challenge() string {
	if t.acceptBearer {
		return "Bearer"
	}
	// there is no registered scheme for a token in a custom header, and
	// answering "Bearer" for a header goproxy does not read only tells the
	// client to retry in a way that cannot work
	return ""
}

func (t *tokenAuth) Strip(r *http.Request) {
	if t.forward {
		return
	}
	r.Header.Del(t.header)
	if t.acceptBearer && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		r.Header.Del("Authorization")
	}
}
