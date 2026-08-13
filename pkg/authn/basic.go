package authn

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"goproxy/pkg/config"
)

// bcryptCacheTTL is how long a successful bcrypt verification is remembered.
// bcrypt is deliberately slow, so without this the proxy becomes a
// bcrypt-per-request machine; with it, a stolen password still stops working
// within the TTL of the config change that revoked it.
const bcryptCacheTTL = time.Minute

type basicAuth struct {
	users             map[string]*basicUser
	realm             string
	forwardUserHeader string
	forwardUserQuery  string
	forward           bool

	cache *verifyCache
}

type basicUser struct {
	name string
	// exactly one of these is set
	hash     [sha256.Size]byte
	bcrypted []byte
}

func newBasic(cfg *config.BasicAuth) (*basicAuth, error) {
	auth := &basicAuth{
		users:             map[string]*basicUser{},
		realm:             cfg.Realm,
		forwardUserHeader: cfg.ForwardUserHeader,
		forwardUserQuery:  cfg.ForwardUserQuery,
		forward:           cfg.Forward,
		cache:             newVerifyCache(),
	}
	if auth.realm == "" {
		auth.realm = "Restricted"
	}
	// a realm is echoed back inside a quoted header value
	auth.realm = strings.NewReplacer(`"`, "", "\r", "", "\n", "").Replace(auth.realm)

	for i, user := range cfg.Users {
		entry := &basicUser{name: user.User}
		switch {
		case user.PasswordHash != "":
			if _, err := bcrypt.Cost([]byte(user.PasswordHash)); err != nil {
				return nil, fmt.Errorf("users[%d].password_hash: not a bcrypt hash: %w", i, err)
			}
			entry.bcrypted = []byte(user.PasswordHash)
		default:
			password, err := resolveSecret(user.Password, "", user.PasswordFile)
			if err != nil {
				return nil, fmt.Errorf("users[%d]: %w", i, err)
			}
			entry.hash = sha256.Sum256([]byte(password))
		}
		auth.users[user.User] = entry
	}
	return auth, nil
}

func (b *basicAuth) Method() string { return MethodBasic }

func (b *basicAuth) Authenticate(r *http.Request) (Identity, bool) {
	user, password, ok := r.BasicAuth()
	if !ok {
		return Identity{}, false
	}
	entry, known := b.users[user]
	if !known {
		// spend the same work as a known user would, so that which user names
		// exist cannot be read off the response time
		var decoy [sha256.Size]byte
		presented := sha256.Sum256([]byte(password))
		subtle.ConstantTimeCompare(presented[:], decoy[:])
		return Identity{}, false
	}
	if !b.verify(entry, password) {
		return Identity{}, false
	}
	identity := Identity{User: user}
	if b.forwardUserHeader != "" {
		identity.addHeader(b.forwardUserHeader, user)
	}
	if b.forwardUserQuery != "" {
		identity.addQuery(b.forwardUserQuery, user)
	}
	return identity, true
}

func (b *basicAuth) verify(entry *basicUser, password string) bool {
	if entry.bcrypted == nil {
		presented := sha256.Sum256([]byte(password))
		return subtle.ConstantTimeCompare(presented[:], entry.hash[:]) == 1
	}
	key := sha256.Sum256(append([]byte(entry.name+":"), password...))
	if cached, ok := b.cache.get(key); ok {
		return cached
	}
	ok := bcrypt.CompareHashAndPassword(entry.bcrypted, []byte(password)) == nil
	b.cache.put(key, ok)
	return ok
}

func (b *basicAuth) Challenge() string {
	return `Basic realm="` + b.realm + `"`
}

func (b *basicAuth) Strip(r *http.Request) {
	if b.forward {
		return
	}
	// only strip credentials this authenticator could have consumed: a bearer
	// token in the same header belongs to the token authenticator
	if value := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(value), "basic ") {
		r.Header.Del("Authorization")
	}
}

// verifyCache remembers bcrypt outcomes for a short while.
type verifyCache struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]verifyCacheEntry
}

type verifyCacheEntry struct {
	ok      bool
	expires time.Time
}

func newVerifyCache() *verifyCache {
	return &verifyCache{entries: map[[sha256.Size]byte]verifyCacheEntry{}}
}

func (c *verifyCache) get(key [sha256.Size]byte) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expires) {
		return false, false
	}
	return entry.ok, true
}

func (c *verifyCache) put(key [sha256.Size]byte, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 1024 {
		// a password guesser must not be able to grow this without bound
		now := time.Now()
		for existing, entry := range c.entries {
			if now.After(entry.expires) {
				delete(c.entries, existing)
			}
		}
		if len(c.entries) > 1024 {
			clear(c.entries)
		}
	}
	c.entries[key] = verifyCacheEntry{ok: ok, expires: time.Now().Add(bcryptCacheTTL)}
}
