package authn

import (
	"strings"

	"goproxy/pkg/config"
)

// Allowlist is a rule's allow block, ready for the request path: of the
// identities the rule's auth block accepts, the ones that may use the rule.
type Allowlist struct {
	users  map[string]bool
	groups map[string]bool
	cfg    *config.Allow
}

// NewAllowlist compiles an allow block. A nil block is a nil list, which
// allows everyone.
func NewAllowlist(cfg *config.Allow) *Allowlist {
	if cfg == nil {
		return nil
	}
	list := &Allowlist{users: map[string]bool{}, groups: map[string]bool{}, cfg: cfg}
	for _, user := range cfg.Users {
		list.users[user] = true
	}
	for _, group := range cfg.Groups {
		list.groups[group] = true
	}
	return list
}

// Allows reports whether an identity is one of the users or has one of the
// groups. An identity that did not authenticate is never allowed, so a list
// that is somehow reached without authentication fails closed.
func (a *Allowlist) Allows(identity Identity) bool {
	if a == nil {
		return true
	}
	if !identity.Authenticated() {
		return false
	}
	if subject := identity.Subject(); subject != "" && a.users[subject] {
		return true
	}
	for _, group := range identity.Groups {
		if a.groups[group] {
			return true
		}
	}
	return false
}

// String describes the list for `goproxy explain`: "users robert; groups
// owner, guest".
func (a *Allowlist) String() string {
	if a == nil {
		return ""
	}
	var parts []string
	if len(a.cfg.Users) > 0 {
		parts = append(parts, "users "+strings.Join(a.cfg.Users, ", "))
	}
	if len(a.cfg.Groups) > 0 {
		parts = append(parts, "groups "+strings.Join(a.cfg.Groups, ", "))
	}
	return strings.Join(parts, "; ")
}
