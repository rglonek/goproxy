package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"goproxy/pkg/config"
)

// forwardedHeaders are the headers a client can use to claim it is speaking on
// behalf of somebody else. They are only believed from a peer in
// trusted_proxies.
var forwardedHeaders = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Real-Ip",
}

// TrustedProxies is the set of peers whose forwarded headers are believed.
// Empty by default: from anyone else, a claim about the "original" client is a
// guess at best and a forgery at worst.
type TrustedProxies struct {
	// nets is swapped rather than mutated, so a reload can change the list
	// while requests are being served
	nets atomic.Pointer[[]netip.Prefix]
	warn sync.Once
}

// NewTrustedProxies parses the trusted_proxies list.
func NewTrustedProxies(cidrs []string) (*TrustedProxies, error) {
	trusted := &TrustedProxies{}
	if err := trusted.Set(cidrs); err != nil {
		return nil, err
	}
	return trusted, nil
}

// Set replaces the list, so that a reload applies a change to trusted_proxies
// instead of silently keeping the list the process started with.
func (t *TrustedProxies) Set(cidrs []string) error {
	nets := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := config.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		nets = append(nets, prefix)
	}
	t.nets.Store(&nets)
	return nil
}

// Empty reports whether no peer is trusted.
func (t *TrustedProxies) Empty() bool {
	if t == nil {
		return true
	}
	nets := t.nets.Load()
	return nets == nil || len(*nets) == 0
}

// Trusts reports whether an address literal is a proxy whose forwarded headers
// should be believed.
func (t *TrustedProxies) Trusts(addr string) bool {
	ip, ok := parseIP(addr)
	if !ok {
		return false
	}
	return t.trustsIP(ip)
}

func (t *TrustedProxies) trustsIP(ip netip.Addr) bool {
	if t.Empty() {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range *t.nets.Load() {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP returns the address of the real client: the peer, unless the peer is
// a trusted proxy, in which case it is the rightmost address in X-Forwarded-For
// that is not itself trusted.
func (t *TrustedProxies) ClientIP(r *http.Request) string {
	peer, ok := parseIP(r.RemoteAddr)
	if !ok {
		return strings.TrimSpace(r.RemoteAddr)
	}
	if !t.trustsIP(peer) {
		return peer.String()
	}
	forwarded := forwardedFor(r.Header)
	for i := len(forwarded) - 1; i >= 0; i-- {
		ip, ok := parseIP(forwarded[i])
		if !ok {
			continue
		}
		if !t.trustsIP(ip) {
			return ip.String()
		}
	}
	return peer.String()
}

func forwardedFor(header http.Header) []string {
	var out []string
	for _, value := range header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func parseIP(addr string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	addr = strings.TrimSpace(addr)
	if i := strings.Index(addr, "%"); i >= 0 {
		addr = addr[:i] // a zone is not part of the identity we compare
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// RealIP works out who the client is and, when the peer is not trusted, drops
// the forwarded headers it sent so that nothing downstream believes them.
func (t *TrustedProxies) RealIP(logf func(string, ...any)) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !t.Trusts(r.RemoteAddr) {
				if hasForwarded(r.Header) {
					t.warn.Do(func() {
						logf("dropped inbound X-Forwarded-* headers from an untrusted peer; add it to trusted_proxies if goproxy runs behind another proxy",
							"peer", hostOnly(r.RemoteAddr))
					})
				}
				for _, name := range forwardedHeaders {
					r.Header.Del(name)
				}
			}
			if state := StateOf(r); state != nil {
				state.ClientIP = t.ClientIP(r)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasForwarded(header http.Header) bool {
	for _, name := range forwardedHeaders {
		if _, ok := header[http.CanonicalHeaderKey(name)]; ok {
			return true
		}
	}
	return false
}
