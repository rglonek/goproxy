package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// forwardedHeaders are the headers a client can use to claim it is speaking on
// behalf of somebody else. They are only believed when they come from a peer
// listed in trusted_proxies.
var forwardedHeaders = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Real-Ip",
}

type trustedProxies struct {
	nets []netip.Prefix
}

func newTrustedProxies(cidrs []string) (*trustedProxies, error) {
	t := &trustedProxies{}
	for i, c := range cidrs {
		prefix, err := parseTrustedProxy(c)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies[%d]: %w", i, err)
		}
		// compare v4-mapped v6 prefixes in their v4 form, so that 127.0.0.1 and
		// ::ffff:127.0.0.1 are the same host
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			if unmapped, err := prefix.Addr().Unmap().Prefix(prefix.Bits() - 96); err == nil {
				prefix = unmapped
			}
		}
		t.nets = append(t.nets, prefix)
	}
	return t, nil
}

func (t *trustedProxies) empty() bool {
	return t == nil || len(t.nets) == 0
}

// trusts reports whether an address literal ("1.2.3.4:5678" or "1.2.3.4") is a
// proxy whose forwarded headers should be believed.
func (t *trustedProxies) trusts(addr string) bool {
	if t.empty() {
		return false
	}
	ip, ok := parseIP(addr)
	if !ok {
		return false
	}
	return t.trustsIP(ip)
}

func (t *trustedProxies) trustsIP(ip netip.Addr) bool {
	if t.empty() {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range t.nets {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func parseIP(addr string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	addr = strings.TrimSpace(addr)
	// an address such as "fe80::1%eth0" carries a zone that is not part of the
	// identity we compare against
	if i := strings.Index(addr, "%"); i >= 0 {
		addr = addr[:i]
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// clientIP returns the address of the client as far as goproxy can tell: the
// peer address, unless the peer is a trusted proxy, in which case it is the
// rightmost address in X-Forwarded-For that is not itself trusted.
func (t *trustedProxies) clientIP(r *http.Request) string {
	peer, ok := parseIP(r.RemoteAddr)
	if !ok {
		return strings.TrimSpace(r.RemoteAddr)
	}
	if !t.trustsIP(peer) {
		return peer.String()
	}
	candidates := forwardedForList(r.Header)
	for i := len(candidates) - 1; i >= 0; i-- {
		ip, ok := parseIP(candidates[i])
		if !ok {
			continue
		}
		if !t.trustsIP(ip) {
			return ip.String()
		}
	}
	return peer.String()
}

func forwardedForList(header http.Header) []string {
	var out []string
	for _, value := range header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// hasForwardedHeaders reports whether the client sent any claim about who it is
// speaking for.
func hasForwardedHeaders(header http.Header) bool {
	for _, name := range forwardedHeaders {
		if _, ok := header[http.CanonicalHeaderKey(name)]; ok {
			return true
		}
	}
	return false
}

// copyForwardedHeaders carries the inbound forwarded headers over to the
// outbound request. httputil.ReverseProxy strips them before calling Rewrite,
// so they have to be put back for a peer we trust to have set them honestly.
func copyForwardedHeaders(dst, src http.Header) {
	for _, name := range forwardedHeaders {
		key := http.CanonicalHeaderKey(name)
		values, ok := src[key]
		if !ok {
			continue
		}
		dst[key] = slices.Clone(values)
	}
}

// removeForwardedHeaders drops every forwarded header.
func removeForwardedHeaders(header http.Header) {
	for _, name := range forwardedHeaders {
		header.Del(name)
	}
}
