package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"goproxy/pkg/config"
)

// countingBackend is an echo backend that also counts what reached it, so a
// test can tell a refused request from one that was proxied.
func countingBackend(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(echo{Path: r.URL.Path, RawQuery: r.URL.RawQuery, Header: r.Header})
	}))
	t.Cleanup(backend.Close)
	return backend, hits
}

// identityValues collects every header the backend received that a backend
// might read as name: any case, "_" for "-".
func identityValues(header http.Header, name string) []string {
	var values []string
	for key, got := range header {
		if config.IdentityHeaderKey(key) == config.IdentityHeaderKey(name) {
			values = append(values, got...)
		}
	}
	return values
}

// spoof adds every way a client might try to claim an identity header: the
// plain name, a second line of it, another case, the underscore spelling a
// CGI-style backend reads as the same variable, and a Connection header naming
// it, which would make ReverseProxy drop goproxy's own value.
func spoof(req *http.Request, name, value string) {
	req.Header.Add(name, value)
	req.Header.Add(name, value+"-again")
	req.Header[strings.ToLower(name)] = append(req.Header[strings.ToLower(name)], value+"-lower")
	req.Header[strings.ReplaceAll(name, "-", "_")] = []string{value + "-underscore"}
	req.Header.Add("Connection", name)
}

const identityConfig = `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
admin: { addr: "127.0.0.1:0" }
auth:
  people:
    token:
      tokens: [{ id: ci, value: "ci-token", groups: [owner] }]
    basic:
      users:
        - { user: robert, password: "robert-pw", groups: [owner] }
        - { user: gina, password: "gina-pw", groups: [guest] }
        - { user: robin, password: "robin-pw", groups: [guest, viewer] }
        - { user: nogroups, password: "nogroups-pw" }
      forward_user_header: X-Alice-User
      forward_groups_header: X-Alice-Role
      forward_user_query: user
rules:
  - name: owner-only
    match: { path: /owner }
    auth: people
    allow: { groups: [owner] }
    proxy:
      url: %[1]q
      request_headers:
        set: { Authorization: "Bearer upstream-key" }
  - name: open
    match: { path: /open }
    proxy: { url: %[1]q }
  - name: open-but-careful
    match: { path: /careful }
    proxy:
      url: %[1]q
      request_headers:
        remove: [X-Alice-User, X-Alice-Role]
  - name: people
    auth: people
    proxy:
      url: %[1]q
      request_headers:
        set: { Authorization: "Bearer upstream-key" }
`

// The headers that say who the client is come from goproxy alone: whatever a
// client sends under those names, in whatever spelling, never reaches the
// backend on a rule whose auth block declares them.
func TestIdentityHeadersComeFromGoproxyAlone(t *testing.T) {
	backend, hits := countingBackend(t)
	server := newTestServer(t, fmt.Sprintf(identityConfig, backend.URL))

	send := func(path string, prepare func(*http.Request)) (*http.Response, string) {
		t.Helper()
		req := request(t, http.MethodGet, server.url(path), nil)
		prepare(req)
		return do(t, req)
	}
	spoofAll := func(req *http.Request) {
		spoof(req, "X-Alice-User", "mallory")
		spoof(req, "X-Alice-Role", "owner")
	}

	t.Run("basic auth: the backend gets goproxy's values and nothing else", func(t *testing.T) {
		resp, body := send("/x?user=mallory&page=2", func(req *http.Request) {
			req.SetBasicAuth("gina", "gina-pw")
			spoofAll(req)
			req.Header.Add("Connection", "Authorization")
		})
		equal(t, "status", resp.StatusCode, http.StatusOK)
		got := decodeEcho(t, body)
		equal(t, "X-Alice-User", strings.Join(identityValues(got.Header, "X-Alice-User"), "|"), "gina")
		equal(t, "X-Alice-Role", strings.Join(identityValues(got.Header, "X-Alice-Role"), "|"), "guest")
		equal(t, "query", got.RawQuery, "page=2&user=gina")
		// request_headers.set is applied after the Connection-named headers go
		equal(t, "Authorization", got.Header.Get("Authorization"), "Bearer upstream-key")
	})

	t.Run("groups are comma-joined into one value", func(t *testing.T) {
		resp, body := send("/x", func(req *http.Request) { req.SetBasicAuth("robin", "robin-pw") })
		equal(t, "status", resp.StatusCode, http.StatusOK)
		equal(t, "X-Alice-Role", strings.Join(decodeEcho(t, body).Header.Values("X-Alice-Role"), "|"), "guest,viewer")
	})

	t.Run("a user with no groups gets no role header, not the client's", func(t *testing.T) {
		resp, body := send("/x", func(req *http.Request) {
			req.SetBasicAuth("nogroups", "nogroups-pw")
			spoofAll(req)
		})
		equal(t, "status", resp.StatusCode, http.StatusOK)
		got := decodeEcho(t, body)
		equal(t, "X-Alice-User", strings.Join(identityValues(got.Header, "X-Alice-User"), "|"), "nogroups")
		equal(t, "X-Alice-Role", len(identityValues(got.Header, "X-Alice-Role")), 0)
	})

	// basic's headers are not set when a token wins; without the strip the
	// client's would have gone through instead
	t.Run("another authenticator wins: no identity headers at all", func(t *testing.T) {
		resp, body := send("/x?user=mallory&page=2", func(req *http.Request) {
			req.Header.Set("X-TOKEN", "ci-token")
			spoofAll(req)
		})
		equal(t, "status", resp.StatusCode, http.StatusOK)
		got := decodeEcho(t, body)
		equal(t, "X-Alice-User", len(identityValues(got.Header, "X-Alice-User")), 0)
		equal(t, "X-Alice-Role", len(identityValues(got.Header, "X-Alice-Role")), 0)
		equal(t, "query", got.RawQuery, "page=2")
	})

	t.Run("a request that fails authentication is not proxied", func(t *testing.T) {
		before := hits.Load()
		resp, body := send("/x", func(req *http.Request) {
			req.SetBasicAuth("robert", "wrong")
			spoofAll(req)
		})
		equal(t, "status", resp.StatusCode, http.StatusUnauthorized)
		equal(t, "body", strings.TrimSpace(body), "Unauthorized")
		equal(t, "backend hits", hits.Load(), before)
	})

	t.Run("a request the allow list refuses is not proxied", func(t *testing.T) {
		before := hits.Load()
		resp, body := send("/owner", func(req *http.Request) {
			req.SetBasicAuth("gina", "gina-pw")
			spoofAll(req)
		})
		equal(t, "status", resp.StatusCode, http.StatusForbidden)
		equal(t, "body", strings.TrimSpace(body), "Forbidden")
		equal(t, "backend hits", hits.Load(), before)
	})

	// documented: a rule without auth does not know the headers mean
	// anything, and passes them through like any other; request_headers.remove
	// is how such a rule keeps them from a backend that trusts them
	t.Run("a rule without auth passes them through", func(t *testing.T) {
		resp, body := send("/open", func(req *http.Request) { req.Header.Set("X-Alice-User", "mallory") })
		equal(t, "status", resp.StatusCode, http.StatusOK)
		equal(t, "X-Alice-User", decodeEcho(t, body).Header.Get("X-Alice-User"), "mallory")

		resp, body = send("/careful", func(req *http.Request) {
			req.Header.Set("X-Alice-User", "mallory")
			req.Header.Set("X-Alice-Role", "owner")
		})
		equal(t, "status", resp.StatusCode, http.StatusOK)
		got := decodeEcho(t, body)
		equal(t, "X-Alice-User", got.Header.Get("X-Alice-User"), "")
		equal(t, "X-Alice-Role", got.Header.Get("X-Alice-Role"), "")
	})
}

// allow answers an authenticated client it does not name with 403 - not 401,
// and no challenge, since new credentials would not help - and the refusal is
// logged and counted, with no credential anywhere.
func TestAllow(t *testing.T) {
	backend, _ := countingBackend(t)
	server := newTestServer(t, fmt.Sprintf(identityConfig, backend.URL))

	call := func(user, password string) *http.Response {
		req := request(t, http.MethodGet, server.url("/owner"), nil)
		req.SetBasicAuth(user, password)
		resp, _ := do(t, req)
		return resp
	}
	equal(t, "owner", call("robert", "robert-pw").StatusCode, http.StatusOK)
	refused := call("gina", "gina-pw")
	equal(t, "guest", refused.StatusCode, http.StatusForbidden)
	equal(t, "challenge", refused.Header.Get("WWW-Authenticate"), "")
	equal(t, "wrong password", call("robert", "nope").StatusCode, http.StatusUnauthorized)

	// a token is matched by its groups too
	req := request(t, http.MethodGet, server.url("/owner"), nil)
	req.Header.Set("X-TOKEN", "ci-token")
	resp, _ := do(t, req)
	equal(t, "token with the group", resp.StatusCode, http.StatusOK)

	logs := server.log()
	contains(t, logs, `"msg":"authorization failed","rule":"owner-only"`)
	contains(t, logs, `"user":"gina"`)
	contains(t, logs, `"error":"forbidden"`) // the access-log record
	for _, secret := range []string{"robert-pw", "gina-pw", "ci-token", "nope"} {
		notContains(t, logs, secret)
	}

	_, body := get(t, server.adminURL("/metrics"))
	contains(t, body, `goproxy_auth_forbidden_total{rule="owner-only",method="basic"} 1`)
}

// A forward-auth service never sees what a client claimed in user_header or
// groups_header, and what it did not answer with in copy_headers does not
// reach the backend as the client's. It does see the client's copy of a
// copy_headers header, which may be its credential.
func TestForwardAuthIdentityHeaders(t *testing.T) {
	backend, _ := countingBackend(t)
	var sawUser, sawGroups, sawAuthorization atomic.Value
	authService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawUser.Store(strings.Join(identityValues(r.Header, "X-Auth-User"), "|"))
		sawGroups.Store(strings.Join(identityValues(r.Header, "X-Auth-Groups"), "|"))
		sawAuthorization.Store(r.Header.Get("Authorization"))
		switch r.Header.Get("Authorization") {
		case "Bearer carol":
			w.Header().Set("X-Auth-User", "carol")
			w.Header().Set("X-Auth-Groups", "staff, ops")
			w.Header().Set("Authorization", "Bearer internal-jwt")
		case "Bearer dave":
			w.Header().Set("X-Auth-User", "dave") // and no groups
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(authService.Close)

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
auth:
  sso:
    forward:
      url: %q
      user_header: X-Auth-User
      groups_header: X-Auth-Groups
      copy_headers: [X-Auth-User, X-Auth-Groups, Authorization]
rules:
  - name: admins
    match: { path: /admin }
    auth: sso
    allow: { groups: [admins] }
    proxy: { url: %[2]q }
  - name: ops
    auth: sso
    allow: { groups: [ops], users: [dave] }
    proxy: { url: %[2]q }
`, authService.URL, backend.URL))

	send := func(path, bearer string) (*http.Response, string) {
		req := request(t, http.MethodGet, server.url(path), nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		spoof(req, "X-Auth-User", "mallory")
		spoof(req, "X-Auth-Groups", "admins")
		return do(t, req)
	}

	resp, body := send("/x", "carol")
	equal(t, "carol", resp.StatusCode, http.StatusOK)
	equal(t, "auth service saw X-Auth-User", sawUser.Load(), "")
	equal(t, "auth service saw X-Auth-Groups", sawGroups.Load(), "")
	equal(t, "auth service saw Authorization", sawAuthorization.Load(), "Bearer carol")
	got := decodeEcho(t, body)
	equal(t, "X-Auth-User", strings.Join(identityValues(got.Header, "X-Auth-User"), "|"), "carol")
	equal(t, "X-Auth-Groups", strings.Join(identityValues(got.Header, "X-Auth-Groups"), "|"), "staff, ops")
	equal(t, "Authorization", got.Header.Get("Authorization"), "Bearer internal-jwt")

	// dave's answer carries no groups, so the backend gets none - not the
	// client's "admins"
	resp, body = send("/x", "dave")
	equal(t, "dave", resp.StatusCode, http.StatusOK)
	got = decodeEcho(t, body)
	equal(t, "X-Auth-Groups", len(identityValues(got.Header, "X-Auth-Groups")), 0)
	equal(t, "Authorization", got.Header.Get("Authorization"), "")

	// the client's claim to admins does not reach the allow list either
	resp, _ = send("/admin", "carol")
	equal(t, "carol on admins", resp.StatusCode, http.StatusForbidden)

	resp, _ = send("/x", "mallory")
	equal(t, "refused by the auth service", resp.StatusCode, http.StatusUnauthorized)
	equal(t, "auth service saw X-Auth-User on a refusal", sawUser.Load(), "")
}
