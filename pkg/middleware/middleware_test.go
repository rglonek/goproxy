package middleware

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"goproxy/pkg/authn"
	"goproxy/pkg/config"
	"goproxy/pkg/observe"
)

func serve(handler http.Handler, r *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(NewRecorder(recorder), r)
	return recorder
}

func withState(r *http.Request) (*http.Request, *State) {
	return NewState(r)
}

func TestChainOrder(t *testing.T) {
	var order []string
	stage := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	handler := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "action")
	}), stage("first"), nil, stage("second"))

	serve(handler, httptest.NewRequest("GET", "/", nil))
	if strings.Join(order, ",") != "first,second,action" {
		t.Errorf("order = %v, want the first listed to be outermost (and nil stages skipped)", order)
	}
}

// Request ids have to sort in arrival order: that is what makes them useful in
// a log.
func TestRequestIDsAreSortableAndUnique(t *testing.T) {
	generator := newIDGenerator()
	ids := make([]string, 0, 500)
	for range 500 {
		ids = append(ids, generator.next())
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	for i := range ids {
		if ids[i] != sorted[i] {
			t.Fatalf("ids do not sort in arrival order at %d: %q vs %q", i, ids[i], sorted[i])
		}
	}
}

// An id from an untrusted peer is a way to poison the log, so it is only
// believed from a trusted one - and only when it is printable.
func TestRequestIDFromThePeer(t *testing.T) {
	trusted, err := NewTrustedProxies([]string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	middleware := RequestID(trusted)

	tests := []struct {
		name       string
		remoteAddr string
		inbound    string
		want       string
	}{
		{"untrusted peer", "10.0.0.1:1234", "client-chosen", ""},
		{"trusted peer", "192.0.2.1:1234", "client-chosen", "client-chosen"},
		{"trusted peer, unprintable id", "192.0.2.1:1234", "bad\nid", ""},
		{"trusted peer, absurd id", "192.0.2.1:1234", strings.Repeat("x", 100), ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "/", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("X-Request-Id", test.inbound)
			request, state := withState(request)

			handler := middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			recorder := serve(handler, request)

			if test.want != "" && state.ID != test.want {
				t.Errorf("id = %q, want %q", state.ID, test.want)
			}
			if test.want == "" && state.ID == test.inbound {
				t.Errorf("id = %q, want a generated one", state.ID)
			}
			if recorder.Header().Get("X-Request-Id") != state.ID {
				t.Errorf("the id was not echoed: %q", recorder.Header().Get("X-Request-Id"))
			}
			if request.Header.Get("X-Request-Id") != state.ID {
				t.Errorf("the id was not propagated upstream: %q", request.Header.Get("X-Request-Id"))
			}
		})
	}
}

func TestRealIPDropsUntrustedClaims(t *testing.T) {
	trusted, err := NewTrustedProxies([]string{"192.0.2.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	warnings := 0
	middleware := trusted.RealIP(func(string, ...any) { warnings++ })

	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.0.0.1:1234"
	request.Header.Set("X-Forwarded-For", "1.2.3.4")
	request.Header.Set("X-Real-Ip", "1.2.3.4")
	request, state := withState(request)
	serve(middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})), request)

	if state.ClientIP != "10.0.0.1" {
		t.Errorf("client ip = %q, want the peer", state.ClientIP)
	}
	if request.Header.Get("X-Forwarded-For") != "" || request.Header.Get("X-Real-Ip") != "" {
		t.Errorf("an untrusted claim survived: %v", request.Header)
	}
	if warnings != 1 {
		t.Errorf("warnings = %d, want one naming the peer", warnings)
	}

	// from a trusted peer the claim is believed, and the rightmost untrusted
	// address is the client
	request = httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Header.Set("X-Forwarded-For", "1.2.3.4, 192.0.2.1")
	request, state = withState(request)
	serve(middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})), request)
	if state.ClientIP != "1.2.3.4" {
		t.Errorf("client ip = %q, want the rightmost untrusted address", state.ClientIP)
	}
}

func TestRateLimiterRefills(t *testing.T) {
	limiter := newRateLimiter(100, 2) // 100/s, burst 2
	for i := range 2 {
		if !limiter.allow("a") {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}
	if limiter.allow("a") {
		t.Fatal("a third request was allowed immediately")
	}
	// a different client has its own bucket
	if !limiter.allow("b") {
		t.Fatal("another client shared the first one's bucket")
	}
	time.Sleep(30 * time.Millisecond) // ~3 tokens at 100/s
	if !limiter.allow("a") {
		t.Fatal("the bucket did not refill")
	}
}

func TestMethodsFallThroughIsNotThisMiddleware(t *testing.T) {
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), Methods([]string{"GET"}))

	recorder := serve(handler, httptest.NewRequest("POST", "/", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != "GET" {
		t.Errorf("Allow = %q", got)
	}
}

func TestRecorderCountsWhatWasSent(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := NewRecorder(recorder).(*responseRecorder)
	writer.WriteHeader(http.StatusTeapot)
	_, _ = writer.Write([]byte("hello"))
	// a second WriteHeader must not change what was recorded
	writer.WriteHeader(http.StatusOK)

	if writer.Status() != http.StatusTeapot {
		t.Errorf("status = %d", writer.Status())
	}
	if writer.written != 5 {
		t.Errorf("written = %d, want 5", writer.written)
	}
	if Unwrap(writer) != http.ResponseWriter(recorder) {
		t.Error("Unwrap did not reach the real writer")
	}
}

func TestRecorderDefaultsToOK(t *testing.T) {
	writer := NewRecorder(httptest.NewRecorder()).(*responseRecorder)
	_, _ = writer.Write([]byte("no explicit status"))
	if writer.Status() != http.StatusOK {
		t.Errorf("status = %d, want 200", writer.Status())
	}
}

// A client that authenticated but is not on the rule's allow list gets 403
// with no challenge: asking it for credentials again cannot help.
func TestAuthorize(t *testing.T) {
	allow := authn.NewAllowlist(&config.Allow{Groups: []string{"owner"}})
	metrics := observe.NewMetrics("test", "test")
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, nil))
	reached := false
	handler := Authorize(allow, "owner-only", metrics, log)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	request, state := withState(httptest.NewRequest("GET", "/", nil))
	state.Identity = authn.Identity{Method: authn.MethodBasic, User: "gina", Groups: []string{"guest"}}
	recorder := serve(handler, request)
	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", recorder.Code)
	}
	if got := recorder.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q, want none", got)
	}
	if reached {
		t.Error("the action ran for a refused client")
	}
	if state.Err != "forbidden" {
		t.Errorf("state.Err = %q", state.Err)
	}
	if !strings.Contains(logs.String(), "authorization failed") || !strings.Contains(logs.String(), "user=gina") {
		t.Errorf("log = %q, want the refusal and who it was", logs.String())
	}
	var exposition strings.Builder
	_, _ = metrics.Registry().WriteTo(&exposition)
	if !strings.Contains(exposition.String(), `goproxy_auth_forbidden_total{rule="owner-only",method="basic"} 1`) {
		t.Errorf("metrics = %s", exposition.String())
	}

	request, state = withState(httptest.NewRequest("GET", "/", nil))
	state.Identity = authn.Identity{Method: authn.MethodBasic, User: "robert", Groups: []string{"owner"}}
	if recorder := serve(handler, request); recorder.Code != http.StatusOK || !reached {
		t.Errorf("status = %d, reached = %v, want an owner through", recorder.Code, reached)
	}

	if Authorize(nil, "open", metrics, log) != nil {
		t.Error("a rule without allow got an authorization stage")
	}
}
