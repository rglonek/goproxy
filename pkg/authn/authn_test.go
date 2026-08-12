package authn

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"goproxy/pkg/config"
)

func chain(t *testing.T, cfg *config.Auth) *Chain {
	t.Helper()
	built, err := New(cfg)
	if err != nil {
		t.Fatalf("build chain: %v", err)
	}
	return built
}

func TestTokenAuth(t *testing.T) {
	c := chain(t, &config.Auth{Token: &config.TokenAuth{
		Tokens: []config.Token{{ID: "ci", Value: "t0ken"}, {Value: "second"}},
	}})

	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-TOKEN", "t0ken")
	identity, ok := c.Authenticate(request)
	if !ok {
		t.Fatal("a valid token was refused")
	}
	if identity.TokenID != "ci" {
		t.Errorf("token id = %q, want the configured id", identity.TokenID)
	}
	if identity.Method != MethodToken {
		t.Errorf("method = %q", identity.Method)
	}

	// a token with no id is identified by its position, never by its value
	request = httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-TOKEN", "second")
	identity, _ = c.Authenticate(request)
	if identity.TokenID != "1" {
		t.Errorf("token id = %q, want the index", identity.TokenID)
	}

	request = httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-TOKEN", "wrong")
	if _, ok := c.Authenticate(request); ok {
		t.Error("an unknown token was accepted")
	}

	request = httptest.NewRequest("GET", "/", nil)
	if _, ok := c.Authenticate(request); ok {
		t.Error("a request with no token was accepted")
	}
}

func TestTokenAuthAcceptsBearerByDefault(t *testing.T) {
	c := chain(t, &config.Auth{Token: &config.TokenAuth{Tokens: []config.Token{{Value: "t0ken"}}}})
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Authorization", "Bearer t0ken")
	if _, ok := c.Authenticate(request); !ok {
		t.Fatal("a bearer token was refused")
	}
	if challenges := c.Challenges(); len(challenges) != 1 || challenges[0] != "Bearer" {
		t.Errorf("challenges = %v, want a bearer challenge", challenges)
	}

	// with accept_bearer off there is no bearer challenge, because answering
	// one would tell the client to retry in a way that cannot work
	off := false
	c = chain(t, &config.Auth{Token: &config.TokenAuth{
		AcceptBearer: &off,
		Tokens:       []config.Token{{Value: "t0ken"}},
	}})
	if challenges := c.Challenges(); len(challenges) != 0 {
		t.Errorf("challenges = %v, want none", challenges)
	}
}

// The credential goproxy consumed is stripped whether or not it was accepted,
// so a rejected token is never forwarded upstream.
func TestStripRemovesConsumedCredentials(t *testing.T) {
	c := chain(t, &config.Auth{
		Token: &config.TokenAuth{Tokens: []config.Token{{Value: "good"}}},
		Basic: &config.BasicAuth{Users: []config.User{{User: "alice", Password: "pw"}}},
	})

	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-TOKEN", "rejected")
	request.SetBasicAuth("alice", "pw")
	identity, ok := c.Authenticate(request)
	if !ok || identity.Method != MethodBasic {
		t.Fatalf("identity = %+v, ok = %v, want basic auth to rescue the request", identity, ok)
	}
	c.Strip(request)
	if got := request.Header.Get("X-TOKEN"); got != "" {
		t.Errorf("the rejected token survived: %q", got)
	}
	if got := request.Header.Get("Authorization"); got != "" {
		t.Errorf("the consumed basic credential survived: %q", got)
	}
}

func TestForwardKeepsCredentials(t *testing.T) {
	c := chain(t, &config.Auth{
		Token: &config.TokenAuth{Forward: true, Tokens: []config.Token{{Value: "good"}}},
	})
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-TOKEN", "good")
	c.Strip(request)
	if got := request.Header.Get("X-TOKEN"); got != "good" {
		t.Errorf("X-TOKEN = %q, want it forwarded", got)
	}
}

func TestBasicAuth(t *testing.T) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("bobs-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(t.TempDir(), "carol.pw")
	if err := os.WriteFile(passwordFile, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := chain(t, &config.Auth{Basic: &config.BasicAuth{
		Users: []config.User{
			{User: "alice", Password: "wonderland"},
			{User: "bob", PasswordHash: string(hashed)},
			{User: "carol", PasswordFile: passwordFile},
		},
		Realm:             "Internal",
		ForwardUserHeader: "X-User",
		ForwardUserQuery:  "user",
	}})

	tests := []struct {
		user, password string
		want           bool
	}{
		{"alice", "wonderland", true},
		{"alice", "wrong", false},
		{"bob", "bobs-password", true},
		{"bob", "wrong", false},
		{"carol", "from-a-file", true},
		{"mallory", "anything", false},
	}
	for _, test := range tests {
		request := httptest.NewRequest("GET", "/", nil)
		request.SetBasicAuth(test.user, test.password)
		identity, ok := c.Authenticate(request)
		if ok != test.want {
			t.Errorf("%s: ok = %v, want %v", test.user, ok, test.want)
			continue
		}
		if ok {
			if identity.User != test.user {
				t.Errorf("user = %q, want %q", identity.User, test.user)
			}
			if identity.Headers.Get("X-User") != test.user {
				t.Errorf("forwarded user header = %q", identity.Headers.Get("X-User"))
			}
			if identity.Query["user"] != test.user {
				t.Errorf("forwarded user query = %q", identity.Query["user"])
			}
		}
	}

	if got := c.Challenges(); len(got) != 1 || got[0] != `Basic realm="Internal"` {
		t.Errorf("challenges = %v", got)
	}
}

func TestSecretsFromTheEnvironment(t *testing.T) {
	t.Setenv("GOPROXY_TEST_SECRET", "env-token")
	c := chain(t, &config.Auth{Token: &config.TokenAuth{
		Tokens: []config.Token{{ID: "env", ValueEnv: "GOPROXY_TEST_SECRET"}},
	}})
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("X-TOKEN", "env-token")
	if _, ok := c.Authenticate(request); !ok {
		t.Error("a token read from the environment was refused")
	}

	// an unset variable is a startup error, not a rule that silently accepts
	// nothing
	if _, err := New(&config.Auth{Token: &config.TokenAuth{
		Tokens: []config.Token{{ValueEnv: "GOPROXY_TEST_UNSET"}},
	}}); err == nil {
		t.Error("an unset environment variable was accepted")
	}
}

func TestForwardAuth(t *testing.T) {
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-Method") != "POST" {
			t.Errorf("the auth service was not told the method: %v", r.Header)
		}
		if r.Header.Get("X-Session") != "good" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("X-User", "carol")
		w.Header().Set("X-Groups", "staff")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer service.Close()

	c := chain(t, &config.Auth{Forward: &config.ForwardAuth{
		URL:         service.URL,
		UserHeader:  "X-User",
		CopyHeaders: []string{"X-Groups"},
	}})

	request := httptest.NewRequest("POST", "/x", nil)
	request.Header.Set("X-Session", "good")
	identity, ok := c.Authenticate(request)
	if !ok {
		t.Fatal("a request the auth service allowed was refused")
	}
	if identity.User != "carol" {
		t.Errorf("user = %q", identity.User)
	}
	if identity.Headers.Get("X-Groups") != "staff" {
		t.Errorf("copied header = %q", identity.Headers.Get("X-Groups"))
	}

	request = httptest.NewRequest("POST", "/x", nil)
	if _, ok := c.Authenticate(request); ok {
		t.Error("a request the auth service refused was accepted")
	}
}

func TestEmptyChainAllowsEverything(t *testing.T) {
	var c *Chain
	if !c.Empty() {
		t.Error("a nil chain is not empty")
	}
	if _, ok := c.Authenticate(httptest.NewRequest("GET", "/", nil)); !ok {
		t.Error("a nil chain refused a request")
	}
}
