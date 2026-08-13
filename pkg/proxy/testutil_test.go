package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"goproxy/pkg/config"
)

// testServer is a real goproxy listening on a real port, driven by a real
// client. Its log output is captured so that tests can assert on what was, and
// was not, written to it.
type testServer struct {
	*Server
	t    *testing.T
	logs *syncBuffer
}

// newTestServer parses a v2 config, starts it on whatever port the kernel hands
// out, and shuts it down when the test ends.
func newTestServer(t *testing.T, yamlText string) *testServer {
	t.Helper()
	cfg, err := config.Parse([]byte(yamlText))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return startTestServer(t, cfg)
}

func startTestServer(t *testing.T, cfg *config.Config) *testServer {
	t.Helper()
	logs := &syncBuffer{}
	server, err := New(cfg, WithLogOutput(logs))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return &testServer{Server: server, t: t, logs: logs}
}

func (ts *testServer) url(path string) string    { return "http://" + ts.HTTPAddr() + path }
func (ts *testServer) tlsURL(path string) string { return "https://" + ts.HTTPSAddr() + path }
func (ts *testServer) adminURL(path string) string {
	return "http://" + ts.AdminAddr() + path
}
func (ts *testServer) log() string { return ts.logs.String() }

// syncBuffer collects log output from every goroutine that writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func get(t *testing.T, rawurl string) (*http.Response, string) {
	t.Helper()
	return do(t, request(t, http.MethodGet, rawurl, nil))
}

func request(t *testing.T, method, rawurl string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawurl, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

func do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	return doWith(t, noRedirectClient(), req)
}

func doWith(t *testing.T, client *http.Client, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, string(body)
}

// echo is what the test backend reports about the request it received.
type echo struct {
	Backend  string
	Method   string
	Path     string
	RawPath  string
	RawQuery string
	Host     string
	Header   http.Header
	Body     string
}

// newEchoBackend describes the request it was given, so a test can assert on
// exactly what goproxy forwarded.
func newEchoBackend(t *testing.T, name string) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(echo{
			Backend: name, Method: r.Method, Path: r.URL.Path, RawPath: r.URL.RawPath,
			RawQuery: r.URL.RawQuery, Host: r.Host, Header: r.Header, Body: string(body),
		})
	}))
	t.Cleanup(backend.Close)
	return backend
}

func decodeEcho(t *testing.T, body string) echo {
	t.Helper()
	var e echo
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("decode echo %q: %v", body, err)
	}
	return e
}

// testCert generates a self-signed certificate and writes it to a temp
// directory. It returns the file names and a pool that trusts it.
func testCert(t *testing.T, hosts ...string) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	if len(hosts) == 0 {
		hosts = []string{"localhost", "example.com"}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: hosts[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              hosts,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	writeFileAt(t, certFile, string(certPEM))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writeFileAt(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})))
	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append cert to pool")
	}
	return certFile, keyFile, pool
}

func tlsClient(pool *x509.CertPool) *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	full := filepath.Join(dir, name)
	writeFileAt(t, full, content)
	return full
}

func writeFileAt(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func contains(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected %q to contain %q", haystack, needle)
	}
}

func notContains(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Fatalf("expected %q not to contain %q", haystack, needle)
	}
}

func equal[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func parse(t *testing.T, yamlText string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yamlText))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func parseFile(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.ParseFile(path)
	if err != nil {
		t.Fatalf("parse config file: %v", err)
	}
	return cfg
}
