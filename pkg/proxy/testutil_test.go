package proxy

import (
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
	"testing"
	"time"

	"github.com/rglonek/logger"
)

// testServer is a real goproxy listening on a real port, driven by a real
// client. The log output is captured so tests can assert on what was, and was
// not, written to it.
type testServer struct {
	*Server
	t       *testing.T
	logFile string
}

// newTestServer parses the config, starts the server on whatever port the
// kernel hands out, and shuts it down when the test ends.
func newTestServer(t *testing.T, yamlText string) *testServer {
	t.Helper()
	config, err := ParseConfig([]byte(yamlText))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return startTestServer(t, config)
}

// captureLogger writes everything to a file instead of stderr, so a test can
// assert on what was logged - and on what was not.
func captureLogger(t *testing.T, logFile string) *logger.Logger {
	t.Helper()
	log := logger.NewLogger()
	log.SetLogLevel(logger.DETAIL)
	log.SinkDisableStderr()
	if err := log.SinkLogToFile(logFile); err != nil {
		t.Fatalf("log sink: %v", err)
	}
	return log
}

func startTestServer(t *testing.T, config *Config) *testServer {
	t.Helper()
	logFile := filepath.Join(t.TempDir(), "goproxy.log")
	log := captureLogger(t, logFile)

	server, err := New(config, WithLogger(log))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := server.Start(context.Background()); err != nil {
		t.Fatalf("start server: %v", err)
	}
	ts := &testServer{Server: server, t: t, logFile: logFile}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	return ts
}

func (ts *testServer) url(path string) string {
	return "http://" + ts.HTTPAddr() + path
}

func (ts *testServer) httpsURL(path string) string {
	return "https://" + ts.HTTPSAddr() + path
}

func (ts *testServer) logs() string {
	ts.t.Helper()
	b, err := os.ReadFile(ts.logFile)
	if err != nil {
		ts.t.Fatalf("read logs: %v", err)
	}
	return string(b)
}

// noRedirectClient does not follow redirects, so tests can assert on the 3xx
// itself.
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func get(t *testing.T, rawurl string) (*http.Response, string) {
	t.Helper()
	return do(t, mustRequest(t, http.MethodGet, rawurl, nil))
}

func mustRequest(t *testing.T, method, rawurl string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawurl, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

func do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := noRedirectClient().Do(req)
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
	Method   string
	Path     string
	RawPath  string
	RawQuery string
	Host     string
	Header   http.Header
	Body     string
}

// newEchoBackend is a backend that describes the request it was given, so tests
// can assert on exactly what goproxy forwarded.
func newEchoBackend(t *testing.T) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(echo{
			Method:   r.Method,
			Path:     r.URL.Path,
			RawPath:  r.URL.RawPath,
			RawQuery: r.URL.RawQuery,
			Host:     r.Host,
			Header:   r.Header,
			Body:     string(body),
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

// testCert generates a self-signed certificate for 127.0.0.1/localhost and
// writes it to a temp directory. It returns the file names and a CA pool that
// trusts it.
func testCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "goproxy test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost", "example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
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

// freePort returns a port that was free a moment ago, for tests that need an
// address before the server is built.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	full := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return full
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
