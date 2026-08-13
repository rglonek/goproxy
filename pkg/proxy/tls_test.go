package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"goproxy/pkg/config"
)

func tlsServerConfig(t *testing.T, certFile, keyFile, extra string) string {
	t.Helper()
	return fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
  https:
    addr: "127.0.0.1:0"
    tls:
%s      certs:
        - cert_file: %q
          key_file: %q
rules:
  - name: catch-all
    respond: { status: 200, body: "ok" }
`, extra, certFile, keyFile)
}

func TestTLSServesAndRedirects(t *testing.T) {
	certFile, keyFile, pool := testCert(t)
	server := newTestServer(t, tlsServerConfig(t, certFile, keyFile, ""))

	resp, err := tlsClient(pool).Get(server.tlsURL("/"))
	if err != nil {
		t.Fatalf("https get: %v", err)
	}
	defer resp.Body.Close()
	equal(t, "https status", resp.StatusCode, http.StatusOK)

	// with an https listener configured, plain http redirects by default
	plain, _ := get(t, server.url("/somewhere?x=1"))
	equal(t, "http status", plain.StatusCode, http.StatusMovedPermanently)
	location := plain.Header.Get("Location")
	if !strings.HasPrefix(location, "https://") || !strings.HasSuffix(location, "/somewhere?x=1") {
		t.Errorf("Location = %q", location)
	}
}

func TestHTTPListenerCanServeRulesAlongsideTLS(t *testing.T) {
	certFile, keyFile, _ := testCert(t)
	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http:
    addr: "127.0.0.1:0"
    redirect_to_https: false
  https:
    addr: "127.0.0.1:0"
    tls:
      certs:
        - cert_file: %q
          key_file: %q
rules:
  - name: catch-all
    respond: { status: 200, body: "plain" }
`, certFile, keyFile))

	resp, body := get(t, server.url("/"))
	equal(t, "status", resp.StatusCode, http.StatusOK)
	equal(t, "body", body, "plain")
}

// A certificate that cannot be used has to be a startup error, not a listener
// that fails every handshake while the process reports success.
func TestBrokenCertificateFailsAtStartup(t *testing.T) {
	dir := t.TempDir()
	certFile := writeFile(t, dir, "cert.pem", "not a cert")
	keyFile := writeFile(t, dir, "key.pem", "not a key")

	cfg := parse(t, tlsServerConfig(t, certFile, keyFile, ""))
	if _, err := New(cfg); err == nil {
		t.Fatal("New accepted a certificate that cannot be parsed")
	} else {
		contains(t, err.Error(), "listeners.https.tls")
	}
}

func TestTLSMinVersionAndHSTS(t *testing.T) {
	certFile, keyFile, pool := testCert(t)
	server := newTestServer(t, tlsServerConfig(t, certFile, keyFile,
		"      min_version: \"1.3\"\n      hsts: { enabled: true, max_age: 86400, include_subdomains: true }\n"))

	old := tlsClient(pool)
	old.Transport.(*http.Transport).TLSClientConfig.MaxVersion = tls.VersionTLS12
	if _, err := old.Get(server.tlsURL("/")); err == nil {
		t.Fatal("a TLS 1.2 client was accepted by a min_version 1.3 server")
	}

	resp, err := tlsClient(pool).Get(server.tlsURL("/"))
	if err != nil {
		t.Fatalf("https get: %v", err)
	}
	defer resp.Body.Close()
	equal(t, "negotiated version", resp.TLS.Version, uint16(tls.VersionTLS13))
	equal(t, "HSTS", resp.Header.Get("Strict-Transport-Security"), "max-age=86400; includeSubDomains")
}

func TestSNISelectsTheRightCertificate(t *testing.T) {
	firstCert, firstKey, firstPool := testCert(t, "first.example.com")
	secondCert, secondKey, secondPool := testCert(t, "second.example.com")

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  https:
    addr: "127.0.0.1:0"
    tls:
      certs:
        - { cert_file: %q, key_file: %q }
        - { cert_file: %q, key_file: %q }
rules:
  - name: catch-all
    respond: { status: 200, body: "ok" }
`, firstCert, firstKey, secondCert, secondKey))

	for _, test := range []struct {
		host string
		pool *x509.CertPool
	}{
		{"first.example.com", firstPool},
		{"second.example.com", secondPool},
	} {
		conn, err := tls.Dial("tcp", server.HTTPSAddr(), &tls.Config{
			ServerName: test.host,
			RootCAs:    test.pool,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("%s: handshake: %v", test.host, err)
		}
		got := conn.ConnectionState().PeerCertificates[0].Subject.CommonName
		conn.Close()
		equal(t, test.host+" certificate", got, test.host)
	}
}

func TestMutualTLS(t *testing.T) {
	serverCert, serverKey, serverPool := testCert(t, "localhost")
	clientCert, clientKey, _ := testCert(t, "client")

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  https:
    addr: "127.0.0.1:0"
    tls:
      certs:
        - { cert_file: %q, key_file: %q }
      client_auth:
        mode: require_and_verify
        ca_file: %q
rules:
  - name: catch-all
    respond: { status: 200, body: "ok" }
`, serverCert, serverKey, clientCert))

	withoutCert := tlsClient(serverPool)
	if _, err := withoutCert.Get(server.tlsURL("/")); err == nil {
		t.Fatal("a client with no certificate was accepted")
	}

	pair, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	withCert := tlsClient(serverPool)
	withCert.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{pair}
	resp, err := withCert.Get(server.tlsURL("/"))
	if err != nil {
		t.Fatalf("mutual TLS request: %v", err)
	}
	defer resp.Body.Close()
	equal(t, "status", resp.StatusCode, http.StatusOK)
}

func TestCertificateReloadOnConfigReload(t *testing.T) {
	dir := t.TempDir()
	firstCert, firstKey, firstPool := testCert(t, "localhost")
	certFile := writeFile(t, dir, "cert.pem", readFile(t, firstCert))
	keyFile := writeFile(t, dir, "key.pem", readFile(t, firstKey))
	path := writeFile(t, dir, "config.yaml", tlsServerConfig(t, certFile, keyFile, ""))

	server := startTestServer(t, parseFile(t, path))
	if _, err := tlsClient(firstPool).Get(server.tlsURL("/")); err != nil {
		t.Fatalf("first certificate: %v", err)
	}

	secondCert, secondKey, secondPool := testCert(t, "localhost")
	writeFileAt(t, certFile, readFile(t, secondCert))
	writeFileAt(t, keyFile, readFile(t, secondKey))
	if err := server.ReloadFile(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := tlsClient(secondPool).Get(server.tlsURL("/")); err != nil {
		t.Fatalf("renewed certificate was not served: %v", err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

// The Slowloris case: a client that opens a connection and never finishes its
// headers must be dropped rather than hold a goroutine forever.
func TestReadHeaderTimeout(t *testing.T) {
	server := newTestServer(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
defaults:
  timeouts: { read_header: 300ms }
rules:
  - respond: { status: 200, body: "ok" }
`)

	conn, err := net.Dial("tcp", server.HTTPAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	if _, err := conn.Read(make([]byte, 128)); err == nil {
		t.Fatal("the server answered a request whose headers never arrived")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("the connection was still open after %s", elapsed)
	}
}

func TestDefaultTimeoutsAreApplied(t *testing.T) {
	server := newTestServer(t, `
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
rules:
  - respond: { status: 200, body: "ok" }
`)
	got := server.httpServer
	equal(t, "ReadHeaderTimeout", got.ReadHeaderTimeout, config.DefaultReadHeaderTimeout)
	equal(t, "ReadTimeout", got.ReadTimeout, config.DefaultReadTimeout)
	equal(t, "WriteTimeout", got.WriteTimeout, config.DefaultWriteTimeout)
	equal(t, "IdleTimeout", got.IdleTimeout, config.DefaultIdleTimeout)
	equal(t, "MaxHeaderBytes", got.MaxHeaderBytes, int(config.DefaultMaxHeaderBytes))
}

func TestMaxRequestBody(t *testing.T) {
	backend := newEchoBackend(t, "app")
	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
defaults:
  limits: { max_request_body: 32 }
rules:
  - name: big
    match: { path: "/big" }
    max_request_body: 1KiB
    proxy: { url: %q }
  - name: app
    proxy: { url: %q }
`, backend.URL, backend.URL))

	resp, body := do(t, request(t, http.MethodPost, server.url("/x"), strings.NewReader("small")))
	equal(t, "within the limit", resp.StatusCode, http.StatusOK)
	equal(t, "body", decodeEcho(t, body).Body, "small")

	resp, _ = do(t, request(t, http.MethodPost, server.url("/x"), strings.NewReader(strings.Repeat("a", 1024))))
	equal(t, "over the limit", resp.StatusCode, http.StatusRequestEntityTooLarge)

	// the rule's own limit overrides the default
	resp, _ = do(t, request(t, http.MethodPost, server.url("/big"), strings.NewReader(strings.Repeat("a", 512))))
	equal(t, "within the rule limit", resp.StatusCode, http.StatusOK)
}

// A write timeout keeps a slow reader from holding a connection open, but it
// would also cut off an event stream. Rules marked streaming run without one.
func TestStreamingRuleIsNotCutOff(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		for i := range 5 {
			fmt.Fprintf(w, "data: %d\n\n", i)
			flusher.Flush()
			time.Sleep(150 * time.Millisecond)
		}
	}))
	t.Cleanup(backend.Close)

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
defaults:
  timeouts: { write: 200ms }
rules:
  - name: events
    match: { path: "/stream" }
    streaming: true
    proxy: { url: %q }
`, backend.URL))

	resp, err := http.Get(server.url("/stream"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	events := 0
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data: ") {
			events++
		}
	}
	if events != 5 {
		t.Fatalf("received %d events, want 5 (err: %v)", events, scanner.Err())
	}
}

// The same protection for a connection upgrade, which is how a websocket
// starts. No flag is needed: the upgrade is visible in the request.
func TestUpgradedConnectionIsNotCutOff(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Time{})
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		buf.Flush()
		for {
			line, err := buf.ReadString('\n')
			if err != nil {
				return
			}
			buf.WriteString("echo: " + line)
			buf.Flush()
		}
	}))
	t.Cleanup(backend.Close)

	server := newTestServer(t, fmt.Sprintf(`
version: 2
listeners:
  http: { addr: "127.0.0.1:0" }
defaults:
  timeouts: { write: 200ms, read: 200ms }
rules:
  - name: ws
    proxy: { url: %q }
`, backend.URL))

	conn, err := net.Dial("tcp", server.HTTPAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	_, _ = io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "101") {
		t.Fatalf("status = %q, want 101", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	// well past the write and read timeouts
	time.Sleep(600 * time.Millisecond)
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("write after the timeout window: %v", err)
	}
	echoed, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read after the timeout window: %v", err)
	}
	equal(t, "echo", echoed, "echo: ping\n")
}
