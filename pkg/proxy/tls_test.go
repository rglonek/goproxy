package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tlsConfigYAML(t *testing.T, certFile, keyFile, extra string) string {
	t.Helper()
	return fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
tls:
  listen_addr: "127.0.0.1:0"
%s  certs:
    cert_file: %q
    key_file: %q
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, extra, certFile, keyFile)
}

func TestTLSServesAndRedirects(t *testing.T) {
	certFile, keyFile, pool := testCert(t)
	server := newTestServer(t, tlsConfigYAML(t, certFile, keyFile, ""))

	t.Run("https serves the rules", func(t *testing.T) {
		resp, err := tlsClient(pool).Get(server.httpsURL("/"))
		if err != nil {
			t.Fatalf("https get: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	})

	t.Run("http redirects to https", func(t *testing.T) {
		resp, _ := get(t, server.url("/somewhere?x=1"))
		if resp.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("status = %d, want 301", resp.StatusCode)
		}
		if got := resp.Header.Get("Location"); !strings.HasPrefix(got, "https://") || !strings.HasSuffix(got, "/somewhere?x=1") {
			t.Errorf("Location = %q", got)
		}
	})
}

// R2 (verified in docs/designs/next/01-current-state.md): v0.1.0 accepted a
// certificate file containing anything at all, reported a successful start and
// then failed every handshake.
func TestBrokenCertificateFailsAtStartup(t *testing.T) {
	dir := t.TempDir()
	certFile := writeFile(t, dir, "cert.pem", "not a cert")
	keyFile := writeFile(t, dir, "key.pem", "not a key")

	config, err := ParseConfig([]byte(tlsConfigYAML(t, certFile, keyFile, "")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := New(config); err == nil {
		t.Fatal("New accepted a certificate that cannot be parsed")
	} else {
		contains(t, err.Error(), "tls: certs")
	}
}

func TestTLSMinVersionIsEnforced(t *testing.T) {
	certFile, keyFile, pool := testCert(t)
	server := newTestServer(t, tlsConfigYAML(t, certFile, keyFile, "  min_version: \"1.3\"\n"))

	client := tlsClient(pool)
	client.Transport.(*http.Transport).TLSClientConfig.MaxVersion = tls.VersionTLS12
	if _, err := client.Get(server.httpsURL("/")); err == nil {
		t.Fatal("a TLS 1.2 client was accepted by a min_version 1.3 server")
	}

	client = tlsClient(pool)
	resp, err := client.Get(server.httpsURL("/"))
	if err != nil {
		t.Fatalf("a TLS 1.3 capable client was rejected: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS.Version != tls.VersionTLS13 {
		t.Errorf("negotiated version = %x, want TLS 1.3", resp.TLS.Version)
	}
}

func TestTLSDefaultMinVersionIs12(t *testing.T) {
	certFile, keyFile, pool := testCert(t)
	server := newTestServer(t, tlsConfigYAML(t, certFile, keyFile, ""))

	client := tlsClient(pool)
	client.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS10
	client.Transport.(*http.Transport).TLSClientConfig.MaxVersion = tls.VersionTLS11
	if _, err := client.Get(server.httpsURL("/")); err == nil {
		t.Fatal("a TLS 1.1 client was accepted")
	}
}

func TestReloadCertificates(t *testing.T) {
	certFile, keyFile, pool := testCert(t)
	server := newTestServer(t, tlsConfigYAML(t, certFile, keyFile, ""))

	newCert, newKey, newPool := testCert(t)
	copyFile(t, newCert, certFile)
	copyFile(t, newKey, keyFile)
	if err := server.ReloadCertificates(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if _, err := tlsClient(newPool).Get(server.httpsURL("/")); err != nil {
		t.Fatalf("the reloaded certificate was not served: %v", err)
	}
	// the old certificate is gone, so the old CA no longer verifies
	if _, err := tlsClient(pool).Get(server.httpsURL("/")); err == nil {
		t.Fatal("the replaced certificate is still being served")
	}
}

func TestReloadCertificatesRejectsBrokenFile(t *testing.T) {
	certFile, keyFile, _ := testCert(t)
	server := newTestServer(t, tlsConfigYAML(t, certFile, keyFile, ""))

	if err := os.WriteFile(certFile, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.ReloadCertificates(); err == nil {
		t.Fatal("ReloadCertificates accepted a broken certificate")
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	content, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, content, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = filepath.Base(to)
}
