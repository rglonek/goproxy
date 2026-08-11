package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func minimalConfig(t *testing.T, addr string) *Config {
	t.Helper()
	config, err := ParseConfig([]byte(fmt.Sprintf(`
listen_addr: %q
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, addr)))
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// R3: v0.1.0 closed an unbuffered channel unconditionally, so the second
// Shutdown panicked with "close of closed channel".
func TestShutdownIsIdempotent(t *testing.T) {
	server, err := Run(minimalConfig(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("Wait after a requested shutdown = %v, want nil", err)
	}
}

func TestShutdownFromTwoGoroutines(t *testing.T) {
	server, err := Run(minimalConfig(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for range 4 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
			done <- struct{}{}
		}()
	}
	for range 4 {
		<-done
	}
	if err := server.Wait(); err != nil {
		t.Fatalf("Wait = %v, want nil", err)
	}
}

// R2/R4: a listener that dies has to reach the operator, not disappear into a
// goroutine.
func TestWaitReportsListenerFailure(t *testing.T) {
	server, err := Run(minimalConfig(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	// pull the listener out from under the serving goroutine
	server.httpLn.Close()

	waited := make(chan error, 1)
	go func() { waited <- server.Wait() }()
	select {
	case err := <-waited:
		if err == nil {
			t.Fatal("Wait returned nil after the listener died")
		}
		contains(t, err.Error(), "http listener")
	case <-time.After(10 * time.Second):
		t.Fatal("Wait did not return after the listener died")
	}
}

func TestListenerFailureContinueKeepsServing(t *testing.T) {
	certFile, keyFile, pool := testCert(t)
	config, err := ParseConfig([]byte(fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
on_listener_error: continue
tls:
  listen_addr: "127.0.0.1:0"
  certs:
    cert_file: %q
    key_file: %q
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`, certFile, keyFile)))
	if err != nil {
		t.Fatal(err)
	}
	server := startTestServer(t, config)
	httpsURL := server.httpsURL("/")

	server.httpLn.Close()
	time.Sleep(100 * time.Millisecond)

	resp, body := func() (*http.Response, string) {
		req := mustRequest(t, http.MethodGet, httpsURL, nil)
		resp, err := tlsClient(pool).Do(req)
		if err != nil {
			t.Fatalf("https request after the http listener died: %v", err)
		}
		defer resp.Body.Close()
		buf := make([]byte, 64)
		n, _ := resp.Body.Read(buf)
		return resp, string(buf[:n])
	}()
	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}

func TestStartReportsBindFailure(t *testing.T) {
	addr := freePort(t)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	server, err := New(minimalConfig(t, addr))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background()); err == nil {
		t.Fatal("Start on a bound port returned no error")
	}
	// a caller waiting on the server must not hang on one that never started
	select {
	case <-server.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait would have hung after a failed Start")
	}
}

func TestStartCancelledContextShutsDown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server, err := New(minimalConfig(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	waited := make(chan error, 1)
	go func() { waited <- server.Wait() }()
	select {
	case err := <-waited:
		if err != nil {
			t.Fatalf("Wait = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelling the start context did not shut the server down")
	}
}

func TestShutdownWaitsForInFlightRequest(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	config := minimalConfig(t, "127.0.0.1:0")
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	// replace the pipeline with a handler the test controls
	server.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Write([]byte("done"))
	})
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	result := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + server.HTTPAddr() + "/")
		if err != nil {
			result <- "error: " + err.Error()
			return
		}
		defer resp.Body.Close()
		buf := make([]byte, 16)
		n, _ := resp.Body.Read(buf)
		result <- string(buf[:n])
	}()

	<-started
	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- server.Shutdown(ctx)
	}()
	time.Sleep(100 * time.Millisecond)
	close(release)

	if got := <-result; got != "done" {
		t.Fatalf("in-flight request got %q, want it to complete", got)
	}
	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// R5: a panicking rule has to produce a 500 and a log line through the
// configured logger, not a stdlib log line and a dropped connection.
func TestPanicIsRecoveredAndLogged(t *testing.T) {
	config := minimalConfig(t, "127.0.0.1:0")
	logFile := filepath.Join(t.TempDir(), "goproxy.log")
	server, err := New(config, WithLogger(captureLogger(t, logFile)))
	if err != nil {
		t.Fatal(err)
	}
	server.handler = recoverPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("rule exploded")
	}), server.log)
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	resp, _ := get(t, "http://"+server.HTTPAddr()+"/")
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	logs, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	contains(t, string(logs), "Mod=Panic")
	contains(t, string(logs), "rule exploded")
}

func TestNoMatchingRuleIs404(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
rules:
  - path_match: "/only-here"
    respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`)
	resp, _ := get(t, server.url("/elsewhere"))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	contains(t, server.logs(), "Mod=NotFound")
}

func TestVersionString(t *testing.T) {
	got := Version().String()
	if !strings.HasPrefix(got, "goproxy version ") {
		t.Fatalf("Version() = %q", got)
	}
	if !strings.Contains(got, "go1.") {
		t.Errorf("Version() = %q, want the Go version in it", got)
	}
}
