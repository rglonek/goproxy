package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// R1: the Slowloris case. A client that opens a connection and never finishes
// its headers held a goroutine and a file descriptor forever in v0.1.0, which
// set no timeouts at all.
func TestReadHeaderTimeoutClosesSlowClient(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
timeouts:
  read_header: 300ms
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`)

	conn, err := net.Dial("tcp", server.HTTPAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// a request that never ends: no blank line, so the headers are never
	// complete
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n"); err != nil {
		t.Fatal(err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	start := time.Now()
	_, err = conn.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("the server answered a request whose headers never arrived")
	}
	if elapsed > 4*time.Second {
		t.Fatalf("the connection was still open after %s: read_header did not apply", elapsed)
	}
}

func TestDefaultTimeoutsAreApplied(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`)
	got := server.httpServer
	if got.ReadHeaderTimeout != DefaultReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %s, want %s", got.ReadHeaderTimeout, DefaultReadHeaderTimeout)
	}
	if got.ReadTimeout != DefaultReadTimeout {
		t.Errorf("ReadTimeout = %s", got.ReadTimeout)
	}
	if got.WriteTimeout != DefaultWriteTimeout {
		t.Errorf("WriteTimeout = %s", got.WriteTimeout)
	}
	if got.IdleTimeout != DefaultIdleTimeout {
		t.Errorf("IdleTimeout = %s", got.IdleTimeout)
	}
	if got.MaxHeaderBytes != int(DefaultMaxHeaderBytes) {
		t.Errorf("MaxHeaderBytes = %d", got.MaxHeaderBytes)
	}
}

func TestTimeoutsCanBeDisabled(t *testing.T) {
	server := newTestServer(t, `
listen_addr: "127.0.0.1:0"
timeouts:
  read: 0
  write: "0s"
rules:
  - respond_rule:
      respond_status_code: 200
      respond_body: "ok"
`)
	if server.httpServer.ReadTimeout != 0 || server.httpServer.WriteTimeout != 0 {
		t.Fatalf("explicit zero timeouts were not honoured: read=%s write=%s",
			server.httpServer.ReadTimeout, server.httpServer.WriteTimeout)
	}
}

// R6: a request body has to have a ceiling, or a rule can be made to read an
// unbounded amount of data.
func TestMaxRequestBody(t *testing.T) {
	backend := newEchoBackend(t)
	server := newTestServer(t, fmt.Sprintf(`
listen_addr: "127.0.0.1:0"
limits:
  max_request_body: 32
rules:
  - proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	t.Run("within the limit", func(t *testing.T) {
		resp, body := do(t, mustRequest(t, http.MethodPost, server.url("/x"), strings.NewReader("small")))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
		}
		if got := decodeEcho(t, body).Body; got != "small" {
			t.Errorf("backend saw body %q", got)
		}
	})

	t.Run("over the limit", func(t *testing.T) {
		resp, _ := do(t, mustRequest(t, http.MethodPost, server.url("/x"), strings.NewReader(strings.Repeat("a", 1024))))
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}
	})
}

// A write timeout is what keeps a slow reader from holding a connection open,
// but it would also cut off an event stream. Rules marked streaming run without
// one.
func TestStreamingRuleIsNotCutOffByWriteTimeout(t *testing.T) {
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
listen_addr: "127.0.0.1:0"
timeouts:
  write: 200ms
rules:
  - path_match: "/stream"
    streaming: true
    proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	resp, err := http.Get(server.url("/stream"))
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	events := 0
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
func TestUpgradedConnectionIsNotCutOffByWriteTimeout(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isUpgradeRequest(r) {
			http.Error(w, "expected an upgrade", http.StatusBadRequest)
			return
		}
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Time{})
		if _, err := buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			return
		}
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
listen_addr: "127.0.0.1:0"
timeouts:
  write: 200ms
  read: 200ms
rules:
  - proxy_rule:
      proxy_url: %q
      proxy_append_path: true
`, backend.URL))

	conn, err := net.Dial("tcp", server.HTTPAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
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

	// well past the write and read timeouts: without the exception the
	// connection would be dead by now
	time.Sleep(600 * time.Millisecond)
	if _, err := io.WriteString(conn, "ping\n"); err != nil {
		t.Fatalf("write after the timeout window: %v", err)
	}
	echoed, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read after the timeout window: %v", err)
	}
	if echoed != "echo: ping\n" {
		t.Fatalf("got %q, want the echo back", echoed)
	}
}
