package observe

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"goproxy/pkg/config"
)

func TestRegistryRendersPrometheusText(t *testing.T) {
	registry := NewRegistry()
	requests := registry.Counter("goproxy_requests_total", "Requests handled.", "rule", "status")
	gauge := registry.Gauge("goproxy_in_flight_requests", "In flight.", "rule")
	histogram := registry.Histogram("goproxy_request_duration_seconds", "Duration.", []float64{0.1, 1}, "rule")

	requests.Inc("api", "200")
	requests.Inc("api", "200")
	requests.Inc("api", "500")
	gauge.Set(3, "api")
	histogram.Observe(0.05, "api")
	histogram.Observe(2, "api")

	var out bytes.Buffer
	if _, err := registry.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	rendered := out.String()
	for _, want := range []string{
		"# TYPE goproxy_requests_total counter",
		`goproxy_requests_total{rule="api",status="200"} 2`,
		`goproxy_requests_total{rule="api",status="500"} 1`,
		`goproxy_in_flight_requests{rule="api"} 3`,
		`goproxy_request_duration_seconds_bucket{rule="api",le="0.1"} 1`,
		`goproxy_request_duration_seconds_bucket{rule="api",le="1"} 1`,
		`goproxy_request_duration_seconds_bucket{rule="api",le="+Inf"} 2`,
		`goproxy_request_duration_seconds_count{rule="api"} 2`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered output is missing %q:\n%s", want, rendered)
		}
	}
}

func TestRegistryEscapesLabelValues(t *testing.T) {
	registry := NewRegistry()
	counter := registry.Counter("goproxy_test_total", "Test.", "rule")
	counter.Inc("a\"b\nc")
	var out bytes.Buffer
	if _, err := registry.WriteTo(&out); err != nil {
		t.Fatal(err)
	}
	line := out.String()
	if strings.Count(line, "\n") > 3 {
		t.Errorf("a label value broke the exposition format:\n%s", line)
	}
}

func TestAccessLogSchema(t *testing.T) {
	var out bytes.Buffer
	logger := NewAccessLogger(config.Log{Format: config.FormatJSON}, &out)
	logger.Log(Record{
		ID: "01ABC", ClientIP: "1.2.3.4", Method: "GET", Host: "example.com",
		Path: "/api", Query: "page=2", Proto: "HTTP/1.1", Scheme: "https",
		Status: 200, BytesOut: 17, Duration: 12400 * time.Microsecond,
		Rule: "api", Action: "proxy", Upstream: "app", Target: "http://10.0.0.1:8081",
		AuthMethod: "token", AuthUser: "ci",
	})
	line := out.String()
	for _, want := range []string{
		`"msg":"request"`, `"id":"01ABC"`, `"client_ip":"1.2.3.4"`, `"status":200`,
		`"bytes_out":17`, `"duration_ms":12.4`, `"rule":"api"`, `"action":"proxy"`,
		`"upstream":"app"`, `"auth_user":"ci"`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("access log line is missing %q:\n%s", want, line)
		}
	}
}

func TestAccessLogRedactsAndExcludes(t *testing.T) {
	var out bytes.Buffer
	logger := NewAccessLogger(config.Log{
		Format: config.FormatJSON,
		Access: config.Access{
			ExcludePaths:      []string{"/healthz"},
			RedactQueryParams: []string{"token"},
		},
	}, &out)

	logger.Log(Record{Path: "/healthz", Status: 200})
	if out.Len() != 0 {
		t.Errorf("an excluded path was logged: %s", out.String())
	}

	logger.Log(Record{Path: "/x", Query: "token=supersecret&page=2", Status: 200})
	line := out.String()
	if strings.Contains(line, "supersecret") {
		t.Errorf("a redacted parameter was logged: %s", line)
	}
	if !strings.Contains(line, "REDACTED") || !strings.Contains(line, "page=2") {
		t.Errorf("redaction dropped the rest of the query: %s", line)
	}
}

func TestAccessLogCanBeDisabled(t *testing.T) {
	var out bytes.Buffer
	disabled := false
	logger := NewAccessLogger(config.Log{Access: config.Access{Enabled: &disabled}}, &out)
	logger.Log(Record{Path: "/x", Status: 200})
	if out.Len() != 0 {
		t.Errorf("the access log was disabled but wrote: %s", out.String())
	}
	if logger.Enabled() {
		t.Error("Enabled() is true for a disabled access log")
	}
}

func TestLoggerUsesGoproxyLevelNames(t *testing.T) {
	var out bytes.Buffer
	logger := NewLogger(config.Log{Level: config.LevelDetail, Format: config.FormatText}, &out)
	logger.Log(context.TODO(), config.LevelDetail.Slog(), "per-request detail")
	logger.Info("lifecycle")
	rendered := out.String()
	if !strings.Contains(rendered, "level=DETAIL") {
		t.Errorf("detail level is not named as the config names it:\n%s", rendered)
	}
	if !strings.Contains(rendered, "level=INFO") {
		t.Errorf("info level missing:\n%s", rendered)
	}
}

func TestLoggerRespectsTheLevel(t *testing.T) {
	var out bytes.Buffer
	logger := NewLogger(config.Log{Level: config.LevelWarn}, &out)
	logger.Info("should not appear")
	logger.Warn("should appear")
	rendered := out.String()
	if strings.Contains(rendered, "should not appear") {
		t.Errorf("a message below the level was written:\n%s", rendered)
	}
	if !strings.Contains(rendered, "should appear") {
		t.Errorf("a message at the level was dropped:\n%s", rendered)
	}
}
