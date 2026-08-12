package observe

import (
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"goproxy/pkg/config"
)

// Record is one access-log entry. The field set is stable: adding a field is a
// minor version, removing or retyping one is a breaking change.
type Record struct {
	ID       string
	ClientIP string
	Method   string
	Host     string
	Path     string
	Query    string
	Proto    string
	Scheme   string
	Status   int
	BytesIn  int64
	BytesOut int64
	Duration time.Duration

	Rule     string
	Action   string
	Upstream string
	Target   string
	// UpstreamDuration is how much of Duration was spent waiting for the
	// upstream to answer.
	UpstreamDuration time.Duration
	Retries          int

	AuthMethod string
	AuthUser   string
	UserAgent  string
	Referer    string
	Error      string
}

// AccessLogger writes one record per request, after the response completes.
type AccessLogger struct {
	log     *slog.Logger
	enabled bool
	exclude map[string]bool
	redact  map[string]bool
}

// NewAccessLogger builds the access log stream. It shares the destination with
// the process logger but not its level.
func NewAccessLogger(cfg config.Log, out io.Writer) *AccessLogger {
	if out == nil {
		out = os.Stderr
	}
	enabled := true
	if cfg.Access.Enabled != nil {
		enabled = *cfg.Access.Enabled
	}
	if cfg.Level == config.LevelNone {
		enabled = false
	}
	logger := &AccessLogger{
		enabled: enabled,
		exclude: map[string]bool{},
		redact:  map[string]bool{},
	}
	for _, path := range cfg.Access.ExcludePaths {
		logger.exclude[path] = true
	}
	for _, param := range cfg.Access.RedactQueryParams {
		logger.redact[param] = true
	}
	options := &slog.HandlerOptions{Level: slog.LevelInfo}
	if resolveFormat(cfg.Format, out) == config.FormatJSON {
		logger.log = slog.New(slog.NewJSONHandler(out, options))
	} else {
		logger.log = slog.New(slog.NewTextHandler(out, options))
	}
	return logger
}

// Enabled reports whether anything will be written, so callers can skip the
// bookkeeping entirely.
func (a *AccessLogger) Enabled() bool {
	return a != nil && a.enabled
}

// Log writes one record.
func (a *AccessLogger) Log(record Record) {
	if !a.Enabled() || a.exclude[record.Path] {
		return
	}
	attrs := []any{
		slog.String("id", record.ID),
		slog.String("client_ip", record.ClientIP),
		slog.String("method", record.Method),
		slog.String("host", record.Host),
		slog.String("path", record.Path),
		slog.String("query", a.redactQuery(record.Query)),
		slog.String("proto", record.Proto),
		slog.String("scheme", record.Scheme),
		slog.Int("status", record.Status),
		slog.Int64("bytes_in", record.BytesIn),
		slog.Int64("bytes_out", record.BytesOut),
		slog.Float64("duration_ms", float64(record.Duration.Microseconds())/1000),
		slog.String("rule", record.Rule),
		slog.String("action", record.Action),
	}
	if record.Upstream != "" || record.Target != "" {
		attrs = append(attrs,
			slog.String("upstream", record.Upstream),
			slog.String("target", record.Target),
			slog.Float64("upstream_ms", float64(record.UpstreamDuration.Microseconds())/1000),
			slog.Int("retries", record.Retries),
		)
	}
	if record.AuthMethod != "" {
		attrs = append(attrs,
			slog.String("auth_method", record.AuthMethod),
			slog.String("auth_user", record.AuthUser),
		)
	}
	if record.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", record.UserAgent))
	}
	if record.Referer != "" {
		attrs = append(attrs, slog.String("referer", record.Referer))
	}
	if record.Error != "" {
		attrs = append(attrs, slog.String("error", record.Error))
	}
	a.log.Info("request", attrs...)
}

// redactQuery replaces the value of any configured parameter, because secrets
// in query strings are common and end up in log aggregators.
func (a *AccessLogger) redactQuery(query string) string {
	if query == "" || len(a.redact) == 0 {
		return query
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		// unparseable: redact the lot rather than leak half of it
		for name := range a.redact {
			if strings.Contains(query, name) {
				return "REDACTED"
			}
		}
		return query
	}
	changed := false
	for name := range values {
		if a.redact[name] {
			values.Set(name, "REDACTED")
			changed = true
		}
	}
	if !changed {
		return query
	}
	return values.Encode()
}
