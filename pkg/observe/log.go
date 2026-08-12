package observe

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"goproxy/pkg/config"
)

// NewLogger builds the process logger from the log section of the config.
// Access logs do not go through it: they are their own stream (see
// NewAccessLogger), because "request logs but not debug noise" and "warnings
// but no per-request lines" are both reasonable.
func NewLogger(cfg config.Log, out io.Writer) *slog.Logger {
	if out == nil {
		out = os.Stderr
	}
	level := cfg.Level
	if level == 0 {
		level = config.LevelInfo
	}
	options := &slog.HandlerOptions{
		Level:       level.Slog(),
		ReplaceAttr: replaceLevel,
	}
	if resolveFormat(cfg.Format, out) == config.FormatJSON {
		return slog.New(slog.NewJSONHandler(out, options))
	}
	return slog.New(slog.NewTextHandler(out, options))
}

// resolveFormat defaults to human-readable output on a terminal and JSON
// everywhere else, which is where logs are collected by a machine.
func resolveFormat(format string, out io.Writer) string {
	if format != "" {
		return format
	}
	if file, ok := out.(*os.File); ok {
		if info, err := file.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			return config.FormatText
		}
	}
	return config.FormatJSON
}

// replaceLevel prints goproxy's level names rather than slog's, so that what
// appears in the log is what the config file says.
func replaceLevel(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) != 0 || attr.Key != slog.LevelKey {
		return attr
	}
	if level, ok := attr.Value.Any().(slog.Level); ok {
		attr.Value = slog.StringValue(strings.ToUpper(config.Level(level).String()))
	}
	return attr
}

// Discard is a logger that throws everything away, for tests and for
// log.level: none.
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: config.LevelNone.Slog()}))
}
