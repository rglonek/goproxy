package config

import (
	"fmt"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"
)

// Level is a log level. The vocabulary is goproxy's; the values map onto
// log/slog so that the standard handlers can be used unchanged.
type Level slog.Level

const (
	// LevelDetail is per-request internals: which rule matched and why.
	LevelDetail = Level(slog.LevelDebug - 4)
	LevelDebug  = Level(slog.LevelDebug)
	LevelInfo   = Level(slog.LevelInfo)
	LevelWarn   = Level(slog.LevelWarn)
	LevelError  = Level(slog.LevelError)
	// LevelFatal logs at error level and then the process exits.
	LevelFatal = Level(slog.LevelError + 4)
	// LevelNone silences everything.
	LevelNone = Level(slog.LevelError + 8)
)

var levelNames = []struct {
	name  string
	level Level
}{
	{"detail", LevelDetail},
	{"debug", LevelDebug},
	{"info", LevelInfo},
	{"warn", LevelWarn},
	{"error", LevelError},
	{"fatal", LevelFatal},
	{"none", LevelNone},
}

func ParseLevel(s string) (Level, error) {
	name := strings.ToLower(strings.TrimSpace(s))
	if name == "fail" {
		name = "fatal" // the spelling v0.1.0's README used
	}
	for _, known := range levelNames {
		if known.name == name {
			return known.level, nil
		}
	}
	return 0, fmt.Errorf("invalid log level %q: expected one of detail, debug, info, warn, error, fatal, none", s)
}

func (l Level) String() string {
	for _, known := range levelNames {
		if known.level == l {
			return known.name
		}
	}
	return slog.Level(l).String()
}

// Slog is the log/slog level this level corresponds to.
func (l Level) Slog() slog.Level {
	return slog.Level(l)
}

func (l *Level) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("invalid log level: expected one of detail, debug, info, warn, error, fatal, none")
	}
	parsed, err := ParseLevel(s)
	if err != nil {
		return err
	}
	*l = parsed
	return nil
}

func (l Level) MarshalYAML() (interface{}, error) {
	return l.String(), nil
}
