package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that accepts either a Go duration string
// ("10s", "1m30s") or a plain number of seconds in YAML.
type Duration time.Duration

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("invalid duration: expected a value like \"10s\", \"1m30s\" or \"0\"")
	}
	s = strings.TrimSpace(s)
	if parsed, err := time.ParseDuration(s); err == nil {
		if parsed < 0 {
			return fmt.Errorf("invalid duration %q: must not be negative", s)
		}
		*d = Duration(parsed)
		return nil
	}
	// a bare number is a count of seconds
	seconds, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("invalid duration %q: expected a value like \"10s\", \"1m30s\" or \"0\"", s)
	}
	if seconds < 0 {
		return fmt.Errorf("invalid duration %q: must not be negative", s)
	}
	*d = Duration(time.Duration(seconds * float64(time.Second)))
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

func (d Duration) String() string {
	return time.Duration(d).String()
}

// Or returns the duration, or fallback when it is not set.
func (d *Duration) Or(fallback time.Duration) time.Duration {
	if d == nil {
		return fallback
	}
	return time.Duration(*d)
}

// ByteSize is a byte count that accepts either a plain number or a suffixed
// string ("32MiB", "1MB", "512KiB") in YAML.
type ByteSize int64

var byteUnits = []struct {
	suffix string
	scale  int64
}{
	{"kib", 1 << 10},
	{"mib", 1 << 20},
	{"gib", 1 << 30},
	{"kb", 1000},
	{"mb", 1000 * 1000},
	{"gb", 1000 * 1000 * 1000},
	{"k", 1 << 10},
	{"m", 1 << 20},
	{"g", 1 << 30},
	{"b", 1},
}

func (b *ByteSize) UnmarshalYAML(value *yaml.Node) error {
	var n int64
	if err := value.Decode(&n); err == nil {
		if n < 0 {
			return fmt.Errorf("invalid size %d: must not be negative", n)
		}
		*b = ByteSize(n)
		return nil
	}
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("invalid size %q: expected a number of bytes or a value like \"32MiB\"", value.Value)
	}
	parsed, err := ParseByteSize(s)
	if err != nil {
		return err
	}
	*b = parsed
	return nil
}

// ParseByteSize parses a byte count such as "32MiB", "1MB" or "1024".
func ParseByteSize(s string) (ByteSize, error) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	if trimmed == "" {
		return 0, fmt.Errorf("invalid size %q: expected a number of bytes or a value like \"32MiB\"", s)
	}
	for _, unit := range byteUnits {
		if !strings.HasSuffix(trimmed, unit.suffix) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(trimmed, unit.suffix))
		value, err := strconv.ParseFloat(number, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid size %q: %q is not a number", s, number)
		}
		if value < 0 {
			return 0, fmt.Errorf("invalid size %q: must not be negative", s)
		}
		return ByteSize(value * float64(unit.scale)), nil
	}
	value, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: expected a number of bytes or a value like \"32MiB\"", s)
	}
	if value < 0 {
		return 0, fmt.Errorf("invalid size %q: must not be negative", s)
	}
	return ByteSize(value), nil
}

func (b ByteSize) MarshalYAML() (interface{}, error) {
	return int64(b), nil
}

func (b ByteSize) String() string {
	return strconv.FormatInt(int64(b), 10)
}

// Or returns the size, or fallback when it is not set.
func (b *ByteSize) Or(fallback ByteSize) int64 {
	if b == nil {
		return int64(fallback)
	}
	return int64(*b)
}

// Percent is a share of something, written as "10%" or as the fraction 0.1.
type Percent float64

func (p *Percent) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return fmt.Errorf("invalid percentage: expected a value like \"10%%\" or 0.1")
	}
	s = strings.TrimSpace(s)
	if fraction, ok := strings.CutSuffix(s, "%"); ok {
		parsed, err := strconv.ParseFloat(strings.TrimSpace(fraction), 64)
		if err != nil {
			return fmt.Errorf("invalid percentage %q: %q is not a number", s, fraction)
		}
		*p = Percent(parsed / 100)
	} else {
		parsed, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("invalid percentage %q: expected a value like \"10%%\" or 0.1", s)
		}
		*p = Percent(parsed)
	}
	if *p < 0 {
		return fmt.Errorf("invalid percentage %q: must not be negative", s)
	}
	return nil
}

func (p Percent) MarshalYAML() (interface{}, error) {
	return strconv.FormatFloat(float64(p)*100, 'f', -1, 64) + "%", nil
}

// Or returns the percentage, or fallback when it is not set.
func (p *Percent) Or(fallback float64) float64 {
	if p == nil {
		return fallback
	}
	return float64(*p)
}
