package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrLegacyConfig is returned for a file that looks like a v0.x config. The
// schema changed shape in v2; docs/MIGRATION.md maps every old key to its new
// home.
var ErrLegacyConfig = errors.New("this looks like a goproxy v0.x config file; the schema changed in v2, see docs/MIGRATION.md")

// legacyKeys are top-level keys that only ever existed in the v0.x schema.
var legacyKeys = []string{"listen_addr", "log_level", "tls"}

// Parse decodes and validates a config. Unknown keys are an error: a
// misspelled option that is silently ignored is worse than one that stops the
// process.
func Parse(data []byte) (*Config, error) {
	config := &Config{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		if isEmptyDocument(err) {
			return nil, errors.New("the config file is empty")
		}
		if legacyHint(data) != nil {
			return nil, ErrLegacyConfig
		}
		return nil, fmt.Errorf("%w", cleanYAMLError(err))
	}
	if config.Version != Version {
		if config.Version == 0 && legacyHint(data) != nil {
			return nil, ErrLegacyConfig
		}
		return nil, fmt.Errorf("version: must be %d, got %d", Version, config.Version)
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return config, nil
}

// ParseFile reads, decodes and validates a config file.
func ParseFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	config.Source = path
	return config, nil
}

func isEmptyDocument(err error) bool {
	return errors.Is(err, io.EOF)
}

// legacyHint reports the v0.x keys present in the document, if any.
func legacyHint(data []byte) []string {
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil
	}
	if _, ok := raw["version"]; ok {
		return nil
	}
	var found []string
	for _, key := range legacyKeys {
		if _, ok := raw[key]; ok {
			found = append(found, key)
		}
	}
	if len(found) == 0 {
		if _, ok := raw["rules"]; !ok {
			return nil
		}
		// a rules list whose entries use the old flat shape
		var probe struct {
			Rules []map[string]yaml.Node `yaml:"rules"`
		}
		if err := yaml.Unmarshal(data, &probe); err != nil {
			return nil
		}
		for _, rule := range probe.Rules {
			for _, key := range []string{"domain_match", "path_match", "proxy_rule", "serve_rule", "redirect_rule", "respond_rule"} {
				if _, ok := rule[key]; ok {
					return []string{key}
				}
			}
		}
		return nil
	}
	return found
}

// cleanYAMLError turns the decoder's multi-line type error into something that
// reads like the rest of goproxy's messages.
func cleanYAMLError(err error) error {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return err
	}
	return errors.New(strings.Join(typeErr.Errors, "; "))
}
