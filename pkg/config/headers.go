package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// HeaderValue is one value in a headers set block. Written as a plain string
// it is used as it is. Written as a mapping, exactly one of value, value_env
// and value_file says where it comes from, and prefix is put in front of it,
// so that "Authorization: Bearer <key>" can be built from a key that is kept
// out of the config file:
//
//	Authorization: { prefix: "Bearer ", value_env: APP_API_KEY }
type HeaderValue struct {
	Prefix    string `yaml:"prefix,omitempty"`
	Value     string `yaml:"value,omitempty"`
	ValueEnv  string `yaml:"value_env,omitempty"`
	ValueFile string `yaml:"value_file,omitempty"`

	// mapped records that the value was written as a mapping, where one of
	// the sources has to be named; a plain string may be empty
	mapped bool
}

// headerValueKeys are the keys a mapping form accepts.
var headerValueKeys = []string{"prefix", "value", "value_env", "value_file"}

func (v *HeaderValue) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return err
		}
		*v = HeaderValue{Value: s}
		return nil
	case yaml.MappingNode:
		parsed := HeaderValue{mapped: true}
		targets := map[string]*string{
			"prefix":     &parsed.Prefix,
			"value":      &parsed.Value,
			"value_env":  &parsed.ValueEnv,
			"value_file": &parsed.ValueFile,
		}
		// a custom unmarshaler does not inherit the decoder's KnownFields, so
		// unknown and repeated keys are refused here, in the decoder's words
		seen := map[string]bool{}
		var problems []string
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			target, known := targets[key.Value]
			switch {
			case !known:
				problems = append(problems, fmt.Sprintf("line %d: field %s not found in type config.HeaderValue (expected one of %s)",
					key.Line, key.Value, strings.Join(headerValueKeys, ", ")))
				continue
			case seen[key.Value]:
				problems = append(problems, fmt.Sprintf("line %d: mapping key %q already defined", key.Line, key.Value))
				continue
			}
			seen[key.Value] = true
			if err := value.Decode(target); err != nil {
				return err
			}
		}
		if len(problems) > 0 {
			return &yaml.TypeError{Errors: problems}
		}
		*v = parsed
		return nil
	}
	return &yaml.TypeError{Errors: []string{fmt.Sprintf(
		"line %d: a header value must be a string, or a mapping with value, value_env or value_file", node.Line)}}
}

// MarshalYAML writes a plain value back as the string it was written as.
func (v HeaderValue) MarshalYAML() (interface{}, error) {
	if !v.mapped && v.Prefix == "" && v.ValueEnv == "" && v.ValueFile == "" {
		return v.Value, nil
	}
	type mapping HeaderValue // without the method, so this does not recurse
	return mapping(v), nil
}

// External reports whether the value is read from the environment or a file,
// which is to say whether the config file holds it at all.
func (v HeaderValue) External() bool {
	return v.ValueEnv != "" || v.ValueFile != ""
}

// Resolve returns the header value to send: the prefix followed by the
// literal, the environment variable or the file's content. Errors name the
// variable or the file but never the value.
func (v HeaderValue) Resolve() (string, error) {
	if !v.External() {
		return v.Prefix + v.Value, nil
	}
	secret, err := ResolveSecret("", v.ValueEnv, v.ValueFile)
	if err != nil {
		return "", err
	}
	// a line break that made it into a file or a variable would otherwise
	// fail every request: net/http refuses to send such a header
	if !validHeaderValue(secret) {
		source := "environment variable " + v.ValueEnv
		if v.ValueFile != "" {
			source = v.ValueFile
		}
		return "", fmt.Errorf("the value in %s contains a line break or another control character", source)
	}
	return v.Prefix + secret, nil
}

// validHeaderValue is the field-value rule of RFC 9110 section 5.5, as
// net/http applies it: no control characters other than tab.
func validHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if b := value[i]; (b < ' ' && b != '\t') || b == 0x7f {
			return false
		}
	}
	return true
}

// credentialHeaderWords are what a header's name contains when its value is a
// credential: Authorization, Proxy-Authorization, Cookie, Set-Cookie,
// X-Api-Key, X-Auth-Token, X-Amz-Security-Token, X-Session-Id and so on.
var credentialHeaderWords = []string{
	"auth", "cookie", "token", "secret", "password", "passwd", "key", "credential", "session",
}

// SensitiveHeader reports whether a header's value should be treated as a
// credential from its name alone. It errs towards yes: redacting a value that
// was not secret costs the reader of /config very little.
func SensitiveHeader(name string) bool {
	lower := strings.ToLower(name)
	for _, word := range credentialHeaderWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}
