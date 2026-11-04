package config

import (
	"fmt"
	"os"
	"strings"
)

// ResolveSecret reads a secret from the config, an environment variable or a
// file, whichever is set. Reading it from outside means the config file itself
// does not have to hold it. A file's trailing line break is dropped, since
// almost every editor adds one.
//
// It is called when a config is compiled, not when it is parsed, so the same
// rule applies to every secret: a missing variable or unreadable file stops
// startup, -check and a reload, and a reload reads the file again.
func ResolveSecret(literal, fromEnv, fromFile string) (string, error) {
	switch {
	case literal != "":
		return literal, nil
	case fromEnv != "":
		value, ok := os.LookupEnv(fromEnv)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", fromEnv)
		}
		if value == "" {
			return "", fmt.Errorf("environment variable %s is empty", fromEnv)
		}
		return value, nil
	case fromFile != "":
		content, err := os.ReadFile(fromFile)
		if err != nil {
			return "", err
		}
		value := strings.TrimRight(string(content), "\r\n")
		if value == "" {
			return "", fmt.Errorf("%s is empty", fromFile)
		}
		return value, nil
	}
	return "", fmt.Errorf("no value configured")
}
