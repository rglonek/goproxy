package proxy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type LogLevel int

const (
	LogLevelDetail LogLevel = 6
	LogLevelDebug  LogLevel = 5
	LogLevelInfo   LogLevel = 4
	LogLevelWarn   LogLevel = 3
	LogLevelError  LogLevel = 2
	LogLevelFatal  LogLevel = 1
	LogLevelNone   LogLevel = 0
)

type Config struct {
	ListenAddr string   `yaml:"listen_addr"`
	TLS        *TLS     `yaml:"tls"`
	Rules      Rules    `yaml:"rules"`
	LogLevel   LogLevel `yaml:"log_level"` // one of: detail, debug, info, warn, error, fatal, none
}

type TLS struct {
	ListenAddr  string       `yaml:"listen_addr"`
	Certs       *Certs       `yaml:"certs,omitempty"`
	LetsEncrypt *LetsEncrypt `yaml:"lets_encrypt,omitempty"`
}

type Certs struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type LetsEncrypt struct {
	Email    string   `yaml:"email"`
	Domains  []string `yaml:"domains"`
	CacheDir string   `yaml:"cache_dir"`
}

func (l *LogLevel) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch strings.ToLower(s) {
	case "detail":
		*l = LogLevelDetail
	case "debug":
		*l = LogLevelDebug
	case "info":
		*l = LogLevelInfo
	case "warn":
		*l = LogLevelWarn
	case "error":
		*l = LogLevelError
	case "fatal", "fail":
		*l = LogLevelFatal
	case "none":
		*l = LogLevelNone
	default:
		return fmt.Errorf("invalid log level: %s", s)
	}
	return nil
}

func (l *LogLevel) MarshalYAML() (interface{}, error) {
	return l.String(), nil
}

func (l *LogLevel) String() string {
	switch *l {
	case LogLevelDetail:
		return "detail"
	case LogLevelDebug:
		return "debug"
	case LogLevelInfo:
		return "info"
	case LogLevelWarn:
		return "warn"
	case LogLevelError:
		return "error"
	case LogLevelFatal:
		return "fatal"
	case LogLevelNone:
		return "none"
	default:
		return "unknown"
	}
}

func (c *TLS) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if c.Certs != nil && c.LetsEncrypt != nil {
		return fmt.Errorf("certs and lets_encrypt cannot be used together")
	}
	if c.Certs == nil && c.LetsEncrypt == nil {
		return fmt.Errorf("certs or lets_encrypt is required")
	}
	if c.Certs != nil {
		if c.Certs.CertFile == "" {
			return fmt.Errorf("cert_file is required")
		}
		if c.Certs.KeyFile == "" {
			return fmt.Errorf("key_file is required")
		}
		if _, err := os.Stat(c.Certs.CertFile); os.IsNotExist(err) {
			return fmt.Errorf("cert_file does not exist")
		}
		if _, err := os.Stat(c.Certs.KeyFile); os.IsNotExist(err) {
			return fmt.Errorf("key_file does not exist")
		}
	}
	if c.LetsEncrypt != nil {
		if c.LetsEncrypt.Email == "" {
			return fmt.Errorf("email is required")
		}
		if len(c.LetsEncrypt.Domains) == 0 {
			return fmt.Errorf("domains is required")
		}
		if c.LetsEncrypt.CacheDir == "" {
			return fmt.Errorf("cache_dir is required")
		}
		if _, err := os.Stat(c.LetsEncrypt.CacheDir); os.IsNotExist(err) {
			if err := os.MkdirAll(c.LetsEncrypt.CacheDir, 0755); err != nil {
				return fmt.Errorf("failed to create cache_dir: %w", err)
			}
		}
	}
	return nil
}

func (c *Config) Validate() error {
	// at least one listener is required; listen_addr may be omitted to serve HTTPS only
	if c.ListenAddr == "" && (c.TLS == nil || c.TLS.ListenAddr == "") {
		return fmt.Errorf("listen_addr is required (omit it only when tls.listen_addr is set, to serve HTTPS only)")
	}
	if len(c.Rules) == 0 {
		return fmt.Errorf("rules is required")
	}
	if c.TLS != nil {
		if err := c.TLS.Validate(); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
		if c.TLS.LetsEncrypt != nil && !strings.HasSuffix(c.ListenAddr, ":80") {
			return fmt.Errorf("lets_encrypt requires listen_addr to end with :80 for the http-01 auth challenge")
		}
	}
	if err := c.Rules.Validate(); err != nil {
		return err
	}
	return nil
}

func ParseConfig(yamlFile []byte) (*Config, error) {
	var config Config
	if err := yaml.Unmarshal(yamlFile, &config); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

func ParseConfigFile(path string) (*Config, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(yamlFile)
}
