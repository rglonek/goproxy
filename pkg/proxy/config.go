package proxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

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

// Default timeouts and limits. They are applied to any value the config does
// not set explicitly; setting a timeout to 0 disables it.
const (
	DefaultReadHeaderTimeout           = 10 * time.Second
	DefaultReadTimeout                 = 30 * time.Second
	DefaultWriteTimeout                = 60 * time.Second
	DefaultIdleTimeout                 = 120 * time.Second
	DefaultShutdownTimeout             = 30 * time.Second
	DefaultUpstreamDialTimeout         = 10 * time.Second
	DefaultUpstreamTLSHandshakeTimeout = 10 * time.Second
	DefaultUpstreamResponseTimeout     = 30 * time.Second

	DefaultMaxHeaderBytes ByteSize = 1 << 20
	DefaultMaxRequestBody ByteSize = 32 << 20
	defaultTLSMinVersion           = tls.VersionTLS12
)

// OnListenerError values.
const (
	// OnListenerErrorShutdown stops the whole server when any listener fails.
	OnListenerErrorShutdown = "shutdown"
	// OnListenerErrorContinue keeps the remaining listeners serving.
	OnListenerErrorContinue = "continue"
)

type Config struct {
	ListenAddr string   `yaml:"listen_addr"`
	TLS        *TLS     `yaml:"tls"`
	Rules      Rules    `yaml:"rules"`
	LogLevel   LogLevel `yaml:"log_level"` // one of: detail, debug, info, warn, error, fatal, none
	// timeouts: server and upstream timeouts; omitted values get safe defaults
	Timeouts *Timeouts `yaml:"timeouts"`
	// limits: request size limits; omitted values get safe defaults
	Limits *Limits `yaml:"limits"`
	// trusted_proxies: CIDRs (or bare IPs) of peers allowed to set X-Forwarded-*
	// headers. Requests from anyone else have those headers replaced with values
	// derived from the connection itself.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// on_listener_error: "shutdown" (default) stops the server when a listener
	// fails; "continue" keeps the other listeners serving.
	OnListenerError string `yaml:"on_listener_error"`

	// unexported fields
	warnings []string
	trusted  *trustedProxies
}

type Timeouts struct {
	// read_header: how long a client may take to send request headers
	ReadHeader *Duration `yaml:"read_header"`
	// read: how long a client may take to send headers plus body
	Read *Duration `yaml:"read"`
	// write: how long a response may take to write. Ignored for rules marked
	// streaming and for connection upgrades (websockets).
	Write *Duration `yaml:"write"`
	// idle: how long an idle keep-alive connection is kept open
	Idle *Duration `yaml:"idle"`
	// shutdown: how long a graceful shutdown waits for in-flight requests
	Shutdown *Duration `yaml:"shutdown"`
	// upstream_dial: connection timeout when proxying
	UpstreamDial *Duration `yaml:"upstream_dial"`
	// upstream_tls_handshake: TLS handshake timeout when proxying
	UpstreamTLSHandshake *Duration `yaml:"upstream_tls_handshake"`
	// upstream_response_header: how long an upstream may take to send response
	// headers
	UpstreamResponseHeader *Duration `yaml:"upstream_response_header"`
}

type Limits struct {
	// max_header_bytes: largest accepted request header block
	MaxHeaderBytes *ByteSize `yaml:"max_header_bytes"`
	// max_request_body: largest accepted request body; 0 disables the limit
	MaxRequestBody *ByteSize `yaml:"max_request_body"`
}

type TLS struct {
	ListenAddr  string       `yaml:"listen_addr"`
	Certs       *Certs       `yaml:"certs,omitempty"`
	LetsEncrypt *LetsEncrypt `yaml:"lets_encrypt,omitempty"`
	// min_version: minimum accepted TLS version, one of 1.0, 1.1, 1.2, 1.3.
	// Defaults to 1.2.
	MinVersion string `yaml:"min_version"`
	// max_version: maximum accepted TLS version. Defaults to unset (the highest
	// version the Go runtime supports).
	MaxVersion string `yaml:"max_version"`
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
		// note: the cache directory is created when the server starts, not
		// here: validating a config must not touch the filesystem.
	}
	minVersion, err := parseTLSVersion(c.MinVersion, defaultTLSMinVersion)
	if err != nil {
		return fmt.Errorf("min_version: %w", err)
	}
	maxVersion, err := parseTLSVersion(c.MaxVersion, 0)
	if err != nil {
		return fmt.Errorf("max_version: %w", err)
	}
	if maxVersion != 0 && maxVersion < minVersion {
		return fmt.Errorf("max_version must not be lower than min_version")
	}
	return nil
}

func parseTLSVersion(s string, fallback uint16) (uint16, error) {
	switch strings.TrimSpace(s) {
	case "":
		return fallback, nil
	case "1.0", "1":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("must be one of 1.0, 1.1, 1.2, 1.3, got %q", s)
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
	switch c.OnListenerError {
	case "", OnListenerErrorShutdown, OnListenerErrorContinue:
	default:
		return fmt.Errorf("on_listener_error: must be %q or %q, got %q", OnListenerErrorShutdown, OnListenerErrorContinue, c.OnListenerError)
	}
	for i, p := range c.TrustedProxies {
		if _, err := parseTrustedProxy(p); err != nil {
			return fmt.Errorf("trusted_proxies[%d]: %w", i, err)
		}
	}
	if err := c.Rules.Validate(); err != nil {
		return err
	}
	return nil
}

// Compile turns the validated schema into the state the serving path needs
// (compiled regexes, parsed CIDRs). It is pure - it touches nothing outside the
// Config - and it is idempotent, so it is safe to call again after changing the
// config by hand.
func (c *Config) Compile() error {
	trusted, err := newTrustedProxies(c.TrustedProxies)
	if err != nil {
		return err
	}
	c.trusted = trusted
	for i, rule := range c.Rules {
		if rule == nil {
			return fmt.Errorf("rules[%d]: rule is empty", i)
		}
		rule.index = i
		if err := rule.Compile(); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
	}
	return nil
}

// Warnings returns non-fatal problems found while parsing the config, such as
// unknown keys. They are logged at startup.
func (c *Config) Warnings() []string {
	return c.warnings
}

func (c *Config) readHeaderTimeout() time.Duration {
	return c.timeout(func(t *Timeouts) *Duration { return t.ReadHeader }, DefaultReadHeaderTimeout)
}

func (c *Config) readTimeout() time.Duration {
	return c.timeout(func(t *Timeouts) *Duration { return t.Read }, DefaultReadTimeout)
}

func (c *Config) writeTimeout() time.Duration {
	return c.timeout(func(t *Timeouts) *Duration { return t.Write }, DefaultWriteTimeout)
}

func (c *Config) idleTimeout() time.Duration {
	return c.timeout(func(t *Timeouts) *Duration { return t.Idle }, DefaultIdleTimeout)
}

// ShutdownTimeout is how long a graceful shutdown waits for in-flight requests
// before connections are force-closed.
func (c *Config) ShutdownTimeout() time.Duration {
	return c.timeout(func(t *Timeouts) *Duration { return t.Shutdown }, DefaultShutdownTimeout)
}

func (c *Config) upstreamDialTimeout() time.Duration {
	return c.timeout(func(t *Timeouts) *Duration { return t.UpstreamDial }, DefaultUpstreamDialTimeout)
}

func (c *Config) upstreamTLSHandshakeTimeout() time.Duration {
	return c.timeout(func(t *Timeouts) *Duration { return t.UpstreamTLSHandshake }, DefaultUpstreamTLSHandshakeTimeout)
}

func (c *Config) upstreamResponseHeaderTimeout() time.Duration {
	return c.timeout(func(t *Timeouts) *Duration { return t.UpstreamResponseHeader }, DefaultUpstreamResponseTimeout)
}

func (c *Config) timeout(pick func(*Timeouts) *Duration, fallback time.Duration) time.Duration {
	if c.Timeouts != nil {
		if d := pick(c.Timeouts); d != nil {
			return d.Duration()
		}
	}
	return fallback
}

func (c *Config) maxHeaderBytes() int {
	if c.Limits != nil && c.Limits.MaxHeaderBytes != nil {
		return int(*c.Limits.MaxHeaderBytes)
	}
	return int(DefaultMaxHeaderBytes)
}

func (c *Config) maxRequestBody() int64 {
	if c.Limits != nil && c.Limits.MaxRequestBody != nil {
		return int64(*c.Limits.MaxRequestBody)
	}
	return int64(DefaultMaxRequestBody)
}

func (c *Config) tlsVersions() (minVersion, maxVersion uint16) {
	if c.TLS == nil {
		return defaultTLSMinVersion, 0
	}
	// already validated
	minVersion, _ = parseTLSVersion(c.TLS.MinVersion, defaultTLSMinVersion)
	maxVersion, _ = parseTLSVersion(c.TLS.MaxVersion, 0)
	return minVersion, maxVersion
}

func parseTrustedProxy(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("must be an IP address or a CIDR, got %q", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ParseConfig parses, validates and compiles a YAML config.
func ParseConfig(yamlFile []byte) (*Config, error) {
	var config Config
	if err := yaml.Unmarshal(yamlFile, &config); err != nil {
		return nil, err
	}
	config.warnings = unknownKeyWarnings(yamlFile)
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := config.Compile(); err != nil {
		return nil, err
	}
	return &config, nil
}

// unknownKeyWarnings re-decodes strictly to find keys the schema does not know
// about. They are reported rather than rejected, because rejecting them would
// break configs that load today (see docs/designs/next, finding A5).
func unknownKeyWarnings(yamlFile []byte) []string {
	var strict Config
	decoder := yaml.NewDecoder(bytes.NewReader(yamlFile))
	decoder.KnownFields(true)
	err := decoder.Decode(&strict)
	if err == nil {
		return nil
	}
	typeErr, ok := err.(*yaml.TypeError)
	if !ok {
		// a real syntax or type error; the non-strict decode above reports it
		return nil
	}
	var warnings []string
	for _, e := range typeErr.Errors {
		if strings.Contains(e, "not found in type") {
			warnings = append(warnings, "unknown config key ignored: "+e)
		}
	}
	return warnings
}

func ParseConfigFile(path string) (*Config, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config, err := ParseConfig(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return config, nil
}
