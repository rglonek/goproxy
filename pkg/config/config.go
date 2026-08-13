// Package config is the goproxy configuration schema. It is plain data: types
// here parse and validate a config file and have no behaviour beyond that.
// Turning a Config into something that can serve requests is the job of
// pkg/route, which compiles it.
package config

import (
	"strconv"
	"time"
)

// Version is the schema version this package understands. It has to be stated
// explicitly in every config file, so that a file written for another version
// is diagnosed instead of half-understood.
const Version = 2

// Defaults applied to anything the config does not set. A timeout of 0 means
// "no timeout"; a limit of 0 means "no limit".
const (
	DefaultReadHeaderTimeout           = 10 * time.Second
	DefaultReadTimeout                 = 30 * time.Second
	DefaultWriteTimeout                = 60 * time.Second
	DefaultIdleTimeout                 = 120 * time.Second
	DefaultShutdownTimeout             = 30 * time.Second
	DefaultUpstreamDialTimeout         = 10 * time.Second
	DefaultUpstreamTLSHandshakeTimeout = 10 * time.Second
	DefaultUpstreamResponseTimeout     = 30 * time.Second
	DefaultForwardAuthTimeout          = 5 * time.Second
	DefaultHealthInterval              = 10 * time.Second
	DefaultHealthTimeout               = 2 * time.Second
	DefaultPassiveCooldown             = 30 * time.Second

	DefaultMaxHeaderBytes ByteSize = 1 << 20
	DefaultMaxRequestBody ByteSize = 32 << 20

	DefaultPassiveFailures = 3
	DefaultRetryBudget     = 0.1
)

// Path match modes.
const (
	PathModePrefix  = "prefix"  // the path starts with the pattern
	PathModeExact   = "exact"   // the path is the pattern
	PathModeSegment = "segment" // the pattern matches whole path segments
	PathModeRegex   = "regex"   // the pattern is a regular expression
)

// Load-balancing policies.
const (
	PolicyRoundRobin   = "round_robin"
	PolicyLeastConn    = "least_conn"
	PolicyIPHash       = "ip_hash"
	PolicyFirstHealthy = "first_healthy"
)

// on_listener_error values.
const (
	OnListenerErrorShutdown = "shutdown"
	OnListenerErrorContinue = "continue"
)

// Mutual TLS modes, mirroring crypto/tls.ClientAuthType.
const (
	ClientAuthNone            = "none"
	ClientAuthRequest         = "request"
	ClientAuthRequire         = "require"
	ClientAuthVerifyIfGiven   = "verify_if_given"
	ClientAuthRequireAndVerfy = "require_and_verify"
)

// Log formats.
const (
	FormatJSON = "json"
	FormatText = "text"
)

// Config is a whole configuration file.
type Config struct {
	Version         int                  `yaml:"version"`
	Log             Log                  `yaml:"log"`
	Listeners       Listeners            `yaml:"listeners"`
	Admin           *Admin               `yaml:"admin"`
	Defaults        Defaults             `yaml:"defaults"`
	TrustedProxies  []string             `yaml:"trusted_proxies"`
	OnListenerError string               `yaml:"on_listener_error"`
	Auth            map[string]*Auth     `yaml:"auth"`
	Upstreams       map[string]*Upstream `yaml:"upstreams"`
	Rules           []*Rule              `yaml:"rules"`

	// Source is the file the config was read from, for error messages.
	Source string `yaml:"-"`
}

type Log struct {
	// level: detail|debug|info|warn|error|fatal|none
	Level Level `yaml:"level"`
	// format: json|text. Defaults to text on a terminal, json otherwise.
	Format string `yaml:"format"`
	Access Access `yaml:"access"`
}

// Access configures the request log, which is its own stream with its own
// switch: "request logs but not debug noise" and "warnings but no per-request
// lines" are both reasonable and neither is expressible through a level.
type Access struct {
	Enabled *bool `yaml:"enabled"`
	// exclude_paths: paths that are not logged, such as a health check
	ExcludePaths []string `yaml:"exclude_paths"`
	// redact_query_params: query parameters whose value is replaced with
	// REDACTED, because secrets in query strings end up in log aggregators
	RedactQueryParams []string `yaml:"redact_query_params"`
}

type Listeners struct {
	HTTP  *HTTPListener  `yaml:"http"`
	HTTPS *HTTPSListener `yaml:"https"`
}

type HTTPListener struct {
	Addr string `yaml:"addr"`
	// redirect_to_https: answer every request with a redirect to https instead
	// of serving the rules. Defaults to true when an https listener is
	// configured, false when it is not.
	RedirectToHTTPS *bool `yaml:"redirect_to_https"`
}

type HTTPSListener struct {
	Addr string `yaml:"addr"`
	TLS  TLS    `yaml:"tls"`
}

type TLS struct {
	// min_version/max_version: 1.0, 1.1, 1.2 or 1.3. Minimum defaults to 1.2.
	MinVersion string `yaml:"min_version"`
	MaxVersion string `yaml:"max_version"`
	// certs: one or more certificate/key pairs, selected by SNI
	Certs []Cert `yaml:"certs"`
	// acme: automatic certificates from Let's Encrypt
	ACME       *ACME       `yaml:"acme"`
	ClientAuth *ClientAuth `yaml:"client_auth"`
	HSTS       *HSTS       `yaml:"hsts"`
}

type Cert struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type ACME struct {
	Email    string   `yaml:"email"`
	Domains  []string `yaml:"domains"`
	CacheDir string   `yaml:"cache_dir"`
}

type ClientAuth struct {
	// mode: none|request|require|verify_if_given|require_and_verify
	Mode   string `yaml:"mode"`
	CAFile string `yaml:"ca_file"`
}

// HSTS is opt-in and never on by default: a wrong max_age is very hard for an
// operator to recover from.
type HSTS struct {
	Enabled           bool      `yaml:"enabled"`
	MaxAge            *Duration `yaml:"max_age"`
	IncludeSubdomains bool      `yaml:"include_subdomains"`
	Preload           bool      `yaml:"preload"`
}

// Admin is a separate listener that is never routed to. Health, metrics and
// reload live there so that they cannot collide with a catch-all rule.
type Admin struct {
	Addr    string `yaml:"addr"`
	Metrics *bool  `yaml:"metrics"`
	// pprof: expose /debug/pprof. Off by default.
	Pprof bool `yaml:"pprof"`
	// reload: allow POST /reload. On by default when an admin listener exists.
	Reload *bool `yaml:"reload"`
}

type Defaults struct {
	Timeouts Timeouts `yaml:"timeouts"`
	Limits   Limits   `yaml:"limits"`
}

type Timeouts struct {
	ReadHeader *Duration `yaml:"read_header"`
	Read       *Duration `yaml:"read"`
	// write: not applied to connection upgrades or to rules marked streaming
	Write    *Duration `yaml:"write"`
	Idle     *Duration `yaml:"idle"`
	Shutdown *Duration `yaml:"shutdown"`

	UpstreamDial           *Duration `yaml:"upstream_dial"`
	UpstreamTLSHandshake   *Duration `yaml:"upstream_tls_handshake"`
	UpstreamResponseHeader *Duration `yaml:"upstream_response_header"`
}

type Limits struct {
	MaxHeaderBytes *ByteSize `yaml:"max_header_bytes"`
	MaxRequestBody *ByteSize `yaml:"max_request_body"`
}

// Auth is a named, reusable authentication block. Authenticators are tried in
// the order token, basic, forward; the first one that accepts the request wins.
type Auth struct {
	Basic   *BasicAuth   `yaml:"basic"`
	Token   *TokenAuth   `yaml:"token"`
	Forward *ForwardAuth `yaml:"forward"`
}

type BasicAuth struct {
	Users []User `yaml:"users"`
	Realm string `yaml:"realm"`
	// forward_user_header: send the authenticated user upstream in this header
	ForwardUserHeader string `yaml:"forward_user_header"`
	// forward_user_query: send the authenticated user upstream in this query
	// parameter
	ForwardUserQuery string `yaml:"forward_user_query"`
	// forward: pass the Authorization header on to the upstream. Off by
	// default: goproxy consumed that credential.
	Forward bool `yaml:"forward"`
}

// User is one account. Exactly one of password, password_hash or password_file
// must be set. password_hash is a bcrypt hash, which is what lets a config be
// committed to a repository.
type User struct {
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	PasswordHash string `yaml:"password_hash"`
	PasswordFile string `yaml:"password_file"`
}

type TokenAuth struct {
	// header: where the token is read from, default X-TOKEN
	Header string `yaml:"header"`
	// accept_bearer: also accept "Authorization: Bearer <token>". On by default.
	AcceptBearer *bool   `yaml:"accept_bearer"`
	Tokens       []Token `yaml:"tokens"`
	// forward: pass the token header on to the upstream. Off by default.
	Forward bool `yaml:"forward"`
}

// Token is one accepted token. Exactly one of value, value_env or value_file
// must be set. The id is what appears in logs and metrics; the token never
// does.
type Token struct {
	ID        string `yaml:"id"`
	Value     string `yaml:"value"`
	ValueEnv  string `yaml:"value_env"`
	ValueFile string `yaml:"value_file"`
}

// ForwardAuth delegates the decision to another service: goproxy issues a
// subrequest and treats 2xx as success. This is the mechanism nginx calls
// auth_request and Traefik calls ForwardAuth.
type ForwardAuth struct {
	URL     string    `yaml:"url"`
	Timeout *Duration `yaml:"timeout"`
	// request_headers: which headers of the original request to send. Empty
	// means all of them.
	RequestHeaders []string `yaml:"request_headers"`
	// copy_headers: headers of the auth response to copy onto the upstream
	// request
	CopyHeaders []string `yaml:"copy_headers"`
	// user_header: header of the auth response carrying the authenticated user
	UserHeader string `yaml:"user_header"`
}

// Upstream is a set of targets plus how to choose between them.
type Upstream struct {
	Targets []Target     `yaml:"targets"`
	Policy  string       `yaml:"policy"`
	Health  *Health      `yaml:"health"`
	Retry   *Retry       `yaml:"retry"`
	TLS     *UpstreamTLS `yaml:"tls"`
}

type Target struct {
	URL    string `yaml:"url"`
	Weight int    `yaml:"weight"`
}

type Health struct {
	Passive *PassiveHealth `yaml:"passive"`
	Active  *ActiveHealth  `yaml:"active"`
}

// PassiveHealth ejects a target after N consecutive failures and re-probes it
// after a cool-off. It is on by default.
type PassiveHealth struct {
	Enabled  *bool     `yaml:"enabled"`
	Failures int       `yaml:"failures"`
	Cooldown *Duration `yaml:"cooldown"`
}

// ActiveHealth polls a path on every target. Opt-in.
type ActiveHealth struct {
	Path         string    `yaml:"path"`
	Interval     *Duration `yaml:"interval"`
	Timeout      *Duration `yaml:"timeout"`
	ExpectStatus []int     `yaml:"expect_status"`
}

// Retry is budgeted: attempts bounds a single request, budget bounds the share
// of live traffic that may be retries, so a failing upstream cannot be turned
// into a traffic multiplier.
type Retry struct {
	Attempts int `yaml:"attempts"`
	// on: connect_error, and/or response status codes such as 502
	On     []string `yaml:"on"`
	Budget *Percent `yaml:"budget"`
}

type UpstreamTLS struct {
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	CAFile             string `yaml:"ca_file"`
	ServerName         string `yaml:"server_name"`
}

// Rule is one entry in the ordered list. The first rule whose match applies
// handles the request.
type Rule struct {
	Name  string `yaml:"name"`
	Match Match  `yaml:"match"`
	// auth: the name of an entry in the top-level auth block
	Auth string `yaml:"auth"`
	// allow_ips/deny_ips: CIDRs or addresses, evaluated before auth
	AllowIPs []string `yaml:"allow_ips"`
	DenyIPs  []string `yaml:"deny_ips"`

	RateLimit *RateLimit `yaml:"rate_limit"`
	CORS      *CORS      `yaml:"cors"`
	// max_request_body: overrides defaults.limits.max_request_body
	MaxRequestBody *ByteSize `yaml:"max_request_body"`
	// streaming: responses are long-lived, so the write timeout is not applied
	Streaming bool `yaml:"streaming"`

	Proxy    *Proxy    `yaml:"proxy"`
	Serve    *Serve    `yaml:"serve"`
	Redirect *Redirect `yaml:"redirect"`
	Respond  *Respond  `yaml:"respond"`
}

type Match struct {
	// host: exact ("app.example.com"), wildcard ("*.example.com") or regex
	// ("^.*\.example\.com$"). Empty matches every host.
	Host string `yaml:"host"`
	// path: matched according to path_mode. Empty matches every path.
	Path string `yaml:"path"`
	// path_mode: prefix (default), exact, segment or regex. segment is what
	// people usually mean: /api matches /api and /api/v1 but not /apifoo.
	PathMode string `yaml:"path_mode"`
	// methods: allowed request methods. Empty means all of them.
	Methods []string `yaml:"methods"`
}

type RateLimit struct {
	// requests_per_second: the sustained rate allowed per key
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	// burst: how much of that rate can arrive at once
	Burst int `yaml:"burst"`
	// by: ip (default) or identity
	By string `yaml:"by"`
}

type CORS struct {
	AllowOrigins     []string  `yaml:"allow_origins"`
	AllowMethods     []string  `yaml:"allow_methods"`
	AllowHeaders     []string  `yaml:"allow_headers"`
	ExposeHeaders    []string  `yaml:"expose_headers"`
	AllowCredentials bool      `yaml:"allow_credentials"`
	MaxAge           *Duration `yaml:"max_age"`
}

// Proxy forwards the request to an upstream. Exactly one of upstream and url
// must be set; url is shorthand for a one-target upstream.
type Proxy struct {
	Upstream string `yaml:"upstream"`
	URL      string `yaml:"url"`
	// strip_prefix: remove this prefix from the path before forwarding
	StripPrefix string `yaml:"strip_prefix"`
	// add_prefix: put this in front of the path before forwarding
	AddPrefix string `yaml:"add_prefix"`
	// host_header: override the Host sent upstream. By default the Host the
	// client sent is forwarded.
	HostHeader      string   `yaml:"host_header"`
	RequestHeaders  *Headers `yaml:"request_headers"`
	ResponseHeaders *Headers `yaml:"response_headers"`
}

type Headers struct {
	Set map[string]string `yaml:"set"`
	// remove: header names, or regular expressions when they start with ^
	Remove []string `yaml:"remove"`
}

type Serve struct {
	Dir   string   `yaml:"dir"`
	Index []string `yaml:"index"`
	// list_directories: generate an index page for a directory that has no
	// index file. Off by default.
	ListDirectories bool `yaml:"list_directories"`
	// allow_dotfiles: serve names starting with a dot. Off by default.
	AllowDotfiles bool   `yaml:"allow_dotfiles"`
	CacheControl  string `yaml:"cache_control"`
	// strip_prefix: remove this prefix from the path before looking the file up
	StripPrefix string `yaml:"strip_prefix"`
}

type Redirect struct {
	// to: the target URL. {path} is replaced with the request path and {query}
	// with the query string.
	To     string `yaml:"to"`
	Status int    `yaml:"status"`
}

type Respond struct {
	Status      int    `yaml:"status"`
	Body        string `yaml:"body"`
	BodyFile    string `yaml:"body_file"`
	ContentType string `yaml:"content_type"`
	// reload: re-read body_file on every request instead of once at startup
	Reload  bool              `yaml:"reload"`
	Headers map[string]string `yaml:"headers"`
}

// Action names the terminal action of a rule, for logs and metrics.
func (r *Rule) Action() string {
	switch {
	case r.Proxy != nil:
		return "proxy"
	case r.Serve != nil:
		return "serve"
	case r.Redirect != nil:
		return "redirect"
	case r.Respond != nil:
		return "respond"
	}
	return "none"
}

// ID is how the rule is identified in logs and metrics: its name, or its
// position when it has none.
func (r *Rule) ID(index int) string {
	if r.Name != "" {
		return r.Name
	}
	return "rules[" + strconv.Itoa(index) + "]"
}
