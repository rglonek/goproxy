// Package route compiles a config into the immutable routing table the serving
// path uses. Nothing outside Compile parses a URL or builds a regex, so there
// is no path by which a half-initialised rule can reach a request.
package route

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"goproxy/pkg/action"
	"goproxy/pkg/authn"
	"goproxy/pkg/config"
	"goproxy/pkg/middleware"
	"goproxy/pkg/observe"
	"goproxy/pkg/upstream"
)

// Deps are what compiling needs from the process.
type Deps struct {
	Log     *slog.Logger
	Metrics *observe.Metrics
	Trusted *middleware.TrustedProxies
}

// Routes is a compiled, immutable routing table. Reload builds a whole new one
// and swaps the pointer.
type Routes struct {
	rules []*Rule
	// byHost holds the rules whose host is an exact match, indexed by host
	byHost map[string][]*Rule
	// others holds every rule whose host is a wildcard, a regex or absent, in
	// config order
	others []*Rule

	pools map[string]*upstream.Pool
	log   *slog.Logger
}

// Rule is one compiled rule: a matcher and a fully assembled handler.
type Rule struct {
	Index  int
	Name   string
	Action string
	// Handler is the rule's middleware chain terminating in its action, built
	// once at compile time.
	Handler   http.Handler
	Streaming bool

	host    hostMatcher
	path    pathMatcher
	methods []string

	action action.Action
	auth   *authn.Chain
	cfg    *config.Rule
}

// Describe is the one-line summary used by `goproxy config explain`.
func (r *Rule) Describe() string {
	if r.action == nil {
		return r.Action
	}
	return r.action.Describe()
}

// Compile turns a validated config into a routing table. Everything that can
// fail - opening a directory, reading a response body, resolving a secret,
// building a transport - fails here, before any request is served.
func Compile(cfg *config.Config, deps Deps) (routes *Routes, err error) {
	if deps.Log == nil {
		deps.Log = observe.Discard()
	}
	if deps.Trusted == nil {
		deps.Trusted, err = middleware.NewTrustedProxies(cfg.TrustedProxies)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %w", err)
		}
	}
	compiled := &Routes{
		byHost: map[string][]*Rule{},
		pools:  map[string]*upstream.Pool{},
		log:    deps.Log,
	}
	// on any failure the half-built table must not leak the roots and
	// transports it has already opened
	defer func() {
		if err != nil {
			compiled.Close()
		}
	}()

	upstreamDeps := upstream.Deps{Log: deps.Log, Metrics: deps.Metrics, Timeouts: cfg.Defaults.Timeouts}
	for name, upstreamCfg := range cfg.Upstreams {
		pool, err := upstream.New(name, upstreamCfg, upstreamDeps)
		if err != nil {
			return nil, fmt.Errorf("upstreams.%s: %w", name, err)
		}
		compiled.pools[name] = pool
	}

	chains := map[string]*authn.Chain{}
	for name, authCfg := range cfg.Auth {
		chain, err := authn.New(authCfg)
		if err != nil {
			return nil, fmt.Errorf("auth.%s: %w", name, err)
		}
		chains[name] = chain
	}

	maxBody := cfg.Defaults.Limits.MaxRequestBody.Or(config.DefaultMaxRequestBody)
	for i, ruleCfg := range cfg.Rules {
		rule, err := compileRule(i, ruleCfg, cfg, compiled, chains, maxBody, deps, upstreamDeps)
		if err != nil {
			return nil, fmt.Errorf("rules[%d]%s: %w", i, nameSuffix(ruleCfg.Name), err)
		}
		compiled.rules = append(compiled.rules, rule)
		if exact, ok := rule.host.(exactHost); ok {
			compiled.byHost[string(exact)] = append(compiled.byHost[string(exact)], rule)
			continue
		}
		compiled.others = append(compiled.others, rule)
	}
	return compiled, nil
}

func nameSuffix(name string) string {
	if name == "" {
		return ""
	}
	return " (" + name + ")"
}

func compileRule(index int, cfg *config.Rule, whole *config.Config, routes *Routes, chains map[string]*authn.Chain,
	defaultMaxBody int64, deps Deps, upstreamDeps upstream.Deps) (*Rule, error) {

	rule := &Rule{
		Index:     index,
		Name:      cfg.ID(index),
		Action:    cfg.Action(),
		Streaming: cfg.Streaming,
		methods:   cfg.Match.Methods,
		cfg:       cfg,
	}
	var err error
	if rule.host, err = newHostMatcher(cfg.Match.Host); err != nil {
		return nil, fmt.Errorf("match.host: %w", err)
	}
	if rule.path, err = newPathMatcher(cfg.Match.Path, cfg.Match.PathMode); err != nil {
		return nil, fmt.Errorf("match.path: %w", err)
	}
	rule.auth = chains[cfg.Auth]

	switch {
	case cfg.Proxy != nil:
		pool := routes.pools[cfg.Proxy.Upstream]
		if pool == nil {
			// an inline url is a one-target upstream named after the rule
			pool, err = upstream.NewSingle(rule.Name, cfg.Proxy.URL, upstreamDeps)
			if err != nil {
				return nil, fmt.Errorf("proxy.url: %w", err)
			}
			routes.pools["rule:"+rule.Name] = pool
		}
		rule.action, err = action.NewProxy(cfg.Proxy, pool, action.ProxyDeps{
			Log: deps.Log, Metrics: deps.Metrics, Trusted: deps.Trusted,
		})
		if err != nil {
			return nil, fmt.Errorf("proxy: %w", err)
		}
	case cfg.Serve != nil:
		rule.action, err = action.NewServe(cfg.Serve, deps.Log)
		if err != nil {
			return nil, fmt.Errorf("serve: %w", err)
		}
	case cfg.Redirect != nil:
		rule.action = action.NewRedirect(cfg.Redirect)
	case cfg.Respond != nil:
		rule.action, err = action.NewRespond(cfg.Respond, deps.Log)
		if err != nil {
			return nil, fmt.Errorf("respond: %w", err)
		}
	}

	ipFilter, err := middleware.IPFilter(cfg.AllowIPs, cfg.DenyIPs, rule.Name, deps.Metrics, deps.Log)
	if err != nil {
		return nil, err
	}
	stages := []middleware.Middleware{
		middleware.MaxBody(cfg.MaxRequestBody.Or(config.ByteSize(defaultMaxBody))),
		ipFilter,
		middleware.CORS(cfg.CORS),
	}
	rateLimit := middleware.RateLimit(cfg.RateLimit, rule.Name, deps.Metrics)
	byIdentity := cfg.RateLimit != nil && cfg.RateLimit.By == "identity"
	if !byIdentity {
		stages = append(stages, rateLimit)
	}
	stages = append(stages, middleware.Authenticate(rule.auth, rule.Name, deps.Metrics, deps.Log))
	if byIdentity {
		// keyed by who the client turned out to be, so it has to run once that
		// is known
		stages = append(stages, rateLimit)
	}
	rule.Handler = middleware.Chain(rule.action, stages...)
	return rule, nil
}

// Rules is every compiled rule, in config order.
func (r *Routes) Rules() []*Rule { return r.rules }

// Pools is every upstream in the table, for health checking and shutdown.
func (r *Routes) Pools() map[string]*upstream.Pool { return r.pools }

// Start begins any background work the table owns, such as active health
// checks.
func (r *Routes) Start(stop <-chan struct{}) {
	for _, pool := range r.pools {
		pool.Start(contextFrom(stop))
	}
}

// Close releases everything the table holds: open directories, idle upstream
// connections and health checkers.
func (r *Routes) Close() {
	if r == nil {
		return
	}
	for _, rule := range r.rules {
		if rule.action != nil {
			_ = rule.action.Close()
		}
	}
	for _, pool := range r.pools {
		pool.Stop()
	}
}

// Match finds the rule that handles a request: the first one, in config order,
// whose host, path and method all match. methodMismatch reports that a rule
// would have matched but for the method, which is a 405 rather than a 404.
func (r *Routes) Match(host, path, method string) (rule *Rule, methodMismatch bool) {
	host = NormalizeHost(host)
	exact := r.byHost[host]
	others := r.others
	i, j := 0, 0
	for i < len(exact) || j < len(others) {
		var candidate *Rule
		if j >= len(others) || (i < len(exact) && exact[i].Index < others[j].Index) {
			candidate = exact[i]
			i++
		} else {
			candidate = others[j]
			j++
		}
		// rules in the exact bucket have already matched on host
		if candidate.host != nil {
			if _, isExact := candidate.host.(exactHost); !isExact && !candidate.host.match(host) {
				continue
			}
		}
		if !candidate.path.match(path) {
			continue
		}
		if !candidate.methodAllowed(method) {
			methodMismatch = true
			continue
		}
		return candidate, false
	}
	return nil, methodMismatch
}

func (r *Rule) methodAllowed(method string) bool {
	if len(r.methods) == 0 {
		return true
	}
	for _, allowed := range r.methods {
		if allowed == method {
			return true
		}
	}
	return false
}

// ServeHTTP matches a request and hands it to the rule's handler. This is the
// whole per-request routing cost: a map lookup, a short scan, and a dispatch.
func (r *Routes) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	rule, methodMismatch := r.Match(request.Host, request.URL.Path, request.Method)
	state := middleware.StateOf(request)
	if rule == nil {
		if methodMismatch {
			if state != nil {
				state.Err = "method_not_allowed"
			}
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		if state != nil {
			state.Err = "no_rule"
		}
		r.log.Log(request.Context(), config.LevelDetail.Slog(), "no rule matched",
			"id", middleware.IDOf(request), "host", request.Host, "path", request.URL.Path)
		http.NotFound(w, request)
		return
	}
	if state != nil {
		state.Rule = rule.Name
		state.Action = rule.Action
		state.Streaming = rule.Streaming
	}
	r.log.Log(request.Context(), config.LevelDetail.Slog(), "rule matched",
		"id", middleware.IDOf(request), "rule", rule.Name, "action", rule.Action)

	// a write timeout would cut a websocket or an event stream off mid-flight,
	// so those requests run without one
	if rule.Streaming || IsUpgrade(request) {
		clearDeadlines(w)
	}
	rule.Handler.ServeHTTP(w, request)
}

// NormalizeHost strips the port and the root-zone trailing dot and lowercases
// what is left: host names are case-insensitive (RFC 9110 section 4.2.3).
func NormalizeHost(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host[i+1:], "]") {
		if !strings.HasPrefix(host, "[") || strings.Contains(host[:i], "]") {
			host = host[:i]
		}
	}
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// IsUpgrade reports whether the client asked to switch protocols, which is how
// a websocket handshake starts.
func IsUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// clearDeadlines removes the connection's read and write deadlines for this
// request. Errors are ignored on purpose: a writer that does not support
// deadlines has none to clear.
func clearDeadlines(w http.ResponseWriter) {
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Time{})
	_ = controller.SetWriteDeadline(time.Time{})
}
