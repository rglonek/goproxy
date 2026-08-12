package middleware

import (
	"crypto/rand"
	"encoding/binary"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"goproxy/pkg/authn"
	"goproxy/pkg/config"
	"goproxy/pkg/observe"
)

// Recover turns a panicking rule into a 500 and a log line through the
// configured logger. Without it net/http writes the panic to the standard
// logger, which ignores the configured level and sinks, and the access log
// never sees the request at all.
func Recover(log *slog.Logger, metrics *observe.Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder, ok := w.(*responseRecorder)
			defer func() {
				recovered := recover()
				if recovered == nil {
					return
				}
				if recovered == http.ErrAbortHandler {
					panic(recovered) // the documented way to abort a response
				}
				if metrics != nil {
					metrics.Panics.Inc()
				}
				log.Error("panic serving request",
					"id", IDOf(r), "method", r.Method, "host", r.Host, "path", r.URL.Path,
					"panic", recovered, "stack", string(debug.Stack()))
				if state := StateOf(r); state != nil {
					state.Err = "panic"
				}
				if !ok || !recorder.wrote {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID assigns every request a sortable id, echoes it to the client and
// passes it upstream, so that an access-log line and the error-log lines for
// the same request can be tied together.
func RequestID(trusted *TrustedProxies) Middleware {
	generator := newIDGenerator()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := ""
			if trusted.Trusts(r.RemoteAddr) {
				// only a peer we trust may name the request; from anyone else
				// an id would be a way to poison the logs
				id = sanitizeID(r.Header.Get("X-Request-Id"))
			}
			if id == "" {
				id = generator.next()
			}
			if state := StateOf(r); state != nil {
				state.ID = id
			}
			r.Header.Set("X-Request-Id", id)
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r)
		})
	}
}

func sanitizeID(id string) string {
	if len(id) > 64 {
		return ""
	}
	for _, r := range id {
		if r < '!' || r > '~' {
			return ""
		}
	}
	return id
}

// idGenerator produces ids that sort in arrival order: a millisecond timestamp
// followed by a counter. Sortable and monotonic is more useful in a log than
// random.
type idGenerator struct {
	mu      sync.Mutex
	last    int64
	counter uint32
	entropy uint32
}

func newIDGenerator() *idGenerator {
	var seed [4]byte
	_, _ = rand.Read(seed[:])
	return &idGenerator{entropy: binary.BigEndian.Uint32(seed[:])}
}

const idAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" // Crockford base32

func (g *idGenerator) next() string {
	now := time.Now().UnixMilli()
	g.mu.Lock()
	if now == g.last {
		g.counter++
	} else {
		g.last = now
		g.counter = 0
	}
	counter := g.counter
	g.mu.Unlock()

	var out [16]byte
	value := uint64(now)
	for i := 9; i >= 0; i-- {
		out[i] = idAlphabet[value&31]
		value >>= 5
	}
	suffix := uint64(counter)<<16 | uint64(g.entropy&0xffff)
	for i := 15; i >= 10; i-- {
		out[i] = idAlphabet[suffix&31]
		suffix >>= 5
	}
	return string(out[:])
}

// AccessLog writes one record per request, after the response completes, and
// keeps the request metrics. It is its own stream: "request logs but not debug
// noise" and "warnings but no per-request lines" are both reasonable.
func AccessLog(log *observe.AccessLogger, metrics *observe.Metrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			recorder, ok := w.(*responseRecorder)
			if !ok {
				recorder = &responseRecorder{ResponseWriter: w}
				w = recorder
			}
			state := StateOf(r)
			next.ServeHTTP(w, r)
			if state == nil {
				return
			}
			duration := time.Since(state.Start)
			rule := state.Rule
			if rule == "" {
				rule = "none"
			}
			action := state.Action
			if action == "" {
				action = "none"
			}
			if metrics != nil {
				status := strconv.Itoa(recorder.Status())
				metrics.Requests.Inc(rule, action, knownMethod(r.Method), status)
				metrics.RequestDuration.Observe(duration.Seconds(), rule, action)
				metrics.ResponseSize.Observe(float64(recorder.written), rule)
				if r.ContentLength > 0 {
					metrics.RequestSize.Observe(float64(r.ContentLength), rule)
				}
			}
			if !log.Enabled() {
				return
			}
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			bytesIn := r.ContentLength
			if bytesIn < 0 {
				bytesIn = 0
			}
			log.Log(observe.Record{
				ID:               state.ID,
				ClientIP:         state.ClientIP,
				Method:           r.Method,
				Host:             r.Host,
				Path:             r.URL.Path,
				Query:            r.URL.RawQuery,
				Proto:            r.Proto,
				Scheme:           scheme,
				Status:           recorder.Status(),
				BytesIn:          bytesIn,
				BytesOut:         recorder.written,
				Duration:         duration,
				Rule:             rule,
				Action:           action,
				Upstream:         state.Upstream,
				Target:           state.Target,
				UpstreamDuration: state.UpstreamDuration,
				Retries:          state.Retries,
				AuthMethod:       state.Identity.Method,
				AuthUser:         state.Identity.Subject(),
				UserAgent:        r.UserAgent(),
				Referer:          r.Referer(),
				Error:            state.Err,
			})
		})
	}
}

// knownMethod bounds the method label: a client can send any token it likes,
// and an unbounded label is how a proxy blows up a Prometheus server.
func knownMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace:
		return method
	}
	return "other"
}

// InFlight keeps the in-flight gauge honest even for requests that panic.
func InFlight(metrics *observe.Metrics) Middleware {
	if metrics == nil {
		return nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metrics.InFlight.Add(1)
			defer metrics.InFlight.Add(-1)
			next.ServeHTTP(w, r)
		})
	}
}

// MaxBody caps how much of a request body a rule can be made to read. A limit
// of 0 disables the cap.
func MaxBody(limit int64) Middleware {
	if limit <= 0 {
		return nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				// MaxBytesReader tells the server to stop reading an oversized
				// body, but only when it is given the server's own writer
				r.Body = http.MaxBytesReader(Unwrap(w), r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Methods refuses anything not in the rule's method list.
func Methods(allowed []string) Middleware {
	if len(allowed) == 0 {
		return nil
	}
	allow := make(map[string]bool, len(allowed))
	for _, method := range allowed {
		allow[strings.ToUpper(method)] = true
	}
	header := strings.Join(allowed, ", ")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allow[r.Method] {
				w.Header().Set("Allow", header)
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IPFilter applies the rule's allow and deny lists. Deny wins over allow, and a
// non-empty allow list means "nothing else".
func IPFilter(allow, deny []string, rule string, metrics *observe.Metrics, log *slog.Logger) (Middleware, error) {
	allowNets, err := NewTrustedProxies(allow)
	if err != nil {
		return nil, err
	}
	denyNets, err := NewTrustedProxies(deny)
	if err != nil {
		return nil, err
	}
	if allowNets.Empty() && denyNets.Empty() {
		return nil, nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client := ClientIP(r)
			blocked := false
			if !denyNets.Empty() && denyNets.Trusts(client) {
				blocked = true
			}
			if !allowNets.Empty() && !allowNets.Trusts(client) {
				blocked = true
			}
			if blocked {
				if metrics != nil {
					metrics.IPFilterDropped.Inc(rule)
				}
				log.Debug("request refused by ip filter", "rule", rule, "client_ip", client)
				if state := StateOf(r); state != nil {
					state.Err = "ip_filter"
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// RateLimit is a token bucket per client, refilled at a fixed rate. It is a
// blunt instrument on purpose: goproxy is not a WAF.
func RateLimit(cfg *config.RateLimit, rule string, metrics *observe.Metrics) Middleware {
	if cfg == nil {
		return nil
	}
	burst := float64(cfg.Burst)
	if burst <= 0 {
		burst = cfg.RequestsPerSecond
	}
	limiter := newRateLimiter(cfg.RequestsPerSecond, burst)
	byIdentity := cfg.By == "identity"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := ClientIP(r)
			if byIdentity {
				if subject := Identity(r).Subject(); subject != "" {
					key = subject
				}
			}
			if !limiter.allow(key) {
				if metrics != nil {
					metrics.RateLimitDropped.Inc(rule)
				}
				if state := StateOf(r); state != nil {
					state.Err = "rate_limited"
				}
				w.Header().Set("Retry-After", strconv.Itoa(limiter.retryAfterSeconds()))
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type rateLimiter struct {
	rate  float64
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
	swept   time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{rate: rate, burst: burst, buckets: map[string]*bucket{}, swept: time.Now()}
}

func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	entry, ok := l.buckets[key]
	if !ok {
		entry = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = entry
	}
	entry.tokens = min(l.burst, entry.tokens+now.Sub(entry.last).Seconds()*l.rate)
	entry.last = now
	if entry.tokens < 1 {
		return false
	}
	entry.tokens--
	return true
}

// sweep drops buckets that have refilled completely, so that a flood of unique
// clients cannot grow the map without bound.
func (l *rateLimiter) sweep(now time.Time) {
	if now.Sub(l.swept) < time.Minute && len(l.buckets) < 10000 {
		return
	}
	l.swept = now
	for key, entry := range l.buckets {
		if now.Sub(entry.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, key)
		}
	}
}

func (l *rateLimiter) retryAfterSeconds() int {
	if l.rate <= 0 {
		return 1
	}
	return max(1, int(1/l.rate))
}

// CORS answers preflight requests and adds the response headers, because
// hand-rolling this in header rewrites is a common source of an accidental
// Access-Control-Allow-Origin: *.
func CORS(cfg *config.CORS) Middleware {
	if cfg == nil {
		return nil
	}
	allowAll := false
	origins := map[string]bool{}
	for _, origin := range cfg.AllowOrigins {
		if origin == "*" {
			allowAll = true
		}
		origins[origin] = true
	}
	methods := strings.Join(cfg.AllowMethods, ", ")
	if methods == "" {
		methods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
	}
	headers := strings.Join(cfg.AllowHeaders, ", ")
	expose := strings.Join(cfg.ExposeHeaders, ", ")
	maxAge := ""
	if cfg.MaxAge != nil {
		maxAge = strconv.Itoa(int(cfg.MaxAge.Duration().Seconds()))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := origin != "" && (allowAll || origins[origin])
			if allowed {
				value := origin
				if allowAll && !cfg.AllowCredentials {
					// credentials and a wildcard origin cannot be combined, and
					// echoing the origin is what callers actually want
					value = "*"
				}
				w.Header().Set("Access-Control-Allow-Origin", value)
				w.Header().Add("Vary", "Origin")
				if cfg.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
				if expose != "" {
					w.Header().Set("Access-Control-Expose-Headers", expose)
				}
			}
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				if allowed {
					w.Header().Set("Access-Control-Allow-Methods", methods)
					requested := r.Header.Get("Access-Control-Request-Headers")
					switch {
					case headers != "":
						w.Header().Set("Access-Control-Allow-Headers", headers)
					case requested != "":
						w.Header().Set("Access-Control-Allow-Headers", requested)
					}
					if maxAge != "" {
						w.Header().Set("Access-Control-Max-Age", maxAge)
					}
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Authenticate runs a rule's authenticator chain. Credentials goproxy consumed
// are stripped whether or not they were accepted, so a rejected token is never
// forwarded upstream when another authenticator rescues the request.
func Authenticate(chain *authn.Chain, rule string, metrics *observe.Metrics, log *slog.Logger) Middleware {
	if chain.Empty() {
		return nil
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := chain.Authenticate(r)
			chain.Strip(r)
			if !ok {
				method := strings.Join(chain.Methods(), "+")
				if metrics != nil {
					metrics.AuthFailures.Inc(rule, method)
				}
				// the credential the client presented is never logged, at any
				// level: it may well be valid somewhere else
				log.Info("authentication failed", "rule", rule, "client_ip", ClientIP(r), "methods", method, "id", IDOf(r))
				if state := StateOf(r); state != nil {
					state.Err = "unauthorized"
				}
				for _, challenge := range chain.Challenges() {
					w.Header().Add("WWW-Authenticate", challenge)
				}
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if state := StateOf(r); state != nil {
				state.Identity = identity
			}
			for name, values := range identity.Headers {
				for _, value := range values {
					r.Header.Set(name, value)
				}
			}
			if len(identity.Query) > 0 {
				query := r.URL.Query()
				for name, value := range identity.Query {
					query.Set(name, value)
				}
				r.URL.RawQuery = query.Encode()
			}
			next.ServeHTTP(w, r)
		})
	}
}
