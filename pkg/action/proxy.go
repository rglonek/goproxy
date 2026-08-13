package action

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"time"

	"goproxy/pkg/config"
	"goproxy/pkg/middleware"
	"goproxy/pkg/observe"
	"goproxy/pkg/upstream"
)

// errNoTarget means every target in the upstream was excluded, which can only
// happen once they have all been tried.
var errNoTarget = errors.New("no upstream target available")

// Proxy forwards a request to an upstream.
type Proxy struct {
	pool    *upstream.Pool
	proxy   *httputil.ReverseProxy
	cfg     *config.Proxy
	log     *slog.Logger
	metrics *observe.Metrics

	removeRequest  []*regexp.Regexp
	removeResponse []*regexp.Regexp
}

// ProxyDeps are what the proxy action needs from the process.
type ProxyDeps struct {
	Log     *slog.Logger
	Metrics *observe.Metrics
	Trusted *middleware.TrustedProxies
}

// NewProxy builds the proxy action for a rule.
func NewProxy(cfg *config.Proxy, pool *upstream.Pool, deps ProxyDeps) (*Proxy, error) {
	action := &Proxy{
		pool:    pool,
		cfg:     cfg,
		log:     deps.Log,
		metrics: deps.Metrics,
	}
	var err error
	if action.removeRequest, err = compileRemovals(cfg.RequestHeaders); err != nil {
		return nil, fmt.Errorf("request_headers.remove: %w", err)
	}
	if action.removeResponse, err = compileRemovals(cfg.ResponseHeaders); err != nil {
		return nil, fmt.Errorf("response_headers.remove: %w", err)
	}
	trusted := deps.Trusted

	action.proxy = &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			// ReverseProxy strips the inbound forwarded headers before calling
			// Rewrite; SetXForwarded puts back values derived from this
			// connection. The RealIP middleware has already dropped anything a
			// peer we do not trust tried to claim.
			if trusted.Trusts(request.In.RemoteAddr) {
				copyForwarded(request.Out.Header, request.In.Header)
			}
			request.SetXForwarded()
			request.Out.Header.Set("X-Real-Ip", middleware.ClientIP(request.In))

			// the Host the client sent is forwarded unless the rule overrides it
			request.Out.Host = request.In.Host
			if cfg.HostHeader != "" {
				request.Out.Host = cfg.HostHeader
			}

			path := request.In.URL.Path
			if cfg.StripPrefix != "" {
				path = stripPrefix(path, cfg.StripPrefix)
			}
			if cfg.AddPrefix != "" {
				path = joinPath(cfg.AddPrefix, path)
			}
			setPath(request.Out.URL, path)

			applyHeaders(request.Out.Header, cfg.RequestHeaders, action.removeRequest)
		},
		Transport: &retryingTransport{action: action},
		ModifyResponse: func(response *http.Response) error {
			if cfg.ResponseHeaders != nil {
				applyHeaders(response.Header, cfg.ResponseHeaders, action.removeResponse)
			}
			return nil
		},
		ErrorLog: slog.NewLogLogger(deps.Log.Handler(), slog.LevelError),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			action.handleError(w, r, err)
		},
	}
	return action, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if state := middleware.StateOf(r); state != nil {
		state.Upstream = p.pool.Name()
	}
	p.proxy.ServeHTTP(w, r)
}

func (p *Proxy) Describe() string {
	target := fmt.Sprintf("%s (%d targets, %s)", p.pool.Name(), len(p.pool.Targets()), p.pool.Policy())
	if len(p.pool.Targets()) == 1 {
		target = p.pool.Targets()[0].Name
	}
	description := "proxy to " + target
	if p.cfg.StripPrefix != "" {
		description += " strip_prefix=" + p.cfg.StripPrefix
	}
	if p.cfg.AddPrefix != "" {
		description += " add_prefix=" + p.cfg.AddPrefix
	}
	return description
}

func (p *Proxy) Close() error { return nil }

// Pool is the upstream this action forwards to.
func (p *Proxy) Pool() *upstream.Pool { return p.pool }

func (p *Proxy) handleError(w http.ResponseWriter, r *http.Request, err error) {
	state := middleware.StateOf(r)
	if errors.Is(err, context.Canceled) {
		// the client went away mid-request; there is nothing to report
		if state != nil {
			state.Err = "client_gone"
		}
		return
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		// the body hit the configured limit while it was being forwarded: that
		// is the client's doing, not the upstream's
		if state != nil {
			state.Err = "body_too_large"
		}
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	if state != nil {
		state.Err = "upstream_unavailable"
	}
	p.log.Error("upstream request failed",
		"id", middleware.IDOf(r), "upstream", p.pool.Name(), "host", r.Host, "path", r.URL.Path, "error", err)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

// retryingTransport is where target selection and retries happen. Doing it in
// the transport rather than around the ReverseProxy means the response is
// streamed straight through on the attempt that succeeds.
type retryingTransport struct {
	action *Proxy
}

func (t *retryingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	pool := t.action.pool
	state := middleware.StateOf(r)
	clientIP := middleware.ClientIP(r)

	var tried []*upstream.Target
	for attempt := 0; ; attempt++ {
		target := pool.Pick(clientIP, tried)
		if target == nil {
			return nil, errNoTarget
		}
		tried = append(tried, target)

		out := r.Clone(r.Context())
		out.URL.Scheme = target.URL.Scheme
		out.URL.Host = target.URL.Host
		if target.URL.Path != "" && target.URL.Path != "/" {
			setPath(out.URL, joinPath(target.URL.Path, r.URL.Path))
		}

		start := time.Now()
		pool.Begin(target)
		response, err := target.Transport.RoundTrip(out)
		elapsed := time.Since(start)
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		pool.End(target, status, err)
		if t.action.metrics != nil {
			t.action.metrics.UpstreamDuration.Observe(elapsed.Seconds(), pool.Name(), target.Name)
		}
		if state != nil {
			state.Target = target.Name
			state.UpstreamDuration += elapsed
			state.Retries = attempt
		}

		if !replayable(r) || !pool.ShouldRetry(attempt+1, status, err) {
			return response, err
		}
		t.action.log.Debug("retrying upstream request",
			"id", middleware.IDOf(r), "upstream", pool.Name(), "target", target.Name,
			"attempt", attempt+1, "status", status, "error", err)
		if response != nil {
			// the body of the attempt being abandoned has to be drained so the
			// connection can go back in the pool
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
			_ = response.Body.Close()
		}
	}
}

// replayable reports whether the request can be sent again. A body that has
// already been read cannot be, so only bodiless requests are retried; that
// covers the GET and HEAD traffic where retrying is worth anything.
func replayable(r *http.Request) bool {
	return r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0
}

func copyForwarded(dst, src http.Header) {
	for _, name := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		key := http.CanonicalHeaderKey(name)
		if values, ok := src[key]; ok {
			dst[key] = append([]string(nil), values...)
		}
	}
}

func compileRemovals(headers *config.Headers) ([]*regexp.Regexp, error) {
	if headers == nil {
		return nil, nil
	}
	compiled := make([]*regexp.Regexp, len(headers.Remove))
	for i, name := range headers.Remove {
		if !strings.HasPrefix(name, "^") {
			continue
		}
		expression, err := regexp.Compile(name)
		if err != nil {
			return nil, err
		}
		compiled[i] = expression
	}
	return compiled, nil
}

func applyHeaders(header http.Header, cfg *config.Headers, removals []*regexp.Regexp) {
	if cfg == nil {
		return
	}
	for i, name := range cfg.Remove {
		if expression := removals[i]; expression != nil {
			for existing := range header {
				if expression.MatchString(existing) {
					header.Del(existing)
				}
			}
			continue
		}
		header.Del(name)
	}
	for name, value := range cfg.Set {
		header.Set(name, value)
	}
}
