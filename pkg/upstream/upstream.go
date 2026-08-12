// Package upstream turns a set of targets into something a proxy can forward
// to: a load-balancing policy, health checking and a retry budget.
package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"goproxy/pkg/config"
	"goproxy/pkg/observe"
)

// Deps are what a pool needs from the rest of the process.
type Deps struct {
	Log     *slog.Logger
	Metrics *observe.Metrics
	// Timeouts are the upstream timeouts from defaults.timeouts.
	Timeouts config.Timeouts
}

// Target is one address behind an upstream.
type Target struct {
	URL       *url.URL
	Weight    int
	Transport http.RoundTripper

	// Name is the target as it appears in logs and metrics.
	Name string

	inFlight atomic.Int64
	failures atomic.Int64
	// ejectedUntil is a unix nano deadline; zero means in service
	ejectedUntil atomic.Int64
	activeDown   atomic.Bool
}

// Healthy reports whether the target is currently in service.
func (t *Target) Healthy() bool {
	if t.activeDown.Load() {
		return false
	}
	until := t.ejectedUntil.Load()
	return until == 0 || time.Now().UnixNano() >= until
}

// InFlight is how many requests are being served by this target right now.
func (t *Target) InFlight() int64 { return t.inFlight.Load() }

// Pool is a named set of targets plus how to choose between them.
type Pool struct {
	name     string
	targets  []*Target
	weighted []*Target // targets repeated by weight, for round-robin and ip-hash
	policy   string

	passiveFailures int
	passiveCooldown time.Duration
	passiveEnabled  bool

	retryAttempts int
	retryOn       []string
	retryStatuses []int
	retryConnect  bool
	budget        *retryBudget

	active   *config.ActiveHealth
	deps     Deps
	counter  atomic.Uint64
	started  atomic.Bool
	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// New builds a pool from its config. Transports are built here, once, from a
// clone of the standard one, so that connection pooling, HTTP/2 and the dial
// and handshake timeouts survive a custom TLS policy.
func New(name string, cfg *config.Upstream, deps Deps) (*Pool, error) {
	if deps.Log == nil {
		deps.Log = slog.New(slog.DiscardHandler)
	}
	transport, err := newTransport(cfg.TLS, deps.Timeouts)
	if err != nil {
		return nil, err
	}
	pool := &Pool{
		name:            name,
		policy:          cfg.Policy,
		passiveEnabled:  true,
		passiveFailures: config.DefaultPassiveFailures,
		passiveCooldown: config.DefaultPassiveCooldown,
		deps:            deps,
		stop:            make(chan struct{}),
		done:            make(chan struct{}),
	}
	if pool.policy == "" {
		pool.policy = config.PolicyRoundRobin
	}
	for _, target := range cfg.Targets {
		parsed, err := url.Parse(target.URL)
		if err != nil {
			return nil, fmt.Errorf("targets: %q: %w", target.URL, err)
		}
		weight := target.Weight
		if weight == 0 {
			weight = 1
		}
		entry := &Target{URL: parsed, Weight: weight, Transport: transport, Name: parsed.String()}
		pool.targets = append(pool.targets, entry)
		// the weighted list is built once so that picking a target is an index
		// operation rather than a walk
		for i := 0; i < weight && i < 1000; i++ {
			pool.weighted = append(pool.weighted, entry)
		}
		if deps.Metrics != nil {
			deps.Metrics.UpstreamHealthy.Set(1, name, entry.Name)
		}
	}
	if cfg.Health != nil {
		if passive := cfg.Health.Passive; passive != nil {
			if passive.Enabled != nil {
				pool.passiveEnabled = *passive.Enabled
			}
			if passive.Failures > 0 {
				pool.passiveFailures = passive.Failures
			}
			pool.passiveCooldown = passive.Cooldown.Or(config.DefaultPassiveCooldown)
		}
		pool.active = cfg.Health.Active
	}
	if cfg.Retry != nil {
		pool.retryAttempts = cfg.Retry.Attempts
		pool.retryOn = cfg.Retry.On
		for _, on := range cfg.Retry.On {
			if on == "connect_error" {
				pool.retryConnect = true
				continue
			}
			if status, err := strconv.Atoi(on); err == nil {
				pool.retryStatuses = append(pool.retryStatuses, status)
			}
		}
		if len(cfg.Retry.On) == 0 {
			// retrying a connection that was never established is always safe
			pool.retryConnect = true
		}
		pool.budget = newRetryBudget(cfg.Retry.Budget.Or(config.DefaultRetryBudget))
	}
	return pool, nil
}

// NewSingle builds a one-target pool, which is what a rule with an inline
// proxy.url gets.
func NewSingle(name, rawURL string, deps Deps) (*Pool, error) {
	return New(name, &config.Upstream{Targets: []config.Target{{URL: rawURL}}}, deps)
}

func newTransport(cfg *config.UpstreamTLS, timeouts config.Timeouts) (http.RoundTripper, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   timeouts.UpstreamDial.Or(config.DefaultUpstreamDialTimeout),
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = timeouts.UpstreamTLSHandshake.Or(config.DefaultUpstreamTLSHandshakeTimeout)
	transport.ResponseHeaderTimeout = timeouts.UpstreamResponseHeader.Or(config.DefaultUpstreamResponseTimeout)
	if cfg == nil {
		return transport, nil
	}
	tlsConfig := transport.TLSClientConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tlsConfig.InsecureSkipVerify = cfg.InsecureSkipVerify
	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("tls.ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls.ca_file: %s contains no certificates", cfg.CAFile)
		}
		// pinning: the upstream is trusted through this CA and no other
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}

// Name is the upstream's name, as it appears in logs and metrics.
func (p *Pool) Name() string { return p.name }

// Targets are every target in the pool, in config order.
func (p *Pool) Targets() []*Target { return p.targets }

// Policy is the load-balancing policy in use.
func (p *Pool) Policy() string { return p.policy }

// Pick chooses a target for a request, skipping any that have already been
// tried and any that are out of service. When every target is out of service it
// falls back to trying them anyway: a total outage is worse than a request to a
// host that might have recovered.
func (p *Pool) Pick(clientIP string, tried []*Target) *Target {
	candidates := make([]*Target, 0, len(p.weighted))
	for _, target := range p.weighted {
		if slices.Contains(tried, target) || !target.Healthy() {
			continue
		}
		candidates = append(candidates, target)
	}
	if len(candidates) == 0 {
		for _, target := range p.weighted {
			if !slices.Contains(tried, target) {
				candidates = append(candidates, target)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	switch p.policy {
	case config.PolicyFirstHealthy:
		return candidates[0]
	case config.PolicyLeastConn:
		best := candidates[0]
		for _, target := range candidates[1:] {
			if target.InFlight() < best.InFlight() {
				best = target
			}
		}
		return best
	case config.PolicyIPHash:
		hash := fnv.New32a()
		_, _ = hash.Write([]byte(clientIP))
		return candidates[int(hash.Sum32()%uint32(len(candidates)))]
	default: // round robin
		next := p.counter.Add(1) - 1
		return candidates[int(next%uint64(len(candidates)))]
	}
}

// Begin records that a request is being sent to a target.
func (p *Pool) Begin(target *Target) {
	target.inFlight.Add(1)
	if p.budget != nil {
		p.budget.request()
	}
}

// End records the outcome of a request and applies passive health checking:
// after enough consecutive failures a target is ejected, and re-probed once the
// cool-off has passed.
func (p *Pool) End(target *Target, status int, err error) {
	target.inFlight.Add(-1)
	if p.deps.Metrics != nil {
		label := "error"
		if err == nil {
			label = strconv.Itoa(status)
		}
		p.deps.Metrics.UpstreamRequests.Inc(p.name, target.Name, label)
	}
	failed := err != nil || status >= 500
	if !p.passiveEnabled {
		return
	}
	if !failed {
		if target.failures.Swap(0) > 0 && p.deps.Metrics != nil {
			p.deps.Metrics.UpstreamHealthy.Set(1, p.name, target.Name)
		}
		target.ejectedUntil.Store(0)
		return
	}
	failures := target.failures.Add(1)
	if int(failures) < p.passiveFailures {
		return
	}
	if target.ejectedUntil.Swap(time.Now().Add(p.passiveCooldown).UnixNano()) == 0 {
		p.deps.Log.Warn("upstream target ejected",
			"upstream", p.name, "target", target.Name,
			"failures", failures, "cooldown", p.passiveCooldown.String())
		if p.deps.Metrics != nil {
			p.deps.Metrics.UpstreamHealthy.Set(0, p.name, target.Name)
		}
	}
}

// ShouldRetry reports whether a failed attempt may be tried against another
// target. Retries are bounded twice: by attempts, and by a budget that caps
// them as a share of live traffic, so a failing upstream cannot be turned into
// a traffic multiplier.
func (p *Pool) ShouldRetry(attempt int, status int, err error) bool {
	if p.retryAttempts <= 0 || attempt > p.retryAttempts {
		return false
	}
	if len(p.targets) == 1 && err == nil {
		// a response the upstream actually produced will be produced again
		return false
	}
	retryable := false
	if err != nil {
		retryable = p.retryConnect
	} else {
		retryable = slices.Contains(p.retryStatuses, status)
	}
	if !retryable {
		return false
	}
	if p.budget != nil && !p.budget.allow() {
		p.deps.Log.Debug("retry refused by budget", "upstream", p.name)
		return false
	}
	if p.deps.Metrics != nil {
		p.deps.Metrics.UpstreamRetries.Inc(p.name)
	}
	return true
}

// Start begins active health checking, if the upstream asked for it.
func (p *Pool) Start(ctx context.Context) {
	p.started.Store(true)
	if p.active == nil {
		close(p.done)
		return
	}
	interval := p.active.Interval.Or(config.DefaultHealthInterval)
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		p.probeAll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.stop:
				return
			case <-ticker.C:
				p.probeAll(ctx)
			}
		}
	}()
}

// Stop ends active health checking and releases idle connections.
func (p *Pool) Stop() {
	p.stopOnce.Do(func() { close(p.stop) })
	if p.started.Load() {
		// only a pool that was started has a goroutine to wait for; closing a
		// table that never served must not block
		<-p.done
	}
	for _, target := range p.targets {
		if closer, ok := target.Transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

func (p *Pool) probeAll(ctx context.Context) {
	timeout := p.active.Timeout.Or(config.DefaultHealthTimeout)
	for _, target := range p.targets {
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		healthy := p.probe(probeCtx, target)
		cancel()
		if was := target.activeDown.Swap(!healthy); was == healthy {
			// state changed
			if healthy {
				p.deps.Log.Info("upstream target back in service", "upstream", p.name, "target", target.Name)
				target.failures.Store(0)
				target.ejectedUntil.Store(0)
			} else {
				p.deps.Log.Warn("upstream target failed its health check", "upstream", p.name, "target", target.Name)
			}
			if p.deps.Metrics != nil {
				value := 0.0
				if healthy {
					value = 1
				}
				p.deps.Metrics.UpstreamHealthy.Set(value, p.name, target.Name)
			}
		}
	}
}

func (p *Pool) probe(ctx context.Context, target *Target) bool {
	probeURL := *target.URL
	probeURL.Path = p.active.Path
	probeURL.RawQuery = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), nil)
	if err != nil {
		return false
	}
	response, err := (&http.Client{Transport: target.Transport}).Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	_ = response.Body.Close()
	expected := p.active.ExpectStatus
	if len(expected) == 0 {
		return response.StatusCode >= 200 && response.StatusCode < 400
	}
	return slices.Contains(expected, response.StatusCode)
}

// retryBudget caps retries as a share of live traffic over a sliding window.
type retryBudget struct {
	ratio float64

	mu       sync.Mutex
	window   time.Time
	requests float64
	retries  float64
}

const retryBudgetWindow = 10 * time.Second

func newRetryBudget(ratio float64) *retryBudget {
	if ratio <= 0 {
		ratio = config.DefaultRetryBudget
	}
	return &retryBudget{ratio: ratio, window: time.Now()}
}

func (b *retryBudget) request() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	b.requests++
}

func (b *retryBudget) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.roll()
	// always allow a small absolute number, so a quiet proxy can still retry
	if b.retries+1 <= math.Max(3, b.requests*b.ratio) {
		b.retries++
		return true
	}
	return false
}

// roll decays the window rather than resetting it, so the budget does not jump
// at a window boundary.
func (b *retryBudget) roll() {
	elapsed := time.Since(b.window)
	if elapsed < retryBudgetWindow {
		return
	}
	periods := float64(elapsed / retryBudgetWindow)
	decay := math.Pow(0.5, periods)
	b.requests *= decay
	b.retries *= decay
	b.window = time.Now()
}

// IsConnectError reports whether an error means the request never reached the
// upstream, which is the case that is always safe to retry.
func IsConnectError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	return errors.Is(err, os.ErrDeadlineExceeded)
}
