package upstream

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"goproxy/pkg/config"
)

func newPool(t *testing.T, cfg *config.Upstream) *Pool {
	t.Helper()
	pool, err := New("app", cfg, Deps{})
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	t.Cleanup(pool.Stop)
	return pool
}

func targets(urls ...string) []config.Target {
	list := make([]config.Target, 0, len(urls))
	for _, url := range urls {
		list = append(list, config.Target{URL: url})
	}
	return list
}

func TestRoundRobinSpreadsRequests(t *testing.T) {
	pool := newPool(t, &config.Upstream{Targets: targets("http://a:1", "http://b:1", "http://c:1")})
	seen := map[string]int{}
	for range 9 {
		seen[pool.Pick("1.2.3.4", nil).Name]++
	}
	for name, count := range seen {
		if count != 3 {
			t.Errorf("%s got %d of 9 requests, want an even split (%v)", name, count, seen)
		}
	}
}

func TestWeightedRoundRobin(t *testing.T) {
	pool := newPool(t, &config.Upstream{Targets: []config.Target{
		{URL: "http://heavy:1", Weight: 3},
		{URL: "http://light:1", Weight: 1},
	}})
	seen := map[string]int{}
	for range 8 {
		seen[pool.Pick("1.2.3.4", nil).Name]++
	}
	if seen["http://heavy:1"] != 6 || seen["http://light:1"] != 2 {
		t.Errorf("spread = %v, want 3:1", seen)
	}
}

func TestIPHashIsStable(t *testing.T) {
	pool := newPool(t, &config.Upstream{
		Targets: targets("http://a:1", "http://b:1", "http://c:1"),
		Policy:  config.PolicyIPHash,
	})
	first := pool.Pick("1.2.3.4", nil).Name
	for range 5 {
		if got := pool.Pick("1.2.3.4", nil).Name; got != first {
			t.Fatalf("ip_hash sent the same client to %s and %s", first, got)
		}
	}
	// and it does not send everybody to the same place
	different := false
	for _, ip := range []string{"9.9.9.9", "8.8.8.8", "7.7.7.7", "6.6.6.6"} {
		if pool.Pick(ip, nil).Name != first {
			different = true
		}
	}
	if !different {
		t.Error("ip_hash sent every client to the same target")
	}
}

func TestLeastConnPrefersTheIdleTarget(t *testing.T) {
	pool := newPool(t, &config.Upstream{
		Targets: targets("http://busy:1", "http://idle:1"),
		Policy:  config.PolicyLeastConn,
	})
	busy := pool.Targets()[0]
	pool.Begin(busy)
	defer pool.End(busy, 200, nil)
	if got := pool.Pick("1.2.3.4", nil).Name; got != "http://idle:1" {
		t.Errorf("picked %s, want the idle target", got)
	}
}

func TestPassiveHealthEjectsAndRecovers(t *testing.T) {
	pool := newPool(t, &config.Upstream{
		Targets: targets("http://a:1", "http://b:1"),
		Health: &config.Health{Passive: &config.PassiveHealth{
			Failures: 2,
			Cooldown: durationOf(50 * time.Millisecond),
		}},
	})
	bad := pool.Targets()[0]

	pool.End(bad, 0, errors.New("connection refused"))
	if !bad.Healthy() {
		t.Fatal("one failure ejected the target, want it to take two")
	}
	pool.End(bad, 0, errors.New("connection refused"))
	if bad.Healthy() {
		t.Fatal("the target was not ejected after two failures")
	}

	// while it is ejected, Pick never returns it
	for range 5 {
		if pool.Pick("1.2.3.4", nil) == bad {
			t.Fatal("an ejected target was picked")
		}
	}

	time.Sleep(80 * time.Millisecond)
	if !bad.Healthy() {
		t.Fatal("the target was not re-probed after the cooldown")
	}
	// a success clears the failure count
	pool.End(bad, 200, nil)
	pool.End(bad, 0, errors.New("connection refused"))
	if !bad.Healthy() {
		t.Fatal("the failure count was not reset by a success")
	}
}

func TestPickFallsBackWhenEverythingIsEjected(t *testing.T) {
	pool := newPool(t, &config.Upstream{
		Targets: targets("http://a:1", "http://b:1"),
		Health:  &config.Health{Passive: &config.PassiveHealth{Failures: 1, Cooldown: durationOf(time.Minute)}},
	})
	for _, target := range pool.Targets() {
		pool.End(target, 0, errors.New("down"))
	}
	// a total outage is worse than a request to a host that might have
	// recovered
	if pool.Pick("1.2.3.4", nil) == nil {
		t.Fatal("Pick returned nothing when every target was ejected")
	}
}

func TestShouldRetry(t *testing.T) {
	pool := newPool(t, &config.Upstream{
		Targets: targets("http://a:1", "http://b:1"),
		Retry:   &config.Retry{Attempts: 2, On: []string{"connect_error", "503"}},
	})
	connectError := errors.New("connection refused")

	if !pool.ShouldRetry(1, 0, connectError) {
		t.Error("a connection error within the attempt budget was not retried")
	}
	if !pool.ShouldRetry(1, http.StatusServiceUnavailable, nil) {
		t.Error("a listed status was not retried")
	}
	if pool.ShouldRetry(1, http.StatusInternalServerError, nil) {
		t.Error("an unlisted status was retried")
	}
	if pool.ShouldRetry(3, 0, connectError) {
		t.Error("retrying continued past attempts")
	}
}

func TestRetryBudgetStopsAmplification(t *testing.T) {
	budget := newRetryBudget(0.1)
	// the first few are always allowed, so that a quiet proxy can still retry
	allowed := 0
	for range 5 {
		if budget.allow() {
			allowed++
		}
	}
	if allowed == 0 {
		t.Fatal("the budget refused every retry on an idle proxy")
	}
	if allowed == 5 {
		t.Fatal("the budget allowed unlimited retries with no traffic")
	}

	for range 1000 {
		budget.request()
	}
	allowed = 0
	for range 1000 {
		if budget.allow() {
			allowed++
		}
	}
	if allowed > 110 {
		t.Errorf("allowed %d retries against 1000 requests, want about 10%%", allowed)
	}
}

func TestSingleTargetIsNotRetriedOnAStatus(t *testing.T) {
	pool := newPool(t, &config.Upstream{
		Targets: targets("http://only:1"),
		Retry:   &config.Retry{Attempts: 3, On: []string{"503"}},
	})
	// a response the upstream actually produced will be produced again
	if pool.ShouldRetry(1, http.StatusServiceUnavailable, nil) {
		t.Error("a single-target upstream retried a real response")
	}
}

func TestTransportKeepsItsTuning(t *testing.T) {
	pool := newPool(t, &config.Upstream{
		Targets: targets("https://a:1"),
		TLS:     &config.UpstreamTLS{InsecureSkipVerify: true},
	})
	transport, ok := pool.Targets()[0].Transport.(*http.Transport)
	if !ok {
		t.Fatal("the transport is not an *http.Transport")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("insecure_skip_verify was not applied")
	}
	// building from a clone of the standard transport is what keeps the
	// connection pool and the timeouts
	if transport.MaxIdleConns == 0 || transport.TLSHandshakeTimeout == 0 || transport.ResponseHeaderTimeout == 0 {
		t.Error("the transport lost the standard tuning")
	}
}

func TestCAPinningRejectsAnUnknownCA(t *testing.T) {
	_, err := New("app", &config.Upstream{
		Targets: targets("https://a:1"),
		TLS:     &config.UpstreamTLS{CAFile: "testdata/not-a-ca.pem"},
	}, Deps{})
	if err == nil {
		t.Fatal("a missing CA file was accepted")
	}
}

func durationOf(d time.Duration) *config.Duration {
	value := config.Duration(d)
	return &value
}
