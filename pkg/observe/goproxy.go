package observe

import "runtime"

// Metrics is the set of metrics goproxy exports. Cardinality is bounded by
// construction: every label is a rule name, an upstream name, a target URL or a
// status code, all fixed by the config. There are deliberately no path, host or
// client-IP labels - that is how a proxy usually blows up a Prometheus server.
type Metrics struct {
	registry *Registry

	BuildInfo *Gauge

	Requests        *Counter
	RequestDuration *Histogram
	RequestSize     *Histogram
	ResponseSize    *Histogram
	InFlight        *Gauge

	UpstreamRequests *Counter
	UpstreamDuration *Histogram
	UpstreamHealthy  *Gauge
	UpstreamRetries  *Counter

	AuthFailures     *Counter
	RateLimitDropped *Counter
	IPFilterDropped  *Counter

	TLSHandshakes  *Counter
	CertExpiry     *Gauge
	ConfigReloads  *Counter
	LastReloadTime *Gauge
	Panics         *Counter
}

// NewMetrics registers the metric set on a new registry.
func NewMetrics(version, commit string) *Metrics {
	r := NewRegistry()
	m := &Metrics{
		registry:         r,
		BuildInfo:        r.Gauge("goproxy_build_info", "Version of the running binary.", "version", "commit", "go_version"),
		Requests:         r.Counter("goproxy_requests_total", "Requests handled, by rule and outcome.", "rule", "action", "method", "status"),
		RequestDuration:  r.Histogram("goproxy_request_duration_seconds", "Time to serve a request.", DefaultBuckets, "rule", "action"),
		RequestSize:      r.Histogram("goproxy_request_size_bytes", "Request body size.", SizeBuckets, "rule"),
		ResponseSize:     r.Histogram("goproxy_response_size_bytes", "Response body size.", SizeBuckets, "rule"),
		InFlight:         r.Gauge("goproxy_in_flight_requests", "Requests currently being served."),
		UpstreamRequests: r.Counter("goproxy_upstream_requests_total", "Requests forwarded to an upstream target.", "upstream", "target", "status"),
		UpstreamDuration: r.Histogram("goproxy_upstream_duration_seconds", "Time an upstream took to answer.", DefaultBuckets, "upstream", "target"),
		UpstreamHealthy:  r.Gauge("goproxy_upstream_healthy", "1 when a target is in service, 0 when it has been ejected.", "upstream", "target"),
		UpstreamRetries:  r.Counter("goproxy_upstream_retries_total", "Requests retried against another target.", "upstream"),
		AuthFailures:     r.Counter("goproxy_auth_failures_total", "Rejected credentials, by rule and method.", "rule", "method"),
		RateLimitDropped: r.Counter("goproxy_ratelimit_dropped_total", "Requests refused by a rate limit.", "rule"),
		IPFilterDropped:  r.Counter("goproxy_ipfilter_dropped_total", "Requests refused by an IP allow or deny list.", "rule"),
		TLSHandshakes:    r.Counter("goproxy_tls_handshakes_total", "TLS handshakes, by version and outcome.", "version", "result"),
		CertExpiry:       r.Gauge("goproxy_tls_cert_expiry_seconds", "Unix time at which a certificate expires.", "subject"),
		ConfigReloads:    r.Counter("goproxy_config_reload_total", "Config reloads, by outcome.", "result"),
		LastReloadTime:   r.Gauge("goproxy_config_last_reload_timestamp_seconds", "Unix time of the last successful config load."),
		Panics:           r.Counter("goproxy_panics_total", "Handler panics recovered."),
	}
	m.BuildInfo.Set(1, version, commit, runtime.Version())
	return m
}

// Registry is where the metrics live, for the admin listener to render.
func (m *Metrics) Registry() *Registry {
	if m == nil {
		return NewRegistry()
	}
	return m.registry
}
