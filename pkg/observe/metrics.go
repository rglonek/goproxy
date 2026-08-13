// Package observe is goproxy's logging and metrics: a structured logger, an
// access log with a stable field schema, and a small Prometheus-format metrics
// registry.
package observe

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Registry holds metric families and renders them in the Prometheus text
// exposition format. It is deliberately small: goproxy is one process in front
// of a handful of services, not a fleet, and a dependency-free registry keeps
// the binary self-contained.
type Registry struct {
	mu       sync.RWMutex
	families map[string]*family
	order    []string
}

type metricType string

const (
	typeCounter   metricType = "counter"
	typeGauge     metricType = "gauge"
	typeHistogram metricType = "histogram"
)

type family struct {
	name    string
	help    string
	typ     metricType
	labels  []string
	buckets []float64

	mu     sync.Mutex
	series map[string]*seriesValue
}

type seriesValue struct {
	labelValues []string
	value       float64
	count       uint64
	sum         float64
	bucketHits  []uint64
}

func NewRegistry() *Registry {
	return &Registry{families: map[string]*family{}}
}

func (r *Registry) register(name, help string, typ metricType, labels []string, buckets []float64) *family {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.families[name]; ok {
		return existing
	}
	f := &family{
		name:    name,
		help:    help,
		typ:     typ,
		labels:  labels,
		buckets: buckets,
		series:  map[string]*seriesValue{},
	}
	if len(labels) == 0 {
		// a metric with no labels is created at zero, so that an alert on it
		// does not wait for the first event to have a series to match
		f.get(nil)
	}
	r.families[name] = f
	r.order = append(r.order, name)
	return f
}

// Counter is a monotonically increasing metric.
type Counter struct{ f *family }

// Gauge is a metric that goes up and down.
type Gauge struct{ f *family }

// Histogram counts observations into buckets.
type Histogram struct{ f *family }

func (r *Registry) Counter(name, help string, labels ...string) *Counter {
	return &Counter{f: r.register(name, help, typeCounter, labels, nil)}
}

func (r *Registry) Gauge(name, help string, labels ...string) *Gauge {
	return &Gauge{f: r.register(name, help, typeGauge, labels, nil)}
}

func (r *Registry) Histogram(name, help string, buckets []float64, labels ...string) *Histogram {
	return &Histogram{f: r.register(name, help, typeHistogram, labels, buckets)}
}

// DefaultBuckets are latency buckets in seconds, from a fast local backend to a
// request that should have given up.
var DefaultBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// SizeBuckets are payload size buckets in bytes.
var SizeBuckets = []float64{128, 1024, 8192, 65536, 524288, 4 << 20, 32 << 20}

func (f *family) get(labelValues []string) *seriesValue {
	key := strings.Join(labelValues, "\x00")
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.series[key]
	if !ok {
		value = &seriesValue{labelValues: append([]string(nil), labelValues...)}
		if f.typ == typeHistogram {
			value.bucketHits = make([]uint64, len(f.buckets))
		}
		f.series[key] = value
	}
	return value
}

func (c *Counter) Add(delta float64, labelValues ...string) {
	if c == nil {
		return
	}
	value := c.f.get(labelValues)
	c.f.mu.Lock()
	value.value += delta
	c.f.mu.Unlock()
}

func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

func (g *Gauge) Set(v float64, labelValues ...string) {
	if g == nil {
		return
	}
	value := g.f.get(labelValues)
	g.f.mu.Lock()
	value.value = v
	g.f.mu.Unlock()
}

func (g *Gauge) Add(delta float64, labelValues ...string) {
	if g == nil {
		return
	}
	value := g.f.get(labelValues)
	g.f.mu.Lock()
	value.value += delta
	g.f.mu.Unlock()
}

func (h *Histogram) Observe(v float64, labelValues ...string) {
	if h == nil {
		return
	}
	value := h.f.get(labelValues)
	h.f.mu.Lock()
	value.count++
	value.sum += v
	for i, bound := range h.f.buckets {
		if v <= bound {
			value.bucketHits[i]++
		}
	}
	h.f.mu.Unlock()
}

// WriteTo renders every metric in the Prometheus text exposition format.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.RLock()
	names := append([]string(nil), r.order...)
	families := make([]*family, 0, len(names))
	for _, name := range names {
		families = append(families, r.families[name])
	}
	r.mu.RUnlock()
	sort.Slice(families, func(i, j int) bool { return families[i].name < families[j].name })

	var out strings.Builder
	for _, f := range families {
		f.mu.Lock()
		series := make([]*seriesValue, 0, len(f.series))
		for _, value := range f.series {
			copied := *value
			copied.bucketHits = append([]uint64(nil), value.bucketHits...)
			series = append(series, &copied)
		}
		f.mu.Unlock()
		if len(series) == 0 {
			continue
		}
		sort.Slice(series, func(i, j int) bool {
			return strings.Join(series[i].labelValues, "\x00") < strings.Join(series[j].labelValues, "\x00")
		})

		fmt.Fprintf(&out, "# HELP %s %s\n", f.name, f.help)
		fmt.Fprintf(&out, "# TYPE %s %s\n", f.name, f.typ)
		for _, value := range series {
			switch f.typ {
			case typeHistogram:
				cumulative := uint64(0)
				for i, bound := range f.buckets {
					cumulative = value.bucketHits[i]
					fmt.Fprintf(&out, "%s_bucket%s %d\n", f.name, labelString(f.labels, value.labelValues, "le", formatFloat(bound)), cumulative)
				}
				fmt.Fprintf(&out, "%s_bucket%s %d\n", f.name, labelString(f.labels, value.labelValues, "le", "+Inf"), value.count)
				fmt.Fprintf(&out, "%s_sum%s %s\n", f.name, labelString(f.labels, value.labelValues), formatFloat(value.sum))
				fmt.Fprintf(&out, "%s_count%s %d\n", f.name, labelString(f.labels, value.labelValues), value.count)
			default:
				fmt.Fprintf(&out, "%s%s %s\n", f.name, labelString(f.labels, value.labelValues), formatFloat(value.value))
			}
		}
	}
	n, err := io.WriteString(w, out.String())
	return int64(n), err
}

func labelString(names, values []string, extra ...string) string {
	if len(names) == 0 && len(extra) == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteString("{")
	first := true
	for i, name := range names {
		value := ""
		if i < len(values) {
			value = values[i]
		}
		if !first {
			out.WriteString(",")
		}
		first = false
		fmt.Fprintf(&out, "%s=%q", name, escapeLabel(value))
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if !first {
			out.WriteString(",")
		}
		first = false
		fmt.Fprintf(&out, "%s=%q", extra[i], escapeLabel(extra[i+1]))
	}
	out.WriteString("}")
	return out.String()
}

func escapeLabel(value string) string {
	return strings.NewReplacer("\n", " ", `"`, `'`, `\`, "/").Replace(value)
}

func formatFloat(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e15 {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}
