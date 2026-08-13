package proxy

import (
	"fmt"
	"net/http"
	"net/http/pprof"

	"gopkg.in/yaml.v3"

	"goproxy/pkg/config"
)

// adminHandler serves the admin listener. It is a separate listener and is
// never reachable through the routing table: on the main listener a health
// endpoint would either collide with a catch-all rule or have to be
// special-cased ahead of the rules.
func (s *Server) adminHandler(cfg *config.Admin) http.Handler {
	mux := http.NewServeMux()

	// Liveness: the process is running and able to answer.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writePlain(w, http.StatusOK, "ok\n")
	})

	// Readiness: 503 while starting or shutting down, so a load balancer takes
	// this instance out before it stops answering.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !s.ready.Load() {
			writePlain(w, http.StatusServiceUnavailable, "not ready\n")
			return
		}
		if unhealthy := s.unhealthyUpstreams(); len(unhealthy) > 0 {
			writePlain(w, http.StatusServiceUnavailable, fmt.Sprintf("no healthy target for upstream %s\n", unhealthy[0]))
			return
		}
		writePlain(w, http.StatusOK, "ok\n")
	})

	if cfg.Metrics == nil || *cfg.Metrics {
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			_, _ = s.metrics.Registry().WriteTo(w)
		})
	}

	// The resolved config, with secrets redacted.
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, r *http.Request) {
		encoded, err := yaml.Marshal(config.Redacted(s.cfg.Load()))
		if err != nil {
			writePlain(w, http.StatusInternalServerError, err.Error()+"\n")
			return
		}
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		_, _ = w.Write(encoded)
	})

	if cfg.Reload == nil || *cfg.Reload {
		// Same as SIGHUP, but with the validation error in the response rather
		// than only in the log.
		mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
			if err := s.ReloadFile(); err != nil {
				s.log.Error("config reload rejected", "error", err)
				writePlain(w, http.StatusBadRequest, err.Error()+"\n")
				return
			}
			writePlain(w, http.StatusOK, "reloaded\n")
		})
	}

	if cfg.Pprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	return mux
}

// unhealthyUpstreams names the upstreams that have no target left in service.
func (s *Server) unhealthyUpstreams() []string {
	var unhealthy []string
	for name, pool := range s.routes.Load().Pools() {
		targets := pool.Targets()
		if len(targets) == 0 {
			continue
		}
		healthy := false
		for _, target := range targets {
			if target.Healthy() {
				healthy = true
				break
			}
		}
		if !healthy {
			unhealthy = append(unhealthy, name)
		}
	}
	return unhealthy
}

func writePlain(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
