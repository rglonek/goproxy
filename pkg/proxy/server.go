// Package proxy is goproxy's public API: build a Server from a config, start
// it, wait for it, reload it, shut it down.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"goproxy/pkg/config"
	"goproxy/pkg/listen"
	"goproxy/pkg/middleware"
	"goproxy/pkg/observe"
	"goproxy/pkg/route"
)

// Server serves a compiled configuration. New compiles and binds nothing;
// Start binds; Wait reports why serving stopped.
type Server struct {
	cfg     atomic.Pointer[config.Config]
	routes  atomic.Pointer[route.Routes]
	log     *slog.Logger
	access  *observe.AccessLogger
	metrics *observe.Metrics
	trusted *middleware.TrustedProxies

	certificates *listen.Certificates
	acme         *autocert.Manager
	logLevel     *slog.LevelVar

	httpServer  *http.Server
	httpsServer *http.Server
	adminServer *http.Server
	httpLn      net.Listener
	httpsLn     net.Listener
	adminLn     net.Listener

	reloadMu sync.Mutex
	stop     chan struct{}

	started      atomic.Bool
	ready        atomic.Bool
	shutdownOnce sync.Once
	doneOnce     sync.Once
	stopOnce     sync.Once
	done         chan struct{}
	wg           sync.WaitGroup
	errMu        sync.Mutex
	err          error
}

// Option customises a Server.
type Option func(*options)

type options struct {
	logOutput io.Writer
	logger    *slog.Logger
	access    *observe.AccessLogger
}

// WithLogOutput sends the logs somewhere other than stderr.
func WithLogOutput(w io.Writer) Option {
	return func(o *options) { o.logOutput = w }
}

// WithLogger replaces the process logger.
func WithLogger(log *slog.Logger) Option {
	return func(o *options) { o.logger = log }
}

// New compiles a config into a server. It binds no listeners: everything that
// can be checked without taking a port - regexes, upstream URLs, static
// directories, response bodies, certificates, secrets - is checked here, so a
// config that cannot work fails before the process claims :80.
func New(cfg *config.Config, opts ...Option) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	settings := &options{logOutput: os.Stderr}
	for _, opt := range opts {
		opt(settings)
	}

	build := Version()
	server := &Server{
		log:     settings.logger,
		access:  settings.access,
		metrics: observe.NewMetrics(build.Version, build.Commit),
		done:    make(chan struct{}),
		stop:    make(chan struct{}),
	}
	if server.log == nil {
		server.log, server.logLevel = observe.NewLevelledLogger(cfg.Log, settings.logOutput)
	}
	if server.access == nil {
		server.access = observe.NewAccessLogger(cfg.Log, settings.logOutput)
	}

	var err error
	if server.trusted, err = middleware.NewTrustedProxies(cfg.TrustedProxies); err != nil {
		return nil, fmt.Errorf("trusted_proxies: %w", err)
	}
	if https := cfg.Listeners.HTTPS; https != nil {
		if https.TLS.ACME != nil {
			server.acme = listen.ACME(&https.TLS)
		} else {
			if server.certificates, err = listen.NewCertificates(https.TLS.Certs); err != nil {
				return nil, fmt.Errorf("listeners.https.tls: %w", err)
			}
		}
	}

	routes, err := route.Compile(cfg, route.Deps{Log: server.log, Metrics: server.metrics, Trusted: server.trusted})
	if err != nil {
		return nil, err
	}
	server.cfg.Store(cfg)
	server.routes.Store(routes)
	server.recordCertExpiry()
	for _, warning := range cfg.Unreachable() {
		server.log.Warn("unreachable rule", "detail", warning)
	}
	return server, nil
}

// Run compiles the config and starts serving. It is New followed by Start.
func Run(cfg *config.Config, opts ...Option) (*Server, error) {
	server, err := New(cfg, opts...)
	if err != nil {
		return nil, err
	}
	if err := server.Start(context.Background()); err != nil {
		return nil, err
	}
	return server, nil
}

// Config is the configuration currently being served.
func (s *Server) Config() *config.Config { return s.cfg.Load() }

// Routes is the compiled routing table currently being served.
func (s *Server) Routes() *route.Routes { return s.routes.Load() }

// Logger is the server's logger.
func (s *Server) Logger() *slog.Logger { return s.log }

// Metrics is the server's metric set.
func (s *Server) Metrics() *observe.Metrics { return s.metrics }

// handler is the per-server pipeline: everything that happens before, and
// regardless of, which rule matches.
func (s *Server) handler() http.Handler {
	routed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.routes.Load().ServeHTTP(w, r)
	})
	return middleware.Chain(routed,
		s.stateMiddleware(),
		middleware.Recover(s.log, s.metrics),
		middleware.RequestID(s.trusted),
		s.trusted.RealIP(func(msg string, args ...any) { s.log.Warn(msg, args...) }),
		middleware.AccessLog(s.access, s.metrics),
		middleware.InFlight(s.metrics),
	)
}

// stateMiddleware attaches the per-request state the rest of the pipeline
// fills in, and wraps the writer so that the status and size can be recorded.
func (s *Server) stateMiddleware() middleware.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			request, _ := middleware.NewState(r)
			next.ServeHTTP(middleware.NewRecorder(w), request)
		})
	}
}

// Start binds the listeners and begins serving. It returns an error if a
// listener cannot be bound; a listener that fails later is reported through
// Wait. Cancelling ctx starts a graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("server already started")
	}
	cfg := s.cfg.Load()
	s.log.Info("starting", "version", Version().Version, "rules", len(cfg.Rules))

	if s.acme != nil {
		// created here rather than during validation: checking a config must
		// not have side effects
		if err := os.MkdirAll(cfg.Listeners.HTTPS.TLS.ACME.CacheDir, 0o700); err != nil {
			return s.failedToStart(fmt.Errorf("listeners.https.tls.acme.cache_dir: %w", err))
		}
	}

	handler := s.handler()
	var listenConfig net.ListenConfig

	if cfg.Listeners.HTTP != nil {
		ln, err := listenConfig.Listen(ctx, "tcp", cfg.Listeners.HTTP.Addr)
		if err != nil {
			return s.failedToStart(err)
		}
		s.httpLn = ln
		s.httpServer = s.newHTTPServer(cfg, s.httpHandler(cfg, handler))
	}
	if cfg.Listeners.HTTPS != nil {
		ln, err := listenConfig.Listen(ctx, "tcp", cfg.Listeners.HTTPS.Addr)
		if err != nil {
			s.closeListeners()
			return s.failedToStart(err)
		}
		s.httpsLn = ln
		httpsHandler := handler
		if hsts := listen.HSTS(cfg.Listeners.HTTPS.TLS.HSTS); hsts != nil {
			httpsHandler = hsts(handler)
		}
		s.httpsServer = s.newHTTPServer(cfg, httpsHandler)
		tlsConfig, err := listen.TLSConfig(cfg.Listeners.HTTPS.TLS, s.certificates, s.acme, s.metrics)
		if err != nil {
			s.closeListeners()
			return s.failedToStart(fmt.Errorf("listeners.https.tls: %w", err))
		}
		s.httpsServer.TLSConfig = tlsConfig
	}
	if cfg.Admin != nil {
		ln, err := listenConfig.Listen(ctx, "tcp", cfg.Admin.Addr)
		if err != nil {
			s.closeListeners()
			return s.failedToStart(fmt.Errorf("admin: %w", err))
		}
		s.adminLn = ln
		s.adminServer = s.newHTTPServer(cfg, s.adminHandler(cfg.Admin))
	}

	s.routes.Load().Start(s.stop)

	if s.httpServer != nil {
		s.serve("http", s.httpServer, s.httpLn, false)
		s.log.Info("listening", "proto", "http", "addr", s.httpLn.Addr().String())
	}
	if s.httpsServer != nil {
		s.serve("https", s.httpsServer, s.httpsLn, true)
		s.log.Info("listening", "proto", "https", "addr", s.httpsLn.Addr().String())
	}
	if s.adminServer != nil {
		s.serve("admin", s.adminServer, s.adminLn, false)
		s.log.Info("listening", "proto", "admin", "addr", s.adminLn.Addr().String())
	}

	go func() {
		s.wg.Wait()
		s.cleanup()
		s.finish()
	}()

	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout())
				defer cancel()
				_ = s.Shutdown(shutdownCtx)
			case <-s.done:
			}
		}()
	}
	s.ready.Store(true)
	return nil
}

// httpHandler is what the plain http listener serves: the rules, or a redirect
// to https, with the ACME challenge handled in front of it.
func (s *Server) httpHandler(cfg *config.Config, routed http.Handler) http.Handler {
	handler := routed
	redirect := cfg.Listeners.HTTPS != nil
	if cfg.Listeners.HTTP.RedirectToHTTPS != nil {
		redirect = *cfg.Listeners.HTTP.RedirectToHTTPS
	}
	if redirect {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
		})
	}
	if s.acme != nil {
		// mounted explicitly rather than wrapping everything, so the
		// interaction with the redirect is visible
		return s.acme.HTTPHandler(handler)
	}
	return handler
}

func (s *Server) newHTTPServer(cfg *config.Config, handler http.Handler) *http.Server {
	timeouts := cfg.Defaults.Timeouts
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: timeouts.ReadHeader.Or(config.DefaultReadHeaderTimeout),
		ReadTimeout:       timeouts.Read.Or(config.DefaultReadTimeout),
		WriteTimeout:      timeouts.Write.Or(config.DefaultWriteTimeout),
		IdleTimeout:       timeouts.Idle.Or(config.DefaultIdleTimeout),
		MaxHeaderBytes:    int(cfg.Defaults.Limits.MaxHeaderBytes.Or(config.DefaultMaxHeaderBytes)),
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

func (s *Server) serve(name string, server *http.Server, ln net.Listener, useTLS bool) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var err error
		if useTLS {
			// the certificates are already loaded and served through
			// TLSConfig.GetCertificate
			err = server.ServeTLS(ln, "", "")
		} else {
			err = server.Serve(ln)
		}
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return
		}
		s.log.Error("listener stopped", "listener", name, "error", err)
		s.setErr(fmt.Errorf("%s listener: %w", name, err))
		if s.cfg.Load().OnListenerError == config.OnListenerErrorContinue {
			s.log.Warn("on_listener_error=continue: the remaining listeners keep serving")
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout())
			defer cancel()
			_ = s.Shutdown(ctx)
		}()
	}()
}

func (s *Server) shutdownTimeout() time.Duration {
	return s.cfg.Load().Defaults.Timeouts.Shutdown.Or(config.DefaultShutdownTimeout)
}

// Reload compiles a new config and swaps it in. The request path reads the
// table through a single atomic load, so there is no lock and no torn state; a
// request that started under the old table finishes under it. A config that
// does not compile is rejected and the old one keeps serving.
func (s *Server) Reload(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("config is required")
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	current := s.cfg.Load()
	if changed := listenerChanges(current, cfg); len(changed) > 0 {
		s.metrics.ConfigReloads.Inc("rejected")
		return fmt.Errorf("%s changed: a restart is required to apply that", changed[0])
	}

	if s.certificates != nil {
		if err := s.certificates.Reload(); err != nil {
			s.metrics.ConfigReloads.Inc("rejected")
			return fmt.Errorf("listeners.https.tls: %w", err)
		}
	}
	// trusted_proxies is server-level rather than part of the routing table, so
	// it is swapped here; without this a change to it would be accepted and
	// then quietly ignored
	if err := s.trusted.Set(cfg.TrustedProxies); err != nil {
		s.metrics.ConfigReloads.Inc("rejected")
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	routes, err := route.Compile(cfg, route.Deps{Log: s.log, Metrics: s.metrics, Trusted: s.trusted})
	if err != nil {
		s.metrics.ConfigReloads.Inc("rejected")
		return err
	}
	routes.Start(s.stop)
	if s.logLevel != nil && cfg.Log.Level != current.Log.Level {
		s.logLevel.Set(cfg.Log.Level.Slog())
	}
	for _, ignored := range staticSettings(current, cfg) {
		s.log.Warn("config change needs a restart to take effect", "setting", ignored)
	}

	old := s.routes.Swap(routes)
	s.cfg.Store(cfg)
	s.recordCertExpiry()
	s.metrics.ConfigReloads.Inc("applied")
	s.metrics.LastReloadTime.Set(float64(time.Now().Unix()))
	for _, warning := range cfg.Unreachable() {
		s.log.Warn("unreachable rule", "detail", warning)
	}
	s.log.Info("config reloaded", "rules", len(cfg.Rules))

	// the old table's resources are released once the requests that were using
	// it have drained
	go func() {
		time.Sleep(s.shutdownTimeout())
		old.Close()
	}()
	return nil
}

// ReloadFile re-reads the config from the file it was loaded from.
func (s *Server) ReloadFile() error {
	source := s.cfg.Load().Source
	if source == "" {
		return errors.New("this server was not loaded from a file")
	}
	cfg, err := config.ParseFile(source)
	if err != nil {
		s.metrics.ConfigReloads.Inc("rejected")
		return err
	}
	return s.Reload(cfg)
}

// listenerChanges reports config changes that cannot be applied by swapping
// the routing table, so that they are reported rather than silently ignored.
func listenerChanges(old, new *config.Config) []string {
	var changed []string
	if addrOf(old.Listeners.HTTP) != addrOf(new.Listeners.HTTP) {
		changed = append(changed, "listeners.http.addr")
	}
	if httpsAddr(old) != httpsAddr(new) {
		changed = append(changed, "listeners.https.addr")
	}
	if adminAddr(old) != adminAddr(new) {
		changed = append(changed, "admin.addr")
	}
	return changed
}

// staticSettings are the changes a reload applies to nothing, because they are
// baked into the logger or the listeners at startup. They are reported rather
// than left for the operator to discover.
func staticSettings(old, updated *config.Config) []string {
	var ignored []string
	if old.Log.Format != updated.Log.Format {
		ignored = append(ignored, "log.format")
	}
	if !slices.Equal(old.Log.Access.ExcludePaths, updated.Log.Access.ExcludePaths) ||
		!slices.Equal(old.Log.Access.RedactQueryParams, updated.Log.Access.RedactQueryParams) ||
		!equalBool(old.Log.Access.Enabled, updated.Log.Access.Enabled) {
		ignored = append(ignored, "log.access")
	}
	if old.Defaults.Timeouts != updated.Defaults.Timeouts {
		ignored = append(ignored, "defaults.timeouts")
	}
	if old.Defaults.Limits.MaxHeaderBytes.Or(0) != updated.Defaults.Limits.MaxHeaderBytes.Or(0) {
		ignored = append(ignored, "defaults.limits.max_header_bytes")
	}
	return ignored
}

func equalBool(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func addrOf(l *config.HTTPListener) string {
	if l == nil {
		return ""
	}
	return l.Addr
}

func httpsAddr(c *config.Config) string {
	if c.Listeners.HTTPS == nil {
		return ""
	}
	return c.Listeners.HTTPS.Addr
}

func adminAddr(c *config.Config) string {
	if c.Admin == nil {
		return ""
	}
	return c.Admin.Addr
}

func (s *Server) recordCertExpiry() {
	if s.certificates == nil {
		return
	}
	for subject, expiry := range s.certificates.Expiry() {
		s.metrics.CertExpiry.Set(float64(expiry.Unix()), subject)
	}
}

// failedToStart records a startup failure and releases anyone blocked in Wait.
func (s *Server) failedToStart(err error) error {
	s.setErr(err)
	s.cleanup()
	s.finish()
	return err
}

func (s *Server) setErr(err error) {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	s.err = errors.Join(s.err, err)
}

func (s *Server) getErr() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return s.err
}

func (s *Server) closeListeners() {
	for _, ln := range []net.Listener{s.httpLn, s.httpsLn, s.adminLn} {
		if ln != nil {
			_ = ln.Close()
		}
	}
}

func (s *Server) cleanup() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.routes.Load().Close()
}

func (s *Server) finish() {
	s.doneOnce.Do(func() { close(s.done) })
}

// HTTPAddr is the address the plain http listener is bound to, or "" if there
// is none. It is the resolved address, so it is useful when the config asked
// for port 0.
func (s *Server) HTTPAddr() string { return addrString(s.httpLn) }

// HTTPSAddr is the address the https listener is bound to, or "".
func (s *Server) HTTPSAddr() string { return addrString(s.httpsLn) }

// AdminAddr is the address the admin listener is bound to, or "".
func (s *Server) AdminAddr() string { return addrString(s.adminLn) }

func addrString(ln net.Listener) string {
	if ln == nil {
		return ""
	}
	return ln.Addr().String()
}

// Shutdown stops the server gracefully: it stops accepting, waits for in-flight
// requests until ctx expires, then force-closes what is left. It is safe to
// call more than once and from several goroutines - the second call is a no-op
// rather than a panic. It must not race with Start.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.shutdownOnce.Do(func() {
		s.ready.Store(false)
		s.log.Info("shutting down")
		err = s.shutdown(ctx)
		if err != nil {
			s.log.Error("shutdown finished with errors", "error", err)
		} else {
			s.log.Info("shutdown complete")
		}
		if !s.started.Load() {
			// nothing is serving, so nothing else will release Wait
			s.cleanup()
			s.finish()
		}
	})
	return err
}

func (s *Server) shutdown(ctx context.Context) error {
	var errs error
	for _, server := range []*http.Server{s.httpServer, s.httpsServer, s.adminServer} {
		if server == nil {
			continue
		}
		if err := server.Shutdown(ctx); err != nil {
			errs = errors.Join(errs, err)
			if err := server.Close(); err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}
	s.closeListeners()
	return errs
}

// Wait blocks until the server has stopped serving and returns the reason: nil
// after a requested shutdown, or the listener error that brought it down.
func (s *Server) Wait() error {
	<-s.done
	return s.getErr()
}
