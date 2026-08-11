package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rglonek/logger"
	"golang.org/x/crypto/acme/autocert"
)

// Server serves a compiled configuration. Build one with New, which binds
// nothing and reports every problem the config has, then Start it.
type Server struct {
	config  *Config
	log     *logger.Logger
	handler http.Handler

	httpServer  *http.Server
	httpsServer *http.Server
	httpLn      net.Listener
	httpsLn     net.Listener

	certManager       *autocert.Manager
	certificate       atomic.Pointer[tls.Certificate]
	defaultTransport  *http.Transport
	insecureTransport *http.Transport

	started      atomic.Bool
	shutdownOnce sync.Once
	doneOnce     sync.Once
	done         chan struct{}
	wg           sync.WaitGroup
	errMu        sync.Mutex
	err          error
	warnDropOnce sync.Once
}

// Option customises a Server.
type Option func(*Server)

// WithLogger replaces the logger the server builds from the config. The log
// level of the supplied logger is left alone.
func WithLogger(l *logger.Logger) Option {
	return func(s *Server) { s.log = l }
}

// New compiles a config into a server. It binds no listeners: everything that
// can be checked without taking a port - regexes, upstream URLs, static
// directories, response bodies, certificates - is checked here, so a config
// that cannot work fails before the process claims :80.
func New(config *Config, options ...Option) (*Server, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}
	if err := config.Compile(); err != nil {
		return nil, err
	}
	s := &Server{
		config: config,
		done:   make(chan struct{}),
	}
	for _, option := range options {
		option(s)
	}
	if s.log == nil {
		s.log = logger.NewLogger()
		s.log.SetLogLevel(logger.LogLevel(config.LogLevel))
		s.log.MillisecondLogging(true)
	}
	for _, warning := range config.Warnings() {
		s.log.Warn("%s", warning)
	}

	s.defaultTransport = s.newTransport(false)
	s.insecureTransport = s.newTransport(true)

	if config.TLS != nil && config.TLS.LetsEncrypt != nil {
		s.certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(config.TLS.LetsEncrypt.Domains...),
			Cache:      autocert.DirCache(config.TLS.LetsEncrypt.CacheDir),
			Email:      config.TLS.LetsEncrypt.Email,
		}
	}
	if config.TLS != nil && config.TLS.Certs != nil {
		// v0.1.0 handed the file names to ServeTLS in a goroutine whose error
		// was discarded, so a broken certificate left a listening socket that
		// failed every handshake. Loading here turns that into a startup error.
		if err := s.ReloadCertificates(); err != nil {
			return nil, err
		}
	}
	if err := s.prepareRules(); err != nil {
		s.closeRules()
		return nil, err
	}
	s.handler = s.buildPipeline()
	return s, nil
}

// Run compiles the config and starts serving. It is New followed by Start.
func Run(config *Config) (*Server, error) {
	s, err := New(config)
	if err != nil {
		return nil, err
	}
	if err := s.Start(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

// prepareRules builds the runtime state of every rule: reverse proxies, static
// file roots and canned response bodies.
func (s *Server) prepareRules() error {
	for i, rule := range s.config.Rules {
		switch {
		case rule.ProxyRule != nil:
			rule.ProxyRule.proxy = s.newReverseProxy(rule)
		case rule.ServeRule != nil:
			handler, err := newServeHandler(rule.ServeRule, s.log)
			if err != nil {
				return fmt.Errorf("rules[%d]: %w", i, err)
			}
			rule.serveHandler = handler
		case rule.RespondRule != nil:
			if rule.RespondRule.RespondBodyFile != "" && !rule.RespondRule.RespondBodyFileReload {
				// read once at startup rather than re-opening the file on every
				// request, and fail now if it cannot be read
				body, err := os.ReadFile(rule.RespondRule.RespondBodyFile)
				if err != nil {
					return fmt.Errorf("rules[%d]: respond_rule: respond_body_file: %w", i, err)
				}
				rule.respondBody = body
			} else if rule.RespondRule.RespondBodyFile == "" {
				rule.respondBody = []byte(rule.RespondRule.RespondBody)
			}
		}
	}
	return nil
}

func (s *Server) closeRules() {
	for _, rule := range s.config.Rules {
		// the handler is closed, not unset: a request that is still in flight
		// when a shutdown deadline expires then gets a 404 from a closed root
		// rather than a nil dereference, and there is no write to race with it
		_ = rule.serveHandler.Close()
	}
}

func (s *Server) newTransport(insecure bool) *http.Transport {
	// start from the standard transport so that connection pooling, HTTP/2 and
	// the proxy-from-environment behaviour are kept; v0.1.0 replaced the whole
	// transport for self-signed targets and lost all of it
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   s.config.upstreamDialTimeout(),
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.TLSHandshakeTimeout = s.config.upstreamTLSHandshakeTimeout()
	transport.ResponseHeaderTimeout = s.config.upstreamResponseHeaderTimeout()
	if insecure {
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
	}
	return transport
}

func (s *Server) newReverseProxy(rule *Rule) *httputil.ReverseProxy {
	target := rule.ProxyRule.proxyURL
	trusted := s.config.trusted
	transport := s.defaultTransport
	if rule.ProxyRule.ProxyTargetAcceptSelfSigned {
		transport = s.insecureTransport
	}
	return &httputil.ReverseProxy{
		Rewrite: func(request *httputil.ProxyRequest) {
			// ReverseProxy strips the inbound forwarded headers before calling
			// Rewrite. Put them back only for a peer we trust to have set them:
			// from anyone else, a claim about the "original" client is a guess
			// at best and a forgery at worst.
			if trusted.trusts(request.In.RemoteAddr) {
				copyForwardedHeaders(request.Out.Header, request.In.Header)
			} else {
				removeForwardedHeaders(request.Out.Header)
				if hasForwardedHeaders(request.In.Header) {
					s.warnDroppedForwarded(request.In.RemoteAddr)
				}
			}
			request.SetURL(target)
			// SetURL points the outbound Host at the target; v0.1.0 forwarded
			// the Host the client sent, so keep doing that
			request.Out.Host = request.In.Host
			request.SetXForwarded()
			request.Out.Header.Set("X-Real-Ip", trusted.clientIP(request.In))
			if rule.ProxyRule.ProxyRewriteHostHeader != "" {
				request.Out.Host = rule.ProxyRule.ProxyRewriteHostHeader
			}
		},
		Transport: transport,
		ErrorLog:  log.New(logWriter{log: s.log}, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) {
				// the client went away mid-request; nothing to report
				return
			}
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				// the request body hit limits.max_request_body while it was
				// being forwarded: that is the client's fault, not the
				// upstream's
				s.log.Warn("Client=%s Host=%s Path=%s Mod=Proxy Rule=%s Error=request body over the %d byte limit", s.config.trusted.clientIP(r), r.Host, r.URL.Path, rule, tooLarge.Limit)
				http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
				return
			}
			s.log.Error("Client=%s Host=%s Path=%s Mod=Proxy Target=%s Rule=%s Error=%v", s.config.trusted.clientIP(r), r.Host, r.URL.Path, rule.ProxyRule.ProxyURL, rule, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
}

func (s *Server) warnDroppedForwarded(peer string) {
	s.warnDropOnce.Do(func() {
		s.log.Warn("Dropped inbound X-Forwarded-* headers from %s: the peer is not listed in trusted_proxies. Add it there if goproxy runs behind another proxy.", peer)
	})
}

// logWriter adapts an io.Writer sink (http.Server.ErrorLog) onto the configured
// logger, so net/http's own errors honour the configured level and sinks.
type logWriter struct {
	log *logger.Logger
}

func (w logWriter) Write(p []byte) (int, error) {
	w.log.Error("%s", strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// ReloadCertificates re-reads the certificate and key named in the config.
// Certificates are served through GetCertificate, so a renewed certificate is
// picked up without dropping connections.
func (s *Server) ReloadCertificates() error {
	if s.config.TLS == nil || s.config.TLS.Certs == nil {
		return nil
	}
	certificate, err := tls.LoadX509KeyPair(s.config.TLS.Certs.CertFile, s.config.TLS.Certs.KeyFile)
	if err != nil {
		return fmt.Errorf("tls: certs: %w", err)
	}
	s.certificate.Store(&certificate)
	return nil
}

func (s *Server) tlsConfig() *tls.Config {
	minVersion, maxVersion := s.config.tlsVersions()
	config := &tls.Config{
		MinVersion: minVersion,
		MaxVersion: maxVersion,
	}
	if s.certManager != nil {
		config.GetCertificate = s.certManager.GetCertificate
		return config
	}
	config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		certificate := s.certificate.Load()
		if certificate == nil {
			return nil, errors.New("no certificate loaded")
		}
		return certificate, nil
	}
	return config
}

func (s *Server) newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: s.config.readHeaderTimeout(),
		ReadTimeout:       s.config.readTimeout(),
		WriteTimeout:      s.config.writeTimeout(),
		IdleTimeout:       s.config.idleTimeout(),
		MaxHeaderBytes:    s.config.maxHeaderBytes(),
		ErrorLog:          log.New(logWriter{log: s.log}, "", 0),
	}
}

// Start binds the listeners and begins serving. It returns an error if any
// listener cannot be bound; a listener that fails later is reported through
// Wait. Cancelling ctx starts a graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("server already started")
	}
	s.log.Info("Starting proxy server...")

	if s.certManager != nil {
		// created here rather than during validation: checking a config must
		// not have side effects
		if err := os.MkdirAll(s.config.TLS.LetsEncrypt.CacheDir, 0o755); err != nil {
			return s.failedToStart(fmt.Errorf("tls: lets_encrypt: failed to create cache_dir: %w", err))
		}
	}

	var listenConfig net.ListenConfig
	if s.config.ListenAddr != "" {
		ln, err := listenConfig.Listen(ctx, "tcp", s.config.ListenAddr)
		if err != nil {
			return s.failedToStart(err)
		}
		s.httpLn = ln
		s.httpServer = s.newHTTPServer(s.config.ListenAddr, s.httpHandler())
	}
	if s.config.TLS != nil {
		ln, err := listenConfig.Listen(ctx, "tcp", s.config.TLS.ListenAddr)
		if err != nil {
			s.closeListeners()
			return s.failedToStart(err)
		}
		s.httpsLn = ln
		s.httpsServer = s.newHTTPServer(s.config.TLS.ListenAddr, s.handler)
		s.httpsServer.TLSConfig = s.tlsConfig()
	}

	if s.httpServer != nil {
		s.serve("http", s.httpServer, s.httpLn, false)
		s.log.Info("Listening for HTTP on %s", s.httpLn.Addr())
	}
	if s.httpsServer != nil {
		s.serve("https", s.httpsServer, s.httpsLn, true)
		s.log.Info("Listening for HTTPS on %s", s.httpsLn.Addr())
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
				shutdownCtx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout())
				defer cancel()
				_ = s.Shutdown(shutdownCtx)
			case <-s.done:
			}
		}()
	}

	s.log.Info("Proxy server started")
	return nil
}

// httpHandler is what the plain HTTP listener serves: the rules, or - when TLS
// is configured - a redirect to https, with the ACME http-01 challenge handled
// in front of it.
func (s *Server) httpHandler() http.Handler {
	if s.config.TLS == nil {
		return s.handler
	}
	redirector := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
	})
	if s.certManager != nil {
		return s.certManager.HTTPHandler(redirector)
	}
	return redirector
}

func (s *Server) serve(name string, server *http.Server, ln net.Listener, useTLS bool) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var err error
		if useTLS {
			// the certificate is already loaded and served through
			// TLSConfig.GetCertificate
			err = server.ServeTLS(ln, "", "")
		} else {
			err = server.Serve(ln)
		}
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return
		}
		s.log.Error("%s listener stopped: %v", name, err)
		s.setErr(fmt.Errorf("%s listener: %w", name, err))
		if s.config.OnListenerError == OnListenerErrorContinue {
			s.log.Warn("on_listener_error=continue: the remaining listeners keep serving")
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout())
			defer cancel()
			_ = s.Shutdown(ctx)
		}()
	}()
}

// failedToStart records a startup failure and releases anyone blocked in Wait,
// so a caller that starts the server in one goroutine and waits in another does
// not hang on a server that never came up.
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
	if s.httpLn != nil {
		s.httpLn.Close()
	}
	if s.httpsLn != nil {
		s.httpsLn.Close()
	}
}

func (s *Server) cleanup() {
	s.closeRules()
	s.defaultTransport.CloseIdleConnections()
	s.insecureTransport.CloseIdleConnections()
}

func (s *Server) finish() {
	s.doneOnce.Do(func() { close(s.done) })
}

// HTTPAddr is the address the plain HTTP listener is bound to, or "" if there
// is none. It is the resolved address, so it is useful when the config asked
// for port 0.
func (s *Server) HTTPAddr() string {
	if s.httpLn == nil {
		return ""
	}
	return s.httpLn.Addr().String()
}

// HTTPSAddr is the address the TLS listener is bound to, or "" if there is none.
func (s *Server) HTTPSAddr() string {
	if s.httpsLn == nil {
		return ""
	}
	return s.httpsLn.Addr().String()
}

// Shutdown stops the server gracefully: it stops accepting, waits for in-flight
// requests until ctx expires, then force-closes what is left. It is safe to
// call more than once and from several goroutines - the second call is a no-op
// rather than a panic. It must not race with Start: shut down a server that has
// started.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	s.shutdownOnce.Do(func() {
		s.log.Info("Shutting down proxy server")
		err = s.shutdown(ctx)
		if err != nil {
			s.log.Error("Proxy server shut down with errors: %v", err)
		} else {
			s.log.Info("Proxy server shut down")
		}
		if !s.started.Load() {
			// nothing is serving, so nothing will release Wait
			s.cleanup()
			s.finish()
		}
	})
	return err
}

func (s *Server) shutdown(ctx context.Context) error {
	var errs error
	for _, server := range []*http.Server{s.httpServer, s.httpsServer} {
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
