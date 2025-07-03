package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/rglonek/logger"
	"golang.org/x/crypto/acme/autocert"
)

func Run(config *Config) (*proxy, error) {
	p := &proxy{}
	err := p.run(config)
	if err != nil {
		return nil, err
	}
	return p, nil
}

type proxy struct {
	config      *Config
	log         *logger.Logger
	httpServer  *http.Server
	httpsServer *http.Server
	shutdown    chan struct{}
}

func (p *proxy) run(config *Config) error {
	p.shutdown = make(chan struct{})
	p.config = config

	p.setLogger()

	p.log.Info("Starting proxy server...")
	err := p.setRouter()
	if err != nil {
		return err
	}

	err = p.startServer()
	if err != nil {
		return err
	}

	p.log.Info("Proxy server started")
	return nil
}

func (p *proxy) setLogger() {
	p.log = logger.NewLogger()
	p.log.SetLogLevel(logger.LogLevel(p.config.LogLevel))
	p.log.MillisecondLogging(true)
}

func (p *proxy) startServer() error {
	// early-create certManager if needed to handle http auth challenge for letsencrypt
	var certManager *autocert.Manager
	if p.config.TLS != nil && p.config.TLS.LetsEncrypt != nil {
		certManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(p.config.TLS.LetsEncrypt.Domains...),
			Cache:      autocert.DirCache(p.config.TLS.LetsEncrypt.CacheDir),
			Email:      p.config.TLS.LetsEncrypt.Email,
		}
	}

	// listen on HTTP if defined
	if p.config.ListenAddr != "" {
		httpHandler := (http.Handler)(&handler{proxy: p}) // http handler is the proxy itself
		// if TLS is enabled, redirect HTTP to HTTPS
		if p.config.TLS != nil {
			redirector := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			})
			if certManager != nil {
				httpHandler = certManager.HTTPHandler(redirector)
			} else {
				httpHandler = redirector
			}
		}
		p.httpServer = &http.Server{
			Addr:    p.config.ListenAddr,
			Handler: httpHandler,
		}
		ln, err := net.Listen("tcp", p.config.ListenAddr)
		if err != nil {
			return err
		}
		go p.httpServer.Serve(ln)
	}

	// listen on HTTPS if defined
	if p.config.TLS != nil {
		if p.config.TLS.LetsEncrypt != nil {
			p.httpsServer = &http.Server{
				Addr:    p.config.TLS.ListenAddr,
				Handler: &handler{proxy: p},
				TLSConfig: &tls.Config{
					GetCertificate: certManager.GetCertificate,
				},
			}
			ln, err := net.Listen("tcp", p.config.TLS.ListenAddr)
			if err != nil {
				if p.httpServer != nil {
					p.httpServer.Shutdown(context.Background())
				}
				return err
			}
			go p.httpsServer.Serve(ln)
		} else if p.config.TLS.Certs != nil {
			p.httpsServer = &http.Server{
				Addr:    p.config.TLS.ListenAddr,
				Handler: &handler{proxy: p},
			}
			ln, err := net.Listen("tcp", p.config.TLS.ListenAddr)
			if err != nil {
				if p.httpServer != nil {
					p.httpServer.Shutdown(context.Background())
				}
				return err
			}
			go p.httpsServer.ServeTLS(ln, p.config.TLS.Certs.CertFile, p.config.TLS.Certs.KeyFile)
		}
	}
	return nil
}

func (p *proxy) Shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	p.log.Info("Shutting down proxy server")
	var errs error
	if p.httpServer != nil {
		err := p.httpServer.Shutdown(ctx)
		if err != nil {
			errs = errors.Join(errs, err)
			err := p.httpServer.Close()
			if err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}
	if p.httpsServer != nil {
		err := p.httpsServer.Shutdown(ctx)
		if err != nil {
			errs = errors.Join(errs, err)
			err := p.httpsServer.Close()
			if err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}
	if errs != nil {
		p.log.Error("Proxy server shut down with errors: %v", errs)
	} else {
		p.log.Info("Proxy server shut down")
	}
	close(p.shutdown)
	return errs
}

func (p *proxy) Wait() error {
	<-p.shutdown
	return nil
}
