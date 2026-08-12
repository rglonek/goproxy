// Package listen builds listeners: TLS configuration, certificate loading and
// reloading, ACME wiring and HSTS.
package listen

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"goproxy/pkg/config"
	"goproxy/pkg/observe"
)

// Certificates holds the certificates the https listener serves. They are
// loaded and parsed up front - handing file names to ServeTLS and discarding
// the error is how a broken certificate becomes a listener that fails every
// handshake while the process reports success.
type Certificates struct {
	files  []config.Cert
	loaded atomic.Pointer[[]tls.Certificate]
}

// NewCertificates loads every configured certificate/key pair.
func NewCertificates(files []config.Cert) (*Certificates, error) {
	certificates := &Certificates{files: files}
	if err := certificates.Reload(); err != nil {
		return nil, err
	}
	return certificates, nil
}

// Reload re-reads the certificate files. Certificates are served through
// GetCertificate, so a renewed certificate is picked up without a restart and
// without dropping connections.
func (c *Certificates) Reload() error {
	loaded := make([]tls.Certificate, 0, len(c.files))
	for i, file := range c.files {
		certificate, err := tls.LoadX509KeyPair(file.CertFile, file.KeyFile)
		if err != nil {
			return fmt.Errorf("certs[%d]: %w", i, err)
		}
		if certificate.Leaf == nil && len(certificate.Certificate) > 0 {
			// keeping the parsed leaf is what makes SNI selection and the
			// expiry metric possible
			if leaf, err := x509.ParseCertificate(certificate.Certificate[0]); err == nil {
				certificate.Leaf = leaf
			}
		}
		loaded = append(loaded, certificate)
	}
	c.loaded.Store(&loaded)
	return nil
}

// GetCertificate picks the certificate for a connection by SNI, falling back to
// the first one configured.
func (c *Certificates) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	loaded := c.loaded.Load()
	if loaded == nil || len(*loaded) == 0 {
		return nil, fmt.Errorf("no certificate loaded")
	}
	certificates := *loaded
	for i := range certificates {
		if err := hello.SupportsCertificate(&certificates[i]); err == nil {
			return &certificates[i], nil
		}
	}
	return &certificates[0], nil
}

// Expiry reports when each loaded certificate expires, keyed by subject. "The
// certificate expired" is the most common way a small deployment goes down.
func (c *Certificates) Expiry() map[string]time.Time {
	expiry := map[string]time.Time{}
	loaded := c.loaded.Load()
	if loaded == nil {
		return expiry
	}
	for _, certificate := range *loaded {
		if certificate.Leaf == nil {
			continue
		}
		subject := certificate.Leaf.Subject.CommonName
		if subject == "" && len(certificate.Leaf.DNSNames) > 0 {
			subject = certificate.Leaf.DNSNames[0]
		}
		expiry[subject] = certificate.Leaf.NotAfter
	}
	return expiry
}

// TLSConfig builds the server's TLS configuration. MinVersion is set
// explicitly rather than inherited, so it is visible in the config and cannot
// move underneath the operator with a Go release.
func TLSConfig(cfg config.TLS, certificates *Certificates, manager *autocert.Manager, metrics *observe.Metrics) (*tls.Config, error) {
	minVersion, err := config.ParseTLSVersion(cfg.MinVersion, tls.VersionTLS12)
	if err != nil {
		return nil, fmt.Errorf("min_version: %w", err)
	}
	maxVersion, err := config.ParseTLSVersion(cfg.MaxVersion, 0)
	if err != nil {
		return nil, fmt.Errorf("max_version: %w", err)
	}
	tlsConfig := &tls.Config{MinVersion: minVersion, MaxVersion: maxVersion}

	switch {
	case manager != nil:
		tlsConfig.GetCertificate = manager.GetCertificate
	default:
		tlsConfig.GetCertificate = certificates.GetCertificate
	}

	if cfg.ClientAuth != nil {
		mode, err := config.ParseClientAuth(cfg.ClientAuth.Mode)
		if err != nil {
			return nil, fmt.Errorf("client_auth.mode: %w", err)
		}
		tlsConfig.ClientAuth = mode
		if cfg.ClientAuth.CAFile != "" {
			pem, err := os.ReadFile(cfg.ClientAuth.CAFile)
			if err != nil {
				return nil, fmt.Errorf("client_auth.ca_file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("client_auth.ca_file: %s contains no certificates", cfg.ClientAuth.CAFile)
			}
			tlsConfig.ClientCAs = pool
		}
	}

	if metrics != nil {
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			metrics.TLSHandshakes.Inc(TLSVersionName(state.Version), "ok")
			return nil
		}
	}
	return tlsConfig, nil
}

// TLSVersionName is the human name of a TLS version constant.
func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return "unknown"
}

// HSTS adds Strict-Transport-Security to responses on the TLS listener. It is
// opt-in and never on by default: a wrong max_age is very difficult for an
// operator to recover from.
func HSTS(cfg *config.HSTS) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	maxAge := int(cfg.MaxAge.Or(365 * 24 * time.Hour).Seconds())
	value := "max-age=" + strconv.Itoa(maxAge)
	if cfg.IncludeSubdomains {
		value += "; includeSubDomains"
	}
	if cfg.Preload {
		value += "; preload"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Strict-Transport-Security", value)
			next.ServeHTTP(w, r)
		})
	}
}

// ACME builds the Let's Encrypt manager, if the config asked for one.
func ACME(cfg *config.TLS) *autocert.Manager {
	if cfg.ACME == nil {
		return nil
	}
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.ACME.Domains...),
		Cache:      autocert.DirCache(cfg.ACME.CacheDir),
		Email:      cfg.ACME.Email,
	}
}
