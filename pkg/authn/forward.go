package authn

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"goproxy/pkg/config"
)

// forwardAuth asks another service whether a request is allowed: goproxy
// issues a subrequest carrying the original method, path and headers, and
// treats 2xx as success. This is the mechanism nginx spells auth_request and
// Traefik spells ForwardAuth. It is a subrequest rather than a process fork per
// request, which is what FUTURE.md's "handoff to a separate binary" would have
// cost.
type forwardAuth struct {
	url            *url.URL
	client         *http.Client
	requestHeaders []string
	copyHeaders    []string
	userHeader     string
}

func newForward(cfg *config.ForwardAuth) (*forwardAuth, error) {
	target, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("url: %w", err)
	}
	timeout := cfg.Timeout.Or(config.DefaultForwardAuthTimeout)
	return &forwardAuth{
		url:            target,
		requestHeaders: cfg.RequestHeaders,
		copyHeaders:    cfg.CopyHeaders,
		userHeader:     cfg.UserHeader,
		client: &http.Client{
			Timeout: timeout,
			// the auth service's answer is about this request; a redirect
			// would be answering a different one
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
				MaxIdleConnsPerHost:   4,
			},
		},
	}, nil
}

func (f *forwardAuth) Method() string { return MethodForward }

func (f *forwardAuth) Authenticate(r *http.Request) (Identity, bool) {
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, f.url.String(), nil)
	if err != nil {
		return Identity{}, false
	}
	if len(f.requestHeaders) == 0 {
		for name, values := range r.Header {
			for _, value := range values {
				request.Header.Add(name, value)
			}
		}
	} else {
		for _, name := range f.requestHeaders {
			if value := r.Header.Get(name); value != "" {
				request.Header.Set(name, value)
			}
		}
	}
	// what the auth service needs to know about the request it is deciding on
	request.Header.Set("X-Forwarded-Method", r.Method)
	request.Header.Set("X-Forwarded-Uri", r.URL.RequestURI())
	request.Header.Set("X-Forwarded-Host", r.Host)

	response, err := f.client.Do(request)
	if err != nil {
		return Identity{}, false
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return Identity{}, false
	}

	identity := Identity{}
	for _, name := range f.copyHeaders {
		if value := response.Header.Get(name); value != "" {
			identity.addHeader(name, value)
		}
	}
	if f.userHeader != "" {
		identity.User = response.Header.Get(f.userHeader)
	}
	return identity, true
}

func (f *forwardAuth) Challenge() string { return "" }

// Strip does nothing: forward auth reads the request but consumes no
// credential of its own.
func (f *forwardAuth) Strip(*http.Request) {}
