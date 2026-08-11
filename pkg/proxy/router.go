package proxy

import (
	"io"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rglonek/logger"
)

// handler is the terminal stage of the request pipeline: it matches a rule,
// authenticates, and hands over to the rule's action.
type handler struct {
	server *Server
	config *Config
	log    *logger.Logger
}

func (h *handler) clientIP(r *http.Request) string {
	return h.config.trusted.clientIP(r)
}

// buildPipeline assembles the per-server middleware chain once, at startup:
//
//	recover -> request body limit -> match -> authn -> action
func (s *Server) buildPipeline() http.Handler {
	h := &handler{server: s, config: s.config, log: s.log}
	var chain http.Handler = h
	chain = limitRequestBody(chain, s.config.maxRequestBody())
	chain = recoverPanics(chain, s.log)
	return chain
}

// recoverPanics turns a panicking rule into a 500 and a log line through the
// configured logger. Without it net/http writes the panic to the standard
// logger, which ignores the configured log level and sinks.
func recoverPanics(next http.Handler, log *logger.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &statusRecorder{ResponseWriter: w}
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			if rec == http.ErrAbortHandler {
				// the documented way for a handler to abort a response; net/http
				// expects to see it
				panic(rec)
			}
			log.Error("Client=%s Host=%s Path=%s Mod=Panic Error=%v\n%s", r.RemoteAddr, r.Host, r.URL.Path, rec, debug.Stack())
			if !recorder.wrote {
				http.Error(recorder, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(recorder, r)
	})
}

// limitRequestBody caps how much of a request body a rule can be made to read.
// A limit of 0 disables the cap.
func limitRequestBody(next http.Handler, limit int64) http.Handler {
	if limit <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			// MaxBytesReader tells the server to stop reading the rest of an
			// oversized body, but only when it is given the server's own
			// ResponseWriter - not a wrapper around it
			r.Body = http.MaxBytesReader(unwrapResponseWriter(w), r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

func unwrapResponseWriter(w http.ResponseWriter) http.ResponseWriter {
	for {
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		w = unwrapper.Unwrap()
	}
}

// statusRecorder remembers whether the response has been started, so the
// recover middleware knows whether it can still write a 500. It forwards
// everything else through Unwrap, which is how http.ResponseController reaches
// the real writer for flushing, hijacking and deadlines.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusRecorder) WriteHeader(code int) {
	if !w.wrote {
		w.wrote = true
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusRecorder) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// ReadFrom keeps the fast path net/http uses to send a file to the socket:
// without it, wrapping the writer would cost every static file a copy through
// user space.
func (w *statusRecorder) ReadFrom(r io.Reader) (int64, error) {
	if !w.wrote {
		w.wrote = true
		w.status = http.StatusOK
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return readerFrom.ReadFrom(r)
	}
	return io.Copy(w.ResponseWriter, r)
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rule, _ := h.config.Rules.Match(r.Host, r.URL.Path)
	if rule == nil {
		h.log.Info("Client=%s Host=%s Path=%s Mod=NotFound", h.clientIP(r), r.Host, r.URL.Path)
		http.NotFound(w, r)
		return
	}

	// a write timeout would cut a websocket or an event stream off mid-flight,
	// so those requests run without one
	if rule.Streaming || isUpgradeRequest(r) {
		clearDeadlines(w)
	}

	id, ok := h.authenticate(w, r, rule)
	if !ok {
		return
	}

	switch {
	case rule.RedirectRule != nil:
		h.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Redirect Target=%s Rule=%s", h.clientIP(r), r.Host, r.URL.Path, id.authType(), rule.RedirectRule.RedirectURL, rule)
		http.Redirect(w, r, rule.RedirectRule.RedirectURL, rule.RedirectRule.RedirectStatusCode)

	case rule.ServeRule != nil:
		h.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Serve LocalDir=%s Rule=%s", h.clientIP(r), r.Host, r.URL.Path, id.authType(), rule.ServeRule.ServeLocalDir, rule)
		stripped := rule.stripPathPrefix(r.URL.Path)
		// what the strip removed is still part of the URL the client sees, so
		// the file server needs it to build correct redirects
		urlPrefix := strings.TrimSuffix(r.URL.Path, stripped)
		setPath(r.URL, stripped)
		rule.serveHandler.serve(w, r, urlPrefix)

	case rule.RespondRule != nil:
		h.respond(w, r, rule, id)

	case rule.ProxyRule != nil:
		h.proxy(w, r, rule, id)
	}
}

func (h *handler) proxy(w http.ResponseWriter, r *http.Request, rule *Rule, id identity) {
	h.log.Info("Client=%s Host=%s Path=%s AuthType=%s Mod=Proxy Target=%s Rule=%s", h.clientIP(r), r.Host, r.URL.Path, id.authType(), rule.ProxyRule.ProxyURL, rule)

	id.stripConsumedCredentials(r, rule)
	if id.method == authBasic {
		if rule.BasicAuth.SetUserHeader != nil {
			r.Header.Set(*rule.BasicAuth.SetUserHeader, id.user)
		}
		if rule.BasicAuth.SetUserGETVar != nil {
			q := r.URL.Query()
			q.Set(*rule.BasicAuth.SetUserGETVar, id.user)
			r.URL.RawQuery = q.Encode()
		}
	}

	if !rule.ProxyRule.ProxyAppendPath {
		setPath(r.URL, rule.stripPathPrefix(r.URL.Path))
	}

	for idx, header := range rule.ProxyRule.ProxyRemoveHeaders {
		rx := rule.ProxyRule.proxyRemoveHeadersRegex[idx]
		if rx != nil {
			for k := range r.Header {
				if rx.MatchString(k) {
					r.Header.Del(k)
				}
			}
		} else {
			r.Header.Del(header)
		}
	}
	for key, value := range rule.ProxyRule.ProxySetHeaders {
		r.Header.Set(key, value)
	}
	rule.ProxyRule.proxy.ServeHTTP(w, r)
}

// setPath replaces the path of a URL, discarding the escaped form so that the
// URL re-encodes from the value we just computed.
func setPath(u *url.URL, path string) {
	u.Path = path
	u.RawPath = ""
}

// isUpgradeRequest reports whether the client asked to switch protocols, which
// is how a websocket handshake starts.
func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// clearDeadlines removes the connection's read and write deadlines for the
// current request. Errors are ignored on purpose: a ResponseWriter that does
// not support deadlines (an httptest recorder, HTTP/2) simply has none to
// clear.
func clearDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
}
