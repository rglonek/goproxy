// Package middleware is the request pipeline: small, individually testable
// stages of the standard func(http.Handler) http.Handler shape, so that
// ordering is data and the stages compose.
package middleware

import (
	"context"
	"io"
	"net/http"
	"time"

	"goproxy/pkg/authn"
)

// Middleware wraps a handler. Every stage of the pipeline has this shape.
type Middleware func(http.Handler) http.Handler

// Chain applies middleware in order, so that the first one listed is the
// outermost and sees the request first.
func Chain(handler http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		if middlewares[i] == nil {
			continue
		}
		handler = middlewares[i](handler)
	}
	return handler
}

type stateKey struct{}

// State is what the pipeline learns about a request as it goes: the matcher
// records which rule won, the authenticator records who the client is, the
// proxy records which upstream answered. The access log reads all of it at the
// end. It is owned by the one goroutine serving the request.
type State struct {
	ID       string
	ClientIP string
	Start    time.Time

	Rule     string
	Action   string
	Identity authn.Identity

	Upstream         string
	Target           string
	UpstreamDuration time.Duration
	Retries          int

	// Streaming rules opt out of the write timeout.
	Streaming bool
	// Err is a short reason the request failed, for the access log.
	Err string
}

// NewState attaches a fresh state to the request.
func NewState(r *http.Request) (*http.Request, *State) {
	state := &State{Start: time.Now()}
	return r.WithContext(context.WithValue(r.Context(), stateKey{}, state)), state
}

// StateOf returns the request's state, or nil outside the pipeline.
func StateOf(r *http.Request) *State {
	state, _ := r.Context().Value(stateKey{}).(*State)
	return state
}

// ClientIP is the address of the client as far as goproxy can tell: the peer,
// or - behind a trusted proxy - the rightmost address in X-Forwarded-For that
// is not itself trusted.
func ClientIP(r *http.Request) string {
	if state := StateOf(r); state != nil && state.ClientIP != "" {
		return state.ClientIP
	}
	return hostOnly(r.RemoteAddr)
}

// IDOf is the request id assigned to this request, or "" if there is none.
func IDOf(r *http.Request) string {
	if state := StateOf(r); state != nil {
		return state.ID
	}
	return ""
}

// Identity is who the request authenticated as.
func Identity(r *http.Request) authn.Identity {
	if state := StateOf(r); state != nil {
		return state.Identity
	}
	return authn.Identity{}
}

// responseRecorder counts what was sent, which is what the access log and the
// size metrics need. It forwards everything else to the real writer through
// Unwrap, which is how http.ResponseController reaches it for flushing,
// hijacking and deadlines.
type responseRecorder struct {
	http.ResponseWriter
	status  int
	written int64
	wrote   bool
}

func (w *responseRecorder) WriteHeader(status int) {
	if !w.wrote {
		w.wrote = true
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseRecorder) Write(b []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += int64(n)
	return n, err
}

func (w *responseRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ReadFrom keeps net/http's fast path for sending a file to a socket.
func (w *responseRecorder) ReadFrom(r io.Reader) (int64, error) {
	if !w.wrote {
		w.wrote = true
		w.status = http.StatusOK
	}
	var n int64
	var err error
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err = readerFrom.ReadFrom(r)
	} else {
		n, err = io.Copy(w.ResponseWriter, r)
	}
	w.written += n
	return n, err
}

// Status is what was sent, defaulting to 200 for a handler that wrote a body
// without calling WriteHeader.
func (w *responseRecorder) Status() int {
	if !w.wrote {
		return http.StatusOK
	}
	return w.status
}

// Unwrap walks a chain of ResponseWriter wrappers down to the real one.
func Unwrap(w http.ResponseWriter) http.ResponseWriter {
	for {
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		w = unwrapper.Unwrap()
	}
}

// NewRecorder wraps a ResponseWriter so that the status and the number of
// bytes sent can be recorded. It is what the server puts at the head of the
// pipeline.
func NewRecorder(w http.ResponseWriter) http.ResponseWriter {
	if _, ok := w.(*responseRecorder); ok {
		return w
	}
	return &responseRecorder{ResponseWriter: w}
}
