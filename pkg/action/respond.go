package action

import (
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"goproxy/pkg/config"
	"goproxy/pkg/middleware"
)

// Respond answers with a canned status, body and headers.
type Respond struct {
	cfg         *config.Respond
	body        []byte
	contentType string
	log         *slog.Logger
}

func NewRespond(cfg *config.Respond, log *slog.Logger) (*Respond, error) {
	action := &Respond{cfg: cfg, log: log}
	switch {
	case cfg.BodyFile != "" && !cfg.Reload:
		// read once at startup rather than re-opening the file on every
		// request, and fail now if it cannot be read
		body, err := os.ReadFile(cfg.BodyFile)
		if err != nil {
			return nil, fmt.Errorf("body_file: %w", err)
		}
		action.body = body
	case cfg.BodyFile == "":
		action.body = []byte(cfg.Body)
	}
	action.contentType = contentTypeFor(cfg, action.body)
	return action, nil
}

func (r *Respond) Describe() string {
	description := "respond " + strconv.Itoa(r.cfg.Status)
	if r.cfg.BodyFile != "" {
		description += " from " + r.cfg.BodyFile
	}
	return description
}

func (r *Respond) Close() error { return nil }

func (r *Respond) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	body := r.body
	contentType := r.contentType
	if r.cfg.Reload && r.cfg.BodyFile != "" {
		reloaded, err := os.ReadFile(r.cfg.BodyFile)
		if err != nil {
			r.log.Error("cannot read respond body file",
				"id", middleware.IDOf(request), "file", r.cfg.BodyFile, "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		body = reloaded
		contentType = contentTypeFor(r.cfg, body)
	}

	header := w.Header()
	for name, value := range r.cfg.Headers {
		header.Set(name, value)
	}
	if contentType != "" && header.Get("Content-Type") == "" {
		header.Set("Content-Type", contentType)
	}
	if !bodyAllowed(r.cfg.Status) {
		w.WriteHeader(r.cfg.Status)
		return
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(r.cfg.Status)
	if request.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// contentTypeFor uses the configured type, or works one out: v0.1.0 forced
// text/plain, so an HTML error page was impossible.
func contentTypeFor(cfg *config.Respond, body []byte) string {
	if cfg.ContentType != "" {
		return cfg.ContentType
	}
	if cfg.BodyFile != "" {
		if byExtension := mime.TypeByExtension(filepath.Ext(cfg.BodyFile)); byExtension != "" {
			return byExtension
		}
	}
	if len(body) == 0 {
		return ""
	}
	return http.DetectContentType(body)
}

// bodyAllowed reports whether a response with this status may carry a body.
func bodyAllowed(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	}
	return true
}

// Redirect answers with a 3xx to a fixed or interpolated URL.
type Redirect struct {
	cfg *config.Redirect
}

func NewRedirect(cfg *config.Redirect) *Redirect {
	return &Redirect{cfg: cfg}
}

func (r *Redirect) Describe() string {
	return fmt.Sprintf("redirect %d to %s", r.cfg.Status, r.cfg.To)
}

func (r *Redirect) Close() error { return nil }

func (r *Redirect) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	http.Redirect(w, request, r.expand(request), r.cfg.Status)
}

// expand fills in {path} and {query}, which is what makes "move this whole
// tree over there" expressible.
func (r *Redirect) expand(request *http.Request) string {
	to := r.cfg.To
	if !strings.Contains(to, "{") {
		return to
	}
	query := request.URL.RawQuery
	if query != "" {
		query = "?" + query
	}
	return strings.NewReplacer(
		"{path}", request.URL.EscapedPath(),
		"{query}", query,
	).Replace(to)
}
