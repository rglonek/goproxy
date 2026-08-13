// Package action holds the terminal handlers a rule can end in: proxy, serve,
// redirect and respond. Each one is built once, at compile time, and is
// immutable afterwards.
package action

import (
	"net/http"
	"net/url"
	"strings"
)

// Action is what a rule does with a request it matched.
type Action interface {
	http.Handler
	// Describe is a one-line summary for logs and `goproxy config explain`.
	Describe() string
	// Close releases whatever the action holds open.
	Close() error
}

// setPath replaces the path of a URL, discarding the escaped form so that the
// URL re-encodes from the value just computed.
func setPath(u *url.URL, path string) {
	u.Path = path
	u.RawPath = ""
}

// stripPrefix removes prefix from path, and only from the front.
func stripPrefix(path, prefix string) string {
	if prefix == "" || !strings.HasPrefix(path, prefix) {
		return path
	}
	stripped := strings.TrimPrefix(path, prefix)
	if stripped == "" {
		return "/"
	}
	if !strings.HasPrefix(stripped, "/") {
		return "/" + stripped
	}
	return stripped
}

// joinPath joins two path segments with exactly one slash between them.
func joinPath(base, rest string) string {
	switch {
	case base == "" || base == "/":
		return rest
	case rest == "" || rest == "/":
		return base
	case strings.HasSuffix(base, "/") && strings.HasPrefix(rest, "/"):
		return base + rest[1:]
	case !strings.HasSuffix(base, "/") && !strings.HasPrefix(rest, "/"):
		return base + "/" + rest
	}
	return base + rest
}
