package proxy

import (
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/rglonek/logger"
)

// serveHandler serves a local directory. It is built once per rule, at startup,
// and it holds an os.Root: the kernel refuses any open that leaves the
// directory, including through a symlink, which http.Dir does not prevent.
type serveHandler struct {
	root          *os.Root
	dir           string
	index         []string
	listDirs      bool
	allowDotfiles bool
	cacheControl  string
	log           *logger.Logger
}

func newServeHandler(rule *ServeRule, log *logger.Logger) (*serveHandler, error) {
	root, err := os.OpenRoot(rule.ServeLocalDir)
	if err != nil {
		return nil, fmt.Errorf("serve_rule: serve_local_dir %q: %w", rule.ServeLocalDir, err)
	}
	index := rule.ServeIndex
	if index == nil {
		index = []string{"index.html"}
	}
	return &serveHandler{
		root:          root,
		dir:           rule.ServeLocalDir,
		index:         index,
		listDirs:      rule.ServeListDirectories,
		allowDotfiles: rule.ServeAllowDotfiles,
		cacheControl:  rule.ServeCacheControl,
		log:           log,
	}, nil
}

func (s *serveHandler) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

// serve answers a request for a file below the rule's directory. urlPrefix is
// the part of the request path the rule stripped before matching, and is put
// back on any redirect this handler generates.
func (s *serveHandler) serve(w http.ResponseWriter, r *http.Request, urlPrefix string) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
	}
	name := path.Clean(upath)
	if !s.allowDotfiles && containsDotFile(name) {
		http.NotFound(w, r)
		return
	}

	fsName := strings.TrimPrefix(name, "/")
	if fsName == "" {
		fsName = "."
	}

	f, info, err := s.open(fsName)
	if err != nil {
		s.serveError(w, r, name, err)
		return
	}
	defer f.Close()

	if info.IsDir() {
		// a directory must be addressed with a trailing slash, or every
		// relative link inside it resolves against the wrong base
		if !strings.HasSuffix(upath, "/") {
			localRedirect(w, r, s.directoryLocation(urlPrefix, name))
			return
		}
		for _, indexName := range s.index {
			if indexName == "" {
				continue
			}
			indexFile, indexInfo, err := s.open(path.Join(fsName, indexName))
			if err != nil {
				continue
			}
			if indexInfo.IsDir() || !indexInfo.Mode().IsRegular() {
				indexFile.Close()
				continue
			}
			defer indexFile.Close()
			s.serveContent(w, r, indexName, indexInfo, indexFile)
			return
		}
		if !s.listDirs {
			// directory listings are opt-in: an accidental listing of a
			// directory without an index file discloses more than intended
			http.NotFound(w, r)
			return
		}
		s.list(w, r, f)
		return
	}

	if !info.Mode().IsRegular() {
		// device nodes, sockets and fifos are not documents
		http.NotFound(w, r)
		return
	}
	s.serveContent(w, r, name, info, f)
}

func (s *serveHandler) open(name string) (*os.File, fs.FileInfo, error) {
	f, err := s.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

func (s *serveHandler) serveContent(w http.ResponseWriter, r *http.Request, name string, info fs.FileInfo, content io.ReadSeeker) {
	if s.cacheControl != "" && w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", s.cacheControl)
	}
	http.ServeContent(w, r, path.Base(name), info.ModTime(), content)
}

func (s *serveHandler) serveError(w http.ResponseWriter, r *http.Request, name string, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		http.NotFound(w, r)
	case errors.Is(err, fs.ErrPermission):
		http.Error(w, "Forbidden", http.StatusForbidden)
	default:
		// os.Root refuses a path that would escape the directory; that is a
		// blocked request, not a server fault
		s.log.Warn("Client=%s Host=%s Path=%s Mod=Serve LocalDir=%s Error=%v", r.RemoteAddr, r.Host, name, s.dir, err)
		http.NotFound(w, r)
	}
}

func (s *serveHandler) list(w http.ResponseWriter, r *http.Request, dir *os.File) {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		s.log.Error("Client=%s Host=%s Path=%s Mod=Serve LocalDir=%s Error=%v", r.RemoteAddr, r.Host, r.URL.Path, s.dir, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var body strings.Builder
	body.WriteString("<!DOCTYPE html>\n<html>\n<head><meta charset=\"utf-8\"><title>Index of ")
	body.WriteString(html.EscapeString(r.URL.Path))
	body.WriteString("</title></head>\n<body>\n<h1>Index of ")
	body.WriteString(html.EscapeString(r.URL.Path))
	body.WriteString("</h1>\n<pre>\n")
	for _, entry := range entries {
		name := entry.Name()
		if !s.allowDotfiles && strings.HasPrefix(name, ".") {
			continue
		}
		if entry.IsDir() {
			name += "/"
		}
		body.WriteString("<a href=\"")
		body.WriteString(html.EscapeString((&url.URL{Path: name}).String()))
		body.WriteString("\">")
		body.WriteString(html.EscapeString(name))
		body.WriteString("</a>\n")
	}
	body.WriteString("</pre>\n</body>\n</html>\n")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(body.Len()))
	if s.cacheControl != "" {
		w.Header().Set("Cache-Control", s.cacheControl)
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, body.String())
}

// containsDotFile reports whether any element of the path starts with a dot.
// Dotfiles (.git, .env, .htpasswd) are hidden unless the rule opts in.
func containsDotFile(name string) bool {
	for _, part := range strings.Split(name, "/") {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." {
			return true
		}
	}
	return false
}

// directoryLocation is where a request for a directory without a trailing slash
// is sent. It is built from the cleaned path, and it falls back to a relative
// reference rather than ever emitting a location starting with "//" - a browser
// reads that as another host, which would make this an open redirect.
func (s *serveHandler) directoryLocation(urlPrefix, name string) string {
	location := urlPrefix + name + "/"
	if !strings.HasPrefix(location, "/") || strings.HasPrefix(location, "//") {
		return path.Base(name) + "/"
	}
	return location
}

// localRedirect sends the client to newPath, preserving the query string.
func localRedirect(w http.ResponseWriter, r *http.Request, newPath string) {
	if q := r.URL.RawQuery; q != "" {
		newPath += "?" + q
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(http.StatusMovedPermanently)
}
