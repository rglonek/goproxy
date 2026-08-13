package action

import (
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"goproxy/pkg/config"
	"goproxy/pkg/middleware"
)

// Serve serves a local directory. It holds an os.Root, so the kernel refuses
// any open that leaves the directory - including through a symlink, which
// http.Dir does not prevent.
type Serve struct {
	root          *os.Root
	dir           string
	index         []string
	listDirs      bool
	allowDotfiles bool
	cacheControl  string
	stripPrefix   string
	log           *slog.Logger
}

func NewServe(cfg *config.Serve, log *slog.Logger) (*Serve, error) {
	root, err := os.OpenRoot(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("dir %q: %w", cfg.Dir, err)
	}
	index := cfg.Index
	if index == nil {
		index = []string{"index.html"}
	}
	return &Serve{
		root:          root,
		dir:           cfg.Dir,
		index:         index,
		listDirs:      cfg.ListDirectories,
		allowDotfiles: cfg.AllowDotfiles,
		cacheControl:  cfg.CacheControl,
		stripPrefix:   cfg.StripPrefix,
		log:           log,
	}, nil
}

func (s *Serve) Describe() string {
	description := "serve " + s.dir
	if s.stripPrefix != "" {
		description += " strip_prefix=" + s.stripPrefix
	}
	if s.listDirs {
		description += " list_directories=true"
	}
	return description
}

func (s *Serve) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

func (s *Serve) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
	}
	// what the strip removes is still part of the URL the client sees, so it
	// is put back on any redirect this handler generates
	urlPrefix := ""
	if s.stripPrefix != "" {
		stripped := stripPrefix(upath, s.stripPrefix)
		if stripped != upath {
			urlPrefix = strings.TrimSuffix(upath, strings.TrimPrefix(stripped, "/"))
			urlPrefix = strings.TrimSuffix(urlPrefix, "/")
			upath = stripped
		}
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

	file, info, err := s.open(fsName)
	if err != nil {
		s.serveError(w, r, name, err)
		return
	}
	defer file.Close()

	if info.IsDir() {
		// a directory must be addressed with a trailing slash, or every
		// relative link inside it resolves against the wrong base
		if !strings.HasSuffix(upath, "/") {
			localRedirect(w, r, directoryLocation(urlPrefix, name))
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
			if !indexInfo.Mode().IsRegular() {
				indexFile.Close()
				continue
			}
			defer indexFile.Close()
			s.serveContent(w, r, indexName, indexInfo, indexFile)
			return
		}
		if !s.listDirs {
			// listings are opt-in: listing a directory that happens to have no
			// index file discloses more than was intended
			http.NotFound(w, r)
			return
		}
		s.list(w, r, file)
		return
	}

	if !info.Mode().IsRegular() {
		// device nodes, sockets and fifos are not documents
		http.NotFound(w, r)
		return
	}
	s.serveContent(w, r, name, info, file)
}

func (s *Serve) open(name string) (*os.File, fs.FileInfo, error) {
	file, err := s.root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func (s *Serve) serveContent(w http.ResponseWriter, r *http.Request, name string, info fs.FileInfo, content io.ReadSeeker) {
	if s.cacheControl != "" && w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", s.cacheControl)
	}
	http.ServeContent(w, r, path.Base(name), info.ModTime(), content)
}

func (s *Serve) serveError(w http.ResponseWriter, r *http.Request, name string, err error) {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		http.NotFound(w, r)
	case errors.Is(err, fs.ErrPermission):
		http.Error(w, "Forbidden", http.StatusForbidden)
	default:
		// os.Root refuses a path that would escape the directory: that is a
		// blocked request, not a server fault
		s.log.Warn("static file refused",
			"id", middleware.IDOf(r), "dir", s.dir, "path", name, "error", err)
		http.NotFound(w, r)
	}
}

func (s *Serve) list(w http.ResponseWriter, r *http.Request, dir *os.File) {
	entries, err := dir.ReadDir(-1)
	if err != nil {
		s.log.Error("cannot list directory", "id", middleware.IDOf(r), "dir", s.dir, "path", r.URL.Path, "error", err)
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
	_, _ = io.WriteString(w, body.String())
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

// directoryLocation is where a request for a directory without a trailing
// slash is sent. It never emits a location starting with "//": a browser reads
// that as another host, which would make this an open redirect.
func directoryLocation(urlPrefix, name string) string {
	location := urlPrefix + name + "/"
	if !strings.HasPrefix(location, "/") || strings.HasPrefix(location, "//") {
		return path.Base(name) + "/"
	}
	return location
}

// localRedirect sends the client to newPath, preserving the query string.
func localRedirect(w http.ResponseWriter, r *http.Request, newPath string) {
	if query := r.URL.RawQuery; query != "" {
		newPath += "?" + query
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(http.StatusMovedPermanently)
}
