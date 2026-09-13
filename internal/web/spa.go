package web

import (
	"bytes"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// SPA serves the built web assets. Inject, when set, is given the app shell
// on every page request and may return it with a tracking snippet added; it
// gets the request so it can read the per-request nonce and the path.
type SPA struct {
	Dir    string
	Inject func(r *http.Request, page []byte) []byte
}

func (s SPA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/mcp" || r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/metrics" {
		http.NotFound(w, r)
		return
	}
	clean := path.Clean("/" + r.URL.Path)
	file := path.Join(s.Dir, clean)
	if st, err := os.Stat(file); err == nil && !st.IsDir() {
		setStaticHeaders(w, file)
		http.ServeFile(w, r, file)
		return
	}
	if path.Ext(clean) != "" {
		http.NotFound(w, r)
		return
	}
	index := path.Join(s.Dir, "index.html")
	if _, err := os.Stat(index); err != nil {
		http.Error(w, "SecCheck web assets are not installed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.Inject == nil {
		http.ServeFile(w, r, index)
		return
	}
	page, err := os.ReadFile(index)
	if err != nil {
		http.Error(w, "SecCheck web assets are not installed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(s.Inject(r, page)))
}

func setStaticHeaders(w http.ResponseWriter, file string) {
	if strings.Contains(file, "/assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func Exists(dir string) bool { _, err := fs.Stat(os.DirFS(dir), "index.html"); return err == nil }
