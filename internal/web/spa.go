package web

import (
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

type SPA struct{ Dir string }

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
	index := path.Join(s.Dir, "index.html")
	if _, err := os.Stat(index); err != nil {
		http.Error(w, "SecCheck web assets are not installed", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, index)
}

func setStaticHeaders(w http.ResponseWriter, file string) {
	if strings.Contains(file, "/assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func Exists(dir string) bool { _, err := fs.Stat(os.DirFS(dir), "index.html"); return err == nil }
