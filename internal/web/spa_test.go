package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSPACacheAndFallbackPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("app shell"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "assets", "app.js"), []byte("export{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler := SPA{Dir: dir}

	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
	if asset.Code != http.StatusOK || asset.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("unexpected asset response: status=%d cache=%q", asset.Code, asset.Header().Get("Cache-Control"))
	}

	route := httptest.NewRecorder()
	handler.ServeHTTP(route, httptest.NewRequest(http.MethodGet, "/reviews/123", nil))
	if route.Code != http.StatusOK || route.Body.String() != "app shell" || route.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected route fallback: status=%d cache=%q body=%q", route.Code, route.Header().Get("Cache-Control"), route.Body.String())
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing static file returned %d, want 404", missing.Code)
	}
}
