package web

import (
	"net/http"
	"strings"
	"testing"
)

func TestSecurityHeadersDisallowInlineCodeAndIsolateOrigins(t *testing.T) {
	header := make(http.Header)
	setSecurityHeaders(header)
	csp := header.Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "style-src 'self'") {
		t.Fatalf("unexpected CSP: %s", csp)
	}
	want := map[string]string{
		"Cross-Origin-Embedder-Policy": "require-corp",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
	}
	for key, value := range want {
		if got := header.Get(key); got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
}
