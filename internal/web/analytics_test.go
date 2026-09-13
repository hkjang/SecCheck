package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hkjang/SecCheck/internal/analytics"
)

// cachedServer is a Server whose tracking settings are already in the cache,
// so the handlers under test never reach for a database.
func cachedServer(config analytics.Config) *Server {
	return &Server{analyticsConf: config, analyticsAt: time.Now(), violations: analytics.NewRecorder()}
}

func TestPagePolicyIsTheStrictOneUntilTrackingIsOn(t *testing.T) {
	off := pagePolicy(analytics.Config{}, "/reviews/1", "n0nce")
	want := "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests"
	if off != want {
		t.Fatalf("with tracking off the policy must be what it always was:\n got %s\nwant %s", off, want)
	}
	if strings.Contains(off, "nonce") || strings.Contains(off, "report-uri") {
		t.Fatal("an idle policy must carry neither a nonce nor a report-uri")
	}

	on := analytics.Config{Enabled: true, Provider: analytics.ProviderCustom, CustomSnippet: `<script src="https://cdn.tracker.example/t.js"></script>`, AllowedHosts: "https://collect.example"}
	policy := pagePolicy(on, "/reviews/1", "n0nce")
	for _, part := range []string{"script-src 'self' 'nonce-n0nce' https://cdn.tracker.example https://collect.example;", "connect-src 'self' https://cdn.tracker.example https://collect.example;", "img-src 'self' data: blob: https://cdn.tracker.example https://collect.example;", "; report-uri " + cspReportPath} {
		if !strings.Contains(policy, part) {
			t.Errorf("policy lacks %q: %s", part, policy)
		}
	}
	if strings.Contains(policy, "unsafe-inline") {
		t.Fatalf("the policy must never be loosened with 'unsafe-inline': %s", policy)
	}
	if admin := pagePolicy(on, "/admin/settings", "n0nce"); admin != want {
		t.Fatalf("an administrative page stays strict unless include_admin is set: %s", admin)
	}
	if api := pagePolicy(on, "/api/v1/me", "n0nce"); api != want {
		t.Fatalf("pagePolicy on a non-page path adds nothing: %s", api)
	}
}

func TestMomentoThroughTheProxyNamesNoExternalOrigin(t *testing.T) {
	config := analytics.Config{Enabled: true, Provider: analytics.ProviderMomento, MomentoURL: "https://momento.internal", MomentoSiteID: "seccheck"}
	policy := pagePolicy(config, "/", "abc")
	if strings.Contains(policy, "momento.internal") {
		t.Fatalf("the proxied setup must not put the collector into the policy: %s", policy)
	}
	if !strings.Contains(policy, "script-src 'self' 'nonce-abc';") {
		t.Fatalf("only the nonce is added: %s", policy)
	}
}

func TestSPAInjectsTheSnippetOnlyWhereTheServerSays(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html><head></head><body></body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := cachedServer(analytics.Config{Enabled: true, Provider: analytics.ProviderCustom, CustomSnippet: "<script>t()</script>", Placement: "body"})
	handler := SPA{Dir: dir, Inject: s.inject}

	serve := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(context.WithValue(req.Context(), nonceKey, "n0nce"))
		handler.ServeHTTP(rec, req)
		return rec
	}
	page := serve("/reviews/1")
	if page.Code != 200 || !strings.Contains(page.Body.String(), `<script nonce="n0nce">t()</script>`+"\n</body>") {
		t.Fatalf("page: %d %s", page.Code, page.Body.String())
	}
	if ct := page.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content type %q", ct)
	}
	if admin := serve("/admin/settings"); strings.Contains(admin.Body.String(), "<script") {
		t.Fatalf("administrative shell must be untouched: %s", admin.Body.String())
	}
	s.analyticsConf.Enabled = false
	if off := serve("/reviews/1"); off.Body.String() != "<html><head></head><body></body></html>" {
		t.Fatalf("with tracking off the shell is served byte for byte: %s", off.Body.String())
	}
}

func TestCSPReportsAreKeptOnlyWhileTrackingIsOn(t *testing.T) {
	s := cachedServer(analytics.Config{Enabled: true, Provider: analytics.ProviderGA4, MeasurementID: "G-1"})
	report := `{"csp-report":{"document-uri":"https://seccheck.internal/reviews/1","blocked-uri":"https://collect.example/v1/hit","violated-directive":"connect-src 'self'","effective-directive":"connect-src"}}`
	post := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, cspReportPath, strings.NewReader(report))
		req.Header.Set("Content-Type", "application/csp-report")
		s.receiveCSPReport(rec, req)
		return rec.Code
	}
	if code := post(); code != http.StatusNoContent {
		t.Fatalf("a report is always accepted, got %d", code)
	}
	post()
	items := s.violations.List(s.analyticsConf)
	if len(items) != 1 || items[0].Origin != "https://collect.example" || items[0].Directive != "connect-src" || items[0].Count != 2 || items[0].Page != "/reviews/1" {
		t.Fatalf("unexpected record: %+v", items)
	}
	s.violations.Forget()
	s.analyticsConf.Enabled = false
	if code := post(); code != http.StatusNoContent {
		t.Fatalf("got %d", code)
	}
	if got := s.violations.List(s.analyticsConf); len(got) != 0 {
		t.Fatalf("with tracking off a stale page's report is dropped: %+v", got)
	}
}

func TestNoncesAreFreshAndUnguessable(t *testing.T) {
	a, b := newNonce(), newNonce()
	if a == "" || a == b || len(a) < 20 {
		t.Fatalf("nonces %q %q", a, b)
	}
}
