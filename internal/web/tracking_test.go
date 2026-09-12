package web_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The pages are locked to script-src 'self', so a tracking snippet pasted in
// would be dropped silently. Turning tracking on has to change exactly three
// things -- the snippet in the shell, a nonce that ties it to the policy,
// and the origins it needs -- and turning it off has to leave nothing
// behind.
func TestVisitorTrackingIsOffUntilAnAdministratorTurnsItOn(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(filepath.Join(h.webDir, "index.html"), []byte("<!doctype html><html><head><title>SecCheck</title></head><body><div id=\"root\"></div></body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.user("tracking-admin", "SYSTEM_ADMIN")
	admin := h.login("tracking-admin")
	anyone := &client{h: h}

	strict := "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests"

	// Fresh install: the shell and the policy are exactly what they were.
	page := anyone.do(http.MethodGet, "/reviews/1", nil)
	if page.status != http.StatusOK || strings.Contains(page.body, "<script") {
		t.Fatalf("a fresh install must serve the bare shell: %d %s", page.status, page.body)
	}
	if got := page.raw.Header.Get("Content-Security-Policy"); got != strict {
		t.Fatalf("a fresh install's page policy changed:\n got %s\nwant %s", got, strict)
	}
	if got := admin.do(http.MethodGet, "/api/v1/me", nil).raw.Header.Get("Content-Security-Policy"); got != "default-src 'none'; frame-ancestors 'none'" {
		t.Fatalf("the API renders nothing and gets a policy that allows nothing: %s", got)
	}
	if res := anyone.do(http.MethodGet, "/momento/tracker.js", nil); res.status != http.StatusNotFound {
		t.Fatalf("the collector proxy must not exist while Momento is not configured: %d", res.status)
	}

	// A snippet over the limit is refused, whether or not tracking is on.
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/analytics", map[string]any{"enabled": false, "provider": "custom", "custom_snippet": strings.Repeat("<script></script>", 600)}); res.status != http.StatusUnprocessableEntity || res.errorCode() != "VALIDATION_FAILED" {
		t.Fatalf("an 8KB+ snippet must be refused: %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/analytics", map[string]any{"enabled": true, "provider": "momento", "momento_url": "https://momento.internal"}); res.status != http.StatusUnprocessableEntity {
		t.Fatalf("momento without a site id must be refused: %d %s", res.status, res.body)
	}

	// A stand-in collector, reached only through the same-origin proxy.
	var collectorSawCookie, collectorHits int
	var collectorPath string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		collectorHits++
		collectorPath = r.URL.Path
		if r.Header.Get("Cookie") != "" {
			collectorSawCookie++
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("/* tracker */"))
	}))
	defer collector.Close()

	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/analytics", map[string]any{"enabled": true, "provider": "momento", "momento_url": collector.URL, "momento_site_id": "seccheck", "momento_proxy": true, "include_admin": false, "placement": "head"}); res.status != http.StatusOK {
		t.Fatalf("turning tracking on: %d %s", res.status, res.body)
	}

	page = anyone.do(http.MethodGet, "/reviews/1", nil)
	nonce := regexp.MustCompile(`<script nonce="([^"]+)" async src="/momento/tracker.js"[^>]*data-endpoint="/momento"></script>\n</head>`).FindStringSubmatch(page.body)
	if nonce == nil {
		t.Fatalf("the momento snippet must sit at the end of <head> with a nonce: %s", page.body)
	}
	policy := page.raw.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'self' 'nonce-"+nonce[1]+"';") {
		t.Fatalf("the policy must carry the same nonce as the snippet: %s", policy)
	}
	if !strings.HasSuffix(policy, "; report-uri /api/v1/analytics/csp-report") || strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, collector.URL) {
		t.Fatalf("a proxied Momento names no external origin and never loosens the policy: %s", policy)
	}
	second := anyone.do(http.MethodGet, "/reviews/1", nil)
	if strings.Contains(second.body, nonce[1]) {
		t.Fatal("the nonce must change on every request")
	}
	if adminPage := admin.do(http.MethodGet, "/admin/settings", nil); strings.Contains(adminPage.body, "<script") || adminPage.raw.Header.Get("Content-Security-Policy") != strict {
		t.Fatalf("administrative screens stay untouched while include_admin is off: %s", adminPage.body)
	}
	if got := admin.do(http.MethodGet, "/api/v1/me", nil).raw.Header.Get("Content-Security-Policy"); got != "default-src 'none'; frame-ancestors 'none'" {
		t.Fatalf("the API policy does not widen with tracking: %s", got)
	}

	// The proxy forwards to the collector without this origin's cookies.
	if res := admin.do(http.MethodGet, "/momento/tracker.js", nil); res.status != http.StatusOK || res.body != "/* tracker */" || collectorPath != "/tracker.js" || collectorHits != 1 {
		t.Fatalf("proxy: %d %q path=%q hits=%d", res.status, res.body, collectorPath, collectorHits)
	}
	if collectorSawCookie != 0 {
		t.Fatal("the session cookie must never reach the collector")
	}

	// What the browser refuses is recorded once per origin and directive, and
	// one click puts it on the allow list.
	report := `{"csp-report":{"document-uri":"` + h.server.URL + `/reviews/1?tab=items","blocked-uri":"https://cdn.tracker.example/lib.js?v=3","effective-directive":"script-src-elem","violated-directive":"script-src-elem 'self'"}}`
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodPost, h.server.URL+"/api/v1/analytics/csp-report", strings.NewReader(report))
		req.Header.Set("Content-Type", "application/csp-report")
		if res := anyone.send(req); res.status != http.StatusNoContent {
			t.Fatalf("a report is accepted without credentials: %d %s", res.status, res.body)
		}
	}
	listed := admin.do(http.MethodGet, "/api/v1/admin/analytics/violations", nil)
	if !strings.Contains(listed.body, `"origin":"https://cdn.tracker.example"`) || !strings.Contains(listed.body, `"count":3`) || !strings.Contains(listed.body, `"allowed":false`) || !strings.Contains(listed.body, `"page":"/reviews/1"`) {
		t.Fatalf("violations: %s", listed.body)
	}
	if res := admin.do(http.MethodPost, "/api/v1/admin/analytics/allow", map[string]string{"origin": "cdn.tracker.example"}); res.status != http.StatusUnprocessableEntity {
		t.Fatalf("a bare host is not an origin: %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodPost, "/api/v1/admin/analytics/allow", map[string]string{"origin": "https://cdn.tracker.example"}); res.status != http.StatusOK || res.json()["allowed_hosts"] != "https://cdn.tracker.example" {
		t.Fatalf("allow: %d %s", res.status, res.body)
	}
	if listed = admin.do(http.MethodGet, "/api/v1/admin/analytics/violations", nil); !strings.Contains(listed.body, `"allowed":true`) {
		t.Fatalf("an allowed origin is marked so: %s", listed.body)
	}
	if policy := anyone.do(http.MethodGet, "/", nil).raw.Header.Get("Content-Security-Policy"); !strings.Contains(policy, "script-src 'self' 'nonce-") || !strings.Contains(policy, " https://cdn.tracker.example;") {
		t.Fatalf("the allowed origin is in the next page's policy: %s", policy)
	}
	if res := admin.do(http.MethodDelete, "/api/v1/admin/analytics/violations", nil); res.status != http.StatusNoContent {
		t.Fatalf("clear: %d", res.status)
	}
	if listed = admin.do(http.MethodGet, "/api/v1/admin/analytics/violations", nil); strings.TrimSpace(listed.body) != "[]" {
		t.Fatalf("cleared: %s", listed.body)
	}

	// Off again: the shell and the policy return to what they were, and the
	// proxy is gone.
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/analytics", map[string]any{"enabled": false, "provider": "momento", "momento_url": collector.URL, "momento_site_id": "seccheck", "allowed_hosts": "https://cdn.tracker.example"}); res.status != http.StatusOK {
		t.Fatalf("turning tracking off: %d %s", res.status, res.body)
	}
	page = anyone.do(http.MethodGet, "/reviews/1", nil)
	if strings.Contains(page.body, "<script") || page.raw.Header.Get("Content-Security-Policy") != strict {
		t.Fatalf("with tracking off nothing must remain: %s / %s", page.body, page.raw.Header.Get("Content-Security-Policy"))
	}
	if res := anyone.do(http.MethodGet, "/momento/tracker.js", nil); res.status != http.StatusNotFound {
		t.Fatalf("the proxy closes with tracking: %d", res.status)
	}
}
