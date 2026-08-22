package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubService answers the calls the selftest makes. Handlers listed in broken
// answer 500 instead, so a failing deployment can be simulated.
func stubService(t *testing.T, broken map[string]bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	answer := func(path string, body any) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if broken[path] {
				http.Error(w, `{"error":{"message":"고장"}}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		})
	}
	answer("/health", map[string]any{"status": "ok"})
	answer("/ready", map[string]any{"status": "ready"})
	answer("/api/v1/auth/login", map[string]any{"csrf_token": "t", "user": map[string]any{"id": "u1", "roles": []string{"REQUESTER"}}})
	answer("/api/openapi.json", map[string]any{"paths": map[string]any{"/api/v1/me": map[string]any{}}})
	answer("/api/v1/templates", map[string]any{"items": []map[string]any{{"name": "개발보안"}}})
	answer("/api/v1/admin/audit/verify", map[string]any{"valid": true, "checked": 3})
	answer("/api/v1/review-requests", map[string]any{"id": "r1"})
	answer("/api/v1/review-requests/r1", map[string]any{"review_number": "SC-2026-000001", "progress": map[string]any{"total": 12}})
	answer("/api/v1/review-requests/r1/cancel", map[string]any{"status": "CANCELLED"})
	for _, format := range []string{"xlsx", "pdf", "zip"} {
		path := "/api/v1/review-requests/r1/export/" + format
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if broken[path] {
				http.Error(w, "FONT_MISSING", http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
		})
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestSelftestPassesAgainstAWorkingService(t *testing.T) {
	server := stubService(t, nil)
	if code := runSelftest([]string{"--base-url", server.URL, "--username", "admin", "--password", "secret", "--full"}); code != 0 {
		t.Fatalf("selftest returned %d against a healthy service", code)
	}
}

// The PDF export needs the Korean font present in the image, which is exactly
// the kind of packaging fault a built image can carry while every test passes.
func TestSelftestFailsWhenAnExportIsBroken(t *testing.T) {
	server := stubService(t, map[string]bool{"/api/v1/review-requests/r1/export/pdf": true})
	if code := runSelftest([]string{"--base-url", server.URL, "--username", "admin", "--password", "secret", "--full"}); code != 1 {
		t.Errorf("a broken PDF export returned %d, want 1", code)
	}
	// Without --full the export is never attempted, so the same service passes.
	if code := runSelftest([]string{"--base-url", server.URL, "--username", "admin", "--password", "secret"}); code != 0 {
		t.Errorf("the read-only run returned %d", code)
	}
}

func TestSelftestFailsOnABrokenChainOrMissingTemplates(t *testing.T) {
	server := stubService(t, map[string]bool{"/api/v1/admin/audit/verify": true})
	if code := runSelftest([]string{"--base-url", server.URL, "--username", "admin", "--password", "secret"}); code != 1 {
		t.Errorf("a failing chain verification returned %d, want 1", code)
	}
}

func TestSelftestRequiresCredentials(t *testing.T) {
	if code := runSelftest([]string{"--base-url", "http://127.0.0.1:1"}); code != 2 {
		t.Errorf("missing credentials returned %d, want 2", code)
	}
	if code := runSelftest([]string{"--nonsense"}); code != 2 {
		t.Errorf("an unknown flag returned %d, want 2", code)
	}
}

// The review the full run creates is cancelled again, so repeating the check
// against a staging environment does not pile up drafts.
func TestSelftestCancelsTheReviewItCreated(t *testing.T) {
	cancelled := false
	server := stubService(t, nil)
	// stubService already answers the cancel; this records that it is called.
	client := &selftestClient{base: server.URL, http: server.Client()}
	steps := client.run("admin", "secret", true)
	for _, step := range steps {
		if step.name == "review-cancel" {
			cancelled = step.err == nil
		}
	}
	if !cancelled {
		t.Error("the full run did not cancel the review it created")
	}
}
