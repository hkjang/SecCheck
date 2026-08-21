package web

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every audit event the code records must be named, or an auditor reads raw
// identifiers like UPDATE_SUBMISSION in a Korean report and the filter
// dropdown silently omits it.
func TestEveryAuditEventIsNamed(t *testing.T) {
	for _, code := range emittedCodes(t, `auditFrom\(r, "([A-Z_]{3,})"`, `EventType: "([A-Z_]{3,})"`) {
		if auditEventLabels[code] == "" {
			t.Errorf("audit event %s is recorded but has no label in auditEventLabels", code)
		}
	}
}

// Every notification the code sends must be in the preference catalogue, or
// the recipient cannot turn it off and the list shows a bare code.
func TestEveryNotificationEventIsInThePreferenceCatalogue(t *testing.T) {
	known := map[string]bool{}
	for _, event := range notificationEvents {
		known[event["code"]] = true
	}
	for _, code := range emittedNotificationCodes(t) {
		if !known[code] {
			t.Errorf("notification %s is sent but is not in notificationEvents, so nobody can mute it", code)
		}
	}
	// And nothing in the catalogue should be an event that is never sent.
	sent := map[string]bool{}
	for _, code := range emittedNotificationCodes(t) {
		sent[code] = true
	}
	for _, event := range notificationEvents {
		if !sent[event["code"]] {
			t.Errorf("notificationEvents offers %s but nothing ever sends it", event["code"])
		}
	}
}

func emittedNotificationCodes(t *testing.T) []string {
	t.Helper()
	// The argument lists contain nested calls such as r.Context(), so the
	// scan is bounded by distance rather than by the next closing bracket.
	codes := emittedCodes(t,
		`(?s)addTargetedNotification\(.{0,160}?"([A-Z_]{3,})"`,
		`(?s)addNotification\(.{0,160}?"([A-Z_]{3,})"`,
		`(?s)notifyReviewer\(.{0,160}?"([A-Z_]{3,})"`,
		`(?s)INSERT INTO notifications\(.{0,200}?'([A-Z_]{3,})'`,
	)
	// Approve and reject pass the decision through as the event type.
	return append(codes, "APPROVED", "REJECTED")
}

// emittedCodes scans the non-test sources of the whole module for the given
// patterns. Reading the source is cruder than a type-checked registry, but it
// cannot be bypassed by adding a call site somewhere new.
func emittedCodes(t *testing.T, patterns ...string) []string {
	t.Helper()
	var source strings.Builder
	for _, dir := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr == nil {
				source.Write(body)
				source.WriteString("\n")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, pattern := range patterns {
		for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(source.String(), -1) {
			// REVIEW_REQUEST is the notification target type, not an event.
			if m[1] == "REVIEW_REQUEST" || seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// The README sells REST/OpenAPI integration, so the document has to describe
// the whole API. It used to be a hand-maintained subset covering a third of
// the endpoints, which misleads an integrator more than having none.
func TestOpenAPIDescribesEveryAPIRoute(t *testing.T) {
	s := &Server{mux: http.NewServeMux()}
	s.routes()

	var api int
	seen := map[string]bool{}
	for _, route := range s.api {
		if !strings.HasPrefix(route.Path, "/api/") && route.Path != "/mcp" {
			continue
		}
		api++
		if route.Summary == "" {
			t.Errorf("%s %s has no summary", route.Method, route.Path)
		}
		if route.Tag == "" {
			t.Errorf("%s %s has no tag", route.Method, route.Path)
		}
		id := operationID(route)
		if seen[id] {
			t.Errorf("operationId %s is not unique", id)
		}
		seen[id] = true
	}
	if api < 90 {
		t.Fatalf("only %d API routes were registered; the table looks incomplete", api)
	}
}
