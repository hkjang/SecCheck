package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWriteCSVIsExcelReadable(t *testing.T) {
	rec := httptest.NewRecorder()
	stamp := time.Date(2026, 8, 21, 9, 30, 0, 0, time.UTC)
	writeCSV(rec, "seccheck-audit", []string{"timestamp", "event_type", "user_name", "after_value"}, []map[string]any{
		{"timestamp": stamp, "event_type": "LOGIN_LOCKED", "user_name": "김보안, 팀장", "after_value": map[string]any{"locked_until": "2026-08-21T09:45:00Z"}},
		{"timestamp": nil, "event_type": "LOGIN", "user_name": nil, "after_value": nil},
	})
	body := rec.Body.String()
	if !strings.HasPrefix(body, "\ufeff") {
		t.Fatal("missing UTF-8 BOM; Excel would mangle the Korean columns")
	}
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="seccheck-audit.csv"` {
		t.Fatalf("Content-Disposition = %q", got)
	}
	lines := strings.Split(strings.TrimSpace(strings.TrimPrefix(body, "\ufeff")), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected a header and two rows, got %d lines: %q", len(lines), body)
	}
	if !strings.Contains(lines[1], `"김보안, 팀장"`) {
		t.Errorf("a value containing a comma must stay quoted: %s", lines[1])
	}
	if !strings.Contains(lines[1], "2026-08-21T09:30:00Z") {
		t.Errorf("timestamp was not rendered as RFC3339: %s", lines[1])
	}
	if !strings.Contains(lines[1], "locked_until") {
		t.Errorf("structured payload was dropped: %s", lines[1])
	}
	if strings.TrimSpace(lines[2]) != ",LOGIN,," {
		t.Errorf("nil values should render as empty cells, got %q", lines[2])
	}
}

// A review can be named anything its requester types, and the admin who
// exports the list opens the file in Excel.
func TestWriteCSVDoesNotHandExcelAFormula(t *testing.T) {
	rec := httptest.NewRecorder()
	writeCSV(rec, "seccheck-reviews", []string{"title", "owner", "score", "note"}, []map[string]any{
		{"title": `=cmd|'/c calc'!A0`, "owner": "@메일", "score": -4, "note": "정상 문구"},
	})
	row := strings.Split(strings.TrimSpace(strings.TrimPrefix(rec.Body.String(), "\ufeff")), "\n")[1]
	for _, want := range []string{`'=cmd`, `'@메일`} {
		if !strings.Contains(row, want) {
			t.Errorf("a formula cell was exported unescaped, expected %s in: %s", want, row)
		}
	}
	if !strings.Contains(row, ",-4,") {
		t.Errorf("a negative number must stay a number: %s", row)
	}
	if !strings.Contains(row, "정상 문구") || strings.Contains(row, "'정상") {
		t.Errorf("ordinary text must not be touched: %s", row)
	}
}

func TestCapExportMarksOnlyTheOverflow(t *testing.T) {
	full := make([]map[string]any, exportRowCap+1)
	rec := httptest.NewRecorder()
	kept, truncated := capExport(rec, full)
	if !truncated || len(kept) != exportRowCap {
		t.Fatalf("kept %d rows, truncated=%v", len(kept), truncated)
	}
	if got := rec.Header().Get("X-Export-Truncated"); got != "50000" {
		t.Errorf("X-Export-Truncated = %q", got)
	}
	exact := httptest.NewRecorder()
	if kept, truncated = capExport(exact, full[:exportRowCap]); truncated || len(kept) != exportRowCap {
		t.Errorf("an export of exactly the cap was reported as truncated")
	}
	if got := exact.Header().Get("X-Export-Truncated"); got != "" {
		t.Errorf("a complete export set X-Export-Truncated to %q", got)
	}
}
