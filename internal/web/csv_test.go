package web

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func seoul(t *testing.T) *time.Location {
	t.Helper()
	zone, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		t.Skipf("no timezone database on this host: %v", err)
	}
	return zone
}

func TestWriteCSVIsExcelReadable(t *testing.T) {
	rec := httptest.NewRecorder()
	stamp := time.Date(2026, 8, 21, 9, 30, 0, 0, time.UTC)
	writeCSV(rec, "seccheck-audit", seoul(t), []string{"timestamp", "event_type", "user_name", "after_value"}, []map[string]any{
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
	if !strings.Contains(lines[1], "2026-08-21 18:30:00") {
		t.Errorf("the timestamp was not rendered in the display timezone: %s", lines[1])
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
	writeCSV(rec, "seccheck-reviews", time.UTC, []string{"title", "owner", "score", "note"}, []map[string]any{
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

// Text stored before those limits existed can still be longer than a
// spreadsheet cell allows, which makes the workbook unopenable rather than
// merely ugly.
func TestAnOverlongCellIsCutRatherThanBreakingTheWorkbook(t *testing.T) {
	if got := spreadsheetValue("짧은 값"); got != "짧은 값" {
		t.Errorf("an ordinary value was altered: %v", got)
	}
	if got := spreadsheetValue(42); got != 42 {
		t.Errorf("a number was altered: %v", got)
	}
	long := strings.Repeat("나", spreadsheetCellLimit+500)
	cut, ok := spreadsheetValue(long).(string)
	if !ok {
		t.Fatalf("a long string came back as %T", spreadsheetValue(long))
	}
	if len([]rune(cut)) > spreadsheetCellLimit {
		t.Errorf("the cut value is still %d characters", len([]rune(cut)))
	}
	if !strings.HasSuffix(cut, "…(이하 생략)") {
		t.Error("the cut value does not say that it was cut")
	}
}

// A row that cannot be read used to end the loop and hand back what had been
// collected so far, as if that were the whole answer -- a short list, with no
// error, in a product whose lists are the record.
type halfRows struct {
	rows   [][]any
	at     int
	broken int
}

func (h *halfRows) Next() bool { h.at++; return h.at <= len(h.rows) }
func (h *halfRows) Values() ([]any, error) {
	if h.at == h.broken {
		return nil, errors.New("connection lost")
	}
	return h.rows[h.at-1], nil
}
func (h *halfRows) Close()     {}
func (h *halfRows) Err() error { return nil }

func TestAPartialReadIsNotAnAnswer(t *testing.T) {
	whole := &halfRows{rows: [][]any{{"a", 1}, {"b", 2}, {"c", 3}}}
	items, err := scanDynamic(whole, []string{"name", "count"})
	if err != nil {
		t.Fatalf("a complete read reported %v", err)
	}
	if len(items) != 3 || items[2]["name"] != "c" {
		t.Fatalf("the complete read returned %v", items)
	}

	broken := &halfRows{rows: [][]any{{"a", 1}, {"b", 2}, {"c", 3}}, broken: 2}
	items, err = scanDynamic(broken, []string{"name", "count"})
	if err == nil {
		t.Fatalf("a read that failed half way returned %d rows and no error", len(items))
	}
	if items != nil {
		t.Errorf("the partial rows were handed back anyway: %v", items)
	}
}
