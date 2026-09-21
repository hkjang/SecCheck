package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"
)

func reportMCP(t *testing.T, c *client, from, to string) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "seccheck.review_report", "arguments": map[string]any{"from": from, "to": to}}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, c.h.server.URL+"/mcp", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	res := c.send(req)
	result, ok := res.json()["result"].(map[string]any)
	if res.status != 200 || !ok || res.json()["error"] != nil {
		t.Fatalf("MCP: %d %s", res.status, res.body)
	}
	return result
}

func TestReportDateFilterRejectsInvalidDates(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	cases := []struct {
		name, from, to string
		fields         []string
	}{}
	for _, value := range []string{"not-a-date", "2026-02-30", "0000-01-01", "2026-2-03", "2026-02-3", "2026-02-03T00:00:00Z", "10000-01-01", "2025-02-29"} {
		cases = append(cases, struct {
			name, from, to string
			fields         []string
		}{"from_" + value, value, "", []string{"from"}}, struct {
			name, from, to string
			fields         []string
		}{"to_" + value, "", value, []string{"to"}})
	}
	cases = append(cases, struct {
		name, from, to string
		fields         []string
	}{"reversed", "2026-03-02", "2026-03-01", []string{"from", "to"}}, struct {
		name, from, to string
		fields         []string
	}{"both_invalid", "bad-from", "bad-to", []string{"from", "to"}})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, format := range []string{"json", "xlsx"} {
				t.Run(format, func(t *testing.T) {
					q := url.Values{"from": {tc.from}, "to": {tc.to}, "format": {format}}
					res := admin.do(http.MethodGet, "/api/v1/reports/reviews?"+q.Encode(), nil)
					if res.status != 422 || res.errorCode() != "VALIDATION_FAILED" {
						t.Fatalf("want 422 VALIDATION_FAILED, got %d code=%s", res.status, res.errorCode())
					}
					details, _ := res.json()["error"].(map[string]any)["details"].(map[string]any)
					for _, field := range tc.fields {
						if details[field] == nil || details[field] == "" {
							t.Errorf("missing %s detail: %s", field, res.body)
						}
					}
				})
			}
			t.Run("mcp", func(t *testing.T) {
				result := reportMCP(t, admin, tc.from, tc.to)
				if result["isError"] != true {
					t.Fatalf("want tool error, got %v", result)
				}
				content, _ := result["content"].([]any)
				if len(content) != 1 {
					t.Fatalf("invalid tool error: %v", result)
				}
				message, _ := content[0].(map[string]any)["text"].(string)
				if !strings.Contains(message, "YYYY-MM-DD") || !strings.Contains(message, "from") || !strings.Contains(message, "to") {
					t.Errorf("missing safe date guidance: %s", message)
				}
				if strings.Contains(message, "SQLSTATE") || strings.Contains(message, "not-a-date") || strings.Contains(message, "bad-from") {
					t.Errorf("raw input or DB error exposed: %s", message)
				}
			})
		})
	}
}

func TestReportDateFilterKeepsAllTransportsInAgreement(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	h.user("date-writer", "REQUESTER")
	writer := h.login("date-writer")
	ids := make([]string, 4)
	for i := range ids {
		ids[i] = writer.createReview(fmt.Sprintf("date boundary %d", i))
	}
	// UTC instants straddle the display day's boundaries in the default Asia/Seoul zone.
	for i, stamp := range []string{"2024-02-28T14:59:59Z", "2024-02-28T15:00:00Z", "2024-02-29T14:59:59.999999Z", "2024-02-29T15:00:00Z"} {
		id := ids[i]
		if _, err := h.db.Pool.Exec(context.Background(), `UPDATE review_requests SET created_at=$2::timestamptz WHERE id=$1`, id, stamp); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, from, to string
		count          float64
	}{
		{"unbounded", "", "", 4}, {"blank", " \t ", " \n ", 4}, {"from_only", "2024-02-29", "", 3}, {"to_only", "", "2024-02-29", 3}, {"same_leap_day", "2024-02-29", "2024-02-29", 2}, {"trimmed", " 2024-02-29 ", " 2024-02-29 ", 2}, {"year_bounds", "0001-01-01", "9999-12-31", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{"from": {tc.from}, "to": {tc.to}}
			res := admin.do(http.MethodGet, "/api/v1/reports/reviews?"+q.Encode(), nil)
			if res.status != 200 {
				t.Fatalf("JSON: %d %s", res.status, res.body)
			}
			report := res.json()
			totals, _ := report["totals"].(map[string]any)
			if totals["created"] != tc.count {
				t.Fatalf("created: %v, want %v", totals, tc.count)
			}
			if report["from"] != strings.TrimSpace(tc.from) || report["to"] != strings.TrimSpace(tc.to) {
				t.Fatalf("noncanonical dates: %v", report)
			}
			result := reportMCP(t, admin, tc.from, tc.to)
			if result["isError"] == true || !reflect.DeepEqual(report, result["structuredContent"]) {
				t.Fatalf("MCP disagrees: %v / %v", report, result)
			}
			q.Set("format", "xlsx")
			xlsx := admin.do(http.MethodGet, "/api/v1/reports/reviews?"+q.Encode(), nil)
			if xlsx.status != 200 {
				t.Fatalf("Excel: %d %s", xlsx.status, xlsx.body)
			}
			book, err := excelize.OpenReader(strings.NewReader(xlsx.body))
			if err != nil {
				t.Fatal(err)
			}
			defer book.Close()
			for i, key := range []string{"created", "submitted", "completed", "rejected", "in_progress"} {
				got, err := book.GetCellValue("요약", fmt.Sprintf("B%d", i+5))
				if err != nil {
					t.Fatal(err)
				}
				if got != fmt.Sprint(totals[key]) {
					t.Errorf("Excel %s=%s, JSON/MCP=%v", key, got, totals[key])
				}
			}
		})
	}
}

func TestReportDateFilterDoesNotExposeDatabaseErrors(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	// Break the real report query in this test's isolated schema. Only known
	// date validation errors may become actionable MCP guidance.
	if _, err := h.db.Pool.Exec(context.Background(), `ALTER TABLE review_requests RENAME COLUMN created_at TO unavailable_created_at`); err != nil {
		t.Fatal(err)
	}
	result := reportMCP(t, admin, "2024-02-29", "2024-02-29")
	if result["isError"] != true {
		t.Fatalf("want tool error: %v", result)
	}
	content, _ := result["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("invalid tool error: %v", result)
	}
	if message := content[0].(map[string]any)["text"]; message != "도구 실행에 실패했습니다." {
		t.Fatalf("database failure was not kept private: %v", message)
	}
}
