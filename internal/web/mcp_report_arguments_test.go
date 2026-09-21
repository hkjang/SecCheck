package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestMCPReviewReportArguments(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("report-arguments-writer", "REQUESTER")
	writer := h.login("report-arguments-writer")
	admin := h.login(adminOf(h))
	var ids []string
	for i := 0; i < 4; i++ {
		ids = append(ids, writer.createReview("report arguments fixture"))
	}
	for i, fixture := range []struct{ day, department string }{
		{"2025-12-15", "보안팀"}, {"2026-01-15", "보안팀"},
		{"2026-01-15", "개발팀"}, {"2026-02-15", "보안팀"},
	} {
		id := ids[i]
		if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET created_at=$2::date + interval '12 hours',department=$3 WHERE id=$1`, id, fixture.day, fixture.department); err != nil {
			t.Fatal(err)
		}
	}
	call := func(c *client, args map[string]any, modern bool) response {
		t.Helper()
		params := map[string]any{"name": "seccheck.review_report"}
		if args != nil {
			params["arguments"] = args
		}
		if modern {
			params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
		}
		payload := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}
		if !modern {
			return c.do(http.MethodPost, "/mcp", payload)
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, h.server.URL+"/mcp", strings.NewReader(string(raw)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", "seccheck.review_report")
		return c.send(req)
	}
	auditCount := func() int {
		t.Helper()
		var count int
		if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='MCP_TOOL_CALL' AND target_id='seccheck.review_report' AND result='SUCCESS'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	assertError := func(t *testing.T, res response, code int) map[string]any {
		t.Helper()
		body := res.json()
		e, ok := body["error"].(map[string]any)
		if res.status != http.StatusOK || !ok || e["code"] != float64(code) {
			t.Fatalf("want HTTP 200 RPC %d, got %d %s", code, res.status, res.body)
		}
		if _, ok := body["result"]; ok {
			t.Errorf("error contains result: %s", res.body)
		}
		if strings.Contains(res.body, "structuredContent") {
			t.Errorf("error contains structuredContent: %s", res.body)
		}
		return e
	}
	for _, modern := range []bool{false, true} {
		protocol := "compatibility"
		if modern {
			protocol = "2026-07-28"
		}
		t.Run(protocol, func(t *testing.T) {
			for _, field := range []string{"from", "to", "department"} {
				for _, invalid := range []struct {
					name  string
					value any
				}{
					{"number", 123}, {"boolean", true}, {"array", []any{"private-filter"}},
					{"object", map[string]any{"private-filter": "private-value"}}, {"null", nil},
				} {
					t.Run(field+"/"+invalid.name, func(t *testing.T) {
						before := auditCount()
						res := call(admin, map[string]any{field: invalid.value}, modern)
						// Check the audit independently, including when the RPC incorrectly succeeds.
						if after := auditCount(); after != before {
							t.Errorf("invalid call added %d successful audit events", after-before)
						}
						e := assertError(t, res, -32602)
						if e["message"] != field+" must be a string" || len(e) != 2 {
							t.Errorf("error should contain only the field and string requirement: %v", e)
						}
					})
				}
			}
		})
	}
	t.Run("requester remains forbidden", func(t *testing.T) {
		for _, args := range []map[string]any{nil, {"from": 123}, {"to": false}, {"department": nil}} {
			before := auditCount()
			assertError(t, call(writer, args, false), -32001)
			if auditCount() != before {
				t.Error("forbidden call added a successful audit event")
			}
		}
	})
	for _, tc := range []struct {
		name  string
		args  map[string]any
		count float64
	}{
		{"omitted", nil, 4}, {"empty object", map[string]any{}, 4},
		{"empty strings", map[string]any{"from": "", "to": "", "department": ""}, 4},
		{"whitespace", map[string]any{"from": " \t\n", "to": " \t\n", "department": " \t\n"}, 4},
		{"from", map[string]any{"from": "2026-01-01"}, 3},
		{"to", map[string]any{"to": "2026-01-31"}, 3},
		{"department", map[string]any{"department": "보안팀"}, 3},
		{"combined", map[string]any{"from": "2026-01-01", "to": "2026-01-31", "department": "보안팀"}, 1},
		{"trimmed", map[string]any{"from": " \t2026-01-01\n", "to": " 2026-01-31 ", "department": " 보안팀\t"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := url.Values{}
			for key, value := range tc.args {
				query.Set(key, strings.TrimSpace(value.(string)))
			}
			rest := admin.do(http.MethodGet, "/api/v1/reports/reviews?"+query.Encode(), nil)
			if rest.status != http.StatusOK {
				t.Fatalf("REST: %d %s", rest.status, rest.body)
			}
			for _, modern := range []bool{false, true} {
				before := auditCount()
				res := call(admin, tc.args, modern)
				result, ok := res.json()["result"].(map[string]any)
				if res.status != http.StatusOK || !ok || result["isError"] == true {
					t.Fatalf("MCP: %d %s", res.status, res.body)
				}
				data, ok := result["structuredContent"].(map[string]any)
				if !ok || !reflect.DeepEqual(data, rest.json()) {
					t.Fatalf("MCP and REST differ: MCP %s REST %s", res.body, rest.body)
				}
				totals, _ := data["totals"].(map[string]any)
				if totals["created"] != tc.count {
					t.Errorf("created=%v, want %v", totals["created"], tc.count)
				}
				if auditCount() != before+1 {
					t.Error("successful call did not add exactly one audit event")
				}
			}
		})
	}
}
