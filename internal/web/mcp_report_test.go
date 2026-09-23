package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
)

// callTool drives a tools/call over the real /mcp transport. The protocol
// header is deliberately absent: sending it makes validateMCPHeaders demand
// Mcp-Method, Mcp-Name and _meta as well, which is a different contract from
// the one under test.
func (c *client) callTool(t *testing.T, query, tool string, arguments map[string]any) map[string]any {
	t.Helper()
	if arguments == nil {
		arguments = map[string]any{}
	}
	res := c.do(http.MethodPost, "/mcp"+query, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": arguments},
	})
	if res.status != http.StatusOK {
		t.Fatalf("tools/call %s%s: status %d body %s", tool, query, res.status, res.body)
	}
	payload := res.json()
	if rpcErr, ok := payload["error"].(map[string]any); ok {
		t.Fatalf("tools/call %s%s returned an error: %v", tool, query, rpcErr)
	}
	result, _ := payload["result"].(map[string]any)
	if result == nil {
		t.Fatalf("tools/call %s%s returned no result: %s", tool, query, res.body)
	}
	if isError, _ := result["isError"].(bool); isError {
		t.Fatalf("tools/call %s%s reported a tool error: %s", tool, query, res.body)
	}
	structured, _ := result["structuredContent"].(map[string]any)
	if structured == nil {
		t.Fatalf("tools/call %s%s returned no structuredContent: %s", tool, query, res.body)
	}
	return structured
}

func followUpCount(t *testing.T, report map[string]any) int {
	t.Helper()
	rows, ok := report["follow_ups"].([]any)
	if !ok {
		t.Fatalf("the report carries no follow_ups list: %v", report["follow_ups"])
	}
	return len(rows)
}

// The MCP tool schema declares from, to and department and nothing else. The
// report scope used to start from the query string of the POST itself, so a
// caller could widen the answer with include_done or format=xlsx -- keys the
// catalogue never advertised and the audit record never captured, leaving the
// filter that ran and the arguments that were logged out of step.
func TestMCPReviewReportIgnoresTheRequestQueryString(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("mcpreport-writer", "REQUESTER")
	h.user("mcpreport-reviewer", "SECURITY_REVIEWER")
	writer := h.login("mcpreport-writer")
	reviewer := h.login("mcpreport-reviewer")

	var reviewerID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='mcpreport-reviewer'`).Scan(&reviewerID); err != nil {
		t.Fatal(err)
	}

	// Two reviews in different departments, each owing a follow-up, so a
	// department argument and the include_done switch both move real rows.
	open := writer.createReview("MCP 리포트 열린 서비스")
	closed := writer.createReview("MCP 리포트 닫힌 서비스")
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET department='인프라팀' WHERE id=$1`, closed); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []struct {
		review string
		done   bool
	}{{open, false}, {closed, true}} {
		itemID := firstItemID(t, h, seed.review)
		if _, err := h.db.Pool.Exec(ctx, `INSERT INTO review_results(id,submission_item_id,reviewer_id,result,opinion,follow_up,follow_up_due_date) VALUES($1,$2,$3,'CONDITIONAL','조건부','로그 보존 연장',current_date+30)`,
			store.NewID(), itemID, reviewerID); err != nil {
			t.Fatal(err)
		}
		if seed.done {
			if _, err := h.db.Pool.Exec(ctx, `UPDATE review_results SET follow_up_done_at=now(),follow_up_done_by=$2 WHERE submission_item_id=$1`, itemID, reviewerID); err != nil {
				t.Fatal(err)
			}
		}
	}

	plain := reviewer.callTool(t, "", "seccheck.review_report", nil)
	// The fixture has to make the query string capable of changing the answer,
	// otherwise the test would pass for the wrong reason.
	if got := followUpCount(t, plain); got != 1 {
		t.Fatalf("the default register holds %d outstanding actions, want the one that is not done", got)
	}

	// include_done and format are not in the tool schema at all, so on their own
	// they must leave the answer exactly as it was.
	offSchema := reviewer.callTool(t, "?include_done=1&format=xlsx", "seccheck.review_report", nil)
	if got := followUpCount(t, offSchema); got != followUpCount(t, plain) {
		t.Errorf("include_done in the URL put %d rows in the register, want %d", got, followUpCount(t, plain))
	}

	// Every key here is either outside the tool schema (include_done, format)
	// or inside it but not supplied as an argument (from, to, department).
	widened := reviewer.callTool(t, "?from=2020-01-01&to=2020-01-02&department=%EC%9D%B8%ED%94%84%EB%9D%BC%ED%8C%80&include_done=1&format=xlsx", "seccheck.review_report", nil)

	want, _ := json.Marshal(plain)
	got, _ := json.Marshal(widened)
	if string(want) != string(got) {
		t.Errorf("the URL query changed the report.\n query-free: %s\n with query: %s", want, got)
	}
	if widened["from"] != "" || widened["to"] != "" {
		t.Errorf("the URL dates leaked into the report scope: from=%v to=%v", widened["from"], widened["to"])
	}
	if departments, _ := widened["by_department"].([]any); len(departments) != 2 {
		t.Errorf("the URL department narrowed the breakdown to %d rows, want both departments", len(departments))
	}

	// Tool arguments still filter, and they are what the audit record holds.
	scoped := reviewer.callTool(t, "?department=%EC%9D%B8%ED%94%84%EB%9D%BC%ED%8C%80", "seccheck.review_report", map[string]any{"department": "보안팀"})
	if departments, _ := scoped["by_department"].([]any); len(departments) != 1 {
		t.Fatalf("the department argument returned %d department rows, want 1", len(departments))
	}
	if followUpCount(t, scoped) != 1 {
		t.Errorf("the register under the department argument holds %d rows, want the 보안팀 action", followUpCount(t, scoped))
	}
	if scoped["from"] != "" || scoped["to"] != "" {
		t.Errorf("an omitted date argument still produced a bounded period: from=%v to=%v", scoped["from"], scoped["to"])
	}
	bounded := reviewer.callTool(t, "", "seccheck.review_report", map[string]any{"from": "2020-01-01", "to": "2020-01-02"})
	if bounded["from"] != "2020-01-01" || bounded["to"] != "2020-01-02" {
		t.Errorf("the date arguments were dropped: from=%v to=%v", bounded["from"], bounded["to"])
	}
	if totals, _ := bounded["totals"].(map[string]any); totals["created"].(float64) != 0 {
		t.Errorf("a period with no reviews counted %v of them", totals["created"])
	}

	// The audit trail has to describe the filter that actually ran.
	var details []byte
	if err := h.db.Pool.QueryRow(ctx, `SELECT after_value FROM audit_logs WHERE event_type='MCP_TOOL_CALL' AND target_id='seccheck.review_report' ORDER BY chain_sequence LIMIT 1`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	var logged struct {
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(details, &logged); err != nil {
		t.Fatalf("audit details are not the expected shape: %s", details)
	}
	if len(logged.Arguments) != 0 {
		t.Errorf("the argument-free call was audited with %v", logged.Arguments)
	}
	var scopedDetails []byte
	if err := h.db.Pool.QueryRow(ctx, `SELECT after_value FROM audit_logs WHERE event_type='MCP_TOOL_CALL' AND target_id='seccheck.review_report' AND after_value->'arguments' ? 'department' ORDER BY chain_sequence LIMIT 1`).Scan(&scopedDetails); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(scopedDetails, &logged); err != nil {
		t.Fatalf("audit details are not the expected shape: %s", scopedDetails)
	}
	if logged.Arguments["department"] != "보안팀" {
		t.Errorf("the audit record says department=%v, but 보안팀 is what was filtered on", logged.Arguments["department"])
	}
}
