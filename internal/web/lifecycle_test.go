package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// The whole point of the service, driven once from end to end by four
// different people: request, review, change request, resubmission, approval.
// Every piece had tests; the path through them had none, and begin-review and
// complete-review were never called by a test at all.
func TestAReviewGoesFromDraftToApproved(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	requesterID := h.user("lifecycle-requester", "REQUESTER")
	reviewerID := h.user("lifecycle-reviewer", "SECURITY_REVIEWER")
	approverID := h.user("lifecycle-approver", "APPROVER")
	requester := h.login("lifecycle-requester")
	reviewer := h.login("lifecycle-reviewer")
	approver := h.login("lifecycle-approver")

	// The approval step is what an organisation with a sign-off policy runs.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"approval_enabled":true}'::jsonb WHERE key='workflow'`); err != nil {
		t.Fatal(err)
	}

	status := func(id string) string {
		t.Helper()
		var s string
		if err := h.db.Pool.QueryRow(ctx, `SELECT status FROM review_requests WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	post := func(c *client, path string, body any, want int, step string) map[string]any {
		t.Helper()
		res := c.do(http.MethodPost, path, body)
		if res.status != want {
			t.Fatalf("%s: %d %s", step, res.status, res.body)
		}
		return res.json()
	}

	// 1. The requester creates the review; the rule engine assigns the list.
	reviewID := requester.createReview("생애주기 서비스")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("no checklist items were assigned")
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item["id"].(string))
	}

	// The reviewer and approver have to be named before submission when the
	// policy requires them.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2,approver_id=$3 WHERE id=$1`, reviewID, reviewerID, approverID); err != nil {
		t.Fatal(err)
	}

	// 2. Answering everything, then submitting.
	post(requester, "/api/v1/review-requests/"+reviewID+"/responses/bulk",
		map[string]any{"item_ids": ids, "applicability": "N/A", "na_reason": "이 서비스에 해당하지 않음", "self_assessment": "N/A"}, http.StatusOK, "bulk answer")
	post(requester, "/api/v1/review-requests/"+reviewID+"/submit", map[string]any{}, http.StatusOK, "submit")
	if got := status(reviewID); got != "SUBMITTED" {
		t.Fatalf("after submitting the review is %s", got)
	}

	// 3. The reviewer takes it and judges every item.
	post(reviewer, "/api/v1/review-requests/"+reviewID+"/begin-review", map[string]any{}, http.StatusOK, "begin review")
	if got := status(reviewID); got != "REVIEWING" {
		t.Fatalf("after beginning review the review is %s", got)
	}
	post(reviewer, "/api/v1/review-requests/"+reviewID+"/review-results/bulk",
		map[string]any{"item_ids": ids, "result": "COMPLIANT", "opinion": "일괄 적합"}, http.StatusOK, "bulk judgement")

	// 4. One item needs more work, which sends the review back.
	post(reviewer, "/api/v1/review-requests/"+reviewID+"/change-requests",
		map[string]any{"item_id": ids[0], "reason": "증적을 보완하세요", "assignee_id": requesterID, "due_date": ""}, http.StatusCreated, "change request")
	if got := status(reviewID); got != "CHANGE_REQUESTED" {
		t.Fatalf("raising a change request left the review at %s", got)
	}

	// 5. The requester answers it, the reviewer verifies it, and it goes back.
	var changeID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM change_requests WHERE review_request_id=$1`, reviewID).Scan(&changeID); err != nil {
		t.Fatal(err)
	}
	if res := requester.do(http.MethodPatch, "/api/v1/change-requests/"+changeID, map[string]any{"answer": "증적을 보완했습니다", "status": "DONE"}); res.status != http.StatusOK {
		t.Fatalf("answering the change request: %d %s", res.status, res.body)
	}
	if res := reviewer.do(http.MethodPatch, "/api/v1/change-requests/"+changeID, map[string]any{"answer": "", "status": "VERIFIED"}); res.status != http.StatusOK {
		t.Fatalf("verifying the change request: %d %s", res.status, res.body)
	}
	post(requester, "/api/v1/review-requests/"+reviewID+"/submit", map[string]any{}, http.StatusOK, "resubmit")
	if got := status(reviewID); got != "RESUBMITTED" {
		t.Fatalf("after resubmitting the review is %s", got)
	}

	// 6. The reviewer finishes, which hands it to the approver.
	post(reviewer, "/api/v1/review-requests/"+reviewID+"/begin-review", map[string]any{}, http.StatusOK, "begin review again")
	post(reviewer, "/api/v1/review-requests/"+reviewID+"/complete-review",
		map[string]any{"final_opinion": "적합", "final_result": "APPROVED"}, http.StatusOK, "complete review")
	if got := status(reviewID); got != "APPROVAL_PENDING" {
		t.Fatalf("completing the review left it at %s, want APPROVAL_PENDING", got)
	}

	// 7. The approver signs it off.
	post(approver, "/api/v1/review-requests/"+reviewID+"/approve", map[string]string{"comment": "승인합니다"}, http.StatusOK, "approve")
	if got := status(reviewID); got != "APPROVED" {
		t.Fatalf("the final status is %s, want APPROVED", got)
	}

	// 8. What the review produced has to be readable and self-consistent.
	if res := requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/export/xlsx", nil); res.status != http.StatusOK {
		t.Errorf("the completed review could not be exported: %d", res.status)
	}
	var approvals, results int
	if err := h.db.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM approvals WHERE review_request_id=$1),
                (SELECT count(*) FROM review_results rr JOIN submission_items si ON si.id=rr.submission_item_id
                 JOIN submissions s ON s.id=si.submission_id WHERE s.review_request_id=$1)`, reviewID).Scan(&approvals, &results); err != nil {
		t.Fatal(err)
	}
	if approvals != 1 {
		t.Errorf("the approved review holds %d approval records", approvals)
	}
	if results == 0 {
		t.Error("the approved review holds no review results")
	}
	chain := admin.do(http.MethodGet, "/api/v1/admin/audit/verify?full=1", nil).json()
	if valid, _ := chain["valid"].(bool); !valid {
		t.Errorf("the audit chain does not verify after a full lifecycle: %v", chain)
	}
}
