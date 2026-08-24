package web_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
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
		map[string]any{"item_id": ids[0], "reason": "증적을 보완하세요", "assignee_id": requesterID, "due_date": "2030-03-31"}, http.StatusCreated, "change request")
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

	// 8. The workbook is what the organisation files, so it has to carry the
	// decision -- not merely open. A draft's export was checked before; an
	// approved one, which is the version anybody keeps, was not.
	book := requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/export/xlsx", nil)
	if book.status != http.StatusOK {
		t.Fatalf("the completed review could not be exported: %d", book.status)
	}
	text := workbookText(t, book.body)
	var number string
	if err := h.db.Pool.QueryRow(ctx, `SELECT review_number FROM review_requests WHERE id=$1`, reviewID).Scan(&number); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{number, "생애주기 서비스", "최종 결과", "최종 의견", "적합", "항목별 결과", "검토결과"} {
		if !strings.Contains(text, want) {
			t.Errorf("the exported review does not carry %q", want)
		}
	}
	if strings.Contains(text, "보완 요청 사유가 필요") {
		t.Error("the export leaked a validation message")
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

// The other half of a review's purpose. Rejection has more branches than
// approval: a reviewer can reject outright when there is no sign-off step,
// and an approver can reject what a reviewer passed. Closing is what takes a
// finished review off the reviewer's desk, and only the assigned reviewer may
// do it.
func TestAReviewCanBeRejectedAndClosed(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	requesterID := h.user("reject-requester", "REQUESTER")
	reviewerID := h.user("reject-reviewer", "SECURITY_REVIEWER")
	approverID := h.user("reject-approver", "APPROVER")
	requester := h.login("reject-requester")
	reviewer := h.login("reject-reviewer")
	approver := h.login("reject-approver")
	_ = requesterID

	status := func(id string) string {
		t.Helper()
		var s string
		if err := h.db.Pool.QueryRow(ctx, `SELECT status FROM review_requests WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	submitted := func(name string) string {
		t.Helper()
		id := requester.createReview(name)
		items := []map[string]any{}
		if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+id+"/items", nil).body), &items); err != nil {
			t.Fatal(err)
		}
		ids := make([]string, 0, len(items))
		for _, item := range items {
			ids = append(ids, item["id"].(string))
		}
		if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2,approver_id=$3 WHERE id=$1`, id, reviewerID, approverID); err != nil {
			t.Fatal(err)
		}
		if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+id+"/responses/bulk",
			map[string]any{"item_ids": ids, "applicability": "N/A", "na_reason": "해당 없음", "self_assessment": "N/A"}); res.status != http.StatusOK {
			t.Fatalf("bulk answer: %d %s", res.status, res.body)
		}
		if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+id+"/submit", map[string]any{}); res.status != http.StatusOK {
			t.Fatalf("submit: %d %s", res.status, res.body)
		}
		if res := reviewer.do(http.MethodPost, "/api/v1/review-requests/"+id+"/begin-review", map[string]any{}); res.status != http.StatusOK {
			t.Fatalf("begin review: %d %s", res.status, res.body)
		}
		// Completing a review -- approving or rejecting -- requires a verdict
		// on every item, so that a rejection is still a record of what was
		// examined rather than an opinion about the whole thing.
		if res := reviewer.do(http.MethodPost, "/api/v1/review-requests/"+id+"/review-results/bulk",
			map[string]any{"item_ids": ids, "result": "NON_COMPLIANT", "opinion": "요건 미충족"}); res.status != http.StatusOK {
			t.Fatalf("bulk judgement: %d %s", res.status, res.body)
		}
		return id
	}

	// Without a sign-off step the reviewer's verdict is final.
	direct := submitted("반려 서비스 (승인 절차 없음)")
	if res := reviewer.do(http.MethodPost, "/api/v1/review-requests/"+direct+"/complete-review",
		map[string]any{"final_opinion": "요건 미충족", "final_result": "REJECTED"}); res.status != http.StatusOK {
		t.Fatalf("rejecting: %d %s", res.status, res.body)
	}
	if got := status(direct); got != "REJECTED" {
		t.Fatalf("a rejected review is %s, want REJECTED", got)
	}

	// Only the reviewer it was assigned to may close it.
	if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+direct+"/close", map[string]any{}); res.status == http.StatusOK {
		t.Error("the requester closed a review that was not theirs to close")
	}
	if res := reviewer.do(http.MethodPost, "/api/v1/review-requests/"+direct+"/close", map[string]any{}); res.status != http.StatusOK {
		t.Fatalf("closing: %d %s", res.status, res.body)
	}
	if got := status(direct); got != "CLOSED" {
		t.Errorf("the closed review is %s", got)
	}

	// With the sign-off step the approver can reject what the reviewer passed.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"approval_enabled":true}'::jsonb WHERE key='workflow'`); err != nil {
		t.Fatal(err)
	}
	escalated := submitted("반려 서비스 (승인 절차 있음)")
	if res := reviewer.do(http.MethodPost, "/api/v1/review-requests/"+escalated+"/complete-review",
		map[string]any{"final_opinion": "적합", "final_result": "APPROVED"}); res.status != http.StatusOK {
		t.Fatalf("completing: %d %s", res.status, res.body)
	}
	if got := status(escalated); got != "APPROVAL_PENDING" {
		t.Fatalf("with sign-off enabled the review is %s", got)
	}
	if res := approver.do(http.MethodPost, "/api/v1/review-requests/"+escalated+"/reject", map[string]string{"comment": "추가 통제 필요"}); res.status != http.StatusOK {
		t.Fatalf("approver rejection: %d %s", res.status, res.body)
	}
	if got := status(escalated); got != "REJECTED" {
		t.Errorf("after the approver rejected it the review is %s", got)
	}
	var finalResult string
	if err := h.db.Pool.QueryRow(ctx, `SELECT COALESCE(final_result,'') FROM review_requests WHERE id=$1`, escalated).Scan(&finalResult); err != nil {
		t.Fatal(err)
	}
	if finalResult != "REJECTED" {
		t.Errorf("the reviewer's APPROVED verdict survived the rejection: final_result=%s", finalResult)
	}
	var decisions int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE review_request_id=$1 AND decision='REJECTED'`, escalated).Scan(&decisions); err != nil {
		t.Fatal(err)
	}
	if decisions != 1 {
		t.Errorf("the rejection left %d decision records", decisions)
	}
	chain := admin.do(http.MethodGet, "/api/v1/admin/audit/verify?full=1", nil).json()
	if valid, _ := chain["valid"].(bool); !valid {
		t.Errorf("the audit chain does not verify after rejections: %v", chain)
	}
}

// workbookText returns every string an xlsx carries, which is enough to say
// whether a value reached the document without depending on where in the
// sheet it landed.
func workbookText(t *testing.T, body string) string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader([]byte(body)), int64(len(body)))
	if err != nil {
		t.Fatalf("the export is not a workbook: %v", err)
	}
	var out strings.Builder
	for _, file := range reader.File {
		if !strings.HasPrefix(file.Name, "xl/sharedStrings") && !strings.HasPrefix(file.Name, "xl/worksheets") && file.Name != "xl/workbook.xml" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		out.Write(content)
	}
	return out.String()
}

// The hash chain is the product's central claim and the only thing whose cost
// grows with the whole history, which is why day-to-day verification is
// incremental. This measures both against a real chain so the numbers in the
// operations guide are measured rather than hoped for.
func TestChainVerificationCostAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("writes several thousand chained events")
	}
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	var uid string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='integration-admin'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}

	const events = 3000
	start := time.Now()
	for i := 0; i < events; i++ {
		if err := h.db.Audit(ctx, store.AuditEvent{UserID: uid, UserName: "scale", EventType: "LOGIN", TargetType: "USER", TargetID: fmt.Sprintf("t%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	writeRate := float64(events) / time.Since(start).Seconds()
	t.Logf("appended %d events at %.0f/s", events, writeRate)

	start = time.Now()
	full := admin.do(http.MethodGet, "/api/v1/admin/audit/verify?full=1", nil).json()
	fullTime := time.Since(start)
	if valid, _ := full["valid"].(bool); !valid {
		t.Fatalf("a chain the service wrote itself does not verify: %v", full)
	}
	checked, _ := full["checked"].(float64)
	t.Logf("full verification checked %.0f events in %v", checked, fullTime)
	if int(checked) < events {
		t.Errorf("full verification checked %.0f events, fewer than the %d written", checked, events)
	}

	// The incremental pass is what an operator runs daily; having just
	// verified everything it must have almost nothing left to do.
	start = time.Now()
	incremental := admin.do(http.MethodGet, "/api/v1/admin/audit/verify", nil).json()
	incrementalTime := time.Since(start)
	if valid, _ := incremental["valid"].(bool); !valid {
		t.Fatalf("the incremental pass failed: %v", incremental)
	}
	again, _ := incremental["checked"].(float64)
	t.Logf("incremental re-check covered %.0f events in %v", again, incrementalTime)
	// How much it re-reads is the property that matters and the one that can
	// be measured honestly. Comparing the two wall-clock times was a race
	// between two sub-100ms measurements on a shared runner: the incremental
	// pass read a single event and still "lost", which failed a release for
	// scheduler noise rather than for anything about the checkpoint.
	if again > checked/2 {
		t.Errorf("the incremental pass re-checked %.0f of %.0f events; the checkpoint is not being used", again, checked)
	}
	t.Logf("full %v over %.0f events, incremental %v over %.0f", fullTime, checked, incrementalTime, again)
}

// A change request sends the whole review back, not one item, and the author
// can edit anything while it is there. Completing the review then counted the
// verdicts that were recorded before those edits, so a reviewer could sign off
// on answers nobody had read.
func TestCompletingAReviewCatchesVerdictsTheAuthorEditedAway(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	requesterID := h.user("stale-requester", "REQUESTER")
	reviewerID := h.user("stale-reviewer", "SECURITY_REVIEWER")
	requester, reviewer := h.login("stale-requester"), h.login("stale-reviewer")

	reviewID := requester.createReview("판정 후 수정 서비스")
	var items []map[string]any
	if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) < 3 {
		t.Fatalf("the template assigned %d items; the test needs three", len(items))
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item["id"].(string))
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2 WHERE id=$1`, reviewID, reviewerID); err != nil {
		t.Fatal(err)
	}
	step := func(c *client, method, path string, body any, want int, what string) {
		t.Helper()
		if res := c.do(method, path, body); res.status != want {
			t.Fatalf("%s: %d %s", what, res.status, res.body)
		}
	}
	answer := map[string]any{"item_ids": ids, "applicability": "N/A", "na_reason": "해당 없음", "self_assessment": "N/A"}
	step(requester, http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk", answer, http.StatusOK, "bulk answer")
	step(requester, http.MethodPost, "/api/v1/review-requests/"+reviewID+"/submit", map[string]any{}, http.StatusOK, "submit")
	step(reviewer, http.MethodPost, "/api/v1/review-requests/"+reviewID+"/begin-review", map[string]any{}, http.StatusOK, "begin review")
	step(reviewer, http.MethodPost, "/api/v1/review-requests/"+reviewID+"/review-results/bulk",
		map[string]any{"item_ids": ids, "result": "COMPLIANT", "opinion": "일괄 적합"}, http.StatusOK, "bulk judgement")

	// The reviewer asks about the first item; the author also rewrites the
	// second one, which nobody asked about and which is already judged.
	step(reviewer, http.MethodPost, "/api/v1/review-requests/"+reviewID+"/change-requests",
		map[string]any{"item_id": ids[0], "reason": "증적을 보완하세요", "assignee_id": requesterID, "due_date": "2030-03-31"}, http.StatusCreated, "change request")
	step(requester, http.MethodPut, "/api/v1/review-requests/"+reviewID+"/responses/"+ids[1],
		map[string]any{"applicability": "Y", "self_assessment": "COMPLIANT", "current_state": "판정 이후에 답을 바꿨습니다"}, http.StatusOK, "rewrite a judged item")
	// Evidence adequacy is part of the verdict too, so a file that arrives
	// after the judgement invalidates it exactly as a rewritten answer does.
	if res := requester.upload("/api/v1/review-requests/"+reviewID+"/items/"+ids[2]+"/evidences", "증적.txt", "판정 이후에 올린 증적"); res.status != http.StatusCreated {
		t.Fatalf("attaching evidence to a judged item: %d %s", res.status, res.body)
	}

	var changeID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM change_requests WHERE review_request_id=$1`, reviewID).Scan(&changeID); err != nil {
		t.Fatal(err)
	}
	step(requester, http.MethodPatch, "/api/v1/change-requests/"+changeID, map[string]any{"answer": "보완했습니다", "status": "DONE"}, http.StatusOK, "answer the change request")
	// Pressing the same button twice must not send the reviewer a second notice.
	step(requester, http.MethodPatch, "/api/v1/change-requests/"+changeID, map[string]any{"answer": "보완했습니다", "status": "DONE"}, http.StatusConflict, "answer the change request twice")
	step(reviewer, http.MethodPatch, "/api/v1/change-requests/"+changeID, map[string]any{"answer": "", "status": "VERIFIED"}, http.StatusOK, "verify the change request")
	// A verified request is closed: reopening it would block the completion of
	// a review that is otherwise finished, or leave an approved one with work
	// outstanding in the register.
	step(requester, http.MethodPatch, "/api/v1/change-requests/"+changeID, map[string]any{"answer": "다시 열기", "status": "DONE"}, http.StatusConflict, "reopen a verified change request")
	var finalStatus string
	if err := h.db.Pool.QueryRow(ctx, `SELECT status FROM change_requests WHERE id=$1`, changeID).Scan(&finalStatus); err != nil {
		t.Fatal(err)
	}
	if finalStatus != "VERIFIED" {
		t.Errorf("the change request is %s after a refused reopen", finalStatus)
	}
	var notices int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_type='CHANGE_DONE'`).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices != 1 {
		t.Errorf("the reviewer received %d 조치 완료 notices for one change request", notices)
	}
	step(requester, http.MethodPost, "/api/v1/review-requests/"+reviewID+"/submit", map[string]any{}, http.StatusOK, "resubmit")
	step(reviewer, http.MethodPost, "/api/v1/review-requests/"+reviewID+"/begin-review", map[string]any{}, http.StatusOK, "begin review again")

	// The reviewer is told a checklist came back, not that a new one arrived,
	// and the count is what sends them to the right items.
	var title, body string
	if err := h.db.Pool.QueryRow(ctx, `SELECT title,body FROM notifications WHERE recipient_id=$1 AND event_type='REVIEW_SUBMITTED' ORDER BY created_at DESC LIMIT 1`, reviewerID).Scan(&title, &body); err != nil {
		t.Fatal(err)
	}
	if title != "심의 재제출" || !strings.Contains(body, "바뀐 항목 2건") {
		t.Errorf("the resubmission notice reads %q / %q", title, body)
	}

	// The screen has to say so before the reviewer presses the button, and with
	// the same counts the button itself refuses on.
	detail := reviewer.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil).json()
	blockers, _ := detail["completion_blockers"].(map[string]any)
	if blockers == nil {
		t.Fatalf("the review detail carries no completion_blockers: %v", detail["result_summary"])
	}
	if got, _ := blockers["stale_verdicts"].(float64); got != 2 {
		t.Errorf("the screen reports %v edited-since-judged items before the button is pressed, want 2", blockers["stale_verdicts"])
	}
	if got, _ := blockers["unreviewed_items"].(float64); got != 0 {
		t.Errorf("unreviewed_items = %v, want 0", blockers["unreviewed_items"])
	}

	summary, _ := reviewer.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil).json()["result_summary"].(map[string]any)
	if got, _ := summary["stale_verdicts"].(float64); got != 2 {
		t.Errorf("the review summary reports %v edited-since-judged items, want 2", summary["stale_verdicts"])
	}
	// The item list has to point at them, or the reviewer is told a number
	// and left to find the items by hand.
	var reread []map[string]any
	if err := json.Unmarshal([]byte(reviewer.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &reread); err != nil {
		t.Fatal(err)
	}
	flagged := map[string]bool{}
	for _, item := range reread {
		if stale, _ := item["stale_verdict"].(bool); stale {
			flagged[item["id"].(string)] = true
		}
	}
	if !flagged[ids[1]] || !flagged[ids[2]] || len(flagged) != 2 {
		t.Errorf("the item list flags %v, want the rewritten and the re-evidenced item", flagged)
	}

	res := reviewer.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/complete-review",
		map[string]any{"final_opinion": "적합", "final_result": "APPROVED"})
	if res.status != http.StatusUnprocessableEntity {
		t.Fatalf("completing a review over an answer edited after judgement: %d %s", res.status, res.body)
	}
	fault, _ := res.json()["error"].(map[string]any)
	if !strings.Contains(fmt.Sprint(fault["message"]), "검토 후 답변이 바뀐 항목 2건") {
		t.Errorf("the refusal does not say what is left: %v", fault["message"])
	}
	if details, _ := fault["details"].(map[string]any); details != nil {
		if got, _ := details["stale_verdicts"].(float64); got != 2 {
			t.Errorf("stale_verdicts = %v, want 2", details["stale_verdicts"])
		}
	} else {
		t.Errorf("the refusal carries no counts: %v", fault)
	}

	// Re-reading the item and judging it again is the whole remedy.
	for _, itemID := range []string{ids[1], ids[2]} {
		step(reviewer, http.MethodPut, "/api/v1/review-requests/"+reviewID+"/review-results/"+itemID,
			map[string]any{"final_applicability": "Y", "result": "COMPLIANT", "opinion": "바뀐 내용도 적합", "evidence_adequacy": "ADEQUATE"}, http.StatusOK, "re-judge the changed item")
	}
	step(reviewer, http.MethodPost, "/api/v1/review-requests/"+reviewID+"/complete-review",
		map[string]any{"final_opinion": "적합", "final_result": "APPROVED"}, http.StatusOK, "complete review after re-judging")
}

// A reviewer who loses the role -- a transfer, a leaver, a corrected mistake --
// keeps every review they were assigned. They are refused every action on it,
// and because the queue treats an assigned review as somebody else's business,
// no other reviewer sees it either. Nothing fails, so nothing is noticed: the
// review simply stops.
func TestAReviewLeftWithAReviewerWhoCannotActGoesBackToTheQueue(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("orphan-requester", "REQUESTER")
	leaverID := h.user("orphan-leaver", "SECURITY_REVIEWER")
	h.user("orphan-successor", "SECURITY_REVIEWER")
	requester, successor := h.login("orphan-requester"), h.login("orphan-successor")

	reviewID := requester.createReview("담당자 이탈 서비스")
	var items []map[string]any
	if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item["id"].(string))
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2 WHERE id=$1`, reviewID, leaverID); err != nil {
		t.Fatal(err)
	}
	if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk",
		map[string]any{"item_ids": ids, "applicability": "N/A", "na_reason": "해당 없음", "self_assessment": "N/A"}); res.status != http.StatusOK {
		t.Fatalf("bulk answer: %d %s", res.status, res.body)
	}
	if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/submit", map[string]any{}); res.status != http.StatusOK {
		t.Fatalf("submit: %d %s", res.status, res.body)
	}

	mine := func(c *client) bool {
		t.Helper()
		body := c.do(http.MethodGet, "/api/v1/review-requests?mine=1&limit=100", nil).json()
		list, _ := body["items"].([]any)
		for _, row := range list {
			if item, _ := row.(map[string]any); item != nil && item["id"] == reviewID {
				return true
			}
		}
		return false
	}
	if mine(successor) {
		t.Fatal("a review assigned to a working reviewer is already in another reviewer's queue")
	}

	// The assignment survives the role, which is what makes this silent.
	if _, err := h.db.Pool.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_code='SECURITY_REVIEWER'`, leaverID); err != nil {
		t.Fatal(err)
	}
	if !mine(successor) {
		t.Error("a review whose reviewer lost the role is in nobody's queue")
	}
	if res := successor.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/begin-review", map[string]any{}); res.status != http.StatusOK {
		t.Fatalf("taking over a stuck review: %d %s", res.status, res.body)
	}
	var owner string
	if err := h.db.Pool.QueryRow(ctx, `SELECT reviewer_id FROM review_requests WHERE id=$1`, reviewID).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	me, _ := successor.do(http.MethodGet, "/api/v1/me", nil).json()["user"].(map[string]any)
	if successorID, _ := me["id"].(string); owner != successorID {
		t.Errorf("the review is still assigned to %s after somebody else took it over", owner)
	}
	// And with a working owner again it is nobody else's business.
	detail := successor.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil).json()
	if canAct, _ := detail["reviewer_can_act"].(bool); !canAct {
		t.Error("the detail still reports the reviewer cannot act after the takeover")
	}
}

// The new-review form asks for three service owners -- builder, developer and
// operator. A checklist item may be assigned to any of them, and the assignment
// even notifies them. Only the first two could open the review the notification
// linked to: the operator was named on it and refused by it.
func TestTheOperatorNamedOnAReviewCanOpenIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("ops-requester", "REQUESTER")
	operatorID := h.user("운영담당-ops", "REQUESTER")
	requester, operator := h.login("ops-requester"), h.login("운영담당-ops")

	reviewID := requester.createReview("운영 담당자 서비스")
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET operator_id=$2 WHERE id=$1`, reviewID, operatorID); err != nil {
		t.Fatal(err)
	}
	if res := operator.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil); res.status != http.StatusOK {
		t.Fatalf("the operator cannot open the review they are named on: %d %s", res.status, res.body)
	}
	listed := func(query string) bool {
		t.Helper()
		body := operator.do(http.MethodGet, "/api/v1/review-requests?"+query, nil).json()
		rows, _ := body["items"].([]any)
		for _, row := range rows {
			if item, _ := row.(map[string]any); item != nil && item["id"] == reviewID {
				return true
			}
		}
		return false
	}
	if !listed("limit=100") {
		t.Error("the review is missing from the operator's list")
	}
	// A draft is work for the people who run the service, so it is their turn.
	if !listed("mine=1&limit=100") {
		t.Error("a draft the operator can fill in is not in their queue")
	}

	// Searching by the operator's name has to find the service they run: the
	// search reads every other owner's name.
	found := operator.do(http.MethodGet, "/api/v1/search?q="+url.QueryEscape("운영담당"), nil).json()
	reviews, _ := found["reviews"].([]any)
	hit := false
	for _, row := range reviews {
		if item, _ := row.(map[string]any); item != nil && item["id"] == reviewID {
			hit = true
		}
	}
	if !hit {
		t.Errorf("searching for the operator's name did not find their review: %v", found["reviews"])
	}

	// Assignment already believed the operator was a participant; opening the
	// item and answering it has to agree.
	var items []map[string]any
	if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	itemID := items[0]["id"].(string)
	if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk",
		map[string]any{"item_ids": []string{itemID}, "assigned_to": operatorID, "assign_only": true}); res.status != http.StatusOK {
		t.Fatalf("assigning an item to the operator: %d %s", res.status, res.body)
	}
	if res := operator.do(http.MethodPut, "/api/v1/review-requests/"+reviewID+"/responses/"+itemID,
		map[string]any{"applicability": "Y", "self_assessment": "COMPLIANT", "current_state": "운영 중"}); res.status != http.StatusOK {
		t.Fatalf("the operator cannot answer the item assigned to them: %d %s", res.status, res.body)
	}
}

// The audit log's result column defaults to SUCCESS, so an attempt the service
// refused was written down as if it had happened. A refused password change --
// what somebody probing a hijacked session leaves behind -- read as an ordinary
// password change, and there was no way to ask the screen for refusals at all.
func TestARefusedPasswordChangeIsRecordedAsRefused(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	if res := admin.do(http.MethodPut, "/api/v1/me/password", map[string]string{"current_password": "완전히-틀린-비밀번호", "new_password": "새로운비밀번호12자이상"}); res.status != http.StatusForbidden {
		t.Fatalf("a wrong current password returned %d %s", res.status, res.body)
	}
	var result, after string
	if err := h.db.Pool.QueryRow(ctx, `SELECT result,after_value FROM audit_logs WHERE event_type='CHANGE_PASSWORD' ORDER BY timestamp DESC LIMIT 1`).Scan(&result, &after); err != nil {
		t.Fatal(err)
	}
	if result != "FAILURE" {
		t.Errorf("the refused attempt is recorded as %s: an auditor counting password changes counts it as one", result)
	}
	if !strings.Contains(after, "mismatch") {
		t.Errorf("the record does not say why it was refused: %s", after)
	}

	// And the screen can be asked for refusals, which is the question an
	// auditor opens it with.
	listed := admin.do(http.MethodGet, "/api/v1/admin/audit?result=FAILURE&limit=50", nil).json()
	rows, _ := listed["items"].([]any)
	if len(rows) == 0 {
		t.Fatal("filtering the audit log by result returned nothing")
	}
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		if row["result"] != "FAILURE" {
			t.Errorf("the failure filter returned a %v row", row["result"])
		}
	}
}

// "Somebody asked for something their role does not allow" is the one refusal
// the chain did not hold: a failed login is written down, a download of
// somebody else's evidence is written down, and an account walking the admin
// endpoints was refused and forgotten.
func TestAnAttemptRefusedOnPermissionIsWrittenDown(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("denied-requester", "REQUESTER")
	requester := h.login("denied-requester")

	if res := requester.do(http.MethodGet, "/api/v1/admin/users", nil); res.status != http.StatusForbidden {
		t.Fatalf("a requester reading the user list returned %d %s", res.status, res.body)
	}
	var result, target, after string
	if err := h.db.Pool.QueryRow(ctx, `SELECT result,target_id,after_value FROM audit_logs WHERE event_type='ACCESS_DENIED' ORDER BY timestamp DESC LIMIT 1`).Scan(&result, &target, &after); err != nil {
		t.Fatalf("the refused request left no audit event: %v", err)
	}
	if result != "FAILURE" {
		t.Errorf("the refusal is recorded as %s", result)
	}
	if target != "/api/v1/admin/users" {
		t.Errorf("the record does not name what was asked for: %q", target)
	}
	if !strings.Contains(after, "SYSTEM_ADMIN") {
		t.Errorf("the record does not say what the endpoint required: %s", after)
	}

	// Work the person is allowed to do must not fill the log with denials.
	before := 0
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='ACCESS_DENIED'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	requester.createReview("권한 있는 작업")
	after2 := 0
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='ACCESS_DENIED'`).Scan(&after2); err != nil {
		t.Fatal(err)
	}
	if after2 != before {
		t.Errorf("an allowed action recorded %d denials", after2-before)
	}
}

// The dashboard's first query fails loudly and the counts beside it did not, so
// a database refusing mid-request produced a page that said "nothing opens
// soon, no change request is open" -- the numbers people act on -- next to
// status counts that were real.
func TestTheDashboardRefusesRatherThanReportZero(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	if res := admin.do(http.MethodGet, "/api/v1/dashboard", nil); res.status != http.StatusOK {
		t.Fatalf("a healthy dashboard returned %d %s", res.status, res.body)
	}
	// Taking one table out from under the handler is what a statement timeout
	// or a permission change looks like to it.
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE change_requests RENAME TO change_requests_hidden`); err != nil {
		t.Fatal(err)
	}
	res := admin.do(http.MethodGet, "/api/v1/dashboard", nil)
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE change_requests_hidden RENAME TO change_requests`); err != nil {
		t.Fatal(err)
	}
	if res.status == http.StatusOK {
		body := res.json()
		t.Fatalf("the dashboard answered 200 with open_change_requests=%v while the table was unreadable", body["open_change_requests"])
	}
	if res.errorCode() != "QUERY_FAILED" {
		t.Errorf("the failure is reported as %s", res.errorCode())
	}
}

// A re-review copies last year's answers into the new checklist -- that is what
// it is for. But a copied answer looked exactly like one somebody wrote this
// cycle, so a review where nobody re-examined anything was indistinguishable
// from one where everybody did.
func TestACarriedAnswerSaysThatItWasCarried(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("carry-requester", "REQUESTER")
	requester := h.login("carry-requester")

	firstID := requester.createReview("작년 심의")
	var items []map[string]any
	if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+firstID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item["id"].(string))
	}
	if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+firstID+"/responses/bulk",
		map[string]any{"item_ids": ids, "applicability": "N/A", "na_reason": "작년에 적은 사유", "self_assessment": "N/A"}); res.status != http.StatusOK {
		t.Fatalf("answering last year's review: %d %s", res.status, res.body)
	}

	copied := requester.do(http.MethodPost, "/api/v1/review-requests/"+firstID+"/copy", map[string]any{})
	if copied.status != http.StatusCreated {
		t.Fatalf("re-review: %d %s", copied.status, copied.body)
	}
	secondID, _ := copied.json()["id"].(string)

	read := func() []map[string]any {
		t.Helper()
		var out []map[string]any
		if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+secondID+"/items", nil).body), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	fresh := read()
	carried := 0
	var firstItem string
	for _, item := range fresh {
		response, _ := item["response"].(map[string]any)
		if response != nil && response["carried_at"] != nil {
			carried++
			if firstItem == "" {
				firstItem = item["id"].(string)
			}
		}
	}
	if carried == 0 {
		t.Fatal("every answer was copied from last year and none of them says so")
	}

	// Looking at the answer again is what clears it -- that is the whole point
	// of the mark.
	if res := requester.do(http.MethodPut, "/api/v1/review-requests/"+secondID+"/responses/"+firstItem,
		map[string]any{"applicability": "N/A", "na_reason": "올해 다시 확인했습니다", "self_assessment": "N/A"}); res.status != http.StatusOK {
		t.Fatalf("re-answering: %d %s", res.status, res.body)
	}
	var still bool
	if err := h.db.Pool.QueryRow(ctx, `SELECT carried_at IS NOT NULL FROM responses WHERE submission_item_id=$1`, firstItem).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if still {
		t.Error("an answer the requester rewrote is still marked as carried over")
	}
}

// The dashboard counted reviews nobody had picked up and reviews that had
// stopped moving, and then showed neither: the numbers were computed on every
// load of the busiest screen and read by no screen and no tool. They are worth
// showing -- but a number a security lead cannot click is a fact they then have
// to reproduce by hand, so the list has to hold exactly the same set.
func TestTheQueueHealthNumbersMatchTheListBehindThem(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	h.user("queue-requester", "REQUESTER")
	requester := h.login("queue-requester")

	// One review waiting with nobody on it, one that a reviewer took and left.
	waiting := requester.createReview("담당자 없는 심의")
	stalled := requester.createReview("멈춘 심의")
	reviewerID := h.user("queue-reviewer", "SECURITY_REVIEWER")
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET status='SUBMITTED' WHERE id=$1`, waiting); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET status='REVIEWING',reviewer_id=$2,updated_at=now()-interval '30 days' WHERE id=$1`, stalled, reviewerID); err != nil {
		t.Fatal(err)
	}

	data := admin.do(http.MethodGet, "/api/v1/dashboard", nil).json()
	analytics, _ := data["security_analytics"].(map[string]any)
	if analytics == nil {
		t.Fatal("the dashboard carries no queue health for a security lead")
	}
	unassigned, _ := analytics["unassigned"].(float64)
	longPending, _ := analytics["long_pending"].(float64)
	if unassigned < 1 || longPending < 1 {
		t.Fatalf("queue health reports unassigned=%v stalled=%v", unassigned, longPending)
	}

	listed := func(query string) []string {
		t.Helper()
		body := admin.do(http.MethodGet, "/api/v1/review-requests?"+query+"&limit=100", nil).json()
		rows, _ := body["items"].([]any)
		var ids []string
		for _, raw := range rows {
			if row, _ := raw.(map[string]any); row != nil {
				ids = append(ids, row["id"].(string))
			}
		}
		return ids
	}
	if got := listed("unassigned=1"); len(got) != int(unassigned) || !contains(got, waiting) {
		t.Errorf("the unassigned filter returned %v for a count of %v", got, unassigned)
	}
	if got := listed("stalled=1"); len(got) != int(longPending) || !contains(got, stalled) {
		t.Errorf("the stalled filter returned %v for a count of %v", got, longPending)
	}
	// Anything nobody counted must not appear in either list.
	if got := listed("unassigned=1"); contains(got, stalled) {
		t.Error("a review with a reviewer is listed as unassigned")
	}
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
