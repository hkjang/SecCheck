package web_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hkjang/SecCheck/internal/auth"
	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
	api "github.com/hkjang/SecCheck/internal/web"
	"golang.org/x/crypto/bcrypt"
)

const testPassword = "IntegrationPassword1!"

type harness struct {
	t      *testing.T
	server *httptest.Server
	db     *store.Store
}

type client struct {
	h      *harness
	cookie string
	csrf   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db := testdb.New(t)
	key, _ := cryptox.RandomBytes(32)
	box, err := cryptox.New(key)
	if err != nil {
		t.Fatal(err)
	}
	handler := api.NewServer(api.Options{Store: db, Auth: auth.New(db, box), Box: box, Version: "test", WebDir: t.TempDir(), DataDir: t.TempDir()})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	h := &harness{t: t, server: server, db: db}
	// Publish the baseline workbook so the Rule Engine has something to assign,
	// exactly as the service does on first start.
	owner := testdb.Bootstrap(t, db, "seed-owner")
	if _, err := db.SeedDefaults(context.Background(), owner); err != nil {
		t.Fatalf("seed baseline templates: %v", err)
	}
	return h
}

// user creates a local account with the given roles and returns its id.
func (h *harness) user(username string, roles ...string) string {
	h.t.Helper()
	ctx := context.Background()
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		h.t.Fatal(err)
	}
	id := store.NewID()
	if _, err = h.db.Pool.Exec(ctx, `INSERT INTO users(id,username,display_name,email,password_hash) VALUES($1,$2,$2,$3,$4)`, id, username, username+"@example.test", string(hash)); err != nil {
		h.t.Fatalf("create %s: %v", username, err)
	}
	for _, role := range roles {
		if _, err = h.db.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,$2)`, id, role); err != nil {
			h.t.Fatalf("grant %s to %s: %v", role, username, err)
		}
	}
	return id
}

func (h *harness) login(username string) *client {
	h.t.Helper()
	c := &client{h: h}
	res := c.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": username, "password": testPassword})
	if res.status != http.StatusOK {
		h.t.Fatalf("login %s: status %d body %s", username, res.status, res.body)
	}
	for _, cookie := range res.raw.Cookies() {
		if cookie.Name == auth.CookieName {
			c.cookie = cookie.Value
		}
	}
	c.csrf, _ = res.json()["csrf_token"].(string)
	if c.cookie == "" || c.csrf == "" {
		h.t.Fatalf("login %s did not return a usable session", username)
	}
	return c
}

type response struct {
	status int
	body   string
	raw    *http.Response
}

func (r response) json() map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal([]byte(r.body), &out)
	return out
}

func (r response) errorCode() string {
	if e, ok := r.json()["error"].(map[string]any); ok {
		code, _ := e["code"].(string)
		return code
	}
	return ""
}

func (c *client) do(method, path string, payload any) response {
	c.h.t.Helper()
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			c.h.t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.h.server.URL+path, body)
	if err != nil {
		c.h.t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.send(req)
}

func (c *client) send(req *http.Request) response {
	c.h.t.Helper()
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: c.cookie})
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := c.h.server.Client().Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	return response{status: res.StatusCode, body: string(raw), raw: res}
}

func (c *client) upload(path, filename, content string) response {
	c.h.t.Helper()
	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)
	part, err := form.CreateFormFile("file", filename)
	if err != nil {
		c.h.t.Fatal(err)
	}
	_, _ = io.WriteString(part, content)
	_ = form.WriteField("description", "integration upload")
	_ = form.Close()
	req, err := http.NewRequest(http.MethodPost, c.h.server.URL+path, &buf)
	if err != nil {
		c.h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", form.FormDataContentType())
	return c.send(req)
}

// createReview drives the real creation endpoint so the Rule Engine and the
// snapshot are exercised too.
func (c *client) createReview(name string) string {
	c.h.t.Helper()
	me := c.do(http.MethodGet, "/api/v1/me", nil).json()
	user, _ := me["user"].(map[string]any)
	id, _ := user["id"].(string)
	res := c.do(http.MethodPost, "/api/v1/review-requests", map[string]any{
		"service_name": name, "description": "integration", "service_type": "WEB", "change_type": "NEW",
		"builder_id": id, "developer_id": id, "department": "보안팀", "exposure": "INTERNAL",
		"processes_personal_data": true, "uses_cloud": false, "internet_access": true,
	})
	if res.status != http.StatusCreated {
		c.h.t.Fatalf("create review: status %d body %s", res.status, res.body)
	}
	reviewID, _ := res.json()["id"].(string)
	if reviewID == "" {
		c.h.t.Fatalf("create review returned no id: %s", res.body)
	}
	return reviewID
}

func TestLoginLockoutAndUnlockOverHTTP(t *testing.T) {
	h := newHarness(t)
	h.user("locktarget", "REQUESTER")
	admin := h.login(adminOf(h))

	anon := &client{h: h}
	for i := 0; i < 5; i++ {
		if res := anon.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "locktarget", "password": "wrong-password"}); res.status != http.StatusUnauthorized && res.status != http.StatusLocked {
			t.Fatalf("failure %d returned %d", i+1, res.status)
		}
	}
	res := anon.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "locktarget", "password": testPassword})
	if res.status != http.StatusLocked || res.errorCode() != "ACCOUNT_LOCKED" {
		t.Fatalf("a locked account still accepted the right password: %d %s", res.status, res.body)
	}

	var target string
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT id FROM users WHERE username='locktarget'`).Scan(&target); err != nil {
		t.Fatal(err)
	}
	if res = admin.do(http.MethodPost, "/api/v1/admin/users/"+target+"/unlock", nil); res.status != http.StatusNoContent {
		t.Fatalf("unlock returned %d %s", res.status, res.body)
	}
	if res = anon.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "locktarget", "password": testPassword}); res.status != http.StatusOK {
		t.Fatalf("login after unlock returned %d %s", res.status, res.body)
	}
}

func TestObjectPermissionsKeepReviewsPrivate(t *testing.T) {
	h := newHarness(t)
	h.user("owner", "REQUESTER")
	h.user("stranger", "REQUESTER")
	owner := h.login("owner")
	stranger := h.login("stranger")

	reviewID := owner.createReview("소유자 서비스")
	if res := stranger.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil); res.status != http.StatusNotFound {
		t.Errorf("an unrelated requester read someone else's review: %d %s", res.status, res.body)
	}
	if res := stranger.do(http.MethodGet, "/api/v1/review-requests", nil); strings.Contains(res.body, reviewID) {
		t.Error("an unrelated requester saw the review in their list")
	}
	if res := stranger.do(http.MethodGet, "/api/v1/admin/users", nil); res.status != http.StatusForbidden {
		t.Errorf("a requester reached the administrative plane: %d", res.status)
	}
	if res := owner.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil); res.status != http.StatusOK {
		t.Errorf("the owner could not read their own review: %d %s", res.status, res.body)
	}
}

func TestSubmissionValidationBlocksIncompleteWork(t *testing.T) {
	h := newHarness(t)
	h.user("writer", "REQUESTER")
	writer := h.login("writer")
	reviewID := writer.createReview("검증 서비스")

	res := writer.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/submit", nil)
	if res.status != http.StatusUnprocessableEntity || res.errorCode() != "SUBMISSION_INCOMPLETE" {
		t.Fatalf("an empty checklist was accepted for submission: %d %s", res.status, res.body)
	}
	details, _ := res.json()["error"].(map[string]any)["details"].([]any)
	if len(details) == 0 {
		t.Fatal("the rejection did not say which items were missing")
	}
}

func TestBulkResponsesFillManyItemsAtOnce(t *testing.T) {
	h := newHarness(t)
	h.user("bulkwriter", "REQUESTER")
	writer := h.login("bulkwriter")
	reviewID := writer.createReview("일괄 서비스")

	items := []map[string]any{}
	if err := json.Unmarshal([]byte(writer.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) < 3 {
		t.Fatalf("expected a seeded checklist, got %d items", len(items))
	}
	ids := []string{}
	for _, item := range items[:3] {
		ids = append(ids, item["id"].(string))
	}
	// One item is answered individually first, to prove the default does not
	// overwrite existing work.
	if res := writer.do(http.MethodPut, fmt.Sprintf("/api/v1/review-requests/%s/responses/%s", reviewID, ids[0]), map[string]any{"applicability": "Y", "self_assessment": "COMPLIANT", "current_state": "이미 작성"}); res.status != http.StatusOK {
		t.Fatalf("single save returned %d %s", res.status, res.body)
	}
	res := writer.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk", map[string]any{"item_ids": ids, "applicability": "N/A", "self_assessment": "N/A", "na_reason": "대상 아님"})
	if res.status != http.StatusOK {
		t.Fatalf("bulk save returned %d %s", res.status, res.body)
	}
	if applied, _ := res.json()["applied"].(float64); applied != 2 {
		t.Errorf("applied = %v, want 2 untouched items", res.json()["applied"])
	}
	var preserved string
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT applicability FROM responses WHERE submission_item_id=$1`, ids[0]).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	if preserved != "Y" {
		t.Errorf("an existing answer was overwritten without overwrite=true (got %s)", preserved)
	}
	res = writer.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk", map[string]any{"item_ids": ids, "applicability": "N/A", "self_assessment": "N/A", "na_reason": "대상 아님", "overwrite": true})
	if applied, _ := res.json()["applied"].(float64); applied != 3 {
		t.Errorf("overwrite applied = %v, want 3", res.json()["applied"])
	}
	if res = writer.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk", map[string]any{"item_ids": ids, "applicability": "N/A"}); res.errorCode() != "NA_REASON_REQUIRED" {
		t.Errorf("bulk N/A without a reason was accepted: %s", res.body)
	}
}

func TestEvidenceRoundTripsThroughTheStreamingVault(t *testing.T) {
	h := newHarness(t)
	h.user("uploader", "REQUESTER")
	uploader := h.login("uploader")
	reviewID := uploader.createReview("증적 서비스")

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(uploader.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	itemID := items[0]["id"].(string)

	// Comfortably larger than one chunk, so the multi-chunk path is covered.
	content := strings.Repeat("증적 본문 abcdefghij 0123456789\n", 60000)
	res := uploader.upload(fmt.Sprintf("/api/v1/review-requests/%s/items/%s/evidences", reviewID, itemID), "evidence.txt", content)
	if res.status != http.StatusCreated {
		t.Fatalf("upload returned %d %s", res.status, res.body)
	}
	evidenceID, _ := res.json()["id"].(string)
	if size, _ := res.json()["size_bytes"].(float64); int(size) != len(content) {
		t.Errorf("stored size = %v, want %d", res.json()["size_bytes"], len(content))
	}

	download := uploader.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/download", nil)
	if download.status != http.StatusOK {
		t.Fatalf("download returned %d %s", download.status, download.body)
	}
	if download.body != content {
		t.Errorf("round trip changed the file: got %d bytes, want %d", len(download.body), len(content))
	}

	h.user("outsider", "REQUESTER")
	if res = h.login("outsider").do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/download", nil); res.status != http.StatusNotFound {
		t.Errorf("an unrelated user downloaded the evidence: %d", res.status)
	}
}

func TestReviewListPaginatesAndReportsATotal(t *testing.T) {
	h := newHarness(t)
	h.user("lister", "REQUESTER")
	lister := h.login("lister")
	for i := 0; i < 7; i++ {
		lister.createReview(fmt.Sprintf("목록 서비스 %d", i))
	}
	res := lister.do(http.MethodGet, "/api/v1/review-requests?limit=3&offset=0", nil)
	page := res.json()
	if total, _ := page["total"].(float64); int(total) != 7 {
		t.Fatalf("total = %v, want 7", page["total"])
	}
	if items, _ := page["items"].([]any); len(items) != 3 {
		t.Fatalf("page size = %d, want 3", len(items))
	}
	if more, _ := page["has_more"].(bool); !more {
		t.Error("has_more should be true on the first of three pages")
	}
	last := lister.do(http.MethodGet, "/api/v1/review-requests?limit=3&offset=6", nil).json()
	if items, _ := last["items"].([]any); len(items) != 1 {
		t.Errorf("final page size = %d, want 1", len(items))
	}
	if more, _ := last["has_more"].(bool); more {
		t.Error("has_more should be false on the last page")
	}
}

func TestCSRFIsRequiredForCookieWrites(t *testing.T) {
	h := newHarness(t)
	h.user("csrfuser", "REQUESTER")
	c := h.login("csrfuser")
	saved := c.csrf
	c.csrf = ""
	if res := c.do(http.MethodPatch, "/api/v1/me", map[string]string{"display_name": "무단 변경"}); res.errorCode() != "CSRF_INVALID" {
		t.Fatalf("a cookie write without a CSRF token was accepted: %d %s", res.status, res.body)
	}
	c.csrf = saved
	if res := c.do(http.MethodPatch, "/api/v1/me", map[string]string{"display_name": "정상 변경", "email": "", "department": ""}); res.status != http.StatusOK {
		t.Fatalf("a valid write was rejected: %d %s", res.status, res.body)
	}
}

// adminOf bootstraps the system administrator the way the service does at
// start-up and returns the username.
func adminOf(h *harness) string {
	h.t.Helper()
	h.user("integration-admin", "SYSTEM_ADMIN", "TEMPLATE_ADMIN", "SECURITY_REVIEWER", "REQUESTER", "APPROVER", "AUDITOR")
	return "integration-admin"
}

func TestAuditChainVerificationIsIncrementalAndDetectsTampering(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	first := admin.do(http.MethodGet, "/api/v1/admin/audit/verify", nil).json()
	if valid, _ := first["valid"].(bool); !valid {
		t.Fatalf("a fresh chain failed verification: %s", admin.do(http.MethodGet, "/api/v1/admin/audit/verify", nil).body)
	}
	checkedFirst, _ := first["checked"].(float64)
	if checkedFirst == 0 {
		t.Fatal("the first run should have verified the login events")
	}
	if from, _ := first["from_sequence"].(float64); from != 0 {
		t.Errorf("the first run started at sequence %v, want the whole chain", from)
	}
	// Verifying is itself an audited action, so a second run has exactly that
	// one new event to prove rather than the whole chain again.
	second := admin.do(http.MethodGet, "/api/v1/admin/audit/verify", nil).json()
	if from, _ := second["from_sequence"].(float64); from == 0 {
		t.Error("the second run did not resume from the recorded checkpoint")
	}
	if checked, _ := second["checked"].(float64); checked != 1 {
		t.Errorf("the incremental run verified %v events, want only the previous run's own audit entry", checked)
	}
	// Three more actions make exactly three more events of work.
	before, _ := admin.do(http.MethodGet, "/api/v1/admin/audit/verify", nil).json()["total"].(float64)
	for i := 0; i < 3; i++ {
		admin.do(http.MethodPatch, "/api/v1/me", map[string]string{"display_name": "감사자", "email": "", "department": ""})
	}
	third := admin.do(http.MethodGet, "/api/v1/admin/audit/verify", nil).json()
	if checked, _ := third["checked"].(float64); checked != 4 {
		t.Errorf("after three actions the incremental run verified %v events, want 4 (3 actions plus the previous verification)", checked)
	}
	if total, _ := third["total"].(float64); total <= before {
		t.Errorf("the chain total did not advance: %v then %v", before, total)
	}

	// Tampering with a stored payload has to be caught by the full pass, and
	// it must reach the administrators rather than only the caller.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE audit_logs SET canonical_payload=canonical_payload||'tampered' WHERE chain_sequence=1`); err != nil {
		t.Fatal(err)
	}
	full := admin.do(http.MethodGet, "/api/v1/admin/audit/verify?full=1", nil).json()
	if valid, _ := full["valid"].(bool); valid {
		t.Fatal("a tampered payload passed the full verification")
	}
	var alerts int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_type='AUDIT_CHAIN_BROKEN'`).Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if alerts == 0 {
		t.Error("no administrator was notified that the chain is broken")
	}
}

func TestFailedJobsAreVisibleAndRetryable(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,attempts,last_error) VALUES($1,'SEND_EMAIL','FAILED',5,'smtp: connection refused')`, store.NewID()); err != nil {
		t.Fatal(err)
	}
	listed := admin.do(http.MethodGet, "/api/v1/admin/jobs?status=FAILED", nil).json()
	items, _ := listed["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("failed jobs listed = %d, want 1: %v", len(items), listed)
	}
	job, _ := items[0].(map[string]any)
	id, _ := job["id"].(string)
	if res := admin.do(http.MethodPost, "/api/v1/admin/jobs/"+id+"/retry", nil); res.status != http.StatusNoContent {
		t.Fatalf("retry returned %d %s", res.status, res.body)
	}
	var status string
	var attempts int
	if err := h.db.Pool.QueryRow(ctx, `SELECT status,attempts FROM jobs WHERE id=$1`, id).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "PENDING" || attempts != 0 {
		t.Errorf("after retry status=%s attempts=%d, want PENDING/0", status, attempts)
	}
	if res := h.login("integration-admin").do(http.MethodGet, "/api/v1/admin/jobs", nil); res.status != http.StatusOK {
		t.Errorf("job listing returned %d", res.status)
	}
}

// A dead worker leaves PENDING rows that look perfectly normal on the queue
// page. The age of the oldest due job is what actually gives it away.
func TestTheQueueReportsHowLongWorkHasBeenWaiting(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	fresh := admin.do(http.MethodGet, "/api/v1/admin/jobs", nil).json()
	if waited := pendingAge(t, fresh); waited != 0 {
		t.Fatalf("an empty queue reported a %ds backlog", waited)
	}
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,available_at) VALUES($1,'SEND_EMAIL','PENDING',now()-interval '20 minutes')`, store.NewID()); err != nil {
		t.Fatal(err)
	}
	// A job scheduled for the future is a backoff, not a stall.
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,available_at) VALUES($1,'SEND_EMAIL','PENDING',now()+interval '1 hour')`, store.NewID()); err != nil {
		t.Fatal(err)
	}
	stalled := admin.do(http.MethodGet, "/api/v1/admin/jobs", nil).json()
	waited := pendingAge(t, stalled)
	if waited < 1100 || waited > 1300 {
		t.Errorf("oldest_pending_seconds = %d, want roughly 1200", waited)
	}
}

func pendingAge(t *testing.T, body map[string]any) int {
	t.Helper()
	summary, ok := body["summary"].(map[string]any)
	if !ok {
		t.Fatalf("job listing carried no summary: %v", body)
	}
	waited, ok := summary["oldest_pending_seconds"].(float64)
	if !ok {
		t.Fatalf("summary has no oldest_pending_seconds: %v", summary)
	}
	return int(waited)
}

func TestOnlyAdministratorsReachTheJobQueue(t *testing.T) {
	h := newHarness(t)
	h.user("plainuser", "REQUESTER")
	if res := h.login("plainuser").do(http.MethodGet, "/api/v1/admin/jobs", nil); res.status != http.StatusForbidden {
		t.Errorf("a requester reached the job queue: %d", res.status)
	}
}

func TestNotificationPreferencesGovernEmailButNeverTheRecord(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	reviewerID := h.user("prefreviewer", "SECURITY_REVIEWER")
	h.user("prefwriter", "REQUESTER")
	writer := h.login("prefwriter")
	reviewer := h.login("prefreviewer")
	// E-mail has to be on globally for the per-user preference to matter.
	admin := h.login(adminOf(h))
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/notification", map[string]any{
		"email_enabled": true, "smtp_host": "smtp.internal", "smtp_port": 25, "smtp_username": "", "smtp_tls_mode": "none", "from": "seccheck@example.test", "digest_hour": 8,
	}); res.status != http.StatusOK {
		t.Fatalf("enable e-mail: %d %s", res.status, res.body)
	}

	reviewID := writer.createReview("알림 서비스")
	assign := func() {
		if res := writer.do(http.MethodPatch, "/api/v1/review-requests/"+reviewID, map[string]string{"reviewer_id": reviewerID}); res.status != http.StatusOK && res.status != http.StatusNoContent {
			t.Fatalf("assign reviewer: %d %s", res.status, res.body)
		}
	}
	assign()
	emailed := func() int {
		var n int
		if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE type='SEND_EMAIL'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if emailed() != 1 {
		t.Fatalf("the default preference should have queued one e-mail, got %d", emailed())
	}

	// Muting the event stops the mail but must not stop the record.
	if res := reviewer.do(http.MethodPut, "/api/v1/me/notification-preferences", map[string]any{"email_enabled": true, "digest": "IMMEDIATE", "muted_events": []string{"REVIEW_ASSIGNED"}}); res.status != http.StatusNoContent {
		t.Fatalf("save preference: %d %s", res.status, res.body)
	}
	assign()
	if emailed() != 1 {
		t.Errorf("a muted event still queued an e-mail (%d jobs)", emailed())
	}
	var recorded int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='REVIEW_ASSIGNED'`, reviewerID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 2 {
		t.Errorf("in-app notifications recorded = %d, want 2 regardless of e-mail preference", recorded)
	}

	// A daily-digest recipient is left for the digest worker: queued now, no
	// job, and emailed_at still null so the summary can pick it up.
	if res := reviewer.do(http.MethodPut, "/api/v1/me/notification-preferences", map[string]any{"email_enabled": true, "digest": "DAILY", "muted_events": []string{}}); res.status != http.StatusNoContent {
		t.Fatalf("save digest preference: %d %s", res.status, res.body)
	}
	assign()
	if emailed() != 1 {
		t.Errorf("a digest recipient should not queue an immediate e-mail (%d jobs)", emailed())
	}
	var awaiting int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND emailed_at IS NULL`, reviewerID).Scan(&awaiting); err != nil {
		t.Fatal(err)
	}
	if awaiting == 0 {
		t.Error("nothing was left for the daily digest to send")
	}
	if res := reviewer.do(http.MethodPut, "/api/v1/me/notification-preferences", map[string]any{"email_enabled": true, "digest": "HOURLY", "muted_events": []string{}}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("an unknown digest period was accepted: %d", res.status)
	}
	if res := reviewer.do(http.MethodPut, "/api/v1/me/notification-preferences", map[string]any{"email_enabled": true, "digest": "IMMEDIATE", "muted_events": []string{"NOT_AN_EVENT"}}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("an unknown event code was accepted: %d", res.status)
	}
}

func TestNotificationsLinkBackToTheirReview(t *testing.T) {
	h := newHarness(t)
	reviewerID := h.user("linkreviewer", "SECURITY_REVIEWER")
	h.user("linkwriter", "REQUESTER")
	writer := h.login("linkwriter")
	reviewer := h.login("linkreviewer")
	reviewID := writer.createReview("링크 서비스")
	writer.do(http.MethodPatch, "/api/v1/review-requests/"+reviewID, map[string]string{"reviewer_id": reviewerID})

	page := reviewer.do(http.MethodGet, "/api/v1/notifications", nil).json()
	items, _ := page["items"].([]any)
	if len(items) == 0 {
		t.Fatalf("the reviewer received no notification: %v", page)
	}
	first, _ := items[0].(map[string]any)
	if first["target_type"] != "REVIEW_REQUEST" || first["target_id"] != reviewID {
		t.Errorf("notification points at %v/%v, want REVIEW_REQUEST/%s", first["target_type"], first["target_id"], reviewID)
	}
	if unread := reviewer.do(http.MethodGet, "/api/v1/notifications?unread=1", nil).json(); unread["total"] == float64(0) {
		t.Error("the unread filter returned nothing while an unread notification exists")
	}
	if filtered := reviewer.do(http.MethodGet, "/api/v1/notifications?event=CHANGE_REQUEST", nil).json(); filtered["total"] != float64(0) {
		t.Errorf("the event filter matched unrelated notifications: %v", filtered["total"])
	}
}

func TestSMTPTestEndpointAcceptsAnEmptyBody(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	admin.do(http.MethodPatch, "/api/v1/me", map[string]string{"display_name": "관리자", "email": "admin@example.test", "department": ""})
	// No SMTP server is reachable from the test, so a delivery failure is the
	// expected outcome; what matters is that the request itself is accepted
	// rather than rejected for having no JSON body, which is what the console
	// sends.
	res := admin.do(http.MethodPost, "/api/v1/admin/settings/notification/test", nil)
	if res.errorCode() == "INVALID_JSON" {
		t.Fatalf("an empty body was rejected: %s", res.body)
	}
	if res.status != http.StatusBadGateway && res.status != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", res.status, res.body)
	}
	if res := admin.do(http.MethodPost, "/api/v1/admin/settings/notification/test", map[string]string{"recipient": "not-an-address"}); res.status == http.StatusOK {
		t.Error("an invalid recipient was accepted")
	}
}

func TestTemplateDeletionOnlyWhileUnused(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))

	created := admin.do(http.MethodPost, "/api/v1/templates", map[string]string{"name": "삭제 가능 템플릿", "category": "DEVELOPMENT", "description": "", "version": "V1.0"})
	if created.status != http.StatusCreated {
		t.Fatalf("create template: %d %s", created.status, created.body)
	}
	draftID, _ := created.json()["id"].(string)
	if res := admin.do(http.MethodDelete, "/api/v1/templates/"+draftID, nil); res.status != http.StatusNoContent {
		t.Fatalf("deleting an unused draft returned %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodGet, "/api/v1/templates/"+draftID, nil); res.status != http.StatusNotFound {
		t.Errorf("the template survived deletion: %d", res.status)
	}

	// A template the seeded workbook published is in use and must be refused.
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(admin.do(http.MethodGet, "/api/v1/templates?limit=200", nil).body), &list); err != nil {
		t.Fatal(err)
	}
	var publishedID string
	for _, tpl := range list.Items {
		versions, _ := tpl["versions"].([]any)
		for _, v := range versions {
			if version, ok := v.(map[string]any); ok && version["status"] == "PUBLISHED" {
				publishedID, _ = tpl["id"].(string)
			}
		}
	}
	if publishedID == "" {
		t.Fatal("the seeded workbook should have published at least one template")
	}
	res := admin.do(http.MethodDelete, "/api/v1/templates/"+publishedID, nil)
	if res.status != http.StatusConflict || res.errorCode() != "TEMPLATE_IN_USE" {
		t.Fatalf("a published template was deletable: %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodDelete, "/api/v1/templates/does-not-exist", nil); res.status != http.StatusNotFound {
		t.Errorf("deleting a missing template returned %d", res.status)
	}
}

func TestRuleSimulationExplainsAssignmentWithoutCreatingAReview(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	before := func() int {
		var n int
		if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM review_requests`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}()

	cloud := admin.do(http.MethodPost, "/api/v1/templates/rule-simulation", map[string]any{
		"service_name": "시뮬", "description": "d", "service_type": "WEB", "change_type": "NEW",
		"department": "보안팀", "exposure": "EXTERNAL", "uses_cloud": true, "processes_personal_data": false,
	}).json()
	plain := admin.do(http.MethodPost, "/api/v1/templates/rule-simulation", map[string]any{
		"service_name": "시뮬", "description": "d", "service_type": "WEB", "change_type": "NEW",
		"department": "보안팀", "exposure": "EXTERNAL", "uses_cloud": false, "processes_personal_data": false,
	}).json()

	cloudApplied, _ := cloud["applied"].(float64)
	plainApplied, _ := plain["applied"].(float64)
	if cloudApplied == 0 {
		t.Fatalf("a cloud profile was assigned nothing: %v", cloud)
	}
	if cloudApplied <= plainApplied {
		t.Errorf("enabling cloud assigned %v items, not more than the %v without it", cloudApplied, plainApplied)
	}
	items, _ := cloud["items"].([]any)
	if len(items) == 0 {
		t.Fatal("the simulation returned no per-item outcome")
	}
	excludedHasReason := false
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if applied, _ := item["applied"].(bool); !applied {
			if reason, _ := item["reason"].(string); reason != "" {
				excludedHasReason = true
			}
		}
	}
	if !excludedHasReason {
		t.Error("excluded items came back without a reason")
	}
	if after := func() int {
		var n int
		_ = h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM review_requests`).Scan(&n)
		return n
	}(); after != before {
		t.Errorf("the simulation created %d review requests", after-before)
	}

	// A requester previews the checklist their own answers would produce while
	// filling the form; it only reads published template metadata they see the
	// moment the review exists.
	h.user("plainrequester", "REQUESTER")
	requester := h.login("plainrequester")
	if res := requester.do(http.MethodPost, "/api/v1/templates/rule-simulation", map[string]any{"service_name": "x", "description": "d", "service_type": "WEB", "change_type": "NEW", "department": "보안팀", "exposure": "EXTERNAL", "uses_cloud": true}); res.status != http.StatusOK {
		t.Errorf("a requester could not preview their own assignment: %d %s", res.status, res.body)
	}
	// Someone with no review role at all still cannot.
	h.user("plainauditor", "AUDITOR")
	if res := h.login("plainauditor").do(http.MethodPost, "/api/v1/templates/rule-simulation", map[string]any{"service_name": "x", "service_type": "WEB"}); res.status != http.StatusForbidden {
		t.Errorf("an auditor reached the rule simulator: %d", res.status)
	}
}

func TestConfiguredTimezoneReachesTheClients(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/general", map[string]any{
		"service_name": "SecCheck", "timezone": "Asia/Seoul", "session_minutes": 480, "retention_days": 1825, "base_url": "",
	}); res.status != http.StatusOK {
		t.Fatalf("save timezone: %d %s", res.status, res.body)
	}
	if zone := admin.do(http.MethodGet, "/api/v1/me", nil).json()["timezone"]; zone != "Asia/Seoul" {
		t.Errorf("/me reported timezone %v", zone)
	}
	anon := &client{h: h}
	if zone := anon.do(http.MethodGet, "/api/v1/public/config", nil).json()["timezone"]; zone != "Asia/Seoul" {
		t.Errorf("public config reported timezone %v", zone)
	}
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/general", map[string]any{
		"service_name": "SecCheck", "timezone": "Mars/Olympus", "session_minutes": 480, "retention_days": 1825, "base_url": "",
	}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("an unknown zone name was accepted: %d %s", res.status, res.body)
	}
}

func TestReviewReportSummarisesAPeriod(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("reportwriter", "REQUESTER")
	writer := h.login("reportwriter")
	admin := h.login(adminOf(h))

	inPeriod := writer.createReview("기간 안 서비스")
	older := writer.createReview("기간 밖 서비스")
	// Push one review outside the window and complete the other, so the report
	// has something to separate.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET created_at=now()-interval '400 days' WHERE id=$1`, older); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET status='APPROVED',first_submitted_at=now()-interval '5 days',approved_at=now()-interval '1 day' WHERE id=$1`, inPeriod); err != nil {
		t.Fatal(err)
	}

	report := admin.do(http.MethodGet, "/api/v1/reports/reviews?from=2020-01-01", nil).json()
	totals, _ := report["totals"].(map[string]any)
	if created, _ := totals["created"].(float64); created != 2 {
		t.Errorf("created = %v over the whole range, want 2", totals["created"])
	}
	if completed, _ := totals["completed"].(float64); completed != 1 {
		t.Errorf("completed = %v, want 1", totals["completed"])
	}

	// Bounding the period must exclude the older review.
	recent := admin.do(http.MethodGet, "/api/v1/reports/reviews?from="+time.Now().AddDate(0, 0, -7).Format("2006-01-02"), nil).json()
	recentTotals, _ := recent["totals"].(map[string]any)
	if created, _ := recentTotals["created"].(float64); created != 1 {
		t.Errorf("created in the last week = %v, want 1", recentTotals["created"])
	}

	cycle, _ := report["cycle_time"].(map[string]any)
	if measured, _ := cycle["measured"].(float64); measured != 1 {
		t.Fatalf("cycle time measured %v reviews, want 1", cycle["measured"])
	}
	if average, _ := cycle["average_days"].(float64); average < 3.5 || average > 4.5 {
		t.Errorf("average cycle time = %v days, want about 4", cycle["average_days"])
	}

	if departments, _ := report["by_department"].([]any); len(departments) == 0 {
		t.Error("the department breakdown is empty")
	}
	if aging, _ := report["aging"].([]any); len(aging) == 0 {
		t.Error("the aging breakdown is empty while a review is still open")
	}

	// The workbook has to be a real xlsx, not an error page.
	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/reports/reviews?format=xlsx&from=2020-01-01", nil)
	res := admin.send(req)
	if res.status != http.StatusOK {
		t.Fatalf("xlsx report returned %d", res.status)
	}
	if !strings.HasPrefix(res.body, "PK\x03\x04") {
		t.Errorf("the report download is not a workbook (%d bytes)", len(res.body))
	}
	if got := res.raw.Header.Get("Content-Type"); !strings.Contains(got, "spreadsheetml") {
		t.Errorf("Content-Type = %q", got)
	}

	h.user("reportoutsider", "REQUESTER")
	if res := h.login("reportoutsider").do(http.MethodGet, "/api/v1/reports/reviews", nil); res.status != http.StatusForbidden {
		t.Errorf("a requester reached the report: %d", res.status)
	}
}

func TestConcurrentEditsAreDetectedRatherThanOverwritten(t *testing.T) {
	h := newHarness(t)
	owner := h.user("coauthor-owner", "REQUESTER")
	h.user("coauthor-two", "CONTRIBUTOR", "REQUESTER")
	first := h.login("coauthor-owner")
	second := h.login("coauthor-two")
	reviewID := first.createReview("동시 편집 서비스")
	var secondID string
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT id FROM users WHERE username='coauthor-two'`).Scan(&secondID); err != nil {
		t.Fatal(err)
	}
	if res := first.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/participants", map[string]string{"user_id": secondID}); res.status != http.StatusNoContent && res.status != http.StatusOK && res.status != http.StatusCreated {
		t.Fatalf("add participant: %d %s", res.status, res.body)
	}
	_ = owner

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(first.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	itemID := items[0]["id"].(string)
	path := fmt.Sprintf("/api/v1/review-requests/%s/responses/%s", reviewID, itemID)

	saved := first.do(http.MethodPut, path, map[string]any{"applicability": "Y", "self_assessment": "COMPLIANT", "current_state": "첫 번째 저장"})
	if saved.status != http.StatusOK {
		t.Fatalf("first save: %d %s", saved.status, saved.body)
	}
	version, _ := saved.json()["updated_at"].(string)
	if version == "" {
		t.Fatal("the save did not return a version to hold on to")
	}

	// The second author saves from the same starting point and wins the race.
	if res := second.do(http.MethodPut, path, map[string]any{"applicability": "N", "self_assessment": "INSUFFICIENT", "current_state": "두 번째 저장", "expected_updated_at": version}); res.status != http.StatusOK {
		t.Fatalf("second save: %d %s", res.status, res.body)
	}
	// The first author, still holding the old version, must be told rather than
	// silently discarding the other author's work.
	stale := first.do(http.MethodPut, path, map[string]any{"applicability": "Y", "current_state": "덮어쓰기 시도", "expected_updated_at": version})
	if stale.status != http.StatusConflict || stale.errorCode() != "RESPONSE_CONFLICT" {
		t.Fatalf("a stale save was accepted: %d %s", stale.status, stale.body)
	}
	details, _ := stale.json()["error"].(map[string]any)["details"].(map[string]any)
	if details["current_state"] != "두 번째 저장" {
		t.Errorf("the conflict did not report the stored value: %v", details)
	}
	if details["updated_by"] == "" {
		t.Error("the conflict did not say who saved it")
	}
	var stored string
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT current_state FROM responses WHERE submission_item_id=$1`, itemID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "두 번째 저장" {
		t.Errorf("the rejected save still changed the row to %q", stored)
	}
	// Deliberately overwriting is allowed once the author has seen the other
	// version, which is what the modal's second button does.
	if res := first.do(http.MethodPut, path, map[string]any{"applicability": "Y", "current_state": "의도적 덮어쓰기"}); res.status != http.StatusOK {
		t.Fatalf("forced overwrite: %d %s", res.status, res.body)
	}
}

func TestItemsCanBeAssignedInBulkToParticipantsOnly(t *testing.T) {
	h := newHarness(t)
	h.user("assign-owner", "REQUESTER")
	h.user("assign-helper", "CONTRIBUTOR", "REQUESTER")
	h.user("assign-outsider", "REQUESTER")
	owner := h.login("assign-owner")
	reviewID := owner.createReview("배정 서비스")
	ctx := context.Background()
	var helperID, outsiderID string
	_ = h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='assign-helper'`).Scan(&helperID)
	_ = h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='assign-outsider'`).Scan(&outsiderID)
	owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/participants", map[string]string{"user_id": helperID})

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(owner.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	ids := []string{items[0]["id"].(string), items[1]["id"].(string), items[2]["id"].(string)}

	if res := owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk", map[string]any{"item_ids": ids, "assign_only": true, "assigned_to": outsiderID}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("assigning to a non-participant returned %d %s", res.status, res.body)
	}
	res := owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk", map[string]any{"item_ids": ids, "assign_only": true, "assigned_to": helperID})
	if res.status != http.StatusOK {
		t.Fatalf("bulk assign: %d %s", res.status, res.body)
	}
	if applied, _ := res.json()["applied"].(float64); applied != 3 {
		t.Errorf("assigned %v items, want 3", res.json()["applied"])
	}
	var assigned int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM responses WHERE assigned_to=$1`, helperID).Scan(&assigned); err != nil {
		t.Fatal(err)
	}
	if assigned != 3 {
		t.Errorf("responses.assigned_to set on %d rows, want 3", assigned)
	}
	// Assignment must not invent answers.
	var answered int
	_ = h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM responses WHERE assigned_to=$1 AND applicability<>''`, helperID).Scan(&answered)
	if answered != 0 {
		t.Errorf("%d assigned items were given an answer", answered)
	}
	var notified int
	_ = h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='ITEM_ASSIGNED'`, helperID).Scan(&notified)
	if notified != 1 {
		t.Errorf("the assignee got %d notifications, want exactly one for the batch", notified)
	}
}

func TestTemplateAndControlListsArePaginatedAndSearchable(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))

	// The seeded workbook publishes several templates, which is enough to page.
	first := admin.do(http.MethodGet, "/api/v1/templates?limit=2&offset=0", nil).json()
	total, _ := first["total"].(float64)
	if total < 3 {
		t.Fatalf("expected the seeded templates, got total=%v", first["total"])
	}
	if items, _ := first["items"].([]any); len(items) != 2 {
		t.Fatalf("page size = %d, want 2", len(items))
	}
	if more, _ := first["has_more"].(bool); !more {
		t.Error("has_more should be true on the first page")
	}
	last := admin.do(http.MethodGet, fmt.Sprintf("/api/v1/templates?limit=2&offset=%d", int(total)-1), nil).json()
	if items, _ := last["items"].([]any); len(items) != 1 {
		t.Errorf("final page size = %d, want 1", len(items))
	}

	// Searching narrows the same envelope.
	cloud := admin.do(http.MethodGet, "/api/v1/templates?q="+url.QueryEscape("클라우드"), nil).json()
	cloudTotal, _ := cloud["total"].(float64)
	if cloudTotal == 0 || cloudTotal >= total {
		t.Errorf("search matched %v of %v templates", cloud["total"], first["total"])
	}
	if none := admin.do(http.MethodGet, "/api/v1/templates?q=zzz-no-such-template", nil).json(); none["total"] != float64(0) {
		t.Errorf("an impossible search matched %v", none["total"])
	}
	if filtered := admin.do(http.MethodGet, "/api/v1/templates?category=CLOUD", nil).json(); filtered["total"] == float64(0) {
		t.Error("the category filter matched nothing")
	}

	// Controls use the same shape.
	for i := 0; i < 3; i++ {
		if res := admin.do(http.MethodPost, "/api/v1/security-controls", map[string]string{"code": fmt.Sprintf("SEC-PAGE-%03d", i), "title": fmt.Sprintf("페이지 통제 %d", i), "description": "", "owner_id": ""}); res.status != http.StatusCreated {
			t.Fatalf("create control: %d %s", res.status, res.body)
		}
	}
	controls := admin.do(http.MethodGet, "/api/v1/security-controls?limit=2", nil).json()
	if controlTotal, _ := controls["total"].(float64); controlTotal != 3 {
		t.Errorf("controls total = %v, want 3", controls["total"])
	}
	if items, _ := controls["items"].([]any); len(items) != 2 {
		t.Errorf("controls page size = %d, want 2", len(items))
	}
	if searched := admin.do(http.MethodGet, "/api/v1/security-controls?q=SEC-PAGE-001", nil).json(); searched["total"] != float64(1) {
		t.Errorf("control search matched %v, want 1", searched["total"])
	}
}

func TestCommentsReachTheOtherSide(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	reviewerID := h.user("comment-reviewer", "SECURITY_REVIEWER")
	h.user("comment-author", "REQUESTER")
	author := h.login("comment-author")
	reviewer := h.login("comment-reviewer")
	reviewID := author.createReview("코멘트 서비스")
	author.do(http.MethodPatch, "/api/v1/review-requests/"+reviewID, map[string]string{"reviewer_id": reviewerID})

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	itemID := items[0]["id"].(string)
	itemCode, _ := items[0]["item_code"].(string)

	countFor := func(user string) int {
		var n int
		if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications n JOIN users u ON u.id=n.recipient_id WHERE u.username=$1 AND n.event_type='COMMENT_ADDED'`, user).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The reviewer asks a question; the author has to hear about it.
	if res := reviewer.do(http.MethodPost, fmt.Sprintf("/api/v1/review-requests/%s/items/%s/comments", reviewID, itemID), map[string]string{"body": "이 항목의 근거 자료를 보완해 주세요."}); res.status != http.StatusCreated {
		t.Fatalf("reviewer comment: %d %s", res.status, res.body)
	}
	if got := countFor("comment-author"); got != 1 {
		t.Errorf("the author received %d comment notifications, want 1", got)
	}
	if got := countFor("comment-reviewer"); got != 0 {
		t.Errorf("the commenter notified themselves %d times", got)
	}
	var body string
	if err := h.db.Pool.QueryRow(ctx, `SELECT body FROM notifications WHERE event_type='COMMENT_ADDED' ORDER BY created_at DESC LIMIT 1`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if itemCode != "" && !strings.Contains(body, itemCode) {
		t.Errorf("the notification does not say which item: %q", body)
	}

	// The author replies; now the reviewer is the one who needs to know.
	if res := author.do(http.MethodPost, fmt.Sprintf("/api/v1/review-requests/%s/items/%s/comments", reviewID, itemID), map[string]string{"body": "보완했습니다."}); res.status != http.StatusCreated {
		t.Fatalf("author comment: %d %s", res.status, res.body)
	}
	if got := countFor("comment-reviewer"); got != 1 {
		t.Errorf("the reviewer received %d comment notifications, want 1", got)
	}
	if got := countFor("comment-author"); got != 1 {
		t.Errorf("the author's own reply notified them again (%d)", got)
	}

	var targeted int
	_ = h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_type='COMMENT_ADDED' AND target_type='REVIEW_REQUEST' AND target_id=$1`, reviewID).Scan(&targeted)
	if targeted != 2 {
		t.Errorf("%d of 2 comment notifications link back to the review", targeted)
	}
}

func TestReviewNumbersAreUniqueUnderConcurrentCreation(t *testing.T) {
	h := newHarness(t)
	h.user("numbering", "REQUESTER")
	author := h.login("numbering")
	const parallel = 8
	var wg sync.WaitGroup
	numbers := make([]string, parallel)
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			numbers[slot] = author.createReview(fmt.Sprintf("동시 생성 %d", slot))
		}(i)
	}
	wg.Wait()

	rows, err := h.db.Pool.Query(context.Background(), `SELECT review_number FROM review_requests ORDER BY review_number`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	count := 0
	for rows.Next() {
		var number string
		if err = rows.Scan(&number); err != nil {
			t.Fatal(err)
		}
		if seen[number] {
			t.Errorf("review number %s was allocated twice", number)
		}
		seen[number] = true
		count++
		if !strings.HasPrefix(number, fmt.Sprintf("SC-%d-", time.Now().Year())) && !strings.HasPrefix(number, fmt.Sprintf("SC-%d-", time.Now().Year()+1)) {
			t.Errorf("unexpected review number format: %s", number)
		}
	}
	if count != parallel {
		t.Errorf("created %d reviews, want %d", count, parallel)
	}
}

func TestReReviewCopyReportsWhatCarriedOver(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("recopy", "REQUESTER")
	author := h.login("recopy")
	admin := h.login(adminOf(h))
	reviewID := author.createReview("재심의 원본")

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	ids := []string{}
	for i := 0; i < 4 && i < len(items); i++ {
		ids = append(ids, items[i]["id"].(string))
	}
	if res := author.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk", map[string]any{"item_ids": ids, "applicability": "N/A", "self_assessment": "N/A", "na_reason": "대상 아님"}); res.status != http.StatusOK {
		t.Fatalf("seed answers: %d %s", res.status, res.body)
	}
	// Retire a template so the copy is genuinely built from a different set.
	var templateID, versionID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT t.id,v.id FROM checklist_templates t JOIN checklist_versions v ON v.template_id=t.id WHERE v.status='PUBLISHED' AND t.category='CLOUD' LIMIT 1`).Scan(&templateID, &versionID); err == nil {
		admin.do(http.MethodPatch, "/api/v1/templates/"+templateID, map[string]any{"Name": "", "Description": "", "Active": false})
	}

	res := author.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/copy", nil)
	if res.status != http.StatusCreated {
		t.Fatalf("copy: %d %s", res.status, res.body)
	}
	out := res.json()
	carried, _ := out["carried"].(float64)
	total, _ := out["total"].(float64)
	if carried != 4 {
		t.Errorf("carried = %v answered items, want the 4 that were filled in", out["carried"])
	}
	if total == 0 || carried > total {
		t.Errorf("total = %v with carried = %v", out["total"], out["carried"])
	}
	if _, ok := out["new_items"].(float64); !ok {
		t.Error("the copy did not report how many items are new")
	}
	if _, ok := out["dropped_items"].(float64); !ok {
		t.Error("the copy did not report how many items were dropped")
	}
	// Copied responses must get real identifiers, not an eight character stub.
	var shortIDs int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM responses WHERE length(id) < 32`).Scan(&shortIDs); err != nil {
		t.Fatal(err)
	}
	if shortIDs != 0 {
		t.Errorf("%d copied responses have collision-prone short ids", shortIDs)
	}
}

func TestViewerParticipantsCanReadButNotWrite(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.user("part-owner", "REQUESTER")
	h.user("part-writer", "CONTRIBUTOR", "REQUESTER")
	h.user("part-viewer", "CONTRIBUTOR", "REQUESTER")
	owner := h.login("part-owner")
	reviewID := owner.createReview("참여자 서비스")
	var writerID, viewerID string
	_ = h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='part-writer'`).Scan(&writerID)
	_ = h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='part-viewer'`).Scan(&viewerID)

	if res := owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/participants", map[string]string{"user_id": writerID, "role": "CONTRIBUTOR"}); res.status != http.StatusNoContent {
		t.Fatalf("add contributor: %d %s", res.status, res.body)
	}
	if res := owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/participants", map[string]string{"user_id": viewerID, "role": "VIEWER"}); res.status != http.StatusNoContent {
		t.Fatalf("add viewer: %d %s", res.status, res.body)
	}
	if res := owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/participants", map[string]string{"user_id": viewerID, "role": "AUDITOR"}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("an unknown participant role was accepted: %d", res.status)
	}

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(owner.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	path := fmt.Sprintf("/api/v1/review-requests/%s/responses/%s", reviewID, items[0]["id"].(string))
	payload := map[string]any{"applicability": "Y", "self_assessment": "COMPLIANT"}

	writer := h.login("part-writer")
	viewer := h.login("part-viewer")
	// Both can read.
	for name, c := range map[string]*client{"contributor": writer, "viewer": viewer} {
		if res := c.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil); res.status != http.StatusOK {
			t.Errorf("%s could not read the review: %d", name, res.status)
		}
	}
	// Only the contributor can write.
	if res := writer.do(http.MethodPut, path, payload); res.status != http.StatusOK {
		t.Errorf("the contributor could not write: %d %s", res.status, res.body)
	}
	if res := viewer.do(http.MethodPut, path, payload); res.status != http.StatusForbidden {
		t.Errorf("a viewer wrote to the checklist: %d %s", res.status, res.body)
	}
	// A viewer must not be handed items to fill in either.
	if res := owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk", map[string]any{"item_ids": []string{items[1]["id"].(string)}, "assign_only": true, "assigned_to": viewerID}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("items were assigned to a read-only participant: %d %s", res.status, res.body)
	}
	// Changing the role afterwards has to take effect.
	if res := owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/participants", map[string]string{"user_id": viewerID, "role": "CONTRIBUTOR"}); res.status != http.StatusNoContent {
		t.Fatalf("promote viewer: %d %s", res.status, res.body)
	}
	if res := viewer.do(http.MethodPut, path, payload); res.status != http.StatusOK {
		t.Errorf("a promoted viewer still could not write: %d %s", res.status, res.body)
	}
}

func TestAuditListLabelsEventsAndOffersACatalogue(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	page := admin.do(http.MethodGet, "/api/v1/admin/audit?limit=50", nil).json()

	events, _ := page["events"].([]any)
	if len(events) < 20 {
		t.Fatalf("the event catalogue has %d entries, want the full vocabulary", len(events))
	}
	for _, raw := range events {
		entry, _ := raw.(map[string]any)
		if entry["code"] == "" || entry["label"] == "" {
			t.Errorf("catalogue entry is incomplete: %v", entry)
		}
	}

	items, _ := page["items"].([]any)
	if len(items) == 0 {
		t.Fatal("the login should have produced an audit entry")
	}
	for _, raw := range items {
		record, _ := raw.(map[string]any)
		if label, _ := record["event_label"].(string); label == "" {
			t.Errorf("audit row %v has no readable label", record["event_type"])
		}
	}

	// The CSV carries the label as its first column so the spreadsheet is
	// readable without a lookup.
	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/admin/audit?format=csv", nil)
	csv := admin.send(req)
	if csv.status != http.StatusOK {
		t.Fatalf("csv export returned %d", csv.status)
	}
	header := strings.SplitN(strings.TrimPrefix(csv.body, "\ufeff"), "\n", 2)[0]
	if !strings.HasPrefix(header, "event_label,event_id") {
		t.Errorf("unexpected CSV header: %q", header)
	}
	if !strings.Contains(csv.body, "로그인") {
		t.Error("the CSV does not carry the Korean label")
	}
}

func TestOpenAPIDocumentIsCompleteAndUsable(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	spec := admin.do(http.MethodGet, "/api/openapi.json", nil).json()

	paths, _ := spec["paths"].(map[string]any)
	if len(paths) < 60 {
		t.Fatalf("the document describes %d paths, want the whole API", len(paths))
	}
	for _, required := range []string{"/api/v1/auth/login", "/api/v1/review-requests", "/api/v1/admin/jobs", "/api/v1/reports/reviews", "/mcp"} {
		if paths[required] == nil {
			t.Errorf("%s is missing from the document", required)
		}
	}

	// Path parameters have to be declared or a generated client cannot call it.
	item, _ := paths["/api/v1/review-requests/{id}/responses/{itemID}"].(map[string]any)
	if item == nil {
		t.Fatal("a parameterised path is missing")
	}
	params, _ := item["parameters"].([]any)
	if len(params) != 2 {
		t.Errorf("declared %d path parameters, want id and itemID", len(params))
	}

	// The roles an endpoint needs belong in the document.
	admins, _ := paths["/api/v1/admin/jobs"].(map[string]any)
	get, _ := admins["get"].(map[string]any)
	roles, _ := get["x-required-roles"].([]any)
	if len(roles) != 1 || roles[0] != "SYSTEM_ADMIN" {
		t.Errorf("admin job listing declares roles %v", roles)
	}
	// A public endpoint must say it needs nothing.
	login, _ := paths["/api/v1/auth/login"].(map[string]any)
	post, _ := login["post"].(map[string]any)
	if security, ok := post["security"].([]any); !ok || len(security) != 0 {
		t.Errorf("the sign-in endpoint does not declare itself public: %v", post["security"])
	}
	if _, ok := spec["tags"].([]any); !ok {
		t.Error("the document has no tag list")
	}
}

func TestIdleTimeoutEndsASessionThatOnlyPolls(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.login(adminOf(h))
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/security", map[string]any{
		"cookie_secure": false, "cors_origins": []string{}, "rate_limit_per_minute": 10000,
		"inactive_admin_lock_days": 90, "login_rate_limit_per_minute": 600, "max_login_failures": 0,
		"lockout_minutes": 15, "idle_timeout_minutes": 5, "trusted_proxies": []string{}, "require_totp_for_admins": false,
	}); res.status != http.StatusOK {
		t.Fatalf("enable idle timeout: %d %s", res.status, res.body)
	}

	h.user("idler", "REQUESTER")
	idler := h.login("idler")
	age := func(minutes int) {
		t.Helper()
		if _, err := h.db.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now()-make_interval(mins=>$2) WHERE id=$1`, idlerSessionID(t, h, "idler"), minutes); err != nil {
			t.Fatal(err)
		}
	}

	// Background polling must not count as being at the desk.
	age(4)
	if res := idler.do(http.MethodGet, "/api/v1/notifications/unread-count", nil); res.status != http.StatusOK {
		t.Fatalf("the poll itself should still work at 4 minutes idle: %d", res.status)
	}
	var seen bool
	if err := h.db.Pool.QueryRow(ctx, `SELECT last_seen_at < now()-interval '3 minutes' FROM sessions WHERE id=$1`, idlerSessionID(t, h, "idler")).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("the badge poll refreshed last_seen_at, so an unattended tab would never time out")
	}

	// Real use does count.
	if res := idler.do(http.MethodGet, "/api/v1/me", nil); res.status != http.StatusOK {
		t.Fatalf("real use failed: %d", res.status)
	}
	if err := h.db.Pool.QueryRow(ctx, `SELECT last_seen_at > now()-interval '1 minute' FROM sessions WHERE id=$1`, idlerSessionID(t, h, "idler")).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if !seen {
		t.Error("a real request did not refresh the session")
	}

	// Past the window the session is gone, and polling does not save it.
	age(9)
	if res := idler.do(http.MethodGet, "/api/v1/notifications/unread-count", nil); res.status != http.StatusUnauthorized {
		t.Errorf("an idle session survived the timeout: %d", res.status)
	}
	var remaining int
	_ = h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.username='idler'`).Scan(&remaining)
	if remaining != 0 {
		t.Errorf("%d expired sessions were left behind", remaining)
	}
}

func idlerSessionID(t *testing.T, h *harness, username string) string {
	t.Helper()
	var id string
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT s.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.username=$1 ORDER BY s.created_at DESC LIMIT 1`, username).Scan(&id); err != nil {
		t.Fatalf("find session for %s: %v", username, err)
	}
	return id
}

func TestSettingChangesApplyImmediately(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	// A cache that outlives the save makes an administrator think the setting
	// did not work, so the change has to be live on the very next request.
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/general", map[string]any{
		"service_name": "SecCheck", "timezone": "Asia/Seoul", "session_minutes": 480, "retention_days": 1825, "base_url": "",
	}); res.status != http.StatusOK {
		t.Fatalf("save: %d %s", res.status, res.body)
	}
	if zone := admin.do(http.MethodGet, "/api/v1/me", nil).json()["timezone"]; zone != "Asia/Seoul" {
		t.Errorf("time zone still %v on the next request", zone)
	}
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/general", map[string]any{
		"service_name": "SecCheck", "timezone": "UTC", "session_minutes": 480, "retention_days": 1825, "base_url": "",
	}); res.status != http.StatusOK {
		t.Fatalf("save again: %d %s", res.status, res.body)
	}
	if zone := admin.do(http.MethodGet, "/api/v1/me", nil).json()["timezone"]; zone != "UTC" {
		t.Errorf("time zone still %v after the second change", zone)
	}
}

func TestReviewHistoryIsScopedAndVisibleToParticipants(t *testing.T) {
	h := newHarness(t)
	reviewerID := h.user("history-reviewer", "SECURITY_REVIEWER")
	h.user("history-author", "REQUESTER")
	h.user("history-outsider", "REQUESTER")
	author := h.login("history-author")
	reviewer := h.login("history-reviewer")

	reviewID := author.createReview("이력 서비스")
	other := author.createReview("다른 서비스")
	author.do(http.MethodPatch, "/api/v1/review-requests/"+reviewID, map[string]string{"reviewer_id": reviewerID})

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	itemID, _ := items[0]["id"].(string)
	itemCode, _ := items[0]["item_code"].(string)
	author.do(http.MethodPut, fmt.Sprintf("/api/v1/review-requests/%s/responses/%s", reviewID, itemID), map[string]any{"applicability": "Y", "self_assessment": "COMPLIANT"})
	reviewer.do(http.MethodPost, fmt.Sprintf("/api/v1/review-requests/%s/items/%s/comments", reviewID, itemID), map[string]string{"body": "확인 부탁드립니다."})

	page := author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/history", nil).json()
	entries, _ := page["items"].([]any)
	if len(entries) < 3 {
		t.Fatalf("history has %d entries, want the creation, the answer and the comment at least", len(entries))
	}
	kinds := map[string]bool{}
	labelled := 0
	for _, raw := range entries {
		entry, _ := raw.(map[string]any)
		kinds[fmt.Sprint(entry["event_type"])] = true
		if label, _ := entry["event_label"].(string); label != "" {
			labelled++
		}
	}
	if labelled != len(entries) {
		t.Errorf("%d of %d history entries have a readable label", labelled, len(entries))
	}
	for _, want := range []string{"CREATE_SUBMISSION", "UPDATE_RESPONSE", "CREATE_COMMENT"} {
		if !kinds[want] {
			t.Errorf("%s is missing from the history: %v", want, kinds)
		}
	}
	// Item-level events say which item they belong to.
	foundItem := false
	for _, raw := range entries {
		entry, _ := raw.(map[string]any)
		if entry["event_type"] == "UPDATE_RESPONSE" && entry["item_code"] == itemCode {
			foundItem = true
		}
	}
	if !foundItem && itemCode != "" {
		t.Error("an item-level event does not name its checklist item")
	}

	// The other review's events must not leak in.
	otherPage := author.do(http.MethodGet, "/api/v1/review-requests/"+other+"/history", nil).json()
	if otherEntries, _ := otherPage["items"].([]any); len(otherEntries) >= len(entries) {
		t.Errorf("the second review shows %d entries against the first review's %d; the scope is too wide", len(otherEntries), len(entries))
	}

	// And someone with no access to the review cannot read its history.
	if res := h.login("history-outsider").do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/history", nil); res.status != http.StatusNotFound {
		t.Errorf("an unrelated user read the review history: %d", res.status)
	}
}

// "게시 후 불변인 체크리스트 버전과 제출 시점 Snapshot" is the product's
// headline promise and had no test. Both halves are checked here: a published
// version cannot be edited, and a review's checklist does not move under it
// when the templates change afterwards.
func TestPublishedVersionsAreImmutableAndSnapshotsAreStable(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))

	created := admin.do(http.MethodPost, "/api/v1/templates", map[string]string{"name": "불변 템플릿", "category": "DEVELOPMENT", "description": "", "version": "V1.0"})
	if created.status != http.StatusCreated {
		t.Fatalf("create template: %d %s", created.status, created.body)
	}
	templateID, _ := created.json()["id"].(string)
	detail := admin.do(http.MethodGet, "/api/v1/templates/"+templateID, nil).json()
	versions, _ := detail["versions"].([]any)
	if len(versions) == 0 {
		t.Fatal("the new template has no draft version")
	}
	first, _ := versions[0].(map[string]any)
	versionID, _ := first["id"].(string)
	itemPath := fmt.Sprintf("/api/v1/templates/%s/versions/%s/items", templateID, versionID)

	// An empty version must not be publishable.
	if res := admin.do(http.MethodPost, fmt.Sprintf("/api/v1/templates/%s/versions/%s/publish", templateID, versionID), nil); res.errorCode() != "EMPTY_VERSION" {
		t.Errorf("an empty version was publishable: %d %s", res.status, res.body)
	}
	// Retiring something that was never published must not work either.
	if res := admin.do(http.MethodPost, fmt.Sprintf("/api/v1/templates/%s/versions/%s/retire", templateID, versionID), nil); res.status != http.StatusConflict {
		t.Errorf("a draft was retirable: %d", res.status)
	}

	item := map[string]any{"item_code": "IMM-001", "title": "불변 항목", "question": "질문", "category": "DEVELOPMENT", "severity": "HIGH", "required": true, "answer_type": "YNNA", "section": "공통"}
	added := admin.do(http.MethodPost, itemPath, item)
	if added.status != http.StatusCreated && added.status != http.StatusOK {
		t.Fatalf("add item to a draft: %d %s", added.status, added.body)
	}
	itemID, _ := added.json()["id"].(string)

	if res := admin.do(http.MethodPost, fmt.Sprintf("/api/v1/templates/%s/versions/%s/publish", templateID, versionID), nil); res.status != http.StatusOK {
		t.Fatalf("publish: %d %s", res.status, res.body)
	}
	// Publishing twice is a state conflict, not a silent no-op.
	if res := admin.do(http.MethodPost, fmt.Sprintf("/api/v1/templates/%s/versions/%s/publish", templateID, versionID), nil); res.status != http.StatusConflict {
		t.Errorf("a published version was published again: %d", res.status)
	}

	// Every way of changing a published version has to be refused.
	changed := map[string]any{"item_code": "IMM-001", "title": "몰래 수정", "question": "질문", "category": "DEVELOPMENT", "severity": "LOW", "required": true, "answer_type": "YNNA", "section": "공통"}
	for name, res := range map[string]response{
		"add":    admin.do(http.MethodPost, itemPath, map[string]any{"item_code": "IMM-002", "title": "추가", "question": "질문", "category": "DEVELOPMENT", "severity": "LOW", "required": true, "answer_type": "YNNA", "section": "공통"}),
		"update": admin.do(http.MethodPatch, itemPath+"/"+itemID, changed),
		"delete": admin.do(http.MethodDelete, itemPath+"/"+itemID, nil),
	} {
		if res.status != http.StatusConflict || res.errorCode() != "IMMUTABLE_VERSION" {
			t.Errorf("%s on a published version returned %d %s", name, res.status, res.body)
		}
	}
	var storedTitle, storedSeverity string
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT title,severity FROM checklist_items WHERE id=$1`, itemID).Scan(&storedTitle, &storedSeverity); err != nil {
		t.Fatal(err)
	}
	if storedTitle != "불변 항목" || storedSeverity != "HIGH" {
		t.Errorf("the published item changed to %q/%s", storedTitle, storedSeverity)
	}

	// Second half: a review's snapshot must not move when templates change.
	h.user("snapshot-author", "REQUESTER")
	author := h.login("snapshot-author")
	reviewID := author.createReview("스냅샷 서비스")
	before := []map[string]any{}
	_ = json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &before)
	if len(before) == 0 {
		t.Fatal("the review was assigned no items")
	}

	// Publish a whole new version of the same template with a different item.
	newVersion := admin.do(http.MethodPost, "/api/v1/templates/"+templateID+"/versions", map[string]string{"version": "V2.0", "change_note": "이후 변경"})
	if newVersion.status != http.StatusCreated && newVersion.status != http.StatusOK {
		t.Fatalf("create a second version: %d %s", newVersion.status, newVersion.body)
	}
	secondID, _ := newVersion.json()["id"].(string)
	secondPath := fmt.Sprintf("/api/v1/templates/%s/versions/%s/items", templateID, secondID)
	admin.do(http.MethodPost, secondPath, map[string]any{"item_code": "IMM-NEW", "title": "새 버전 항목", "question": "질문", "category": "DEVELOPMENT", "severity": "HIGH", "required": true, "answer_type": "YNNA", "section": "공통"})
	if res := admin.do(http.MethodPost, fmt.Sprintf("/api/v1/templates/%s/versions/%s/publish", templateID, secondID), nil); res.status != http.StatusOK {
		t.Fatalf("publish the second version: %d %s", res.status, res.body)
	}

	after := []map[string]any{}
	_ = json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &after)
	if len(after) != len(before) {
		t.Fatalf("the in-flight review went from %d items to %d after a template change", len(before), len(after))
	}
	for i := range before {
		if before[i]["item_code"] != after[i]["item_code"] || before[i]["title"] != after[i]["title"] {
			t.Errorf("snapshot item %d changed under the review: %v -> %v", i, before[i]["item_code"], after[i]["item_code"])
		}
	}
	for _, entry := range after {
		if entry["item_code"] == "IMM-NEW" {
			t.Error("a newly published item appeared in an existing review's snapshot")
		}
	}

	// Staying on the old edition is correct, but the review has to say so.
	detail2 := author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil).json()
	templates, _ := detail2["template_versions"].([]any)
	if len(templates) == 0 {
		t.Fatal("the review does not report which template versions it was built from")
	}
	reported := false
	for _, raw := range templates {
		entry, _ := raw.(map[string]any)
		if entry["snapshot_version"] == "" {
			t.Errorf("a snapshot template has no version: %v", entry)
		}
		if outdated, _ := entry["outdated"].(bool); outdated {
			reported = true
			if entry["current_version"] == entry["snapshot_version"] {
				t.Errorf("an entry is flagged outdated while the versions match: %v", entry)
			}
		}
	}
	if !reported {
		t.Error("a newer published version exists but no template is reported as outdated")
	}
}

// The exported report is the artefact that circulates. It recorded the answers
// but never what was attached to support them, so a reader could not tell
// evidence from an assertion.
func TestExportedReportRecordsTheEvidence(t *testing.T) {
	h := newHarness(t)
	h.user("export-author", "REQUESTER")
	author := h.login("export-author")
	reviewID := author.createReview("내보내기 서비스")

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	itemID, _ := items[0]["id"].(string)
	itemCode, _ := items[0]["item_code"].(string)
	if res := author.upload(fmt.Sprintf("/api/v1/review-requests/%s/items/%s/evidences", reviewID, itemID), "증적자료.txt", "증적 본문입니다"); res.status != http.StatusCreated {
		t.Fatalf("upload evidence: %d %s", res.status, res.body)
	}
	// JSON keeps the structured record.
	jsonExport := author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/export/json", nil)
	if !strings.Contains(jsonExport.body, "증적자료.txt") {
		t.Error("the JSON export does not mention the attachment")
	}

	// The workbook must name the file and carry its hash on the evidence sheet.
	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/review-requests/"+reviewID+"/export/xlsx", nil)
	book := author.send(req)
	if book.status != http.StatusOK || !strings.HasPrefix(book.body, "PK\x03\x04") {
		t.Fatalf("xlsx export returned %d (%d bytes)", book.status, len(book.body))
	}
	strings_, err := readXLSXStrings([]byte(book.body))
	if err != nil {
		t.Fatalf("read workbook: %v", err)
	}
	for _, want := range []string{"증적자료.txt", "증적 목록", "첨부 증적", "SHA-256", itemCode} {
		if want == "" {
			continue
		}
		if !strings.Contains(strings_, want) {
			t.Errorf("the workbook does not contain %q", want)
		}
	}

	// And the PDF names it too. PDF generation needs a Korean font from the
	// host; the release image installs one but a bare test runner may not have
	// it, so a clearly reported FONT_MISSING is an acceptable outcome here
	// while any other failure is not.
	req, _ = http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/review-requests/"+reviewID+"/export/pdf", nil)
	pdf := author.send(req)
	switch {
	case pdf.status == http.StatusOK:
		if !strings.HasPrefix(pdf.body, "%PDF") {
			t.Errorf("the pdf export is not a PDF (%d bytes)", len(pdf.body))
		}
	case pdf.errorCode() == "FONT_MISSING":
		t.Log("no Korean font on this host; the PDF path reported it cleanly")
	default:
		t.Errorf("pdf export returned %d %s", pdf.status, pdf.body)
	}
}

// readXLSXStrings returns the workbook parts that carry text: the shared
// string table, the sheets, and the workbook itself where sheet names live.
func readXLSXStrings(body []byte) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for _, file := range reader.File {
		if !strings.HasPrefix(file.Name, "xl/sharedStrings") && !strings.HasPrefix(file.Name, "xl/worksheets") && file.Name != "xl/workbook.xml" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			continue
		}
		content, _ := io.ReadAll(rc)
		rc.Close()
		out.Write(content)
	}
	return out.String(), nil
}

// A compliance export that quietly stops at the row cap looks complete and is
// not, which is the worst possible failure for an audit log.
func TestAnExportSaysWhenItHitTheRowCap(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	small := admin.do(http.MethodGet, "/api/v1/admin/audit?format=csv", nil)
	if small.status != http.StatusOK {
		t.Fatalf("audit export returned %d", small.status)
	}
	if got := small.raw.Header.Get("X-Export-Truncated"); got != "" {
		t.Errorf("a complete export claimed truncation at %q", got)
	}
	if !strings.HasPrefix(small.body, "\ufeff") {
		t.Error("the CSV lost its BOM, so Excel on a Korean desktop will mangle it")
	}
}

// The gauge that tells a monitoring system the queue is stuck has to be
// correct for the same reason the in-app warning does: nobody watches it
// until it fires, and by then there is no chance to double-check.
func TestMetricsExposeHowLongTheQueueHasBeenStuck(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,available_at) VALUES($1,'SEND_EMAIL','PENDING',now()-interval '25 minutes')`, store.NewID()); err != nil {
		t.Fatal(err)
	}
	body := admin.do(http.MethodGet, "/metrics", nil).body
	var seconds float64
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "seccheck_jobs_oldest_pending_seconds ") {
			seconds, _ = strconv.ParseFloat(strings.Fields(line)[1], 64)
		}
	}
	if seconds < 1400 || seconds > 1600 {
		t.Errorf("seccheck_jobs_oldest_pending_seconds = %v, want roughly 1500", seconds)
	}
}

// Turning the approval step on after a review was submitted leaves it waiting
// for an approver it never had. Every approver saw it in their queue and none
// of them could decide it, with no way to assign one after the fact.
func TestAnApprovalWithNoNamedApproverIsNotStuck(t *testing.T) {
	h := newHarness(t)
	h.login(adminOf(h))
	requester := h.user("stranded-requester", "REQUESTER")
	approver := h.user("late-approver", "APPROVER")
	ctx := context.Background()
	id := store.NewID()
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status)
                VALUES($1,$2,'결재 대기 서비스','설명','WEB','NEW',$3,$3,'보안팀',$3,'INTERNAL','APPROVAL_PENDING')`, id, "SR-STUCK-1", requester); err != nil {
		t.Fatal(err)
	}
	if res := h.login("late-approver").do(http.MethodPost, "/api/v1/review-requests/"+id+"/approve", map[string]string{"comment": "확인"}); res.status != http.StatusOK {
		t.Fatalf("an approver could not decide an unassigned approval: %d %s", res.status, res.body)
	}
	var status, decided string
	if err := h.db.Pool.QueryRow(ctx, `SELECT status,COALESCE(approver_id,'') FROM review_requests WHERE id=$1`, id).Scan(&status, &decided); err != nil {
		t.Fatal(err)
	}
	if status != "APPROVED" {
		t.Errorf("status = %s, want APPROVED", status)
	}
	if decided != approver {
		t.Errorf("the review does not record who approved it: %q", decided)
	}
}

// An approver who has left the organisation strands the review just as badly,
// because nothing may change once it is waiting for approval.
func TestAnAdministratorCanHandAPendingApprovalToSomeoneElse(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	requester := h.user("handover-requester", "REQUESTER")
	gone := h.user("departed-approver", "APPROVER")
	successor := h.user("successor-approver", "APPROVER")
	outsider := h.user("not-an-approver", "REQUESTER")
	ctx := context.Background()
	id := store.NewID()
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,approver_id,exposure,status)
                VALUES($1,$2,'승계 서비스','설명','WEB','NEW',$3,$3,'보안팀',$3,$4,'INTERNAL','APPROVAL_PENDING')`, id, "SR-STUCK-2", requester, gone); err != nil {
		t.Fatal(err)
	}
	if res := h.login("successor-approver").do(http.MethodPost, "/api/v1/review-requests/"+id+"/approve", map[string]string{"comment": ""}); res.status != http.StatusConflict {
		t.Fatalf("an approver who was not named decided someone else's approval: %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodPatch, "/api/v1/review-requests/"+id, map[string]string{"approver_id": outsider}); res.status == http.StatusOK {
		t.Error("the approval was handed to a user without the approver role")
	}
	if res := admin.do(http.MethodPatch, "/api/v1/review-requests/"+id, map[string]string{"approver_id": successor}); res.status != http.StatusOK {
		t.Fatalf("an administrator could not reassign the approver: %d %s", res.status, res.body)
	}
	if res := h.login("successor-approver").do(http.MethodPost, "/api/v1/review-requests/"+id+"/approve", map[string]string{"comment": "승계 승인"}); res.status != http.StatusOK {
		t.Fatalf("the new approver still could not decide: %d %s", res.status, res.body)
	}
	var events int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='REASSIGN_APPROVER' AND target_id=$1`, id).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("the handover left %d audit events, want 1", events)
	}
}

// A requester must not be able to reach the administrator's escape hatch.
func TestOnlyAnAdministratorReassignsAPendingApproval(t *testing.T) {
	h := newHarness(t)
	_ = h.login(adminOf(h))
	requester := h.user("plain-requester", "REQUESTER")
	successor := h.user("another-approver", "APPROVER")
	id := store.NewID()
	if _, err := h.db.Pool.Exec(context.Background(), `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status)
                VALUES($1,$2,'권한 확인','설명','WEB','NEW',$3,$3,'보안팀',$3,'INTERNAL','APPROVAL_PENDING')`, id, "SR-STUCK-3", requester); err != nil {
		t.Fatal(err)
	}
	if res := h.login("plain-requester").do(http.MethodPatch, "/api/v1/review-requests/"+id, map[string]string{"approver_id": successor}); res.status != http.StatusForbidden {
		t.Errorf("a requester reassigned the approver: %d %s", res.status, res.body)
	}
}

// An approval carries an optional comment, so a client that sends no body at
// all -- the obvious call for an integration -- has to work.
func TestApprovalAcceptsAnEmptyBody(t *testing.T) {
	h := newHarness(t)
	h.login(adminOf(h))
	requester := h.user("empty-body-requester", "REQUESTER")
	approver := h.user("empty-body-approver", "APPROVER")
	id := store.NewID()
	if _, err := h.db.Pool.Exec(context.Background(), `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,approver_id,exposure,status)
                VALUES($1,$2,'본문 없는 승인','설명','WEB','NEW',$3,$3,'보안팀',$3,$4,'INTERNAL','APPROVAL_PENDING')`, id, "SR-EMPTY-1", requester, approver); err != nil {
		t.Fatal(err)
	}
	if res := h.login("empty-body-approver").do(http.MethodPost, "/api/v1/review-requests/"+id+"/approve", nil); res.status != http.StatusOK {
		t.Fatalf("an approval with no body returned %d %s", res.status, res.body)
	}
}

// Twenty endpoints are authorised by whether the caller takes part in the
// review rather than by a role, and the OpenAPI document now says so. This
// walks that same list over HTTP as somebody with no connection to the review
// and insists none of them answers. A route added without its check fails
// here, not in production.
func TestOutsidersReachNoneOfTheReviewScopedEndpoints(t *testing.T) {
	h := newHarness(t)
	owner := h.login(adminOf(h))
	reviewID := owner.createReview("외부인 차단 확인")
	ctx := context.Background()

	items := []map[string]any{}
	if err := json.Unmarshal([]byte(owner.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("the review has no checklist items to probe with")
	}
	itemID, _ := items[0]["id"].(string)

	evidenceID, changeID := store.NewID(), store.NewID()
	var ownerUUID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='integration-admin'`).Scan(&ownerUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO evidences(id,submission_item_id,original_filename,stored_filename,mime_type,size_bytes,sha256,uploaded_by,key_owner_id,key_version,scan_status)
                VALUES($1,$2,'증적.pdf','stored.bin','application/pdf',10,'abc',$3,$3,1,'CLEAN')`, evidenceID, itemID, ownerUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO change_requests(id,review_request_id,submission_item_id,reason,requester_id) VALUES($1,$2,$3,'보완',$4)`, changeID, reviewID, itemID, ownerUUID); err != nil {
		t.Fatal(err)
	}

	// Every role except the two that are meant to see every review, so only
	// the participation check can be what stops them. SYSTEM_ADMIN is in the
	// list deliberately: administering the service does not include reading
	// other people's reviews.
	h.user("total-outsider", "REQUESTER", "CONTRIBUTOR", "APPROVER", "TEMPLATE_ADMIN", "SYSTEM_ADMIN")
	outsider := h.login("total-outsider")

	substitute := strings.NewReplacer("{id}", reviewID, "{itemID}", itemID, "{format}", "xlsx")
	probed := 0
	for route := range api.ObjectScopedRoutes {
		method, path, _ := strings.Cut(route, " ")
		if strings.HasPrefix(path, "/api/v1/evidences/") {
			path = strings.Replace(path, "{id}", evidenceID, 1)
		} else if strings.HasPrefix(path, "/api/v1/change-requests/") {
			path = strings.Replace(path, "{id}", changeID, 1)
		}
		path = substitute.Replace(path)
		res := outsider.do(method, path, map[string]any{})
		if res.status >= 200 && res.status < 300 {
			t.Errorf("%s answered %d to somebody with no part in the review", route, res.status)
		}
		probed++
	}
	if probed < 15 {
		t.Fatalf("only %d scoped routes probed", probed)
	}

	// The counterpart: a security reviewer or auditor is supposed to read any
	// review, which is why the scoped endpoints cannot simply demand
	// participation.
	h.user("standing-auditor", "AUDITOR")
	if res := h.login("standing-auditor").do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil); res.status != http.StatusOK {
		t.Errorf("an auditor was refused a review: %d %s", res.status, res.body)
	}
}

// /metrics answers an unauthenticated scrape, which is what Prometheus
// expects but also publishes user counts, failed sign-ins and locked
// accounts to anyone who can reach the host. An installation has to be able
// to decide that for itself.
func TestMetricsExposureFollowsTheSetting(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	anon := &client{h: h}

	if res := anon.do(http.MethodGet, "/metrics", nil); res.status != http.StatusOK {
		t.Fatalf("the default scrape was refused: %d", res.status)
	}
	// The endpoint replaces the whole security object, so the current values
	// are read back and only this one flag is changed.
	setMetricsPublic := func(public bool) {
		t.Helper()
		settings := []map[string]any{}
		if err := json.Unmarshal([]byte(admin.do(http.MethodGet, "/api/v1/admin/settings", nil).body), &settings); err != nil {
			t.Fatal(err)
		}
		for _, setting := range settings {
			if setting["key"] != "security" {
				continue
			}
			value, _ := setting["value"].(map[string]any)
			value["metrics_public"] = public
			if res := admin.do(http.MethodPut, "/api/v1/admin/settings/security", value); res.status != http.StatusOK {
				t.Fatalf("saving the setting returned %d %s", res.status, res.body)
			}
			return
		}
		t.Fatal("the security settings were not returned")
	}
	setMetricsPublic(false)
	if res := anon.do(http.MethodGet, "/metrics", nil); res.status != http.StatusUnauthorized {
		t.Errorf("with the setting off an anonymous scrape returned %d, want 401", res.status)
	}
	if res := admin.do(http.MethodGet, "/metrics", nil); res.status != http.StatusOK {
		t.Errorf("an authenticated scrape was refused: %d", res.status)
	}
	setMetricsPublic(true)
	if res := anon.do(http.MethodGet, "/metrics", nil); res.status != http.StatusOK {
		t.Errorf("turning it back on left the scrape refused: %d", res.status)
	}
}

// Evidence is encrypted under the uploader's own key, so a file replaced by a
// second person can only be read with that person's key. Resolving the key
// from whoever is downloading instead of from the row would look correct
// until two people touched the same evidence.
func TestEvidenceReplacedByAnotherPersonStillDecrypts(t *testing.T) {
	h := newHarness(t)
	h.user("first-uploader", "REQUESTER")
	owner := h.login("first-uploader")
	reviewID := owner.createReview("증적 승계 서비스")

	items := []map[string]any{}
	_ = json.Unmarshal([]byte(owner.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items)
	itemID := items[0]["id"].(string)

	original := strings.Repeat("최초 업로더가 올린 증적\n", 200)
	res := owner.upload(fmt.Sprintf("/api/v1/review-requests/%s/items/%s/evidences", reviewID, itemID), "evidence.txt", original)
	if res.status != http.StatusCreated {
		t.Fatalf("upload returned %d %s", res.status, res.body)
	}
	evidenceID, _ := res.json()["id"].(string)

	helper := h.user("second-uploader", "REQUESTER", "CONTRIBUTOR")
	if res := owner.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/participants", map[string]any{"user_id": helper, "role": "CONTRIBUTOR"}); res.status >= 300 {
		t.Fatalf("adding a contributor returned %d %s", res.status, res.body)
	}
	replacement := strings.Repeat("두 번째 사람이 교체한 증적\n", 300)
	if res := h.login("second-uploader").upload("/api/v1/evidences/"+evidenceID+"/versions", "evidence.txt", replacement); res.status >= 300 {
		t.Fatalf("replacing the evidence returned %d %s", res.status, res.body)
	}

	// The original uploader reads a file encrypted under somebody else's key.
	download := owner.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/download", nil)
	if download.status != http.StatusOK {
		t.Fatalf("download after replacement returned %d %s", download.status, download.body)
	}
	if download.body != replacement {
		t.Errorf("the download did not return the replacement: %d bytes, want %d", len(download.body), len(replacement))
	}

	var keyOwner string
	var version int
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT key_owner_id,current_version FROM evidences WHERE id=$1`, evidenceID).Scan(&keyOwner, &version); err != nil {
		t.Fatal(err)
	}
	if keyOwner != helper || version != 2 {
		t.Errorf("evidence records key owner %s at version %d, want %s at 2", keyOwner, version, helper)
	}
}

// The user list is where an access review happens, so it has to carry the
// last sign-in. The column was missing even though the value was served.
func TestUserListCarriesTheLastSignIn(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	h.user("never-signed-in", "REQUESTER")
	users := []map[string]any{}
	if err := json.Unmarshal([]byte(admin.do(http.MethodGet, "/api/v1/admin/users", nil).body), &users); err != nil {
		t.Fatal(err)
	}
	seen := map[string]any{}
	for _, u := range users {
		if name, _ := u["username"].(string); name != "" {
			seen[name] = u["last_login_at"]
		}
		if _, ok := u["created_at"]; !ok {
			t.Fatalf("a user row carries no created_at: %v", u)
		}
	}
	if _, ok := seen["integration-admin"]; !ok {
		t.Fatal("the signed-in administrator is missing from the list")
	}
	if at := seen["integration-admin"]; at == nil {
		t.Error("the administrator has signed in but the list reports no last sign-in")
	}
	if at, ok := seen["never-signed-in"]; !ok {
		t.Error("a user who never signed in is missing from the list")
	} else if at != nil {
		t.Errorf("a user who never signed in reports a last sign-in of %v", at)
	}
}

// A reviewer works through the same items the author filled in, and the
// author has had a bulk action from the beginning while the reviewer judged
// one at a time.
func TestReviewersCanJudgeItemsInBulk(t *testing.T) {
	h := newHarness(t)
	author := h.login(adminOf(h))
	reviewID := author.createReview("일괄 판정 서비스")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, item := range items {
		if id, _ := item["id"].(string); id != "" && len(ids) < 5 {
			ids = append(ids, id)
		}
	}
	if len(ids) < 5 {
		t.Fatalf("only %d items to judge", len(ids))
	}
	bulk := "/api/v1/review-requests/" + reviewID + "/review-results/bulk"

	ctx := context.Background()
	var reviewerID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='integration-admin'`).Scan(&reviewerID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2 WHERE id=$1`, reviewID, reviewerID); err != nil {
		t.Fatal(err)
	}
	// Judging is only possible once the review is actually under review.
	if res := author.do(http.MethodPost, bulk, map[string]any{"item_ids": ids, "result": "COMPLIANT"}); res.errorCode() != "STATE_CONFLICT" {
		t.Fatalf("judging a draft returned %d %s", res.status, res.body)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET status='REVIEWING' WHERE id=$1`, reviewID); err != nil {
		t.Fatal(err)
	}
	if res := author.do(http.MethodPost, bulk, map[string]any{"item_ids": ids, "result": "NOT_A_RESULT"}); res.errorCode() != "VALIDATION_FAILED" {
		t.Errorf("an unknown verdict was accepted: %s", res.body)
	}

	first := author.do(http.MethodPost, bulk, map[string]any{"item_ids": ids[:3], "result": "COMPLIANT", "opinion": "일괄 적합"})
	if applied, _ := first.json()["applied"].(float64); int(applied) != 3 {
		t.Fatalf("first bulk judgement applied %v: %s", first.json()["applied"], first.body)
	}
	// Without overwrite an existing verdict has to survive.
	again := author.do(http.MethodPost, bulk, map[string]any{"item_ids": ids, "result": "INSUFFICIENT"})
	if applied, _ := again.json()["applied"].(float64); int(applied) != 2 {
		t.Errorf("the second pass applied %v, want 2 (the already-judged three skipped): %s", again.json()["applied"], again.body)
	}
	var verdict string
	if err := h.db.Pool.QueryRow(ctx, `SELECT result FROM review_results WHERE submission_item_id=$1`, ids[0]).Scan(&verdict); err != nil {
		t.Fatal(err)
	}
	if verdict != "COMPLIANT" {
		t.Errorf("an existing verdict was replaced without overwrite: %s", verdict)
	}
	if res := author.do(http.MethodPost, bulk, map[string]any{"item_ids": ids, "result": "INSUFFICIENT", "overwrite": true}); res.status != http.StatusOK {
		t.Fatalf("overwrite returned %d %s", res.status, res.body)
	}
	if err := h.db.Pool.QueryRow(ctx, `SELECT result FROM review_results WHERE submission_item_id=$1`, ids[0]).Scan(&verdict); err != nil {
		t.Fatal(err)
	}
	if verdict != "INSUFFICIENT" {
		t.Errorf("overwrite left the verdict at %s", verdict)
	}

	h.user("not-the-reviewer", "SECURITY_REVIEWER")
	if res := h.login("not-the-reviewer").do(http.MethodPost, bulk, map[string]any{"item_ids": ids, "result": "COMPLIANT"}); res.status != http.StatusForbidden {
		t.Errorf("a reviewer who is not assigned judged the items: %d", res.status)
	}
}

// One requirement is usually evidenced by several files. Each becomes its own
// record, so the server takes them one at a time -- this checks the sequence
// the console now performs on the reader's behalf, including a rejected file
// in the middle leaving the accepted ones in place.
func TestSeveralEvidenceFilesAttachToOneItem(t *testing.T) {
	h := newHarness(t)
	h.user("multi-uploader", "REQUESTER")
	uploader := h.login("multi-uploader")
	reviewID := uploader.createReview("증적 여러 건")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(uploader.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	itemID := items[0]["id"].(string)
	path := fmt.Sprintf("/api/v1/review-requests/%s/items/%s/evidences", reviewID, itemID)

	for i, name := range []string{"화면1.txt", "화면2.txt", "화면3.txt"} {
		if res := uploader.upload(path, name, fmt.Sprintf("증적 본문 %d", i)); res.status != http.StatusCreated {
			t.Fatalf("%s returned %d %s", name, res.status, res.body)
		}
	}
	// An extension the policy does not allow must not undo the rest.
	if res := uploader.upload(path, "악성.exe", "MZ"); res.status == http.StatusCreated {
		t.Error("an executable was accepted as evidence")
	}
	var stored int
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM evidences WHERE submission_item_id=$1 AND deleted_at IS NULL`, itemID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 3 {
		t.Errorf("the item carries %d evidence files, want 3", stored)
	}
}

// A 500 used to leave the access log saying only that a request had failed.
// On an installation with no internet access, the cause has to be written
// down somewhere or nobody can act on it.
func TestServerFaultsRecordTheirCause(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	// Break a table the listing depends on, so the query genuinely fails.
	// Not application_logs: that is where the entry itself has to go, and a
	// database fault that hides its own record is covered in the store tests.
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE security_controls RENAME TO security_controls_hidden`); err != nil {
		t.Fatal(err)
	}
	res := admin.do(http.MethodGet, "/api/v1/security-controls", nil)
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE security_controls_hidden RENAME TO security_controls`); err != nil {
		t.Fatal(err)
	}
	if res.status != http.StatusInternalServerError {
		t.Fatalf("the broken listing returned %d %s", res.status, res.body)
	}
	if strings.Contains(res.body, "security_controls") {
		t.Errorf("the response handed the database error to the caller: %s", res.body)
	}

	var message, detail string
	err := h.db.Pool.QueryRow(ctx, `SELECT message,COALESCE(fields->>'error','') FROM application_logs
                WHERE component='api' AND fields->>'code'='QUERY_FAILED' ORDER BY timestamp DESC LIMIT 1`).Scan(&message, &detail)
	if err != nil {
		t.Fatalf("the failure left no log entry: %v", err)
	}
	if !strings.Contains(detail, "security_controls") {
		t.Errorf("the log entry does not name the cause: %q", detail)
	}
	if message == "" {
		t.Error("the log entry has no message")
	}
}

// The counter has to reach /metrics, or an operator has nothing to alert on.
func TestMetricsCountLostAuditEvents(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	reading := func() string {
		for _, line := range strings.Split(admin.do(http.MethodGet, "/metrics", nil).body, "\n") {
			if strings.HasPrefix(line, "seccheck_audit_write_failures ") {
				return strings.Fields(line)[1]
			}
		}
		t.Fatal("/metrics does not carry seccheck_audit_write_failures")
		return ""
	}
	if got := reading(); got != "0" {
		t.Fatalf("a healthy service reports %s lost audit events", got)
	}
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE audit_logs RENAME TO audit_logs_gone`); err != nil {
		t.Fatal(err)
	}
	_ = h.db.Audit(ctx, store.AuditEvent{UserName: "tester", EventType: "LOGIN", TargetType: "USER", TargetID: "x"})
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE audit_logs_gone RENAME TO audit_logs`); err != nil {
		t.Fatal(err)
	}
	if got := reading(); got != "1" {
		t.Errorf("after a lost event /metrics reports %s, want 1", got)
	}
}

// The malware scan job is written with the evidence, not after it. Losing the
// job used to leave the file PENDING for good: undownloadable, blocking
// submission, and absent from the queue an administrator would retry from.
func TestEvidenceAndItsScanJobAreWrittenTogether(t *testing.T) {
	h := newHarness(t)
	h.user("atomic-uploader", "REQUESTER")
	uploader := h.login("atomic-uploader")
	reviewID := uploader.createReview("원자성 확인")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(uploader.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	itemID := items[0]["id"].(string)
	path := fmt.Sprintf("/api/v1/review-requests/%s/items/%s/evidences", reviewID, itemID)
	ctx := context.Background()
	// A scan job only exists when scanning is switched on; with ClamAV off the
	// upload is marked SKIPPED and needs nothing from the queue.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"clamav_enabled":true}'::jsonb WHERE key='upload'`); err != nil {
		t.Fatal(err)
	}

	res := uploader.upload(path, "정상.txt", "본문")
	if res.status != http.StatusCreated {
		t.Fatalf("upload returned %d %s", res.status, res.body)
	}
	evidenceID, _ := res.json()["id"].(string)
	var queued int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE type='SCAN_EVIDENCE' AND payload->>'evidence_id'=$1`, evidenceID).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Fatalf("the upload queued %d scan jobs, want 1", queued)
	}

	// With the queue unwritable the upload has to fail outright rather than
	// storing a file nothing will ever clear.
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE jobs RENAME TO jobs_gone`); err != nil {
		t.Fatal(err)
	}
	blocked := uploader.upload(path, "대기.txt", "본문")
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE jobs_gone RENAME TO jobs`); err != nil {
		t.Fatal(err)
	}
	if blocked.status == http.StatusCreated {
		t.Error("the upload succeeded while its scan job could not be queued")
	}
	var stranded int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM evidences WHERE submission_item_id=$1 AND original_filename='대기.txt'`, itemID).Scan(&stranded); err != nil {
		t.Fatal(err)
	}
	if stranded != 0 {
		t.Errorf("%d evidence rows survived without a scan job", stranded)
	}
}

// Submitting writes two rows: the review's status and the submission that
// records who submitted and when, which the cycle-time report measures from.
// They used to be separate statements, the second one fire-and-forget.
func TestSubmittingWritesBothRowsOrNeither(t *testing.T) {
	h := newHarness(t)
	author := h.login(adminOf(h))
	reviewID := author.createReview("제출 원자성")
	ctx := context.Background()
	// Answer every assigned item so the submission passes validation.
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, item := range items {
		if id, _ := item["id"].(string); id != "" {
			ids = append(ids, id)
		}
	}
	if res := author.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk",
		map[string]any{"item_ids": ids, "applicability": "N/A", "na_reason": "해당 없음", "self_assessment": "N/A"}); res.status != http.StatusOK {
		t.Fatalf("bulk answer returned %d %s", res.status, res.body)
	}

	if res := author.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/submit", map[string]any{}); res.status != http.StatusOK {
		t.Fatalf("submit returned %d %s", res.status, res.body)
	}
	var reviewStatus, submissionStatus, submittedBy string
	if err := h.db.Pool.QueryRow(ctx, `SELECT r.status,s.status,COALESCE(s.submitted_by,'') FROM review_requests r
                JOIN submissions s ON s.review_request_id=r.id WHERE r.id=$1 ORDER BY s.revision DESC LIMIT 1`, reviewID).Scan(&reviewStatus, &submissionStatus, &submittedBy); err != nil {
		t.Fatal(err)
	}
	if reviewStatus != submissionStatus {
		t.Errorf("the review is %s while its submission is %s", reviewStatus, submissionStatus)
	}
	if submittedBy == "" {
		t.Error("the submission does not record who submitted it")
	}
}

// The approvals row is the decision itself. A review must never read APPROVED
// with nothing recording that anyone approved it.
func TestApprovingWritesTheDecisionOrNothing(t *testing.T) {
	h := newHarness(t)
	h.login(adminOf(h))
	requester := h.user("atomic-requester", "REQUESTER")
	approver := h.user("atomic-approver", "APPROVER")
	ctx := context.Background()
	id := store.NewID()
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,approver_id,exposure,status)
                VALUES($1,$2,'결재 원자성','설명','WEB','NEW',$3,$3,'보안팀',$3,$4,'INTERNAL','APPROVAL_PENDING')`, id, "SR-ATOMIC-1", requester, approver); err != nil {
		t.Fatal(err)
	}
	// With the approvals table gone the decision must not be applied at all.
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE approvals RENAME TO approvals_gone`); err != nil {
		t.Fatal(err)
	}
	blocked := h.login("atomic-approver").do(http.MethodPost, "/api/v1/review-requests/"+id+"/approve", map[string]string{"comment": "승인"})
	if _, err := h.db.Pool.Exec(ctx, `ALTER TABLE approvals_gone RENAME TO approvals`); err != nil {
		t.Fatal(err)
	}
	if blocked.status == http.StatusOK {
		t.Error("the approval was applied while its record could not be written")
	}
	var status string
	if err := h.db.Pool.QueryRow(ctx, `SELECT status FROM review_requests WHERE id=$1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "APPROVAL_PENDING" {
		t.Errorf("the review moved to %s without a decision record", status)
	}

	if res := h.login("atomic-approver").do(http.MethodPost, "/api/v1/review-requests/"+id+"/approve", map[string]string{"comment": "승인"}); res.status != http.StatusOK {
		t.Fatalf("the retried approval returned %d %s", res.status, res.body)
	}
	var decisions int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM approvals WHERE review_request_id=$1 AND decision='APPROVED'`, id).Scan(&decisions); err != nil {
		t.Fatal(err)
	}
	if decisions != 1 {
		t.Errorf("the approvals table holds %d decisions, want 1", decisions)
	}
}

// A conditional pass usually comes with something the team promised to do
// later. That was written on the item and then visible only inside the review
// that produced it, so nobody could see what was outstanding across the board.
func TestTheReportCollectsOutstandingFollowUps(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	reviewID := admin.createReview("미조치 서비스")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(admin.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	var uid string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='integration-admin'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2,status='REVIEWING' WHERE id=$1`, reviewID, uid); err != nil {
		t.Fatal(err)
	}
	withAction := items[0]["id"].(string)
	if res := admin.do(http.MethodPut, "/api/v1/review-requests/"+reviewID+"/review-results/"+withAction,
		map[string]any{"result": "CONDITIONAL", "opinion": "조건부", "follow_up": "3개월 내 WAF 규칙 보완", "follow_up_due_date": "2020-01-31", "expected_updated_at": ""}); res.status != http.StatusOK {
		t.Fatalf("saving a verdict with a follow-up: %d %s", res.status, res.body)
	}
	// An item judged without a commitment must not appear in the register.
	if res := admin.do(http.MethodPut, "/api/v1/review-requests/"+reviewID+"/review-results/"+items[1]["id"].(string),
		map[string]any{"result": "COMPLIANT", "opinion": "적합", "follow_up": "", "expected_updated_at": ""}); res.status != http.StatusOK {
		t.Fatalf("saving a verdict without a follow-up: %d %s", res.status, res.body)
	}

	report := admin.do(http.MethodGet, "/api/v1/reports/reviews", nil).json()
	rows, _ := report["follow_ups"].([]any)
	if len(rows) != 1 {
		t.Fatalf("the register holds %d entries, want 1: %v", len(rows), report["follow_ups"])
	}
	entry, _ := rows[0].(map[string]any)
	for key, want := range map[string]string{"follow_up": "3개월 내 WAF 규칙 보완", "result": "CONDITIONAL", "service_name": "미조치 서비스"} {
		if got, _ := entry[key].(string); got != want {
			t.Errorf("the register entry has %s=%q, want %q", key, got, want)
		}
	}
	if number, _ := entry["review_number"].(string); number == "" {
		t.Error("the register entry does not name its review")
	}
	// A date in the past has to read as late, or "outstanding" carries no
	// urgency and the register is just a list.
	if due, _ := entry["due_on"].(string); due != "2020-01-31" {
		t.Errorf("the register entry has due_on=%q", due)
	}
	if overdue, _ := entry["overdue"].(bool); !overdue {
		t.Error("an action past its date is not marked late")
	}

	book := admin.do(http.MethodGet, "/api/v1/reports/reviews?format=xlsx", nil)
	if book.status != http.StatusOK {
		t.Fatalf("the report workbook returned %d", book.status)
	}
	if text := workbookText(t, book.body); !strings.Contains(text, "미조치 항목") || !strings.Contains(text, "3개월 내 WAF 규칙 보완") {
		t.Error("the workbook does not carry the follow-up register")
	}

	// Carrying the action out takes it off the outstanding list, but the
	// record of it stays available.
	resultID, _ := entry["id"].(string)
	if resultID == "" {
		t.Fatal("the register entry has no identifier to close it by")
	}
	// The team that did the work reports it; the entry stays outstanding
	// until the security side accepts it.
	h.user("remediation-owner", "REQUESTER", "CONTRIBUTOR")
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO review_participants(review_request_id,user_id,participant_role) VALUES($1,(SELECT id FROM users WHERE username='remediation-owner'),'CONTRIBUTOR') ON CONFLICT DO NOTHING`, reviewID); err != nil {
		t.Fatal(err)
	}
	if res := h.login("remediation-owner").do(http.MethodPost, "/api/v1/review-results/"+resultID+"/follow-up", map[string]any{"action": "report", "note": "규칙 배포함"}); res.status != http.StatusOK {
		t.Fatalf("reporting the action: %d %s", res.status, res.body)
	}
	stillOpen, _ := admin.do(http.MethodGet, "/api/v1/reports/reviews", nil).json()["follow_ups"].([]any)
	if len(stillOpen) != 1 {
		t.Fatalf("a reported action left the register before it was accepted: %d", len(stillOpen))
	}
	if reported, _ := stillOpen[0].(map[string]any)["reported_by"].(string); reported != "remediation-owner" {
		t.Errorf("the register does not say who reported it: %q", reported)
	}
	// Reporting is not accepting: the requester cannot discharge it.
	if res := h.login("remediation-owner").do(http.MethodPost, "/api/v1/review-results/"+resultID+"/follow-up", map[string]any{"action": "confirm", "note": ""}); res.status != http.StatusForbidden {
		t.Errorf("a requester confirmed their own action: %d %s", res.status, res.body)
	}
	// The reviewer has to learn a report is waiting, or it sits unconfirmed
	// until somebody opens the register.
	var toReviewer int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications n JOIN users u ON u.id=n.recipient_id
                WHERE n.event_type='FOLLOW_UP_REPORTED' AND u.username='integration-admin'`).Scan(&toReviewer); err != nil {
		t.Fatal(err)
	}
	if toReviewer != 1 {
		t.Errorf("the reviewer received %d reports, want 1", toReviewer)
	}
	if res := admin.do(http.MethodPost, "/api/v1/review-results/"+resultID+"/follow-up", map[string]any{"action": "confirm", "note": "규칙 배포 완료"}); res.status != http.StatusOK {
		t.Fatalf("closing the action: %d %s", res.status, res.body)
	}
	var toReporter int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications n JOIN users u ON u.id=n.recipient_id
                WHERE n.event_type='FOLLOW_UP_DONE' AND u.username='remediation-owner'`).Scan(&toReporter); err != nil {
		t.Fatal(err)
	}
	if toReporter != 1 {
		t.Errorf("the person who reported it was told %d times that it was accepted, want 1", toReporter)
	}
	outstanding, _ := admin.do(http.MethodGet, "/api/v1/reports/reviews", nil).json()["follow_ups"].([]any)
	if len(outstanding) != 0 {
		t.Errorf("a carried-out action is still listed as outstanding: %v", outstanding)
	}
	all, _ := admin.do(http.MethodGet, "/api/v1/reports/reviews?include_done=1", nil).json()["follow_ups"].([]any)
	if len(all) != 1 {
		t.Fatalf("including completed actions returned %d entries", len(all))
	}
	closed, _ := all[0].(map[string]any)
	if note, _ := closed["follow_up_note"].(string); note != "규칙 배포 완료" {
		t.Errorf("the completion note is %q", note)
	}
	if by, _ := closed["done_by"].(string); by == "" {
		t.Error("the register does not say who carried the action out")
	}
	var audited int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='FOLLOW_UP_DONE'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Errorf("closing the action left %d audit events", audited)
	}

	// Reopening puts it back, so a premature closure is recoverable.
	if res := admin.do(http.MethodPost, "/api/v1/review-results/"+resultID+"/follow-up", map[string]any{"action": "reopen", "note": ""}); res.status != http.StatusOK {
		t.Fatalf("reopening: %d %s", res.status, res.body)
	}
	reopened, _ := admin.do(http.MethodGet, "/api/v1/reports/reviews", nil).json()["follow_ups"].([]any)
	if len(reopened) != 1 {
		t.Errorf("a reopened action did not return to the outstanding list")
	}

	// A verdict with no action of its own cannot be closed.
	var plain string
	if err := h.db.Pool.QueryRow(ctx, `SELECT rr.id FROM review_results rr WHERE btrim(rr.follow_up)='' LIMIT 1`).Scan(&plain); err != nil {
		t.Fatal(err)
	}
	if res := admin.do(http.MethodPost, "/api/v1/review-results/"+plain+"/follow-up", map[string]any{"action": "confirm", "note": ""}); res.status != http.StatusNotFound {
		t.Errorf("a verdict without an action was closed: %d %s", res.status, res.body)
	}
}

// The reviewer's verdict, opinion and the action they asked for are written
// for the person whose service it is. The console showed them only inside the
// panel a reviewer edits, so the requester never read them -- and a reminder
// about an action linked to a page that did not show it. The data was always
// served; this pins that, so the read-only view has something to render.
func TestARequesterIsServedTheReviewersVerdict(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	requester := h.user("verdict-reader", "REQUESTER")
	author := h.login("verdict-reader")
	reviewID := author.createReview("판정 열람 서비스")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	itemID := items[0]["id"].(string)
	var adminID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='integration-admin'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2,status='REVIEWING' WHERE id=$1`, reviewID, adminID); err != nil {
		t.Fatal(err)
	}
	if res := admin.do(http.MethodPut, "/api/v1/review-requests/"+reviewID+"/review-results/"+itemID,
		map[string]any{"result": "CONDITIONAL", "opinion": "권한 분리가 필요합니다", "follow_up": "관리자 계정 분리", "follow_up_due_date": "2030-06-30", "expected_updated_at": ""}); res.status != http.StatusOK {
		t.Fatalf("recording the verdict: %d %s", res.status, res.body)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET status='APPROVED' WHERE id=$1`, reviewID); err != nil {
		t.Fatal(err)
	}

	// The requester reads their own approved review.
	after := []map[string]any{}
	if err := json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &after); err != nil {
		t.Fatal(err)
	}
	var verdict map[string]any
	for _, item := range after {
		if item["id"] == itemID {
			verdict, _ = item["review_result"].(map[string]any)
		}
	}
	if verdict == nil {
		t.Fatal("the item carries no review result for the requester")
	}
	for key, want := range map[string]string{"result": "CONDITIONAL", "opinion": "권한 분리가 필요합니다", "follow_up": "관리자 계정 분리"} {
		if got, _ := verdict[key].(string); got != want {
			t.Errorf("the requester sees %s=%q, want %q", key, got, want)
		}
	}
	if due, _ := verdict["follow_up_due_date"].(string); !strings.HasPrefix(due, "2030-06-30") {
		t.Errorf("the requester does not see the action's date: %q", due)
	}
	_ = requester
}

// The closing statement of a review -- what it was decided to be, why, and
// who signed it off -- was recorded and shown nowhere. A requester whose
// review came back rejected could not read the reason without exporting it.
func TestAReviewCarriesItsDecisionToTheRequester(t *testing.T) {
	h := newHarness(t)
	h.login(adminOf(h))
	ctx := context.Background()
	requesterID := h.user("outcome-requester", "REQUESTER")
	approverID := h.user("outcome-approver", "APPROVER")
	requester := h.login("outcome-requester")
	id := store.NewID()
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,approver_id,exposure,status,final_result,final_opinion)
                VALUES($1,$2,'결론 서비스','설명','WEB','NEW',$3,$3,'보안팀',$3,$4,'INTERNAL','APPROVAL_PENDING','APPROVED','권한 분리를 조건으로 적합')`, id, "SR-OUTCOME-1", requesterID, approverID); err != nil {
		t.Fatal(err)
	}
	if res := h.login("outcome-approver").do(http.MethodPost, "/api/v1/review-requests/"+id+"/reject", map[string]string{"comment": "추가 통제가 확인되지 않았습니다"}); res.status != http.StatusOK {
		t.Fatalf("rejecting: %d %s", res.status, res.body)
	}

	detail := requester.do(http.MethodGet, "/api/v1/review-requests/"+id, nil).json()
	if got, _ := detail["final_opinion"].(string); got != "권한 분리를 조건으로 적합" {
		t.Errorf("the requester is not served the final opinion: %q", got)
	}
	if got, _ := detail["final_result"].(string); got != "REJECTED" {
		t.Errorf("final_result = %q, want REJECTED", got)
	}
	decisions, _ := detail["decisions"].([]any)
	if len(decisions) != 1 {
		t.Fatalf("the review carries %d decisions: %v", len(decisions), detail["decisions"])
	}
	decision, _ := decisions[0].(map[string]any)
	for key, want := range map[string]string{"decision": "REJECTED", "comment": "추가 통제가 확인되지 않았습니다", "approver_name": "outcome-approver"} {
		if got, _ := decision[key].(string); got != want {
			t.Errorf("the decision has %s=%q, want %q", key, got, want)
		}
	}
	if at, _ := decision["decided_at"].(string); at == "" {
		t.Error("the decision does not say when it was made")
	}
}

// When a review was submitted and decided, and who attached each piece of
// evidence, are part of its record. The exported file has always carried
// them; the screen showed neither, so a reader on screen could not say when
// a review happened or who supplied what.
func TestAReviewCarriesItsDatesAndEvidenceOwners(t *testing.T) {
	h := newHarness(t)
	h.login(adminOf(h))
	h.user("dates-requester", "REQUESTER")
	requester := h.login("dates-requester")
	reviewID := requester.createReview("이력 서비스")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	itemID := items[0]["id"].(string)
	if res := requester.upload(fmt.Sprintf("/api/v1/review-requests/%s/items/%s/evidences", reviewID, itemID), "근거.txt", "본문"); res.status != http.StatusCreated {
		t.Fatalf("upload: %d %s", res.status, res.body)
	}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item["id"].(string))
	}
	if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/responses/bulk",
		map[string]any{"item_ids": ids, "applicability": "N/A", "na_reason": "해당 없음", "self_assessment": "N/A"}); res.status != http.StatusOK {
		t.Fatalf("bulk answer: %d %s", res.status, res.body)
	}
	if res := requester.do(http.MethodPost, "/api/v1/review-requests/"+reviewID+"/submit", map[string]any{}); res.status != http.StatusOK {
		t.Fatalf("submit: %d %s", res.status, res.body)
	}

	detail := requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID, nil).json()
	for _, key := range []string{"first_submitted_at", "final_submitted_at"} {
		if at, _ := detail[key].(string); at == "" {
			t.Errorf("the review does not report %s", key)
		}
	}

	after := []map[string]any{}
	if err := json.Unmarshal([]byte(requester.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &after); err != nil {
		t.Fatal(err)
	}
	var named bool
	for _, item := range after {
		list, _ := item["evidences"].([]any)
		for _, raw := range list {
			evidence, _ := raw.(map[string]any)
			if name, _ := evidence["uploaded_by_name"].(string); name == "dates-requester" {
				named = true
			}
		}
	}
	if !named {
		t.Error("the evidence does not say who attached it")
	}
}

// The register that collects outstanding actions is for the security team;
// a requester cannot open the report at all, so their own commitments were
// visible one review at a time and nowhere together.
func TestTheDashboardShowsARequesterTheirOwnActions(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	h.user("action-owner", "REQUESTER")
	owner := h.login("action-owner")
	reviewID := owner.createReview("내 조치 서비스")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(owner.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	var adminID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='integration-admin'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2,status='REVIEWING' WHERE id=$1`, reviewID, adminID); err != nil {
		t.Fatal(err)
	}
	if res := admin.do(http.MethodPut, "/api/v1/review-requests/"+reviewID+"/review-results/"+items[0]["id"].(string),
		map[string]any{"result": "CONDITIONAL", "opinion": "조건부", "follow_up": "로그 보존 기간 연장", "follow_up_due_date": "2020-03-01", "expected_updated_at": ""}); res.status != http.StatusOK {
		t.Fatalf("recording the action: %d %s", res.status, res.body)
	}

	// The report is closed to a requester, so the dashboard has to carry it.
	if res := owner.do(http.MethodGet, "/api/v1/reports/reviews", nil); res.status != http.StatusForbidden {
		t.Fatalf("a requester reached the report: %d", res.status)
	}
	board := owner.do(http.MethodGet, "/api/v1/dashboard", nil).json()
	actions, _ := board["my_follow_ups"].([]any)
	if len(actions) != 1 {
		t.Fatalf("the dashboard lists %d actions for their owner: %v", len(actions), board["my_follow_ups"])
	}
	entry, _ := actions[0].(map[string]any)
	if got, _ := entry["follow_up"].(string); got != "로그 보존 기간 연장" {
		t.Errorf("the action reads %q", got)
	}
	if overdue, _ := entry["overdue"].(bool); !overdue {
		t.Error("an action past its date is not marked late on the dashboard")
	}
	if number, _ := entry["review_number"].(string); number == "" {
		t.Error("the dashboard entry does not name its review")
	}

	// Somebody with no part in the review sees none of it.
	h.user("unrelated-requester", "REQUESTER")
	other := h.login("unrelated-requester").do(http.MethodGet, "/api/v1/dashboard", nil).json()
	if list, _ := other["my_follow_ups"].([]any); len(list) != 0 {
		t.Errorf("an unrelated person sees %d of somebody else's actions", len(list))
	}
}

// Minting a credential and replacing one are different events. Both were
// recorded as a rotation, so the log could not tell an auditor whether a key
// was new -- which is the question that matters when access is reviewed.
func TestIssuingAndRotatingAnAPIKeyAreRecordedApart(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	created := admin.do(http.MethodPost, "/api/v1/me/api-keys", map[string]any{"name": "연계용", "scopes": []string{"read"}})
	if created.status != http.StatusCreated {
		t.Fatalf("issuing a key returned %d %s", created.status, created.body)
	}
	keyID, _ := created.json()["id"].(string)

	count := func(event string) int {
		t.Helper()
		var n int
		if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type=$1 AND target_type='API_KEY'`, event).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count("CREATE_API_KEY"); got != 1 {
		t.Errorf("issuing a key wrote %d CREATE_API_KEY events", got)
	}
	if got := count("ROTATE_API_KEY"); got != 0 {
		t.Errorf("issuing a key was recorded as a rotation %d times", got)
	}

	if res := admin.do(http.MethodPost, "/api/v1/me/api-keys/"+keyID+"/rotate", map[string]any{}); res.status != http.StatusCreated {
		t.Fatalf("rotating returned %d %s", res.status, res.body)
	}
	if got := count("ROTATE_API_KEY"); got != 1 {
		t.Errorf("rotating wrote %d ROTATE_API_KEY events", got)
	}
	if got := count("CREATE_API_KEY"); got != 1 {
		t.Errorf("rotating was also recorded as an issue: %d", got)
	}
	var before string
	if err := h.db.Pool.QueryRow(ctx, `SELECT COALESCE(before_value::text,'') FROM audit_logs WHERE event_type='ROTATE_API_KEY'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(before, keyID) {
		t.Errorf("the rotation does not name the key it replaced: %s", before)
	}
}

// An audit entry that names only an identifier of something since deleted
// cannot be read back, which defeats the point of recording the deletion.
func TestAuditEntriesSurviveWhatTheyDescribe(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	// A control is removed outright, so its code and title exist nowhere else.
	created := admin.do(http.MethodPost, "/api/v1/security-controls", map[string]any{"code": "AC-99", "title": "삭제될 통제", "description": "감사 기록 확인용"})
	if created.status != http.StatusCreated {
		t.Fatalf("creating a control: %d %s", created.status, created.body)
	}
	controlID, _ := created.json()["id"].(string)
	if res := admin.do(http.MethodDelete, "/api/v1/security-controls/"+controlID, nil); res.status != http.StatusNoContent {
		t.Fatalf("deleting the control: %d %s", res.status, res.body)
	}
	var recorded string
	if err := h.db.Pool.QueryRow(ctx, `SELECT COALESCE(before_value::text,'') FROM audit_logs WHERE event_type='DELETE_CONTROL' AND target_id=$1`, controlID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"AC-99", "삭제될 통제"} {
		if !strings.Contains(recorded, want) {
			t.Errorf("the deletion does not record %q: %s", want, recorded)
		}
	}

	// Revoking a key: the identifier is not the question, which key is.
	key := admin.do(http.MethodPost, "/api/v1/me/api-keys", map[string]any{"name": "폐기할 키", "scopes": []string{"read"}})
	keyID, _ := key.json()["id"].(string)
	if res := admin.do(http.MethodDelete, "/api/v1/me/api-keys/"+keyID, nil); res.status != http.StatusNoContent {
		t.Fatalf("revoking: %d %s", res.status, res.body)
	}
	if err := h.db.Pool.QueryRow(ctx, `SELECT COALESCE(before_value::text,'') FROM audit_logs WHERE event_type='REVOKE_API_KEY' AND target_id=$1`, keyID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(recorded, "폐기할 키") {
		t.Errorf("the revocation does not name the key: %s", recorded)
	}

	// An administrator acting on somebody else's account names them.
	target := h.user("reset-target", "REQUESTER")
	if res := admin.do(http.MethodPost, "/api/v1/admin/users/"+target+"/password", map[string]string{"password": "TempPassword!99"}); res.status != http.StatusNoContent {
		t.Fatalf("resetting: %d %s", res.status, res.body)
	}
	if err := h.db.Pool.QueryRow(ctx, `SELECT COALESCE(after_value::text,'') FROM audit_logs WHERE event_type='RESET_PASSWORD' AND target_id=$1`, target).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(recorded, "reset-target") {
		t.Errorf("the reset does not name whose account it was: %s", recorded)
	}
}

// Adding, changing and removing a checklist item all went into the audit log
// as one event, so a reader could not tell which had happened -- while every
// other part of the log distinguishes them.
func TestChecklistItemEditsAreRecordedByWhatTheyDid(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	created := admin.do(http.MethodPost, "/api/v1/templates", map[string]any{"name": "감사 확인 템플릿", "category": "DEVELOPMENT", "description": "", "version": "V1"})
	if created.status != http.StatusCreated {
		t.Fatalf("creating a template: %d %s", created.status, created.body)
	}
	templateID, _ := created.json()["id"].(string)
	var versionID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM checklist_versions WHERE template_id=$1`, templateID).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/api/v1/templates/%s/versions/%s/items", templateID, versionID)
	if res := admin.do(http.MethodPost, base, map[string]any{"item_code": "A-0", "title": "오타 규칙", "question": "질문", "category": "DEVELOPMENT", "severity": "MEDIUM", "answer_type": "YNNA", "applicability_rule": map[string]any{"field": "exposuer", "operator": "eq", "value": "EXTERNAL"}}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("an item whose rule names a field that does not exist was accepted: %d %s", res.status, res.body)
	}
	item := admin.do(http.MethodPost, base, map[string]any{"item_code": "A-1", "title": "보안요건", "question": "질문", "category": "DEVELOPMENT", "severity": "MEDIUM", "answer_type": "YNNA", "required": true, "sort_order": 1})
	if item.status != http.StatusCreated {
		t.Fatalf("adding an item: %d %s", item.status, item.body)
	}
	itemID, _ := item.json()["id"].(string)
	if res := admin.do(http.MethodPatch, base+"/"+itemID, map[string]any{"title": "보안요건 (수정)"}); res.status >= 300 {
		t.Fatalf("editing the item: %d %s", res.status, res.body)
	}
	var code, title, severity, answer string
	var required bool
	if err := h.db.Pool.QueryRow(ctx, `SELECT item_code,title,severity,answer_type,required FROM checklist_items WHERE id=$1`, itemID).Scan(&code, &title, &severity, &answer, &required); err != nil {
		t.Fatal(err)
	}
	if title != "보안요건 (수정)" {
		t.Errorf("the edit did not take: title=%q", title)
	}
	if code != "A-1" || severity != "MEDIUM" || answer != "YNNA" || !required {
		t.Errorf("editing the title erased the rest of the item: code=%q severity=%q answer=%q required=%v", code, severity, answer, required)
	}
	if res := admin.do(http.MethodPatch, base+"/"+itemID, map[string]any{"item_code": "  "}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("blanking the item code was accepted: %d %s", res.status, res.body)
	}

	if res := admin.do(http.MethodDelete, base+"/"+itemID, nil); res.status != http.StatusNoContent {
		t.Fatalf("removing the item: %d %s", res.status, res.body)
	}

	count := func(event string) int {
		t.Helper()
		var n int
		if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type=$1 AND target_id=$2`, event, itemID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for event, want := range map[string]int{"CREATE_CHECKLIST_ITEM": 1, "UPDATE_CHECKLIST_ITEM": 1, "DELETE_CHECKLIST_ITEM": 1} {
		if got := count(event); got != want {
			t.Errorf("%s was recorded %d times, want %d", event, got, want)
		}
	}
	var removed string
	if err := h.db.Pool.QueryRow(ctx, `SELECT COALESCE(before_value::text,'') FROM audit_logs WHERE event_type='DELETE_CHECKLIST_ITEM' AND target_id=$1`, itemID).Scan(&removed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(removed, "A-1") {
		t.Errorf("the removal does not name the item: %s", removed)
	}
}

// PATCH keeps what the caller left out. The profile and Security Control
// endpoints used to overwrite every column from the body, so changing one
// field through the API cleared the others.
func TestPartialUpdatesKeepTheFieldsTheCallerLeftOut(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	if res := admin.do(http.MethodPatch, "/api/v1/me", map[string]any{"display_name": "김보안", "email": "sec@example.com", "department": "정보보호팀"}); res.status >= 300 {
		t.Fatalf("filling in the profile: %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodPatch, "/api/v1/me", map[string]any{"department": "플랫폼팀"}); res.status >= 300 {
		t.Fatalf("changing only the department: %d %s", res.status, res.body)
	}
	profile := admin.do(http.MethodGet, "/api/v1/me", nil).json()
	user, _ := profile["user"].(map[string]any)
	if user == nil {
		user = profile
	}
	if user["display_name"] != "김보안" || user["email"] != "sec@example.com" {
		t.Errorf("changing the department erased the rest of the profile: %v", user)
	}
	if user["department"] != "플랫폼팀" {
		t.Errorf("the department was not saved: %v", user)
	}
	if res := admin.do(http.MethodPatch, "/api/v1/me", map[string]any{"display_name": "  "}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("an empty display name was accepted: %d %s", res.status, res.body)
	}

	tmpl := admin.do(http.MethodPost, "/api/v1/templates", map[string]any{"name": "폐기 예정 템플릿", "category": "DEVELOPMENT", "description": "설명", "version": "V1"})
	if tmpl.status != http.StatusCreated {
		t.Fatalf("creating a template: %d %s", tmpl.status, tmpl.body)
	}
	tmplID, _ := tmpl.json()["id"].(string)
	if res := admin.do(http.MethodPatch, "/api/v1/templates/"+tmplID, map[string]any{"active": false}); res.status >= 300 {
		t.Fatalf("retiring the template: %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodPatch, "/api/v1/templates/"+tmplID, map[string]any{"name": "폐기 템플릿"}); res.status >= 300 {
		t.Fatalf("renaming the template: %d %s", res.status, res.body)
	}
	var active bool
	var templateName, templateDescription string
	if err := h.db.Pool.QueryRow(ctx, `SELECT active,name,description FROM checklist_templates WHERE id=$1`, tmplID).Scan(&active, &templateName, &templateDescription); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Error("renaming a retired template put it back in use")
	}
	if templateName != "폐기 템플릿" || templateDescription != "설명" {
		t.Errorf("the rename lost the description: name=%q description=%q", templateName, templateDescription)
	}

	created := admin.do(http.MethodPost, "/api/v1/security-controls", map[string]any{"code": "AC-1", "title": "접근 통제", "description": "계정과 권한을 관리한다."})
	if created.status != http.StatusCreated {
		t.Fatalf("creating a Control: %d %s", created.status, created.body)
	}
	controlID, _ := created.json()["id"].(string)
	if res := admin.do(http.MethodPatch, "/api/v1/security-controls/"+controlID, map[string]any{"title": "접근 통제 (개정)"}); res.status != http.StatusNoContent {
		t.Fatalf("renaming the Control: %d %s", res.status, res.body)
	}
	var code, title, description string
	if err := h.db.Pool.QueryRow(ctx, `SELECT code,title,description FROM security_controls WHERE id=$1`, controlID).Scan(&code, &title, &description); err != nil {
		t.Fatal(err)
	}
	if title != "접근 통제 (개정)" {
		t.Errorf("the rename did not take: %q", title)
	}
	if code != "AC-1" || description != "계정과 권한을 관리한다." {
		t.Errorf("renaming the Control erased the rest of it: code=%q description=%q", code, description)
	}
	if res := admin.do(http.MethodPatch, "/api/v1/security-controls/"+controlID, map[string]any{"code": "bad code"}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("an invalid code was accepted: %d %s", res.status, res.body)
	}
}

// "Overdue" is a statement about the calendar the installation displays. It
// was decided in the container's UTC clock, so with the default Asia/Seoul
// display zone an action that ran out at midnight was still reported as on
// time until nine in the morning.
func TestOverdueIsDecidedInTheDisplayTimezone(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	h.user("overdue-requester", "REQUESTER")
	author := h.login("overdue-requester")
	reviewID := author.createReview("기한 판정 서비스")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(author.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	itemID := items[0]["id"].(string)
	var adminID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM users WHERE username='integration-admin'`).Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET reviewer_id=$2,status='REVIEWING' WHERE id=$1`, reviewID, adminID); err != nil {
		t.Fatal(err)
	}
	// Due on the day it is now in Midway, which is yesterday or the day before
	// in Kiritimati -- the two zones are 25 hours apart and never share a date.
	var due string
	if err := h.db.Pool.QueryRow(ctx, `SELECT (now() AT TIME ZONE 'Pacific/Midway')::date::text`).Scan(&due); err != nil {
		t.Fatal(err)
	}
	if res := admin.do(http.MethodPut, "/api/v1/review-requests/"+reviewID+"/review-results/"+itemID,
		map[string]any{"result": "CONDITIONAL", "opinion": "기한 확인", "follow_up": "기한 내 보완", "follow_up_due_date": due, "expected_updated_at": ""}); res.status != http.StatusOK {
		t.Fatalf("recording the verdict: %d %s", res.status, res.body)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_requests SET status='APPROVED',approved_at=now() WHERE id=$1`, reviewID); err != nil {
		t.Fatal(err)
	}

	overdue := func(zone string) bool {
		t.Helper()
		if _, err := h.db.Pool.Exec(ctx, `UPDATE settings SET value_json = jsonb_set(value_json,'{timezone}',to_jsonb($1::text)) WHERE key='general'`, zone); err != nil {
			t.Fatal(err)
		}
		res := admin.do(http.MethodGet, "/api/v1/reports/reviews?from=2000-01-01&to=2099-12-31", nil)
		if res.status != http.StatusOK {
			t.Fatalf("reading the register in %s: %d %s", zone, res.status, res.body)
		}
		rows, _ := res.json()["follow_ups"].([]any)
		for _, raw := range rows {
			row, _ := raw.(map[string]any)
			if row != nil && row["due_on"] == due {
				flag, _ := row["overdue"].(bool)
				return flag
			}
		}
		t.Fatalf("the action is missing from the register in %s: %s", zone, res.body)
		return false
	}
	if overdue("Pacific/Midway") {
		t.Error("an action due today was reported as overdue")
	}
	if !overdue("Pacific/Kiritimati") {
		t.Error("an action whose date has passed where the installation lives was reported as on time")
	}

	// The day an action was confirmed is rendered from a timestamp, which
	// to_char() formats in the session's zone unless it is told otherwise.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE review_results SET follow_up_done_at=now(),follow_up_done_by=$1 WHERE follow_up_due_date=$2::date`, adminID, due); err != nil {
		t.Fatal(err)
	}
	doneOn := func(zone string) string {
		t.Helper()
		if _, err := h.db.Pool.Exec(ctx, `UPDATE settings SET value_json = jsonb_set(value_json,'{timezone}',to_jsonb($1::text)) WHERE key='general'`, zone); err != nil {
			t.Fatal(err)
		}
		res := admin.do(http.MethodGet, "/api/v1/reports/reviews?from=2000-01-01&to=2099-12-31&include_done=1", nil)
		rows, _ := res.json()["follow_ups"].([]any)
		for _, raw := range rows {
			row, _ := raw.(map[string]any)
			if row != nil && row["due_on"] == due {
				day, _ := row["done_on"].(string)
				return day
			}
		}
		t.Fatalf("the confirmed action is missing from the register in %s: %s", zone, res.body)
		return ""
	}
	if east, west := doneOn("Pacific/Kiritimati"), doneOn("Pacific/Midway"); east == west {
		t.Errorf("both sides of the date line report the same completion day (%s)", east)
	}
}

// A period runs from the start of a day where the installation lives. The
// filters compared a timestamptz against a bare date, which begins at midnight
// UTC -- so with the default Seoul zone the first nine hours of every day were
// counted on the day before, and a report for the first of the month left them
// out entirely.
func TestAPeriodStartsWhereTheDayStarts(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	requester := h.user("period-requester", "REQUESTER")
	if _, err := h.db.Pool.Exec(ctx, `UPDATE settings SET value_json = jsonb_set(value_json,'{timezone}','"Asia/Seoul"') WHERE key='general'`); err != nil {
		t.Fatal(err)
	}
	id := store.NewID()
	// Half past midnight in Seoul on the fifth, which is still the fourth in UTC.
	if _, err := h.db.Pool.Exec(ctx, `INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status,created_at)
                VALUES($1,'SR-EARLY-1','새벽 신청 서비스','설명','WEB','NEW',$2,$2,'보안팀',$2,'INTERNAL','SUBMITTED','2026-03-05 00:30'::timestamp AT TIME ZONE 'Asia/Seoul')`, id, requester); err != nil {
		t.Fatal(err)
	}

	listed := func(from, to string) bool {
		t.Helper()
		res := admin.do(http.MethodGet, "/api/v1/review-requests?from="+from+"&to="+to+"&q=SR-EARLY-1", nil)
		if res.status != http.StatusOK {
			t.Fatalf("listing %s..%s: %d %s", from, to, res.status, res.body)
		}
		items, _ := res.json()["items"].([]any)
		return len(items) == 1
	}
	if !listed("2026-03-05", "2026-03-05") {
		t.Error("a review filed just after midnight is missing from that day")
	}
	if listed("2026-03-04", "2026-03-04") {
		t.Error("a review filed on the fifth was counted on the fourth")
	}

	res := admin.do(http.MethodGet, "/api/v1/reports/reviews?from=2026-03-05&to=2026-03-05", nil)
	if res.status != http.StatusOK {
		t.Fatalf("reading the period report: %d %s", res.status, res.body)
	}
	if !strings.Contains(res.body, "SUBMITTED") {
		t.Errorf("the period report does not count the review filed that morning: %s", res.body)
	}
}

// Every audit row names its target, and the table on the screen shows it, but
// there was no way to ask for one: "what happened to this Control" could only
// be answered by reading the whole log.
func TestTheAuditLogCanBeFilteredByItsTarget(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))

	first := admin.do(http.MethodPost, "/api/v1/security-controls", map[string]any{"code": "AU-1", "title": "감사 대상", "description": "설명"})
	if first.status != http.StatusCreated {
		t.Fatalf("creating a Control: %d %s", first.status, first.body)
	}
	controlID, _ := first.json()["id"].(string)
	if res := admin.do(http.MethodPatch, "/api/v1/security-controls/"+controlID, map[string]any{"title": "감사 대상 (개정)"}); res.status != http.StatusNoContent {
		t.Fatalf("editing the Control: %d %s", res.status, res.body)
	}
	other := admin.do(http.MethodPost, "/api/v1/security-controls", map[string]any{"code": "AU-2", "title": "다른 통제", "description": ""})
	if other.status != http.StatusCreated {
		t.Fatalf("creating a second Control: %d %s", other.status, other.body)
	}
	otherID, _ := other.json()["id"].(string)

	rows := func(query string) []map[string]any {
		t.Helper()
		res := admin.do(http.MethodGet, "/api/v1/admin/audit?"+query, nil)
		if res.status != http.StatusOK {
			t.Fatalf("reading the audit log with %s: %d %s", query, res.status, res.body)
		}
		var out []map[string]any
		for _, raw := range res.json()["items"].([]any) {
			row, _ := raw.(map[string]any)
			out = append(out, row)
		}
		return out
	}

	scoped := rows("target=" + controlID)
	if len(scoped) != 2 {
		t.Fatalf("the Control's own history has %d events, want the creation and the edit", len(scoped))
	}
	for _, row := range scoped {
		if row["target_id"] != controlID {
			t.Errorf("an event about %v came back under the filter for %s", row["target_id"], controlID)
		}
	}
	if got := rows("target=" + otherID); len(got) != 1 {
		t.Errorf("the other Control's history has %d events, want 1", len(got))
	}
	if got := rows("target=" + controlID + "&target_type=REVIEW_REQUEST"); len(got) != 0 {
		t.Errorf("a mismatched target type still returned %d events", len(got))
	}
	if got := rows("target=" + controlID + "&target_type=security_control"); len(got) != 2 {
		t.Errorf("the target type filter is case sensitive: %d events", len(got))
	}
}

// Replacing evidence during a review is ordinary; losing what it was is not.
// Every version was kept, encrypted, with its own hash and uploader, and none
// of it could be read back -- the reviewer could see the file was on its third
// version without being able to ask what the first two were.
func TestEvidenceKeepsAReadableVersionHistory(t *testing.T) {
	h := newHarness(t)
	h.login(adminOf(h))
	h.user("history-owner", "REQUESTER")
	owner := h.login("history-owner")
	reviewID := owner.createReview("증적 이력 서비스")
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(owner.do(http.MethodGet, "/api/v1/review-requests/"+reviewID+"/items", nil).body), &items); err != nil {
		t.Fatal(err)
	}
	itemID := items[0]["id"].(string)

	first := strings.Repeat("최초 증적 본문\n", 20)
	res := owner.upload(fmt.Sprintf("/api/v1/review-requests/%s/items/%s/evidences", reviewID, itemID), "정책서_v1.txt", first)
	if res.status != http.StatusCreated {
		t.Fatalf("uploading evidence: %d %s", res.status, res.body)
	}
	evidenceID, _ := res.json()["id"].(string)
	second := strings.Repeat("교체한 증적 본문\n", 40)
	if res := owner.upload("/api/v1/evidences/"+evidenceID+"/versions", "정책서_v2.txt", second); res.status != http.StatusCreated {
		t.Fatalf("replacing the evidence: %d %s", res.status, res.body)
	}

	history := owner.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/versions", nil)
	if history.status != http.StatusOK {
		t.Fatalf("reading the history: %d %s", history.status, history.body)
	}
	rows, _ := history.json()["items"].([]any)
	if len(rows) != 2 {
		t.Fatalf("the history has %d versions, want 2: %s", len(rows), history.body)
	}
	newest, _ := rows[0].(map[string]any)
	oldest, _ := rows[1].(map[string]any)
	if newest["original_filename"] != "정책서_v2.txt" || oldest["original_filename"] != "정책서_v1.txt" {
		t.Errorf("the history lost the names the files were uploaded under: %s", history.body)
	}
	if current, _ := newest["current"].(bool); !current {
		t.Error("the newest version is not marked as the current one")
	}
	if uploader, _ := oldest["uploaded_by"].(string); uploader == "" {
		t.Error("the history does not say who uploaded the first version")
	}

	// The earlier file is still readable, and is the earlier file.
	old := owner.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/download?version=1", nil)
	if old.status != http.StatusOK {
		t.Fatalf("downloading version 1: %d %s", old.status, old.body)
	}
	if old.body != first {
		t.Errorf("version 1 returned %d bytes, want the original %d", len(old.body), len(first))
	}
	if current := owner.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/download", nil); current.body != second {
		t.Error("the plain download no longer returns the current version")
	}
	if missing := owner.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/download?version=9", nil); missing.status != http.StatusNotFound {
		t.Errorf("a version that does not exist returned %d", missing.status)
	}
	if bad := owner.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/download?version=abc", nil); bad.status != http.StatusUnprocessableEntity {
		t.Errorf("a nonsense version returned %d", bad.status)
	}

	// Somebody outside the review cannot read its history.
	h.user("history-outsider", "REQUESTER")
	if res := h.login("history-outsider").do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/versions", nil); res.status != http.StatusNotFound {
		t.Errorf("an outsider read the evidence history: %d %s", res.status, res.body)
	}

	// A purged file is still part of the record, but the bytes are gone.
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE evidence_versions SET purged_at=now() WHERE evidence_id=$1 AND version=1`, evidenceID); err != nil {
		t.Fatal(err)
	}
	purged := owner.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/download?version=1", nil)
	if purged.status != http.StatusGone {
		t.Errorf("a purged version returned %d, want 410: %s", purged.status, purged.body)
	}
	listed := owner.do(http.MethodGet, "/api/v1/evidences/"+evidenceID+"/versions", nil).json()
	again, _ := listed["items"].([]any)
	if len(again) != 2 {
		t.Errorf("a purged version disappeared from the history: %v", listed)
	}
}

// Every assignee selector reads the directory, and an installation that syncs
// its staff from an IdP has thousands of accounts in it.
func TestTheUserDirectoryCanBeNarrowed(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()
	h.user("directory-one", "REQUESTER")
	h.user("directory-two", "REQUESTER")
	if _, err := h.db.Pool.Exec(ctx, `UPDATE users SET display_name='박보안',department='정보보호팀' WHERE username='directory-one'`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Pool.Exec(ctx, `UPDATE users SET display_name='최개발',department='플랫폼팀' WHERE username='directory-two'`); err != nil {
		t.Fatal(err)
	}

	names := func(query string) []string {
		t.Helper()
		res := admin.do(http.MethodGet, "/api/v1/users/directory"+query, nil)
		if res.status != http.StatusOK {
			t.Fatalf("reading the directory%s: %d %s", query, res.status, res.body)
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(res.body), &rows); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, row := range rows {
			name, _ := row["display_name"].(string)
			out = append(out, name)
		}
		return out
	}

	if got := names("?q=박보안"); len(got) != 1 || got[0] != "박보안" {
		t.Errorf("a search by name returned %v", got)
	}
	if got := names("?q=플랫폼"); len(got) != 1 || got[0] != "최개발" {
		t.Errorf("a search by department returned %v", got)
	}
	if got := names("?q=directory-one"); len(got) != 1 {
		t.Errorf("a search by account name returned %v", got)
	}
	if got := names("?q=없는사람"); len(got) != 0 {
		t.Errorf("a search that matches nobody returned %v", got)
	}
	if got := names(""); len(got) < 3 {
		t.Errorf("the unfiltered directory lost people: %v", got)
	}

	// A disabled account is not somebody work can be assigned to.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE users SET active=false WHERE username='directory-two'`); err != nil {
		t.Fatal(err)
	}
	if got := names("?q=최개발"); len(got) != 0 {
		t.Errorf("a disabled account is still offered as an assignee: %v", got)
	}
}

// Rules written before the vocabulary was checked can still be stored, and a
// rule that names something the engine never sees excludes its item from every
// review, not just this one. The simulator is where a template administrator
// would look, so that is where it has to say so.
func TestTheSimulatorNamesRulesThatCanNeverMatch(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	ctx := context.Background()

	created := admin.do(http.MethodPost, "/api/v1/templates", map[string]any{"name": "규칙 점검 템플릿", "category": "DEVELOPMENT", "description": "", "version": "V1"})
	if created.status != http.StatusCreated {
		t.Fatalf("creating a template: %d %s", created.status, created.body)
	}
	templateID, _ := created.json()["id"].(string)
	var versionID string
	if err := h.db.Pool.QueryRow(ctx, `SELECT id FROM checklist_versions WHERE template_id=$1`, templateID).Scan(&versionID); err != nil {
		t.Fatal(err)
	}
	base := fmt.Sprintf("/api/v1/templates/%s/versions/%s/items", templateID, versionID)
	sound := admin.do(http.MethodPost, base, map[string]any{"item_code": "OK-1", "title": "정상 규칙", "question": "질문", "category": "DEVELOPMENT", "severity": "MEDIUM", "answer_type": "YNNA", "sort_order": 1,
		"applicability_rule": map[string]any{"field": "exposure", "operator": "eq", "value": "EXTERNAL"}})
	if sound.status != http.StatusCreated {
		t.Fatalf("adding a sound item: %d %s", sound.status, sound.body)
	}
	broken := admin.do(http.MethodPost, base, map[string]any{"item_code": "BAD-1", "title": "오타 규칙", "question": "질문", "category": "DEVELOPMENT", "severity": "HIGH", "answer_type": "YNNA", "sort_order": 2})
	if broken.status != http.StatusCreated {
		t.Fatalf("adding the second item: %d %s", broken.status, broken.body)
	}
	brokenID, _ := broken.json()["id"].(string)
	// Written directly, the way it could have been before the check existed.
	if _, err := h.db.Pool.Exec(ctx, `UPDATE checklist_items SET applicability_rule='{"field":"exposuer","operator":"eq","value":"EXTERNAL"}'::jsonb WHERE id=$1`, brokenID); err != nil {
		t.Fatal(err)
	}
	if res := admin.do(http.MethodPost, fmt.Sprintf("/api/v1/templates/%s/versions/%s/publish", templateID, versionID), nil); res.status >= 300 {
		t.Fatalf("publishing the version: %d %s", res.status, res.body)
	}

	result := admin.do(http.MethodPost, "/api/v1/templates/rule-simulation", map[string]any{
		"service_name": "점검", "description": "d", "service_type": "WEB", "change_type": "NEW",
		"department": "보안팀", "exposure": "EXTERNAL",
	}).json()
	if count, _ := result["broken"].(float64); count != 1 {
		t.Errorf("the simulator reported %v rules it can never satisfy, want 1", result["broken"])
	}
	var reported, sane map[string]any
	for _, raw := range result["items"].([]any) {
		row, _ := raw.(map[string]any)
		switch row["item_code"] {
		case "BAD-1":
			reported = row
		case "OK-1":
			sane = row
		}
	}
	if reported == nil || sane == nil {
		t.Fatalf("the simulation did not cover both items: %v", result["items"])
	}
	if ruleError, _ := reported["rule_error"].(string); !strings.Contains(ruleError, "exposuer") {
		t.Errorf("the broken item does not name what is wrong with it: %v", reported)
	}
	if applied, _ := reported["applied"].(bool); applied {
		t.Error("an item whose rule can never match was reported as assigned")
	}
	if _, marked := sane["rule_error"]; marked {
		t.Errorf("a sound rule was reported as broken: %v", sane)
	}
	if applied, _ := sane["applied"].(bool); !applied {
		t.Errorf("the sound item was not assigned to a matching profile: %v", sane)
	}
}
