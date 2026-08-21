package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestOnlyAdministratorsReachTheJobQueue(t *testing.T) {
	h := newHarness(t)
	h.user("plainuser", "REQUESTER")
	if res := h.login("plainuser").do(http.MethodGet, "/api/v1/admin/jobs", nil); res.status != http.StatusForbidden {
		t.Errorf("a requester reached the job queue: %d", res.status)
	}
}
