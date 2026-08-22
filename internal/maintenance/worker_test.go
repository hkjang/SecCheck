package maintenance_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/maintenance"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
	"github.com/hkjang/SecCheck/internal/vault"
)

func TestSweepReclaimsExpiredStateButNeverAuditLogs(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	userID := testdb.Bootstrap(t, db, "sweeper")

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,'c',now()-interval '1 hour')`, store.NewID(), userID, []byte("expired"))
	exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_token,expires_at) VALUES($1,$2,$3,'c',now()+interval '1 hour')`, store.NewID(), userID, []byte("live"))
	exec(`INSERT INTO oidc_states(state_hash,nonce,code_verifier,expires_at) VALUES($1,'n','v',now()-interval '1 hour')`, []byte("stale"))
	exec(`INSERT INTO jobs(id,type,status,updated_at) VALUES($1,'SEND_EMAIL','COMPLETED',now()-interval '30 days')`, store.NewID())
	exec(`INSERT INTO jobs(id,type,status,updated_at) VALUES($1,'SEND_EMAIL','PENDING',now()-interval '30 days')`, store.NewID())
	exec(`INSERT INTO application_logs(timestamp,level,message) VALUES(now()-interval '4000 days','INFO','ancient')`)
	exec(`INSERT INTO application_logs(timestamp,level,message) VALUES(now(),'INFO','recent')`)
	exec(`UPDATE users SET failed_login_count=5,locked_until=now()-interval '1 minute' WHERE id=$1`, userID)
	if err := db.Audit(ctx, store.AuditEvent{UserID: userID, EventType: "TEST", TargetType: "USER", TargetID: userID}); err != nil {
		t.Fatalf("seed audit event: %v", err)
	}

	maintenance.New(db, nil).Sweep(ctx)

	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return n
	}
	if got := count(`SELECT count(*) FROM sessions`); got != 1 {
		t.Errorf("sessions remaining = %d, want only the live one", got)
	}
	if got := count(`SELECT count(*) FROM oidc_states`); got != 0 {
		t.Errorf("expired OIDC states remaining = %d", got)
	}
	if got := count(`SELECT count(*) FROM jobs`); got != 1 {
		t.Errorf("jobs remaining = %d, want only the pending one", got)
	}
	if got := count(`SELECT count(*) FROM application_logs WHERE message='ancient'`); got != 0 {
		t.Error("a log past the retention window survived")
	}
	if got := count(`SELECT count(*) FROM application_logs WHERE message='recent'`); got != 1 {
		t.Error("a log inside the retention window was deleted")
	}
	// The hash chain has to stay verifiable for the life of the installation.
	if got := count(`SELECT count(*) FROM audit_logs`); got == 0 {
		t.Error("audit logs must never be swept")
	}
	var failures int
	var locked *string
	if err := db.Pool.QueryRow(ctx, `SELECT failed_login_count,locked_until::text FROM users WHERE id=$1`, userID).Scan(&failures, &locked); err != nil {
		t.Fatal(err)
	}
	if failures != 0 || locked != nil {
		t.Errorf("an elapsed lockout was not cleared: count=%d until=%v", failures, locked)
	}
}

func TestSweepIsSafeOnAnEmptyDatabase(t *testing.T) {
	db := testdb.New(t)
	removed := maintenance.New(db, nil).Sweep(context.Background())
	for name, n := range removed {
		if n != 0 {
			t.Errorf("%s removed %d rows from an empty database", name, n)
		}
	}
}

// Deleted evidence used to leave its ciphertext on the volume for ever, while
// the code claimed a retention policy that did not exist.
func TestDeletedEvidenceBlobsArePurgedButMetadataSurvives(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	dir := t.TempDir()
	key, err := cryptox.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	box, err := cryptox.New(key)
	if err != nil {
		t.Fatal(err)
	}
	blobs := vault.New(dir, box, db)
	owner := testdb.Bootstrap(t, db, "purger")
	if err = blobs.EnsureUserKey(ctx, owner); err != nil {
		t.Fatal(err)
	}
	userKey, version, err := blobs.ActiveUserKey(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}

	// Two evidence rows: one deleted long ago, one deleted just now.
	type fixture struct{ id, stored string }
	write := func(id string, deletedDaysAgo int) fixture {
		t.Helper()
		stored := store.NewID() + ".enc"
		if _, _, err := blobs.Write(stored, userKey, vault.AAD(id, 1), strings.NewReader("증적 본문")); err != nil {
			t.Fatal(err)
		}
		item := seedEvidenceRow(t, db, id, owner, stored, version, deletedDaysAgo)
		_ = item
		return fixture{id: id, stored: stored}
	}
	old := write(store.NewID(), 200)
	recent := write(store.NewID(), 1)

	removed := maintenance.New(db, blobs).Sweep(ctx)
	if removed["purged_evidence_files"] != 1 {
		t.Fatalf("purged %v files, want exactly the one past the window", removed["purged_evidence_files"])
	}
	if _, err = os.Stat(blobs.Path(old.stored)); !os.IsNotExist(err) {
		t.Error("the expired ciphertext is still on the volume")
	}
	if _, err = os.Stat(blobs.Path(recent.stored)); err != nil {
		t.Errorf("recently deleted evidence was purged early: %v", err)
	}

	// The audit-relevant metadata has to survive the purge.
	var filename, sha string
	var purged *time.Time
	if err = db.Pool.QueryRow(ctx, `SELECT original_filename,sha256,purged_at FROM evidences WHERE id=$1`, old.id).Scan(&filename, &sha, &purged); err != nil {
		t.Fatalf("the evidence row was removed along with the file: %v", err)
	}
	if filename == "" || sha == "" {
		t.Error("the purge erased the metadata that records the file existed")
	}
	if purged == nil {
		t.Error("the evidence row was not marked as purged")
	}
	// Destroying the only copy of a piece of evidence has to reach the
	// tamper-evident record. The application log is deleted by this same
	// retention sweep, so an account kept only there expires with it.
	var events int
	var after string
	if err = db.Pool.QueryRow(ctx, `SELECT count(*),COALESCE(max(after_value::text),'') FROM audit_logs WHERE event_type='PURGE_EVIDENCE' AND target_id=$1`, old.id).Scan(&events, &after); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("the purge left %d audit events", events)
	}
	for _, want := range []string{filename, sha, "retention_days"} {
		if !strings.Contains(after, want) {
			t.Errorf("the audit event does not record %q: %s", want, after)
		}
	}

	// Running again must be a no-op rather than re-counting the same rows.
	if again := maintenance.New(db, blobs).Sweep(ctx); again["purged_evidence_files"] != 0 {
		t.Errorf("a second sweep purged %v files again", again["purged_evidence_files"])
	}
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='PURGE_EVIDENCE'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("a second sweep recorded the same purge again: %d events", events)
	}
}

func seedEvidenceRow(t *testing.T, db *store.Store, id, owner, stored string, keyVersion, deletedDaysAgo int) string {
	t.Helper()
	ctx := context.Background()
	var templateID, versionID, itemID, reviewID, submissionID, submissionItemID string
	templateID, versionID, itemID = store.NewID(), store.NewID(), store.NewID()
	reviewID, submissionID, submissionItemID = store.NewID(), store.NewID(), store.NewID()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO checklist_templates(id,name,category,created_by) VALUES($1,$2,'DEVELOPMENT',$3) ON CONFLICT DO NOTHING`, templateID, "purge-"+templateID[:8], owner)
	exec(`INSERT INTO checklist_versions(id,template_id,version,created_by) VALUES($1,$2,'V1',$3)`, versionID, templateID, owner)
	exec(`INSERT INTO checklist_items(id,version_id,item_code,category,title,question) VALUES($1,$2,$3,'DEVELOPMENT','t','q')`, itemID, versionID, "PURGE-"+itemID[:8])
	exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure) VALUES($1,$2,'s','d','WEB','NEW',$3,$3,'보안팀',$3,'INTERNAL')`, reviewID, "PG-"+reviewID[:8], owner)
	exec(`INSERT INTO submissions(id,review_request_id) VALUES($1,$2)`, submissionID, reviewID)
	exec(`INSERT INTO submission_items(id,submission_id,source_item_id,template_name,template_version,item_code,section,category,title,question,severity,answer_type,required,evidence_required,sort_order) VALUES($1,$2,$3,'t','V1',$4,'','DEVELOPMENT','t','q','MEDIUM','YNNA',true,false,1)`, submissionItemID, submissionID, itemID, "PURGE-"+itemID[:8])
	exec(`INSERT INTO evidences(id,submission_item_id,original_filename,stored_filename,mime_type,size_bytes,sha256,uploaded_by,key_owner_id,key_version,scan_status,deleted_at)
              VALUES($1,$2,'evidence.txt',$3,'text/plain',12,'abc',$4,$4,$5,'CLEAN',now()-make_interval(days=>$6))`, id, submissionItemID, stored, owner, keyVersion, deletedDaysAgo)
	exec(`INSERT INTO evidence_versions(id,evidence_id,version,stored_filename,size_bytes,sha256,mime_type,key_owner_id,key_version,scan_status,uploaded_by) VALUES($1,$2,1,$3,12,'abc','text/plain',$4,$5,'CLEAN',$4)`, store.NewID(), id, stored, owner, keyVersion)
	return submissionItemID
}

// The workers that send email are the ones most likely to be dead, so the
// warning that they are dead cannot itself be an email.
func TestAdministratorsAreAlertedWhenTheQueueStopsDraining(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	adminID := testdb.Bootstrap(t, db, "queue-watcher")
	if _, err := db.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,'SYSTEM_ADMIN') ON CONFLICT DO NOTHING`, adminID); err != nil {
		t.Fatal(err)
	}
	worker := maintenance.New(db, nil)

	// Backoff is not a stall: the job is simply not due yet.
	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,available_at) VALUES($1,'SEND_EMAIL','PENDING',now()+interval '1 hour')`, store.NewID()); err != nil {
		t.Fatal(err)
	}
	worker.Sweep(ctx)
	if n := alerts(t, db, adminID); n != 0 {
		t.Fatalf("a job waiting for its retry window raised %d stall alerts", n)
	}

	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,available_at) VALUES($1,'SEND_EMAIL','PENDING',now()-interval '40 minutes')`, store.NewID()); err != nil {
		t.Fatal(err)
	}
	worker.Sweep(ctx)
	if n := alerts(t, db, adminID); n != 1 {
		t.Fatalf("stall alerts = %d, want 1", n)
	}
	var body string
	if err := db.Pool.QueryRow(ctx, `SELECT body FROM notifications WHERE event_type='JOB_QUEUE_STALLED'`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "40분째") {
		t.Errorf("the alert does not say how long the queue has been stuck: %s", body)
	}

	// An outage lasting days must not refill the inbox on every sweep.
	worker.Sweep(ctx)
	if n := alerts(t, db, adminID); n != 1 {
		t.Errorf("a second sweep during the same outage raised the count to %d", n)
	}
}

func alerts(t *testing.T, db *store.Store, adminID string) int {
	t.Helper()
	var n int
	if err := db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='JOB_QUEUE_STALLED'`, adminID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// An action promised at review time falls due months later, when nobody is
// looking at the review or the report. The register shows it; only a
// notification reaches the person who has to do it.
func TestFollowUpsAreRemindedWhenTheirDateApproaches(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	requester := testdb.Bootstrap(t, db, "follow-up-owner")
	worker := maintenance.New(db, nil)

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	reviewID, submissionID := store.NewID(), store.NewID()
	exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status)
                VALUES($1,'SC-2026-000900','후속조치 서비스','설명','WEB','NEW',$2,$2,'보안팀',$2,'INTERNAL','APPROVED')`, reviewID, requester)
	exec(`INSERT INTO submissions(id,review_request_id,revision,status) VALUES($1,$2,1,'APPROVED')`, submissionID, reviewID)

	// A submitted item points back at the checklist item it was copied from,
	// so a small published template stands in for the seeded baseline.
	templateID, versionID := store.NewID(), store.NewID()
	exec(`INSERT INTO checklist_templates(id,name,category,created_by) VALUES($1,'테스트 템플릿','DEVELOPMENT',$2)`, templateID, requester)
	exec(`INSERT INTO checklist_versions(id,template_id,version,status,created_by) VALUES($1,$2,'V1','PUBLISHED',$3)`, versionID, templateID, requester)
	sources := make([]string, 5)
	for i := range sources {
		sources[i] = store.NewID()
		exec(`INSERT INTO checklist_items(id,version_id,item_code,category,title,question,severity,required,answer_type,evidence_required,sort_order)
                        VALUES($1,$2,$3,'DEVELOPMENT','보안요건','질문','MEDIUM',true,'YNNA',false,$4)`, sources[i], versionID, fmt.Sprintf("S-%d", i), i)
	}
	next := 0
	item := func(code string) string {
		id := store.NewID()
		exec(`INSERT INTO submission_items(id,submission_id,source_item_id,template_name,template_version,item_code,section,category,title,question,severity,required,answer_type,evidence_required,sort_order)
                        VALUES($1,$2,$3,'개발보안','V1',$4,'구분','DEVELOPMENT','보안요건','질문','MEDIUM',true,'YNNA',false,1)`, id, submissionID, sources[next], code)
		next++
		return id
	}
	result := func(itemID, action string, due any, done bool) string {
		id := store.NewID()
		exec(`INSERT INTO review_results(id,submission_item_id,reviewer_id,result,follow_up,follow_up_due_date,follow_up_done_at)
                        VALUES($1,$2,$3,'CONDITIONAL',$4,$5::date,CASE WHEN $6 THEN now() END)`, id, itemID, requester, action, due, done)
		return id
	}
	soon := result(item("A-1"), "곧 기한", time.Now().AddDate(0, 0, 3).Format("2006-01-02"), false)
	late := result(item("A-2"), "이미 지남", time.Now().AddDate(0, 0, -5).Format("2006-01-02"), false)
	distant := result(item("A-3"), "한참 남음", time.Now().AddDate(0, 0, 60).Format("2006-01-02"), false)
	finished := result(item("A-4"), "이미 이행", time.Now().AddDate(0, 0, -5).Format("2006-01-02"), true)
	undated := result(item("A-5"), "기한 없음", nil, false)

	worker.Sweep(ctx)

	reminded := func(id string) bool {
		t.Helper()
		var at *time.Time
		if err := db.Pool.QueryRow(ctx, `SELECT follow_up_reminded_at FROM review_results WHERE id=$1`, id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at != nil
	}
	for name, id := range map[string]string{"due soon": soon, "already late": late} {
		if !reminded(id) {
			t.Errorf("%s was not reminded", name)
		}
	}
	for name, id := range map[string]string{"far off": distant, "already carried out": finished, "with no date": undated} {
		if reminded(id) {
			t.Errorf("%s should not have been reminded", name)
		}
	}

	var notices int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='FOLLOW_UP_DUE'`, requester).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices != 2 {
		t.Fatalf("the sweep sent %d reminders, want 2", notices)
	}
	var late1 int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_type='FOLLOW_UP_DUE' AND title='후속조치 기한 초과'`).Scan(&late1); err != nil {
		t.Fatal(err)
	}
	if late1 != 1 {
		t.Errorf("%d reminders said the date had passed, want 1", late1)
	}

	// A second sweep in the same week must not repeat itself.
	worker.Sweep(ctx)
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='FOLLOW_UP_DUE'`, requester).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices != 2 {
		t.Errorf("a second sweep raised the reminder count to %d", notices)
	}
}

// These dates fall months after a review closes, which is exactly when the
// person who owned the work is most likely to have left. A reminder sent to a
// deactivated account is worse than none: the item looks chased and is not.
func TestRemindersFindSomebodyWhoCanStillAct(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	departed := testdb.Bootstrap(t, db, "departed-owner")
	reviewer := testdb.Bootstrap(t, db, "standing-reviewer")
	worker := maintenance.New(db, nil)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}

	templateID, versionID, sourceID := store.NewID(), store.NewID(), store.NewID()
	exec(`INSERT INTO checklist_templates(id,name,category,created_by) VALUES($1,'템플릿','DEVELOPMENT',$2)`, templateID, reviewer)
	exec(`INSERT INTO checklist_versions(id,template_id,version,status,created_by) VALUES($1,$2,'V1','PUBLISHED',$3)`, versionID, templateID, reviewer)
	exec(`INSERT INTO checklist_items(id,version_id,item_code,category,title,question,severity,required,answer_type,evidence_required,sort_order)
                VALUES($1,$2,'X-1','DEVELOPMENT','보안요건','질문','MEDIUM',true,'YNNA',false,1)`, sourceID, versionID)

	reviewID, submissionID, itemID := store.NewID(), store.NewID(), store.NewID()
	exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,reviewer_id,exposure,status)
                VALUES($1,'SC-2026-000901','퇴사자 서비스','설명','WEB','NEW',$2,$2,'보안팀',$2,$3,'INTERNAL','APPROVED')`, reviewID, departed, reviewer)
	exec(`INSERT INTO submissions(id,review_request_id,revision,status) VALUES($1,$2,1,'APPROVED')`, submissionID, reviewID)
	exec(`INSERT INTO submission_items(id,submission_id,source_item_id,template_name,template_version,item_code,section,category,title,question,severity,required,answer_type,evidence_required,sort_order)
                VALUES($1,$2,$3,'템플릿','V1','X-1','구분','DEVELOPMENT','보안요건','질문','MEDIUM',true,'YNNA',false,1)`, itemID, submissionID, sourceID)
	exec(`INSERT INTO review_results(id,submission_item_id,reviewer_id,result,follow_up,follow_up_due_date)
                VALUES($1,$2,$3,'CONDITIONAL','계정 분리',current_date-1)`, store.NewID(), itemID, reviewer)

	// The person who owned the service has left.
	exec(`UPDATE users SET active=false WHERE id=$1`, departed)
	worker.Sweep(ctx)

	var toDeparted, toReviewer int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE recipient_id=$1), count(*) FILTER(WHERE recipient_id=$2)
                FROM notifications WHERE event_type='FOLLOW_UP_DUE'`, departed, reviewer).Scan(&toDeparted, &toReviewer); err != nil {
		t.Fatal(err)
	}
	if toDeparted != 0 {
		t.Errorf("%d reminders went to a deactivated account", toDeparted)
	}
	if toReviewer != 1 {
		t.Fatalf("the reviewer received %d reminders, want 1", toReviewer)
	}
	var body string
	if err := db.Pool.QueryRow(ctx, `SELECT body FROM notifications WHERE recipient_id=$1 AND event_type='FOLLOW_UP_DUE'`, reviewer).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "비활성") {
		t.Errorf("the reminder does not say why it was redirected: %s", body)
	}
}
