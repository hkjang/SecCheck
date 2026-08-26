package maintenance_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

// A stalled queue is visible as a backlog. A job that has spent all of its
// retries leaves nothing behind at all -- the queue reads as empty because the
// work was given up on, which is exactly what a wrong SMTP password looks like
// from the administrator's side.
func TestAdministratorsAreAlertedWhenJobsRunOutOfRetries(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	adminID := testdb.Bootstrap(t, db, "failure-watcher")
	if _, err := db.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,'SYSTEM_ADMIN') ON CONFLICT DO NOTHING`, adminID); err != nil {
		t.Fatal(err)
	}
	worker := maintenance.New(db, nil)
	failed := func() int64 {
		t.Helper()
		var n int64
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='JOB_FAILED'`, adminID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// A job still working through its retries is not a failure yet.
	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,attempts,available_at) VALUES($1,'SEND_EMAIL','PENDING',3,now()+interval '4 minutes')`, store.NewID()); err != nil {
		t.Fatal(err)
	}
	worker.Sweep(ctx)
	if n := failed(); n != 0 {
		t.Fatalf("a job that is still retrying raised %d failure alerts", n)
	}

	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,attempts,last_error,available_at) VALUES($1,'SEND_EMAIL','FAILED',5,'535 5.7.8 authentication failed',now())`, store.NewID()); err != nil {
		t.Fatal(err)
	}
	worker.Sweep(ctx)
	if n := failed(); n != 1 {
		t.Fatalf("failure alerts = %d, want 1", n)
	}
	var body string
	if err := db.Pool.QueryRow(ctx, `SELECT body FROM notifications WHERE event_type='JOB_FAILED'`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "authentication failed") {
		t.Errorf("the alert does not carry the error an administrator would act on: %s", body)
	}

	// A queue that stays broken must not refill the inbox on every sweep.
	worker.Sweep(ctx)
	if n := failed(); n != 1 {
		t.Errorf("a second sweep during the same outage raised the count to %d", n)
	}

	// Nothing new having failed since is not worth another alert either.
	if _, err := db.Pool.Exec(ctx, `UPDATE jobs SET updated_at=now()-interval '30 days' WHERE status='FAILED'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `DELETE FROM notifications WHERE event_type='JOB_FAILED'`); err != nil {
		t.Fatal(err)
	}
	worker.Sweep(ctx)
	if n := failed(); n != 0 {
		t.Errorf("an old failure nobody can act on raised %d alerts", n)
	}
}

// A deadline reminder exists to reach somebody who is not looking at the
// screen. The workers used to write the notification row and stop, so the mail
// was only ever sent to readers on the daily digest -- everyone else, which is
// the default, had to open the service to find out.
func TestADeadlineReminderIsMailedToWhoeverWantsMailNow(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	reviewer := testdb.Bootstrap(t, db, "reminder-reviewer")
	worker := maintenance.New(db, nil)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`UPDATE settings SET value_json = value_json || '{"email_enabled":true,"smtp_host":"smtp.internal","smtp_port":25,"smtp_from":"seccheck@example.internal"}'::jsonb WHERE key='notification'`)
	exec(`UPDATE users SET email='reviewer@example.internal' WHERE id=$1`, reviewer)
	itemID := seedChangeRequest(t, db, reviewer)

	mailJobs := func() int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE type='SEND_EMAIL'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	worker.Sweep(ctx)
	var notified int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_type='CHANGE_REQUEST_DUE'`).Scan(&notified); err != nil {
		t.Fatal(err)
	}
	if notified != 1 {
		t.Fatalf("the reminder was not recorded: %d notifications", notified)
	}
	if got := mailJobs(); got != 1 {
		t.Errorf("%d e-mails were queued for a reader on immediate delivery, want 1", got)
	}

	// A reader on the daily digest is left to the digest, and a muted event is
	// not mailed at all.
	exec(`DELETE FROM jobs WHERE type='SEND_EMAIL'`)
	exec(`UPDATE change_requests SET reminded_at=NULL WHERE submission_item_id=$1`, itemID)
	exec(`INSERT INTO notification_preferences(user_id,email_enabled,digest) VALUES($1,true,'DAILY') ON CONFLICT(user_id) DO UPDATE SET digest='DAILY',email_enabled=true,muted_events='{}'`, reviewer)
	worker.Sweep(ctx)
	if got := mailJobs(); got != 0 {
		t.Errorf("%d e-mails were queued for a digest reader, want 0", got)
	}
	exec(`UPDATE change_requests SET reminded_at=NULL WHERE submission_item_id=$1`, itemID)
	exec(`UPDATE notification_preferences SET digest='IMMEDIATE',muted_events=ARRAY['CHANGE_REQUEST_DUE'] WHERE user_id=$1`, reviewer)
	worker.Sweep(ctx)
	if got := mailJobs(); got != 0 {
		t.Errorf("%d e-mails were queued for a muted event, want 0", got)
	}
}

// seedChangeRequest builds the smallest review that can carry an open change
// request due tomorrow, and returns the submission item it hangs off.
func seedChangeRequest(t *testing.T, db *store.Store, owner string) string {
	t.Helper()
	ctx := context.Background()
	templateID, versionID, itemID := store.NewID(), store.NewID(), store.NewID()
	reviewID, submissionID, submissionItemID := store.NewID(), store.NewID(), store.NewID()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO checklist_templates(id,name,category,created_by) VALUES($1,$2,'DEVELOPMENT',$3)`, templateID, "due-"+templateID[:8], owner)
	exec(`INSERT INTO checklist_versions(id,template_id,version,created_by) VALUES($1,$2,'V1',$3)`, versionID, templateID, owner)
	exec(`INSERT INTO checklist_items(id,version_id,item_code,category,title,question) VALUES($1,$2,$3,'DEVELOPMENT','t','q')`, itemID, versionID, "DUE-"+itemID[:8])
	exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status) VALUES($1,$2,'s','d','WEB','NEW',$3,$3,'보안팀',$3,'INTERNAL','CHANGE_REQUESTED')`, reviewID, "DUE-"+reviewID[:8], owner)
	exec(`INSERT INTO submissions(id,review_request_id) VALUES($1,$2)`, submissionID, reviewID)
	exec(`INSERT INTO submission_items(id,submission_id,source_item_id,template_name,template_version,item_code,section,category,title,question,severity,answer_type,required,evidence_required,sort_order) VALUES($1,$2,$3,'t','V1',$4,'','DEVELOPMENT','t','q','MEDIUM','YNNA',true,false,1)`, submissionItemID, submissionID, itemID, "DUE-"+itemID[:8])
	exec(`INSERT INTO change_requests(id,review_request_id,submission_item_id,reason,requester_id,assignee_id,due_date) VALUES($1,$2,$3,'보완하세요',$4,$4,display_today()+1)`, store.NewID(), reviewID, submissionItemID, owner)
	return submissionItemID
}

// Reminders only ever pushed the requester side. A review submitted and never
// picked up, or started and left, simply aged: the requester could see no
// movement and had no way to push, and nobody was told they were the holdup.
func TestTheSideHoldingAReviewIsReminded(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	requester := testdb.Bootstrap(t, db, "stall-requester")
	worker := maintenance.New(db, nil)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	reviewer := store.NewID()
	exec(`INSERT INTO users(id,username,display_name,auth_source,active) VALUES($1,'stall-reviewer','검토자','local',true)`, reviewer)
	exec(`INSERT INTO user_roles(user_id,role_code) VALUES($1,'SECURITY_REVIEWER')`, reviewer)
	review := func(number, status, reviewerID string, ageDays int) string {
		t.Helper()
		id := store.NewID()
		exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status,reviewer_id,updated_at)
                      VALUES($1,$2,'s','d','WEB','NEW',$3,$3,'보안팀',$3,'INTERNAL',$4,NULLIF($5,''),now()-make_interval(days=>$6))`, id, number, requester, status, reviewerID, ageDays)
		return id
	}
	notices := func(recipient string) []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `SELECT body FROM notifications WHERE recipient_id=$1 AND event_type='REVIEW_STALLED' ORDER BY created_at`, recipient)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var body string
			if rows.Scan(&body) == nil {
				out = append(out, body)
			}
		}
		return out
	}

	fresh := review("SR-FRESH", "REVIEWING", reviewer, 1)
	assigned := review("SR-STUCK", "REVIEWING", reviewer, 5)
	unclaimed := review("SR-QUEUE", "SUBMITTED", "", 4)
	done := review("SR-DONE", "APPROVED", reviewer, 30)
	_, _ = fresh, done

	worker.Sweep(ctx)
	got := notices(reviewer)
	if len(got) != 2 {
		t.Fatalf("the reviewer was told about %d reviews, want the stuck one and the unclaimed one: %v", len(got), got)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "SR-STUCK") || !strings.Contains(joined, "SR-QUEUE") {
		t.Errorf("the reminders name the wrong reviews: %v", got)
	}
	if strings.Contains(joined, "SR-FRESH") {
		t.Error("a review that moved yesterday was reported as stalled")
	}
	if strings.Contains(joined, "SR-DONE") {
		t.Error("a finished review was reported as stalled")
	}
	if !strings.Contains(joined, "5일째") {
		t.Errorf("the reminder does not say how long it has been waiting: %v", got)
	}

	// The same holdup must not be reported again on the next sweep.
	worker.Sweep(ctx)
	if again := notices(reviewer); len(again) != 2 {
		t.Errorf("a second sweep raised the count to %d", len(again))
	}
	// Once it moves on, it stops being reported.
	exec(`UPDATE review_requests SET status='APPROVED',stalled_reminded_at=NULL WHERE id=$1`, assigned)
	exec(`UPDATE review_requests SET status='APPROVED',stalled_reminded_at=NULL WHERE id=$1`, unclaimed)
	worker.Sweep(ctx)
	if again := notices(reviewer); len(again) != 2 {
		t.Errorf("a review that has moved on was reported again: %d notices", len(again))
	}
}

// A queue nobody is working on must not produce one message per reviewer per
// review. That is a flood, and a flood teaches people to ignore the alert.
func TestUnclaimedReviewsAreGatheredIntoOneReminder(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	requester := testdb.Bootstrap(t, db, "flood-requester")
	worker := maintenance.New(db, nil)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var reviewers []string
	for _, name := range []string{"flood-reviewer-1", "flood-reviewer-2"} {
		id := store.NewID()
		exec(`INSERT INTO users(id,username,display_name,auth_source,active) VALUES($1,$2,$2,'local',true)`, id, name)
		exec(`INSERT INTO user_roles(user_id,role_code) VALUES($1,'SECURITY_REVIEWER')`, id)
		reviewers = append(reviewers, id)
	}
	for i, age := range []int{4, 6, 9, 12} {
		exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status,updated_at)
                      VALUES($1,$2,'s','d','WEB','NEW',$3,$3,'보안팀',$3,'INTERNAL','SUBMITTED',now()-make_interval(days=>$4))`,
			store.NewID(), fmt.Sprintf("SR-OPEN-%d", i), requester, age)
	}

	worker.Sweep(ctx)
	for _, reviewer := range reviewers {
		var bodies []string
		rows, err := db.Pool.Query(ctx, `SELECT body FROM notifications WHERE recipient_id=$1 AND event_type='REVIEW_STALLED'`, reviewer)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var body string
			if rows.Scan(&body) == nil {
				bodies = append(bodies, body)
			}
		}
		rows.Close()
		if len(bodies) != 1 {
			t.Fatalf("a reviewer received %d messages about four unclaimed reviews, want 1: %v", len(bodies), bodies)
		}
		if !strings.Contains(bodies[0], "4건") {
			t.Errorf("the reminder does not say how many are waiting: %s", bodies[0])
		}
		if !strings.Contains(bodies[0], "12일째") {
			t.Errorf("the reminder does not say how long the oldest has waited: %s", bodies[0])
		}
		if !strings.Contains(bodies[0], "외 1건") {
			t.Errorf("the reminder does not account for the ones it did not name: %s", bodies[0])
		}
	}
}

// An appliance that runs offline for years fills its disk eventually. The
// first sign used to be an upload failing for somebody who could do nothing
// about it: the figure was on no screen and in no metric.
func TestAdministratorsAreWarnedBeforeTheEvidenceVolumeFills(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	adminID := testdb.Bootstrap(t, db, "storage-watcher")
	if _, err := db.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,'SYSTEM_ADMIN') ON CONFLICT DO NOTHING`, adminID); err != nil {
		t.Fatal(err)
	}
	key, err := cryptox.RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	box, err := cryptox.New(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	worker := maintenance.New(db, vault.New(dir, box, db))
	alerts := func() int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='STORAGE_LOW'`, adminID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// A volume with room does not raise anything.
	worker.Sweep(ctx)
	if n := alerts(); n != 0 {
		t.Fatalf("a healthy volume raised %d alerts", n)
	}

	// One that cannot be written to does, and says so.
	if err := os.Chmod(filepath.Join(dir, "evidence"), 0o500); err != nil {
		t.Skipf("cannot make the directory read-only here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "evidence"), 0o700) })
	if space := vault.New(dir, box, db).Space(); space.Writable {
		t.Skip("this filesystem ignores the read-only bit for the test user")
	}
	worker.Sweep(ctx)
	if n := alerts(); n != 1 {
		t.Fatalf("a volume that cannot be written to raised %d alerts, want 1", n)
	}
	var body string
	if err := db.Pool.QueryRow(ctx, `SELECT body FROM notifications WHERE event_type='STORAGE_LOW' AND recipient_id=$1`, adminID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "업로드가 모두 실패") {
		t.Errorf("the alert does not say what breaks: %s", body)
	}
	// And it does not repeat while the same problem lasts.
	worker.Sweep(ctx)
	if n := alerts(); n != 1 {
		t.Errorf("a second sweep raised the count to %d", n)
	}
}

// The planned open date is the day the service goes live whether or not the
// review is finished. It was recorded, sorted by and displayed, and nothing
// ever chased it: a review could still be in progress on the launch morning.
func TestTheOpenDateIsChasedWhileThereIsStillTime(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	requester := testdb.Bootstrap(t, db, "launch-requester")
	worker := maintenance.New(db, nil)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	reviewer := store.NewID()
	exec(`INSERT INTO users(id,username,display_name,auth_source,active) VALUES($1,'launch-reviewer','검토자','local',true)`, reviewer)
	// Holding the review means holding the role: the warning goes to whoever
	// can actually finish it.
	exec(`INSERT INTO user_roles(user_id,role_code) VALUES($1,'SECURITY_REVIEWER')`, reviewer)
	review := func(number, status string, openIn int, withReviewer bool) string {
		t.Helper()
		id := store.NewID()
		assigned := ""
		if withReviewer {
			assigned = reviewer
		}
		exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status,reviewer_id,planned_open_date)
                      VALUES($1,$2,'s','d','WEB','NEW',$3,$3,'보안팀',$3,'INTERNAL',$4,NULLIF($5,''),display_today()+$6::int)`, id, number, requester, status, assigned, openIn)
		return id
	}
	notices := func(recipient string) []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `SELECT body FROM notifications WHERE recipient_id=$1 AND event_type='OPEN_DATE_NEAR'`, recipient)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var body string
			if rows.Scan(&body) == nil {
				out = append(out, body)
			}
		}
		return out
	}

	review("SR-SOON", "REVIEWING", 2, true)  // opens in two days, still under review
	review("SR-LATE", "SUBMITTED", -1, true) // opened yesterday and never finished
	review("SR-FAR", "REVIEWING", 30, true)  // plenty of time
	review("SR-DONE", "APPROVED", 1, true)   // finished, nothing to chase

	worker.Sweep(ctx)
	forRequester := strings.Join(notices(requester), "\n")
	if !strings.Contains(forRequester, "SR-SOON") || !strings.Contains(forRequester, "SR-LATE") {
		t.Errorf("the requester was not warned about the launches at risk: %v", forRequester)
	}
	if strings.Contains(forRequester, "SR-FAR") {
		t.Error("a review with a month to go was reported as urgent")
	}
	if strings.Contains(forRequester, "SR-DONE") {
		t.Error("a finished review was chased about its open date")
	}
	if !strings.Contains(forRequester, "지났습니다") {
		t.Errorf("a date already passed is not described as passed: %v", forRequester)
	}
	if !strings.Contains(forRequester, "검토 중") {
		t.Errorf("the message does not say what state the review is in: %v", forRequester)
	}
	// Whoever holds the review hears about it too, and neither side is told twice.
	if got := notices(reviewer); len(got) != 2 {
		t.Errorf("the reviewer received %d warnings, want one per review at risk", len(got))
	}
	worker.Sweep(ctx)
	if got := notices(requester); len(got) != 2 {
		t.Errorf("a second sweep raised the requester's count to %d", len(got))
	}
}

// An account keeps working when the role is taken away, so "still active" is
// not the same as "can still act". A stalled-review reminder addressed to a
// reviewer who no longer holds the role chases somebody the service refuses,
// and the review never reaches the reviewers who could take it.
func TestStalledRemindersSkipAnAssigneeWhoLostTheRole(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	requester := testdb.Bootstrap(t, db, "role-requester")
	worker := maintenance.New(db, nil)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	leaver, successor := store.NewID(), store.NewID()
	for _, person := range []struct{ id, name string }{{leaver, "role-leaver"}, {successor, "role-successor"}} {
		exec(`INSERT INTO users(id,username,display_name,auth_source,active) VALUES($1,$2,$2,'local',true)`, person.id, person.name)
		exec(`INSERT INTO user_roles(user_id,role_code) VALUES($1,'SECURITY_REVIEWER')`, person.id)
	}
	reviewID := store.NewID()
	exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status,reviewer_id,updated_at)
              VALUES($1,'SR-ROLE','s','d','WEB','NEW',$2,$2,'보안팀',$2,'INTERNAL','SUBMITTED',$3,now()-make_interval(days=>7))`, reviewID, requester, leaver)
	exec(`DELETE FROM user_roles WHERE user_id=$1 AND role_code='SECURITY_REVIEWER'`, leaver)

	worker.Sweep(ctx)
	count := func(recipient string) int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND event_type='REVIEW_STALLED'`, recipient).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(leaver); got != 0 {
		t.Errorf("%d reminders were sent to a reviewer who can no longer act on the review", got)
	}
	if got := count(successor); got != 1 {
		t.Errorf("the reviewers who could take it over received %d reminders, want 1", got)
	}
	var body string
	if err := db.Pool.QueryRow(ctx, `SELECT body FROM notifications WHERE recipient_id=$1 AND event_type='REVIEW_STALLED'`, successor).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "SR-ROLE") {
		t.Errorf("the reminder does not name the stuck review: %q", body)
	}
}

// An API key's expiry was written down when it was issued and never mentioned
// again -- not on the screen, not in a message. Whatever ran on the key just
// started failing with 401 one morning.
func TestAnExpiringAPIKeyWarnsItsOwner(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	owner := testdb.Bootstrap(t, db, "key-owner")
	worker := maintenance.New(db, nil)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	key := func(name string, expiresInDays int, revoked bool) {
		t.Helper()
		var expiry any
		if expiresInDays != 0 {
			expiry = time.Now().Add(time.Duration(expiresInDays) * 24 * time.Hour)
		}
		exec(`INSERT INTO api_keys(id,user_id,name,prefix,secret_hash,scopes,expires_at,revoked_at)
                      VALUES($1,$2,$3,'sk_test',$4,ARRAY['read']::text[],$5,CASE WHEN $6 THEN now() ELSE NULL END)`,
			store.NewID(), owner, name, []byte(name), expiry, revoked)
	}
	key("만료임박", 3, false)
	key("여유", 90, false)
	key("무기한", 0, false)
	key("폐기됨", 2, true)

	worker.Sweep(ctx)
	notices := func() []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `SELECT body FROM notifications WHERE recipient_id=$1 AND event_type='API_KEY_EXPIRING'`, owner)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var body string
			if rows.Scan(&body) == nil {
				out = append(out, body)
			}
		}
		return out
	}
	got := notices()
	if len(got) != 1 {
		t.Fatalf("the owner was warned about %d keys, want only the one expiring this week: %v", len(got), got)
	}
	if !strings.Contains(got[0], "만료임박") || !strings.Contains(got[0], "3일 뒤") {
		t.Errorf("the warning does not say which key or when: %q", got[0])
	}
	// A key nobody rotated must not be reported every hour.
	worker.Sweep(ctx)
	if again := notices(); len(again) != 1 {
		t.Errorf("a second sweep raised the count to %d", len(again))
	}
}

// A restart in the middle of a job leaves the row RUNNING with a lock a few
// seconds old. Both workers clear stale locks when they start, but only locks
// older than the same window, so this one survives the restart that caused it
// and nothing looks at it again: an evidence scan stuck this way blocks the
// review's submission for ever, raises no alarm and cannot be retried.
func TestJobsLeftRunningByAStoppedWorkerAreRequeued(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	worker := maintenance.New(db, nil)
	abandoned, running := store.NewID(), store.NewID()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,status,locked_at) VALUES
                ($1,'SCAN_EVIDENCE','RUNNING',now()-interval '30 minutes'),
                ($2,'SCAN_EVIDENCE','RUNNING',now()-interval '1 minute')`, abandoned, running); err != nil {
		t.Fatal(err)
	}
	worker.Sweep(ctx)
	status := func(id string) string {
		t.Helper()
		var s string
		if err := db.Pool.QueryRow(ctx, `SELECT status FROM jobs WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if got := status(abandoned); got != "PENDING" {
		t.Errorf("a job whose worker stopped half an hour ago is %s, want PENDING", got)
	}
	// Work a live worker is holding must not be taken away from it.
	if got := status(running); got != "RUNNING" {
		t.Errorf("a job claimed a minute ago was requeued (%s) under a working worker", got)
	}
}

// The evidence volume is what the service exists to keep, and nothing ever read
// it back: a file lost to a bad disk or a restore that missed the volume was
// found when somebody tried to download it, which for evidence is during an
// audit.
func TestStoredEvidenceIsReadBackAndFailuresAreReported(t *testing.T) {
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
	owner := testdb.Bootstrap(t, db, "integrity-owner")
	if err = blobs.EnsureUserKey(ctx, owner); err != nil {
		t.Fatal(err)
	}
	userKey, keyVersion, err := blobs.ActiveUserKey(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	evidenceID, stored := store.NewID(), store.NewID()+".enc"
	size, digest, err := blobs.Write(stored, userKey, vault.AAD(evidenceID, 1), strings.NewReader("증적 본문입니다"))
	if err != nil {
		t.Fatal(err)
	}
	itemID := seedEvidenceRow(t, db, store.NewID(), owner, store.NewID()+".enc", keyVersion, 200)
	if _, err = db.Pool.Exec(ctx, `INSERT INTO evidences(id,submission_item_id,original_filename,stored_filename,mime_type,size_bytes,sha256,uploaded_by,key_owner_id,key_version,scan_status)
              VALUES($1,$2,'증적.txt',$3,'text/plain',$4,$5,$6,$6,$7,'CLEAN')`, evidenceID, itemID, stored, size, digest, owner, keyVersion); err != nil {
		t.Fatal(err)
	}
	worker := maintenance.New(db, blobs)

	// A healthy volume produces no noise, and the row records that it was read.
	worker.Sweep(ctx)
	alerts := func() int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_type='EVIDENCE_UNREADABLE'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := alerts(); got != 0 {
		t.Fatalf("a healthy volume raised %d alerts", got)
	}
	var verified bool
	if err = db.Pool.QueryRow(ctx, `SELECT verified_at IS NOT NULL FROM evidences WHERE id=$1`, evidenceID).Scan(&verified); err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Error("the sweep did not record that the file was read back")
	}

	// Now the volume loses the file, which is what a failed restore looks like.
	if err = os.Remove(blobs.Path(stored)); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE evidences SET verified_at=NULL WHERE id=$1`, evidenceID); err != nil {
		t.Fatal(err)
	}
	worker.Sweep(ctx)
	if got := alerts(); got == 0 {
		t.Fatal("a missing evidence file was not reported to anybody")
	}
	var body string
	if err = db.Pool.QueryRow(ctx, `SELECT body FROM notifications WHERE event_type='EVIDENCE_UNREADABLE' LIMIT 1`).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "증적.txt") {
		t.Errorf("the alert does not name the file: %q", body)
	}
	// A notification is read once and swept away by retention; the state has to
	// stay on the row so a screen can still say the volume is missing a file.
	var reason string
	if err = db.Pool.QueryRow(ctx, `SELECT verify_error FROM evidences WHERE id=$1`, evidenceID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason == "" {
		t.Error("the failure was announced but not recorded on the evidence")
	}

	// Putting the file back clears it on the next round: a report that never
	// goes green is one nobody trusts.
	if _, _, err = blobs.Write(stored, userKey, vault.AAD(evidenceID, 1), strings.NewReader("증적 본문입니다")); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Pool.Exec(ctx, `UPDATE evidences SET verified_at=NULL WHERE id=$1`, evidenceID); err != nil {
		t.Fatal(err)
	}
	worker.Sweep(ctx)
	if err = db.Pool.QueryRow(ctx, `SELECT verify_error FROM evidences WHERE id=$1`, evidenceID).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason != "" {
		t.Errorf("a restored file is still marked broken: %q", reason)
	}
}

// The audit log is tamper-evident only if somebody checks. Until now that
// somebody was an administrator remembering to press a button, so a row edited
// in the database could sit undetected for as long as nobody looked.
func TestTheSweepProvesTheAuditChainAndReportsABreak(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	adminID := testdb.Bootstrap(t, db, "chain-watcher")
	if _, err := db.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,'SYSTEM_ADMIN') ON CONFLICT DO NOTHING`, adminID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := db.Audit(ctx, store.AuditEvent{UserID: adminID, EventType: "TEST", TargetType: "USER", TargetID: adminID}); err != nil {
			t.Fatal(err)
		}
	}

	checkpoint := func() (int64, string) {
		t.Helper()
		sequence, hash, err := db.AuditCheckpoint(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return sequence, hash
	}
	alerts := func() int {
		t.Helper()
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_type='AUDIT_CHAIN_BROKEN'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// An intact chain is proved and the anchor moves forward, so the next
	// sweep only reads what was appended since.
	maintenance.New(db, nil).Sweep(ctx)
	proved, hash := checkpoint()
	if proved == 0 || hash == "" {
		t.Fatalf("after a sweep the chain is proved only to %d (%q)", proved, hash)
	}
	if got := alerts(); got != 0 {
		t.Fatalf("an intact chain raised %d alerts", got)
	}

	// Somebody edits an event in the database. The stored hash no longer
	// describes the row, and the sweep says so.
	if _, err := db.Pool.Exec(ctx, `UPDATE audit_logs SET canonical_payload=canonical_payload||'tampered' WHERE chain_sequence=$1`, proved); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE audit_chain_state SET verified_sequence=$1,verified_hash=$2 WHERE id=1`, proved-1, ""); err != nil {
		t.Fatal(err)
	}
	// With no anchor the check starts from the beginning, which is what an
	// installation that has never verified also does.
	maintenance.New(db, nil).Sweep(ctx)
	if got := alerts(); got == 0 {
		t.Fatal("a tampered event raised no alert")
	}
	after, _ := checkpoint()
	if after != 0 {
		t.Fatalf("the anchor moved to %d past a break, declaring the tampered stretch proved", after)
	}
	var broken int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM application_logs WHERE level='ERROR' AND message='audit chain verification failed'`).Scan(&broken); err != nil {
		t.Fatal(err)
	}
	if broken == 0 {
		t.Fatal("the break was not recorded in the server log")
	}
}

// Housekeeping runs in a goroutine with nothing watching it: reminders,
// evidence sampling, the audit-chain check and retention purges all stop
// together if it dies, and every screen goes on looking normal.
func TestASweepRecordsThatItRan(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	testdb.Bootstrap(t, db, "upkeep-watcher")

	var before *time.Time
	if err := db.Pool.QueryRow(ctx, `SELECT last_run_at FROM maintenance_state WHERE id=1`).Scan(&before); err != nil {
		t.Fatalf("the housekeeping state row is missing: %v", err)
	}
	if before != nil {
		t.Fatalf("a fresh installation already claims a sweep at %v", before)
	}

	maintenance.New(db, nil).Sweep(ctx)

	var after *time.Time
	var summary []byte
	if err := db.Pool.QueryRow(ctx, `SELECT last_run_at,last_summary FROM maintenance_state WHERE id=1`).Scan(&after, &summary); err != nil {
		t.Fatal(err)
	}
	if after == nil {
		t.Fatal("a completed sweep left no record of itself")
	}
	if time.Since(*after) > time.Minute {
		t.Fatalf("the recorded sweep is %v old", time.Since(*after))
	}
	// The summary is what the run actually did, so an operator reading a stale
	// timestamp can also see what the last healthy run looked like.
	if !strings.Contains(string(summary), "audit_chain_checked") {
		t.Fatalf("the recorded summary does not describe the run: %s", summary)
	}

	// A later sweep keeps the record fresh. The promise this backs is "a
	// timestamp that stops moving means housekeeping stopped", so what matters
	// is that a completed run leaves a recent time -- not that two runs a
	// second apart are strictly ordered, which is a property of the clock
	// rather than of the service.
	time.Sleep(1100 * time.Millisecond)
	maintenance.New(db, nil).Sweep(ctx)
	if err := db.Pool.QueryRow(ctx, `SELECT last_run_at FROM maintenance_state WHERE id=1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after == nil || time.Since(*after) > time.Minute {
		t.Fatalf("after a second sweep the record reads %v", after)
	}
}

// A cancelled review is a service that is not being built. The corrections and
// follow-up actions written on it were never withdrawn, so the sweep went on
// chasing them: every three days a 기한 초과 notice about a review the
// recipient had cancelled themselves and cannot reopen.
func TestCancelledReviewsStopChasingPeople(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	requester := testdb.Bootstrap(t, db, "cancel-owner")
	worker := maintenance.New(db, nil)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	templateID, versionID := store.NewID(), store.NewID()
	exec(`INSERT INTO checklist_templates(id,name,category,created_by) VALUES($1,'취소 템플릿','DEVELOPMENT',$2)`, templateID, requester)
	exec(`INSERT INTO checklist_versions(id,template_id,version,status,created_by) VALUES($1,$2,'V1','PUBLISHED',$3)`, versionID, templateID, requester)

	// Each review carries one overdue correction and one overdue follow-up;
	// the only difference between them is the status of the review itself.
	seed := func(number, status string) (reviewID, changeID, resultID string) {
		t.Helper()
		reviewID, changeID, resultID = store.NewID(), store.NewID(), store.NewID()
		submissionID, sourceID, itemID := store.NewID(), store.NewID(), store.NewID()
		exec(`INSERT INTO review_requests(id,review_number,service_name,description,service_type,change_type,builder_id,developer_id,department,requester_id,exposure,status)
                        VALUES($1,$2,'취소 서비스','설명','WEB','NEW',$3,$3,'보안팀',$3,'INTERNAL',$4)`, reviewID, number, requester, status)
		exec(`INSERT INTO submissions(id,review_request_id,revision,status) VALUES($1,$2,1,'DRAFT')`, submissionID, reviewID)
		exec(`INSERT INTO checklist_items(id,version_id,item_code,category,title,question,severity,required,answer_type,evidence_required,sort_order)
                        VALUES($1,$2,$3,'DEVELOPMENT','보안요건','질문','MEDIUM',true,'YNNA',false,1)`, sourceID, versionID, "C-"+sourceID[:6])
		exec(`INSERT INTO submission_items(id,submission_id,source_item_id,template_name,template_version,item_code,section,category,title,question,severity,required,answer_type,evidence_required,sort_order)
                        VALUES($1,$2,$3,'개발보안','V1',$4,'구분','DEVELOPMENT','보안요건','질문','MEDIUM',true,'YNNA',false,1)`, itemID, submissionID, sourceID, "C-"+sourceID[:6])
		exec(`INSERT INTO change_requests(id,review_request_id,submission_item_id,reason,requester_id,due_date,status)
                        VALUES($1,$2,$3,'보완하세요',$4,$5::date,'OPEN')`, changeID, reviewID, itemID, requester, time.Now().AddDate(0, 0, -3).Format("2006-01-02"))
		exec(`INSERT INTO review_results(id,submission_item_id,reviewer_id,result,follow_up,follow_up_due_date)
                        VALUES($1,$2,$3,'CONDITIONAL','조치하세요',$4::date)`, resultID, itemID, requester, time.Now().AddDate(0, 0, -3).Format("2006-01-02"))
		return reviewID, changeID, resultID
	}
	_, liveChange, liveResult := seed("SC-2026-000910", "CHANGE_REQUESTED")
	_, deadChange, deadResult := seed("SC-2026-000911", "CANCELLED")

	worker.Sweep(ctx)

	remindedChange := func(id string) bool {
		t.Helper()
		var at *time.Time
		if err := db.Pool.QueryRow(ctx, `SELECT reminded_at FROM change_requests WHERE id=$1`, id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at != nil
	}
	remindedResult := func(id string) bool {
		t.Helper()
		var at *time.Time
		if err := db.Pool.QueryRow(ctx, `SELECT follow_up_reminded_at FROM review_results WHERE id=$1`, id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at != nil
	}
	if !remindedChange(liveChange) {
		t.Error("the correction on the live review was not reminded")
	}
	if !remindedResult(liveResult) {
		t.Error("the follow-up on the live review was not reminded")
	}
	if remindedChange(deadChange) {
		t.Error("a correction on a cancelled review was chased")
	}
	if remindedResult(deadResult) {
		t.Error("a follow-up on a cancelled review was chased")
	}
	for _, event := range []string{"CHANGE_REQUEST_DUE", "FOLLOW_UP_DUE"} {
		var notices int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE event_type=$1`, event).Scan(&notices); err != nil {
			t.Fatal(err)
		}
		if notices != 1 {
			t.Errorf("%s notices = %d, want 1 (the live review only)", event, notices)
		}
	}
}

// Every path that writes a blob deletes it again if the database write fails,
// but a machine that stops between the two leaves a file no row points at. It
// is never read, never purged -- the purge works from the rows -- and never
// counted, so the storage alert says the disk is filling up and nothing
// accounts for it.
func TestTheSweepReportsFilesNoReviewCanReach(t *testing.T) {
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
	owner := testdb.Bootstrap(t, db, "orphan-owner")
	if err = blobs.EnsureUserKey(ctx, owner); err != nil {
		t.Fatal(err)
	}
	userKey, version, err := blobs.ActiveUserKey(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}

	// One file the database knows about, one it does not, and one written
	// moments ago -- which may be an upload still in flight.
	known := store.NewID() + ".enc"
	evidenceID := store.NewID()
	if _, _, err = blobs.Write(known, userKey, vault.AAD(evidenceID, 1), strings.NewReader("정상 증적")); err != nil {
		t.Fatal(err)
	}
	seedEvidenceRow(t, db, evidenceID, owner, known, version, 0)
	if _, err = db.Pool.Exec(ctx, `UPDATE evidences SET deleted_at=NULL WHERE id=$1`, evidenceID); err != nil {
		t.Fatal(err)
	}
	stray := store.NewID() + ".enc"
	if _, _, err = blobs.Write(stray, userKey, vault.AAD(store.NewID(), 1), strings.NewReader("아무도 모르는 파일")); err != nil {
		t.Fatal(err)
	}
	fresh := store.NewID() + ".enc"
	if _, _, err = blobs.Write(fresh, userKey, vault.AAD(store.NewID(), 1), strings.NewReader("방금 올라온 파일")); err != nil {
		t.Fatal(err)
	}
	yesterday := time.Now().Add(-48 * time.Hour)
	for _, name := range []string{known, stray} {
		if err = os.Chtimes(blobs.Path(name), yesterday, yesterday); err != nil {
			t.Fatal(err)
		}
	}

	removed := maintenance.New(db, blobs).Sweep(ctx)
	if removed["orphan_evidence_files"] != 1 {
		t.Fatalf("the sweep reports %d files no row points at, want 1 (the stray one)", removed["orphan_evidence_files"])
	}
	// Reporting is the whole job: a sweep that deletes files it does not
	// recognise is a worse failure than the one it is fixing.
	for _, name := range []string{known, stray, fresh} {
		if _, err = os.Stat(blobs.Path(name)); err != nil {
			t.Errorf("the sweep removed %s: %v", name, err)
		}
	}
}
