package maintenance_test

import (
	"context"
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
	// Running again must be a no-op rather than re-counting the same rows.
	if again := maintenance.New(db, blobs).Sweep(ctx); again["purged_evidence_files"] != 0 {
		t.Errorf("a second sweep purged %v files again", again["purged_evidence_files"])
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
