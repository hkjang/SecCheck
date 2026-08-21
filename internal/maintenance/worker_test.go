package maintenance_test

import (
	"context"
	"testing"

	"github.com/hkjang/SecCheck/internal/maintenance"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
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

	maintenance.New(db).Sweep(ctx)

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
	removed := maintenance.New(db).Sweep(context.Background())
	for name, n := range removed {
		if n != 0 {
			t.Errorf("%s removed %d rows from an empty database", name, n)
		}
	}
}
