package main

import (
	"context"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
	"golang.org/x/crypto/bcrypt"
)

// The last administrator of an offline installation locking themselves out
// used to mean editing the database by hand, bcrypt included.
func TestAdminRecoveryRestoresTheOnlyAdministrator(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	admin := testdb.Bootstrap(t, db, "locked-out-admin")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`UPDATE users SET active=false,failed_login_count=9,locked_until=now()+interval '1 hour',totp_enabled=true,totp_secret='ABC' WHERE id=$1`, admin)
	exec(`DELETE FROM user_roles WHERE user_id=$1 AND role_code='SYSTEM_ADMIN'`, admin)
	exec(`INSERT INTO sessions(id,user_id,token_hash,csrf_token,expires_at) VALUES($1,$2,'\x01'::bytea,'c',now()+interval '1 day')`, store.NewID(), admin)

	changes, err := recoverAdmin(ctx, db, "locked-out-admin", "새로운비밀번호12345", true, true, true)
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if len(changes) != 4 {
		t.Errorf("recovery reported %v", changes)
	}

	var hash string
	var active, totp bool
	var failed int
	var lockedUntil *string
	if err := db.Pool.QueryRow(ctx, `SELECT password_hash,active,totp_enabled,failed_login_count,locked_until::text FROM users WHERE id=$1`, admin).Scan(&hash, &active, &totp, &failed, &lockedUntil); err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte("새로운비밀번호12345")) != nil {
		t.Error("the new password does not work")
	}
	if !active || totp || failed != 0 || lockedUntil != nil {
		t.Errorf("the account is still shut out: active=%v totp=%v failed=%d locked=%v", active, totp, failed, lockedUntil)
	}
	var isAdmin bool
	if err := db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1 AND role_code='SYSTEM_ADMIN')`, admin).Scan(&isAdmin); err != nil {
		t.Fatal(err)
	}
	if !isAdmin {
		t.Error("the account did not get its administrator role back")
	}
	var sessions int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1`, admin).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Errorf("%d sessions from before the recovery are still valid", sessions)
	}
	// Restoring a privileged account out of band has to be visible afterwards.
	var recorded int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='RECOVER_ADMIN' AND target_id=$1`, admin).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != 1 {
		t.Errorf("the recovery was recorded %d times in the audit chain", recorded)
	}
}

func TestAdminRecoveryRefusesWhatItShould(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	admin := testdb.Bootstrap(t, db, "oidc-admin")
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET auth_source='oidc' WHERE id=$1`, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverAdmin(ctx, db, "oidc-admin", "새로운비밀번호12345", false, false, false); err == nil {
		t.Error("an IdP account's password was set by the recovery tool")
	}
	if _, err := recoverAdmin(ctx, db, "nobody-here", "새로운비밀번호12345", false, false, false); err == nil {
		t.Error("the tool invented an account that does not exist")
	}
	if code := runAdminRecover([]string{"--username", "oidc-admin"}); code != 2 {
		t.Errorf("a call with nothing to do returned %d, want 2", code)
	}
	if code := runAdminRecover([]string{"--username", "oidc-admin", "--password", "짧다"}); code != 2 {
		t.Errorf("a short password returned %d, want 2", code)
	}
}
