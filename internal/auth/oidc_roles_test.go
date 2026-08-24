package auth

import (
	"context"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

func mappingConfig() OIDCSettings {
	cfg := OIDCSettings{DefaultRole: "REQUESTER", GroupsClaim: "groups"}
	cfg.RoleMappings = []struct {
		Group string `json:"group"`
		Role  string `json:"role"`
	}{
		{Group: "/security-reviewers", Role: "SECURITY_REVIEWER"},
		{Group: "approvers", Role: "APPROVER"},
		{Group: "/security-reviewers", Role: "AUDITOR"},
	}
	return cfg
}

func TestGroupsMapToRoles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{"keycloak writes a leading slash", map[string]any{"groups": []any{"/security-reviewers"}}, []string{"SECURITY_REVIEWER", "AUDITOR"}},
		{"the slash is optional", map[string]any{"groups": []any{"security-reviewers"}}, []string{"SECURITY_REVIEWER", "AUDITOR"}},
		{"case is ignored", map[string]any{"groups": []any{"/Security-Reviewers"}}, []string{"SECURITY_REVIEWER", "AUDITOR"}},
		{"a single string claim counts", map[string]any{"groups": "approvers"}, []string{"APPROVER"}},
		{"several groups combine", map[string]any{"groups": []any{"approvers", "/security-reviewers"}}, []string{"SECURITY_REVIEWER", "APPROVER", "AUDITOR"}},
		{"an unmapped group falls back to the default", map[string]any{"groups": []any{"/interns"}}, []string{"REQUESTER"}},
		{"a missing claim falls back to the default", map[string]any{}, []string{"REQUESTER"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rolesFromGroups(mappingConfig(), tc.claims); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("rolesFromGroups = %v, want %v", got, tc.want)
			}
		})
	}
}

// Mapping the administrator role would let anyone who can edit a directory
// group take over the audit system, so it is not on the assignable list.
func TestSystemAdminIsNotAssignableFromAGroup(t *testing.T) {
	for _, role := range AssignableOIDCRoles() {
		if role == "SYSTEM_ADMIN" {
			t.Fatal("SYSTEM_ADMIN can be granted by a directory group")
		}
	}
	if len(AssignableOIDCRoles()) != 6 {
		t.Errorf("assignable roles = %v", AssignableOIDCRoles())
	}
}

// The point of syncing is that leaving a group takes the access away. Roles
// a mapping can never grant stay put, so a hand-made assignment survives.
func TestSyncRemovesRolesTheDirectoryNoLongerGrants(t *testing.T) {
	db := testdb.New(t)
	userID := testdb.Bootstrap(t, db, "oidc-member")
	ctx := context.Background()
	svc := &Service{Store: db}
	roles := func() []string {
		u, err := db.GetUser(ctx, userID)
		if err != nil {
			t.Fatal(err)
		}
		out := append([]string(nil), u.Roles...)
		sort.Strings(out)
		return out
	}
	for _, role := range []string{"SECURITY_REVIEWER", "APPROVER", "SYSTEM_ADMIN"} {
		if _, err := db.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,$2) ON CONFLICT DO NOTHING`, userID, role); err != nil {
			t.Fatal(err)
		}
	}
	before, err := db.GetUser(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.syncOIDCRoles(ctx, before, []string{"SECURITY_REVIEWER"}, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	got := roles()
	if slices.Contains(got, "APPROVER") {
		t.Errorf("APPROVER survived removal from its group: %v", got)
	}
	if !slices.Contains(got, "SECURITY_REVIEWER") {
		t.Errorf("SECURITY_REVIEWER was not kept: %v", got)
	}
	if !slices.Contains(got, "SYSTEM_ADMIN") {
		t.Errorf("a role no mapping can grant was stripped: %v", got)
	}
}

// A privilege that changes with nobody deciding it still has to be in the
// audit log, or the directory becomes a way to alter access without a trace.
func TestDirectoryRoleChangesAreAudited(t *testing.T) {
	db := testdb.New(t)
	userID := testdb.Bootstrap(t, db, "audited-member")
	ctx := context.Background()
	svc := &Service{Store: db}
	before, err := db.GetUser(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.syncOIDCRoles(ctx, before, []string{"AUDITOR"}, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	var events int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='SYNC_OIDC_ROLES' AND target_id=$1`, userID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("the role change left %d audit events, want 1", events)
	}
	// Signing in again with the same groups must not fill the log with noise.
	after, err := db.GetUser(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.syncOIDCRoles(ctx, after, []string{"AUDITOR"}, "10.0.0.9"); err != nil {
		t.Fatal(err)
	}
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='SYNC_OIDC_ROLES' AND target_id=$1`, userID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("an unchanged sign-in wrote another audit event: %d", events)
	}
}

// The service closes a privileged account on its own when the directory user
// has stayed away too long. Every other way an account loses access is written
// to the chain and visible to the other administrators; this one happened in
// silence, so the log read as if nobody had ever disabled it.
func TestAnAutomaticLockIsRecordedAndAnnounced(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	adminID := testdb.Bootstrap(t, db, "lock-admin")
	svc := &Service{Store: db}
	if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"inactive_admin_lock_days":30}'::jsonb WHERE key='security'`); err != nil {
		t.Fatal(err)
	}
	staleID := store.NewID()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO users(id,username,display_name,auth_source,active,last_login_at) VALUES($1,'lock-leaver','떠난 검토자','oidc',true,now()-interval '200 days')`, staleID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_code) VALUES($1,'SECURITY_REVIEWER')`, staleID); err != nil {
		t.Fatal(err)
	}
	stale, err := db.GetUser(ctx, staleID)
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.enforceInactiveAdminLock(ctx, stale); err == nil {
		t.Fatal("a privileged account away for 200 days was allowed to sign in")
	}
	var active bool
	if err = db.Pool.QueryRow(ctx, `SELECT active FROM users WHERE id=$1`, staleID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Error("the account was not locked")
	}
	var events int
	if err = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE event_type='LOCK_INACTIVE_ACCOUNT' AND target_id=$1`, staleID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("the automatic lock left %d audit events, want 1", events)
	}
	var body string
	if err = db.Pool.QueryRow(ctx, `SELECT body FROM notifications WHERE recipient_id=$1 AND event_type='ACCOUNT_LOCKED'`, adminID).Scan(&body); err != nil {
		t.Fatalf("no administrator was told about the lock: %v", err)
	}
	if !strings.Contains(body, "떠난 검토자") {
		t.Errorf("the notice does not name the account: %q", body)
	}
}
