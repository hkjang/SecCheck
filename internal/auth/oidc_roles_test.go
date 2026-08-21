package auth

import (
	"context"
	"reflect"
	"slices"
	"sort"
	"testing"

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
	if err := svc.syncOIDCRoles(ctx, userID, []string{"SECURITY_REVIEWER"}); err != nil {
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
