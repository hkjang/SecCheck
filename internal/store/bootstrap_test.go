package store_test

import (
	"context"
	"sort"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

// The administration guide asks operators to move the reviewer and approver
// roles off the shared bootstrap account, so that account cannot review what it
// requested. Every restart put them straight back, silently.
func TestRestartingKeepsTheAdminRolesTheOperatorChose(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	roles := func(username string) []string {
		t.Helper()
		rows, err := db.Pool.Query(ctx, `SELECT role_code FROM user_roles ur JOIN users u ON u.id=ur.user_id WHERE u.username=$1`, username)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var code string
			if rows.Scan(&code) == nil {
				out = append(out, code)
			}
		}
		sort.Strings(out)
		return out
	}

	// A first run has to leave an appliance somebody can actually use.
	if err := db.UpsertBootstrap(ctx, store.NewID(), "restart-admin", "hash"); err != nil {
		t.Fatal(err)
	}
	if got := roles("restart-admin"); len(got) != 6 {
		t.Fatalf("a new bootstrap account holds %v, want every role", got)
	}

	// The operator separates the duties the guide tells them to separate.
	for _, code := range []string{"SECURITY_REVIEWER", "APPROVER"} {
		if _, err := db.Pool.Exec(ctx, `DELETE FROM user_roles ur USING users u WHERE u.id=ur.user_id AND u.username=$1 AND ur.role_code=$2`, "restart-admin", code); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpsertBootstrap(ctx, store.NewID(), "restart-admin", "hash"); err != nil {
		t.Fatal(err)
	}
	for _, code := range roles("restart-admin") {
		if code == "SECURITY_REVIEWER" || code == "APPROVER" {
			t.Errorf("restarting restored %s, which the operator had removed", code)
		}
	}

	// Administering the installation is the one thing a restart guarantees:
	// removing it would lock everybody out of the only recovery account.
	if _, err := db.Pool.Exec(ctx, `DELETE FROM user_roles ur USING users u WHERE u.id=ur.user_id AND u.username=$1 AND ur.role_code='SYSTEM_ADMIN'`, "restart-admin"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertBootstrap(ctx, store.NewID(), "restart-admin", "hash"); err != nil {
		t.Fatal(err)
	}
	var admin bool
	if err := db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles ur JOIN users u ON u.id=ur.user_id WHERE u.username=$1 AND ur.role_code='SYSTEM_ADMIN')`, "restart-admin").Scan(&admin); err != nil {
		t.Fatal(err)
	}
	if !admin {
		t.Error("a restart did not restore the bootstrap account's system administrator role")
	}
}
