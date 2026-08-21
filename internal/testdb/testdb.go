// Package testdb gives tests a real PostgreSQL schema so that migrations,
// object-level authorization, workflow transitions and submission validation
// are exercised against the database they actually run on. Without
// TEST_POSTGRES_DSN the helpers skip, so `go test ./...` still works on a
// machine with no database.
package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
)

const DSNEnv = "TEST_POSTGRES_DSN"

var counter atomic.Int64

// DSN returns the configured test database, or "" when the suite should skip.
func DSN() string { return strings.TrimSpace(os.Getenv(DSNEnv)) }

// New creates an isolated schema, applies every migration to it and returns a
// Store bound to that schema. The schema is dropped when the test finishes, so
// parallel packages never see each other's rows.
func New(t *testing.T) *store.Store {
	t.Helper()
	dsn := DSN()
	if dsn == "" {
		t.Skipf("%s is not set; skipping the database-backed test", DSNEnv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	admin, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", DSNEnv, err)
	}
	schema := fmt.Sprintf("t%d_%d", time.Now().UnixNano()%1e9, counter.Add(1))
	if _, err = admin.Pool.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		admin.Close()
		t.Fatalf("create schema %s: %v", schema, err)
	}

	scoped, err := store.Open(ctx, withSearchPath(dsn, schema))
	if err != nil {
		_, _ = admin.Pool.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
		t.Fatalf("connect to schema %s: %v", schema, err)
	}
	if err = scoped.Migrate(ctx); err != nil {
		scoped.Close()
		_, _ = admin.Pool.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
		t.Fatalf("migrate schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		scoped.Close()
		dropCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if _, err := admin.Pool.Exec(dropCtx, `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Logf("drop schema %s: %v", schema, err)
		}
		admin.Close()
	})
	return scoped
}

// Bootstrap creates the initial administrator the way main does, and returns
// the user id.
func Bootstrap(t *testing.T, s *store.Store, username string) string {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertBootstrap(ctx, store.NewID(), username, "$2a$04$C4a8yXqTRIYQGvPMqmzZ2eOWiHZs4v4CjJZaFn8DR5JzS0/oCJhwq"); err != nil {
		t.Fatalf("bootstrap %s: %v", username, err)
	}
	u, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("load %s: %v", username, err)
	}
	return u.ID
}

func withSearchPath(dsn, schema string) string {
	parsed, err := url.Parse(dsn)
	if err != nil {
		separator := "?"
		if strings.Contains(dsn, "?") {
			separator = "&"
		}
		return dsn + separator + "search_path=" + schema
	}
	q := parsed.Query()
	q.Set("search_path", schema)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}
