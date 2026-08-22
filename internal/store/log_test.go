package store_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

// Structured logs live in the database. When the database is the thing that
// broke, the entry describing it cannot be written there -- and losing the
// record of the one failure that matters most is worse than losing any other.
func TestLoggingFallsBackToStandardErrorWhenTheDatabaseCannotTakeIt(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()

	var captured bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&captured, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	if _, err := db.Pool.Exec(ctx, `ALTER TABLE application_logs RENAME TO application_logs_gone`); err != nil {
		t.Fatal(err)
	}
	db.Log(ctx, "ERROR", "req-1", "api", "심의 목록을 불러오지 못했습니다.", map[string]any{"error": "relation does not exist"})
	if _, err := db.Pool.Exec(ctx, `ALTER TABLE application_logs_gone RENAME TO application_logs`); err != nil {
		t.Fatal(err)
	}

	out := captured.String()
	for _, want := range []string{"application log could not be stored", "심의 목록을 불러오지 못했습니다.", "req-1", "relation does not exist"} {
		if !strings.Contains(out, want) {
			t.Errorf("the fallback line does not carry %q:\n%s", want, out)
		}
	}
}

// The ordinary path still writes to the database and says nothing on stderr.
func TestLoggingStaysQuietWhenTheDatabaseAcceptsIt(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	var captured bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&captured, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	db.Log(ctx, "INFO", "req-2", "api", "정상 기록", nil)
	if captured.Len() != 0 {
		t.Errorf("a successful log wrote to stderr as well:\n%s", captured.String())
	}
	var stored int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM application_logs WHERE request_id='req-2'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Errorf("the entry was not stored: %d rows", stored)
	}
	_ = store.NewID()
}

// Callers cannot act on an audit failure -- the action is already done -- so
// the failure has to be impossible to overlook instead: counted, written to
// the application log, and left on standard error for the case where the
// database is what broke.
func TestLostAuditEventsAreCountedAndReported(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	var captured bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&captured, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	userID := testdb.Bootstrap(t, db, "audited")
	if err := db.Audit(ctx, store.AuditEvent{UserID: userID, UserName: "audited", EventType: "LOGIN", TargetType: "USER", TargetID: userID}); err != nil {
		t.Fatalf("a healthy audit write failed: %v", err)
	}
	if n := db.AuditFailures(); n != 0 {
		t.Fatalf("a successful write counted %d failures", n)
	}

	if _, err := db.Pool.Exec(ctx, `ALTER TABLE audit_logs RENAME TO audit_logs_gone`); err != nil {
		t.Fatal(err)
	}
	err := db.Audit(ctx, store.AuditEvent{UserID: userID, UserName: "audited", EventType: "DELETE_EVIDENCE", TargetType: "EVIDENCE", TargetID: "e1"})
	if _, renameErr := db.Pool.Exec(ctx, `ALTER TABLE audit_logs_gone RENAME TO audit_logs`); renameErr != nil {
		t.Fatal(renameErr)
	}
	if err == nil {
		t.Fatal("a write into a missing table reported success")
	}
	if n := db.AuditFailures(); n != 1 {
		t.Errorf("audit failures = %d, want 1", n)
	}
	if out := captured.String(); !strings.Contains(out, "audit event could not be recorded") || !strings.Contains(out, "DELETE_EVIDENCE") {
		t.Errorf("standard error does not name the lost event:\n%s", out)
	}
	var logged int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM application_logs WHERE component='audit' AND fields->>'event_type'='DELETE_EVIDENCE'`).Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if logged != 1 {
		t.Errorf("the application log has %d entries for the lost event, want 1", logged)
	}
}
