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
