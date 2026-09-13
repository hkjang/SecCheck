package store_test

import (
	"context"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

// Nobody wants a message about what they just did. A notification an
// action raises for the very person acting stays on the bell and never
// reaches the mail queue or the daily digest -- except when it is about the
// service itself, which the administrator who found it still wants to read.
func TestYourOwnDoingIsNotMailedToYou(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	me := testdb.Bootstrap(t, db, "self-notifier")
	if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"enabled":true,"smtp_host":"relay","from_address":"seccheck@example.internal"}'::jsonb WHERE key='mail'`); err != nil {
		t.Fatal(err)
	}
	queued := func() int {
		var n int
		if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE type='SEND_EMAIL'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := db.Notify(store.WithActor(ctx, me), me, "REVIEW_ASSIGNED", "내가 나에게", "본문", "", ""); err != nil {
		t.Fatal(err)
	}
	if queued() != 0 {
		t.Error("a notification the recipient caused themselves was queued for mail")
	}
	var pending int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM notifications WHERE recipient_id=$1 AND emailed_at IS NULL`, me).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Error("the self-raised notice is left for the digest to send")
	}
	if err := db.Notify(store.WithActor(ctx, "somebody-else"), me, "REVIEW_ASSIGNED", "남이 나에게", "본문", "", ""); err != nil {
		t.Fatal(err)
	}
	if queued() != 1 {
		t.Error("a notification somebody else caused was not queued")
	}
	if err := db.Notify(ctx, me, "REVIEW_ASSIGNED", "워커가 나에게", "본문", "", ""); err != nil {
		t.Fatal(err)
	}
	if queued() != 2 {
		t.Error("a background worker's notification was not queued")
	}
	if err := db.Notify(store.WithActor(ctx, me), me, "AUDIT_CHAIN_BROKEN", "내가 찾은 장애", "본문", "", ""); err != nil {
		t.Fatal(err)
	}
	if queued() != 3 {
		t.Error("an alert about the service was withheld from the administrator who raised it")
	}
	// The administrator's switch for the group stops that group and only it.
	if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"notify_turn":false}'::jsonb WHERE key='mail'`); err != nil {
		t.Fatal(err)
	}
	if err := db.Notify(ctx, me, "REVIEW_ASSIGNED", "꺼진 종류", "본문", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.Notify(ctx, me, "STORAGE_LOW", "켜진 종류", "본문", "", ""); err != nil {
		t.Fatal(err)
	}
	if queued() != 4 {
		t.Errorf("%d mails are queued after one switched-off and one switched-on event, want 4", queued())
	}
	// A bell-only event is never mailed, whatever the switches say.
	if err := db.Notify(ctx, me, "COMMENT_ADDED", "종에만", "본문", "", ""); err != nil {
		t.Fatal(err)
	}
	if queued() != 4 {
		t.Error("a bell-only event was queued for mail")
	}
}
