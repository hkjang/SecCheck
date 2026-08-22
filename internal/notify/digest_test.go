package notify

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

func digestWorker(t *testing.T) (*Worker, *store.Store, string) {
	t.Helper()
	db := testdb.New(t)
	ctx := context.Background()
	userID := testdb.Bootstrap(t, db, "digest-reader")
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET email='reader@example.internal' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO notification_preferences(user_id,email_enabled,digest) VALUES($1,true,'DAILY')
                ON CONFLICT(user_id) DO UPDATE SET email_enabled=true,digest='DAILY',digest_sent_at=NULL`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"email_enabled":true,"smtp_host":"smtp.internal","smtp_port":25,"smtp_from":"seccheck@example.internal","digest_hour":0}'::jsonb WHERE key='notification'`); err != nil {
		t.Fatal(err)
	}
	return &Worker{Store: db}, db, userID
}

func addNotification(t *testing.T, db *store.Store, userID, title string) string {
	t.Helper()
	id := store.NewID()
	if _, err := db.Pool.Exec(context.Background(), `INSERT INTO notifications(id,recipient_id,event_type,title,body) VALUES($1,$2,'COMMENT_ADDED',$3,'본문')`, id, userID, title); err != nil {
		t.Fatal(err)
	}
	return id
}

// The digest used to mark every unsent notification as sent once it had
// delivered, so anything created while it was being delivered was stamped as
// emailed without ever appearing in one -- lost, with no error anywhere.
func TestADigestOnlyMarksWhatItActuallySent(t *testing.T) {
	worker, db, userID := digestWorker(t)
	ctx := context.Background()
	first := addNotification(t, db, userID, "첫 번째 알림")

	var arrivedLate string
	var delivered string
	worker.Sender = func(_ context.Context, _ emailSettings, _, subject, body string) error {
		delivered = subject + "\n" + body
		// Somebody is notified while the mail is on its way out.
		arrivedLate = addNotification(t, db, userID, "발송 중 도착한 알림")
		return nil
	}
	worker.sendDigests(ctx)

	if !strings.Contains(delivered, "첫 번째 알림") {
		t.Fatalf("the digest did not carry the notification that existed: %s", delivered)
	}
	if strings.Contains(delivered, "발송 중 도착한 알림") {
		t.Fatal("the digest carried a notification created after it was built")
	}
	marked := func(id string) bool {
		var at *string
		if err := db.Pool.QueryRow(ctx, `SELECT emailed_at::text FROM notifications WHERE id=$1`, id).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at != nil
	}
	if !marked(first) {
		t.Error("the notification that was sent is not marked as sent")
	}
	if marked(arrivedLate) {
		t.Error("a notification that was never sent was marked as sent")
	}
}

// A digest that could not be delivered must leave everything unsent, so the
// next run tries again.
func TestAFailedDigestMarksNothing(t *testing.T) {
	worker, db, userID := digestWorker(t)
	ctx := context.Background()
	id := addNotification(t, db, userID, "배달 실패 알림")
	worker.Sender = func(context.Context, emailSettings, string, string, string) error {
		return fmt.Errorf("smtp unavailable")
	}
	worker.sendDigests(ctx)
	var at *string
	if err := db.Pool.QueryRow(ctx, `SELECT emailed_at::text FROM notifications WHERE id=$1`, id).Scan(&at); err != nil {
		t.Fatal(err)
	}
	if at != nil {
		t.Error("an undelivered digest marked its notifications as sent")
	}
}

// The daily digest is due once per calendar day where the reader lives. The
// eligibility check measured the day in the container's UTC clock, so a reader
// in a zone ahead of UTC who had already been sent the 08:00 digest became
// eligible again the moment UTC rolled over -- 09:00 for them, same day, same
// summary.
func TestADigestIsDueOncePerLocalDay(t *testing.T) {
	worker, db, userID := digestWorker(t)
	ctx := context.Background()
	addNotification(t, db, userID, "알림")
	if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"timezone":"Asia/Seoul"}'::jsonb WHERE key='general'`); err != nil {
		t.Fatal(err)
	}

	seoul, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		t.Skipf("no timezone database on this host: %v", err)
	}
	// 08:10 and 09:30 on the same Seoul day, with UTC midnight in between.
	sent := time.Date(2026, 8, 22, 8, 10, 0, 0, seoul)
	later := time.Date(2026, 8, 22, 9, 30, 0, 0, seoul)
	if _, err := db.Pool.Exec(ctx, `UPDATE notification_preferences SET digest_sent_at=$2 WHERE user_id=$1`, userID, sent); err != nil {
		t.Fatal(err)
	}
	due, err := worker.digestRecipients(ctx, "Asia/Seoul", later)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 0 {
		t.Errorf("a second digest was due %v after the first, on the same local day", later.Sub(sent))
	}

	nextMorning := time.Date(2026, 8, 23, 8, 0, 0, 0, seoul)
	if due, err = worker.digestRecipients(ctx, "Asia/Seoul", nextMorning); err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 {
		t.Errorf("the next day's digest was not due: %d recipients", len(due))
	}
}
