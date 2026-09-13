package notify

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/hkjang/SecCheck/internal/mail"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

// Every attempt is written down -- the ones that went out as well as the
// ones that did not -- so that "it never came" has an answer. The body is
// not part of it.
func TestEveryAttemptIsRecordedWithoutTheBody(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	userID := testdb.Bootstrap(t, db, "recorded-reader")
	worker := New(db, nil)
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET email='reader@example.internal' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"enabled":true,"smtp_host":"relay","from_address":"seccheck@example.internal"}'::jsonb WHERE key='mail'`); err != nil {
		t.Fatal(err)
	}
	queue := func(event, title string) job {
		t.Helper()
		notificationID := store.NewID()
		if _, err := db.Pool.Exec(ctx, `INSERT INTO notifications(id,recipient_id,event_type,title,body) VALUES($1,$2,$3,$4,'비밀스러운 본문')`, notificationID, userID, event, title); err != nil {
			t.Fatal(err)
		}
		payload, _ := json.Marshal(map[string]string{"notification_id": notificationID})
		jobID := store.NewID()
		if _, err := db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,payload,status) VALUES($1,'SEND_EMAIL',$2,'RUNNING')`, jobID, payload); err != nil {
			t.Fatal(err)
		}
		return job{ID: jobID, Payload: payload, Attempt: 1}
	}

	worker.Sender = func(_ context.Context, _ mail.Config, _ mail.Message) error { return nil }
	if err := worker.deliver(ctx, queue("REVIEW_ASSIGNED", "심의 배정")); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	worker.Sender = func(_ context.Context, _ mail.Config, _ mail.Message) error { return errors.New("relay refused") }
	if err := worker.deliver(ctx, queue("APPROVED", "심의 완료")); err == nil {
		t.Fatal("a refused delivery was reported as sent")
	}
	// A type the administrator switched off is not tried, and says so.
	if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"notify_decision":false}'::jsonb WHERE key='mail'`); err != nil {
		t.Fatal(err)
	}
	var stop undeliverable
	if err := worker.deliver(ctx, queue("REJECTED", "심의 반려")); !asUndeliverable(err, &stop) {
		t.Fatalf("a switched-off type was %v, want a permanent skip", err)
	}

	page, err := mail.List(ctx, db.Pool, "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 {
		t.Fatalf("%d attempts are recorded, want 3", len(page.Items))
	}
	byTitle := map[string]mail.Delivery{}
	for _, d := range page.Items {
		byTitle[d.Subject] = d
	}
	sent := byTitle["[SecCheck] 심의 배정"]
	if sent.Status != mail.StatusSent || sent.Recipient != "reader@example.internal" || sent.Event != "REVIEW_ASSIGNED" || sent.RecipientID != userID {
		t.Errorf("the successful attempt is recorded as %+v", sent)
	}
	failed := byTitle["[SecCheck] 심의 완료"]
	if failed.Status != mail.StatusFailed || !strings.Contains(failed.Error, "relay refused") {
		t.Errorf("the refused attempt is recorded as %+v", failed)
	}
	skipped := byTitle["[SecCheck] 심의 반려"]
	if skipped.Status != mail.StatusSkipped || !strings.Contains(skipped.Error, "switched off") {
		t.Errorf("the skipped attempt is recorded as %+v", skipped)
	}
	if page.Summary[mail.StatusSent] != 1 || page.Summary[mail.StatusFailed] != 1 || page.Summary[mail.StatusSkipped] != 1 {
		t.Errorf("the summary counts %v", page.Summary)
	}
	var bodies int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM mail_deliveries WHERE to_jsonb(mail_deliveries)::text LIKE '%비밀스러운 본문%'`).Scan(&bodies); err != nil {
		t.Fatal(err)
	}
	if bodies != 0 {
		t.Error("the record carries the body of the mail")
	}
	only, err := mail.List(ctx, db.Pool, "failed", 50, 0)
	if err != nil || len(only.Items) != 1 || only.Items[0].Status != mail.StatusFailed {
		t.Errorf("filtering by status gave %v, %v", only.Items, err)
	}
}
