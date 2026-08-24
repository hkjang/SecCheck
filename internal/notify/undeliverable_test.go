package notify

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hkjang/SecCheck/internal/store"
	"github.com/hkjang/SecCheck/internal/testdb"
)

// A recipient with no e-mail address, or a service with e-mail switched off,
// cannot be reached however many times the job runs. Five retries later the job
// was marked FAILED, and a FAILED job pages every administrator about a queue
// that is working perfectly -- which is how people learn to ignore that alarm.
func TestMailNobodyCanReceiveIsNotRetriedOrAlarmed(t *testing.T) {
	db := testdb.New(t)
	ctx := context.Background()
	userID := testdb.Bootstrap(t, db, "no-address")
	worker := New(db, nil)
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET email='' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	notificationID := store.NewID()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO notifications(id,recipient_id,event_type,title,body) VALUES($1,$2,'REVIEW_ASSIGNED','제목','본문')`, notificationID, userID); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{"notification_id": notificationID})
	if err != nil {
		t.Fatal(err)
	}
	jobID := store.NewID()
	if _, err = db.Pool.Exec(ctx, `INSERT INTO jobs(id,type,payload,status) VALUES($1,'SEND_EMAIL',$2,'RUNNING')`, jobID, payload); err != nil {
		t.Fatal(err)
	}

	deliverErr := worker.deliver(ctx, job{ID: jobID, Payload: payload})
	var stop undeliverable
	if !asUndeliverable(deliverErr, &stop) {
		t.Fatalf("delivery to an addressless recipient returned %v, want a permanent failure", deliverErr)
	}
	worker.giveUp(ctx, job{ID: jobID, Payload: payload}, stop)

	var status, reason string
	var attempts int
	if err = db.Pool.QueryRow(ctx, `SELECT status,last_error,attempts FROM jobs WHERE id=$1`, jobID).Scan(&status, &reason, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "COMPLETED" {
		t.Errorf("the job is %s; an unfixable delivery must not sit in the retry queue or end as FAILED", status)
	}
	if !strings.Contains(reason, "email address") {
		t.Errorf("the job does not record why no mail went out: %q", reason)
	}
	// The in-app notification is the record that always exists, and it stays
	// unmailed so a later digest does not claim it was sent.
	var emailed bool
	if err = db.Pool.QueryRow(ctx, `SELECT emailed_at IS NOT NULL FROM notifications WHERE id=$1`, notificationID).Scan(&emailed); err != nil {
		t.Fatal(err)
	}
	if emailed {
		t.Error("the notification is marked as e-mailed although nothing was sent")
	}
}

func asUndeliverable(err error, out *undeliverable) bool {
	if u, ok := err.(undeliverable); ok {
		*out = u
		return true
	}
	return false
}
