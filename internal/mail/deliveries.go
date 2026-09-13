package mail

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Delivery is one attempt to hand a message to the relay: when, for which
// event, to whom, with what subject, and whether the relay took it. The body
// is deliberately not kept -- the record answers "did it go out", and a
// record that also held every body would be a second copy of everything
// the service ever said.
type Delivery struct {
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	Event          string    `json:"event"`
	RecipientID    string    `json:"recipient_id"`
	Recipient      string    `json:"recipient"`
	Subject        string    `json:"subject"`
	Status         string    `json:"status"`
	Attempt        int       `json:"attempt"`
	Error          string    `json:"error"`
	NotificationID string    `json:"notification_id"`
}

// Delivery statuses. SENT and FAILED are the relay's answer; SKIPPED is the
// service deciding not to try, with the reason in Error, so that "it never
// came" can still be answered from the record.
const (
	StatusSent    = "SENT"
	StatusFailed  = "FAILED"
	StatusSkipped = "SKIPPED"
)

// Events the service itself originates, outside the notification catalogue.
const (
	EventTest   = "TEST"
	EventDigest = "DIGEST"
)

// Record keeps one attempt. The caller has already done or decided the
// sending; a failure to write the record is returned so the caller can log
// it, but it never becomes the failure of the send.
func Record(ctx context.Context, pool *pgxpool.Pool, id string, d Delivery) error {
	if d.Status == "" {
		d.Status = StatusSent
	}
	if d.Attempt < 1 {
		d.Attempt = 1
	}
	_, err := pool.Exec(ctx, `INSERT INTO mail_deliveries(id,event_type,recipient_id,recipient,subject,status,attempt,error,notification_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		id, d.Event, d.RecipientID, d.Recipient, truncate(d.Subject, 500), d.Status, d.Attempt, truncate(d.Error, 1000), d.NotificationID)
	return err
}

// Outcome turns a send result into a status and message for the record.
func Outcome(err error) (status, message string) {
	if err == nil {
		return StatusSent, ""
	}
	return StatusFailed, err.Error()
}

// Page is what the administrator's record screen shows: the newest attempts
// and how many of each outcome exist in total.
type Page struct {
	Items   []Delivery       `json:"items"`
	Summary map[string]int64 `json:"summary"`
}

// List returns the newest attempts, optionally only those with one status,
// newest first, and the count of every status regardless of the filter.
func List(ctx context.Context, pool *pgxpool.Pool, status string, limit, offset int) (Page, error) {
	page := Page{Items: []Delivery{}, Summary: map[string]int64{StatusSent: 0, StatusFailed: 0, StatusSkipped: 0}}
	status = strings.ToUpper(strings.TrimSpace(status))
	rows, err := pool.Query(ctx, `SELECT id,created_at,event_type,recipient_id,recipient,subject,status,attempt,error,notification_id FROM mail_deliveries
                WHERE ($1='' OR status=$1) ORDER BY created_at DESC LIMIT $2 OFFSET $3`, status, limit, offset)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.CreatedAt, &d.Event, &d.RecipientID, &d.Recipient, &d.Subject, &d.Status, &d.Attempt, &d.Error, &d.NotificationID); err != nil {
			return page, err
		}
		page.Items = append(page.Items, d)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	counts, err := pool.Query(ctx, `SELECT status,count(*) FROM mail_deliveries GROUP BY status`)
	if err != nil {
		return page, err
	}
	defer counts.Close()
	for counts.Next() {
		var s string
		var n int64
		if err := counts.Scan(&s, &n); err != nil {
			return page, err
		}
		page.Summary[s] = n
	}
	return page, counts.Err()
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}
