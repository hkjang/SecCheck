package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	netmail "net/mail"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/mail"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/jackc/pgx/v5"
)

type Worker struct {
	Store *store.Store
	Box   *cryptox.Box

	// Sender delivers one message. Only the tests replace it; leaving it nil
	// uses the relay, which is the only thing production ever wants.
	Sender mail.Sender
}

// sendMail hands one message to the relay and records the attempt either
// way. The record is what an administrator reads when somebody says a mail
// never came, so a failure to write it is logged rather than swallowed.
func (w *Worker) sendMail(ctx context.Context, cfg mail.Config, d mail.Delivery, msg mail.Message) error {
	send := w.Sender
	if send == nil {
		send = mail.Send
	}
	err := send(ctx, cfg, msg)
	d.Recipient, d.Subject = msg.To, msg.Subject
	d.Status, d.Error = mail.Outcome(err)
	if recordErr := mail.Record(ctx, w.Store.Pool, store.NewID(), d); recordErr != nil {
		w.Store.Log(ctx, "ERROR", "", "notification", "mail delivery could not be recorded", map[string]any{"event": d.Event, "error": truncate(recordErr.Error(), 300)})
	}
	return err
}

func (w *Worker) config(ctx context.Context) (mail.Config, error) {
	return mail.Load(ctx, w.Store, w.Box)
}

type job struct {
	ID      string
	Payload []byte
	Attempt int
}

func New(s *store.Store, box *cryptox.Box) *Worker { return &Worker{Store: s, Box: box} }

func (w *Worker) Run(ctx context.Context) {
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='PENDING',locked_at=NULL,available_at=now(),updated_at=now() WHERE type='SEND_EMAIL' AND status='RUNNING' AND locked_at<now()-interval '5 minutes'`)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	digestChecked := time.Time{}
	for {
		if time.Since(digestChecked) >= 10*time.Minute {
			w.sendDigests(ctx)
			digestChecked = time.Now()
		}
		for i := 0; i < 10; i++ {
			j, err := w.claim(ctx)
			if errors.Is(err, pgx.ErrNoRows) {
				break
			}
			if err != nil {
				w.Store.Log(ctx, "ERROR", "", "notification", "job claim failed", map[string]any{"error": err.Error()})
				break
			}
			var stop undeliverable
			if err = w.deliver(ctx, j); errors.As(err, &stop) {
				w.giveUp(ctx, j, stop)
			} else if err != nil {
				w.fail(ctx, j, err)
			} else {
				_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='COMPLETED',locked_at=NULL,last_error='',updated_at=now() WHERE id=$1`, j.ID)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sendDigests delivers one summary per recipient who asked for a daily digest
// instead of a message per event. It runs at most once per person per day,
// after the configured hour in the server's local time.
type digestRecipient struct {
	id, email string
	muted     []string
}

// "Once a day" means once a calendar day where the reader lives. Measuring the
// day in the container's UTC clock sent a second digest as soon as UTC rolled
// over, which for a zone ahead of UTC falls in the middle of the reader's
// working day -- two identical summaries, hours apart.
func (w *Worker) digestRecipients(ctx context.Context, zone string, at time.Time, allowed []string) ([]digestRecipient, error) {
	// A muted event stays out of the digest as well. Muting only kept an
	// immediate mail from going out, so a reader on the daily summary was
	// still sent every type they had asked not to hear about. The same goes
	// for a type the administrator has switched off or that is bell-only.
	rows, err := w.Store.Pool.Query(ctx, `SELECT p.user_id,u.email,COALESCE(p.muted_events,'{}') FROM notification_preferences p JOIN users u ON u.id=p.user_id
                WHERE p.digest='DAILY' AND p.email_enabled AND u.active AND u.email<>''
                  AND (p.digest_sent_at IS NULL OR p.digest_sent_at < date_trunc('day', $2::timestamptz AT TIME ZONE $1) AT TIME ZONE $1)
                  AND EXISTS(SELECT 1 FROM notifications n WHERE n.recipient_id=p.user_id AND n.emailed_at IS NULL
                                AND n.event_type <> ALL(COALESCE(p.muted_events,'{}')) AND n.event_type = ANY($3::text[]))`, zone, at, allowed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recipients []digestRecipient
	for rows.Next() {
		var rec digestRecipient
		if rows.Scan(&rec.id, &rec.email, &rec.muted) == nil {
			recipients = append(recipients, rec)
		}
	}
	return recipients, rows.Err()
}

func (w *Worker) sendDigests(ctx context.Context) {
	cfg, err := w.config(ctx)
	if err != nil || !cfg.Enabled {
		return
	}
	if cfg.DigestHour < 0 || cfg.DigestHour > 23 {
		cfg.DigestHour = 8
	}
	// The container almost always runs UTC, so an administrator asking for
	// 08:00 means 08:00 in the configured display zone, not in the container's.
	zone := w.Store.Location(ctx)
	now := time.Now()
	if now.In(zone).Hour() < cfg.DigestHour {
		return
	}
	allowed := cfg.AllowedEvents()
	recipients, err := w.digestRecipients(ctx, zone.String(), now, allowed)
	if err != nil {
		return
	}

	for _, rec := range recipients {
		// The identifiers are carried through so that exactly what was sent is
		// marked as sent. Marking every unsent notification instead swallowed
		// anything that arrived while the digest was being delivered: it was
		// stamped as emailed without ever appearing in one.
		items, err := w.Store.Pool.Query(ctx, `SELECT id,title,body,created_at,COALESCE(target_type,''),COALESCE(target_id,''),COALESCE(item_id,'') FROM notifications WHERE recipient_id=$1 AND emailed_at IS NULL AND event_type <> ALL($2::text[]) AND event_type = ANY($3::text[]) ORDER BY created_at LIMIT 200`, rec.id, rec.muted, allowed)
		if err != nil {
			continue
		}
		var lines []string
		var included []string
		for items.Next() {
			var id, title, body, targetType, targetID, itemID string
			var at time.Time
			if items.Scan(&id, &title, &body, &at, &targetType, &targetID, &itemID) != nil {
				continue
			}
			included = append(included, id)
			line := fmt.Sprintf("[%s] %s\n%s", at.In(w.Store.Location(ctx)).Format("01-02 15:04"), title, truncate(body, 300))
			// A summary of twenty notices is a list of twenty places to go, so
			// each line carries its own way there instead of one link to the
			// notification centre for all of them.
			if targetType == "REVIEW_REQUEST" {
				if link := itemLink(cfg, targetID, itemID); link != "" {
					line += "\n" + link
				}
			}
			lines = append(lines, line)
		}
		items.Close()
		if len(lines) == 0 {
			continue
		}
		subject := fmt.Sprintf("[SecCheck] 알림 요약 %d건", len(lines))
		body := strings.Join(lines, "\n\n") + "\n\n" + cfg.Link("/notifications")
		if err = w.sendMail(ctx, cfg, mail.Delivery{Event: mail.EventDigest, RecipientID: rec.id}, mail.Message{To: rec.email, Subject: subject, Body: body}); err != nil {
			w.Store.Log(ctx, "ERROR", "", "notification", "digest delivery failed", map[string]any{"user_id": rec.id, "error": truncate(err.Error(), 300)})
			continue
		}
		// Failing to mark them means the next digest sends the same items
		// again, so it is worth saying out loud rather than discarding.
		if _, err = w.Store.Pool.Exec(ctx, `UPDATE notifications SET emailed_at=now() WHERE id=ANY($1)`, included); err != nil {
			w.Store.Log(ctx, "ERROR", "", "notification", "digest was delivered but could not be marked as sent", map[string]any{"user_id": rec.id, "items": len(included), "error": truncate(err.Error(), 300)})
		}
		if _, err = w.Store.Pool.Exec(ctx, `UPDATE notification_preferences SET digest_sent_at=now() WHERE user_id=$1`, rec.id); err != nil {
			w.Store.Log(ctx, "ERROR", "", "notification", "digest timestamp could not be recorded", map[string]any{"user_id": rec.id, "error": truncate(err.Error(), 300)})
		}
		w.Store.Log(ctx, "INFO", "", "notification", "digest delivered", map[string]any{"user_id": rec.id, "items": len(lines)})
	}
}

// itemLink turns a notification target into an address people can click.
// Without a configured base URL the e-mail simply omits the link rather than
// guessing a hostname. A notice about one checklist item carries that item, so
// the link opens the item rather than a review with a few hundred of them --
// the same landing the notification centre gives.
func itemLink(cfg mail.Config, targetID, itemID string) string {
	if targetID == "" {
		return cfg.Link("/notifications")
	}
	if itemID != "" {
		return cfg.Link("/reviews/" + targetID + "?item=" + itemID)
	}
	return cfg.Link("/reviews/" + targetID)
}

func (w *Worker) claim(ctx context.Context) (job, error) {
	var j job
	err := pgx.BeginFunc(ctx, w.Store.Pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE jobs SET status='RUNNING',attempts=attempts+1,locked_at=now(),updated_at=now() WHERE id=(SELECT id FROM jobs WHERE type='SEND_EMAIL' AND status='PENDING' AND available_at<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,payload,attempts`).Scan(&j.ID, &j.Payload, &j.Attempt)
	})
	return j, err
}

// undeliverable marks a failure no retry can fix: the recipient has no address,
// e-mail is switched off, or the notification the job points at is gone.
// Retrying those five times ends in a FAILED job, and a FAILED job raises the
// "a job exhausted its retries" alarm -- an alarm about an unfixable condition
// teaches administrators to ignore the alarm that matters.
type undeliverable struct{ reason string }

func (u undeliverable) Error() string { return u.reason }

func (w *Worker) deliver(ctx context.Context, j job) error {
	var payload struct {
		NotificationID string `json:"notification_id"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil || payload.NotificationID == "" {
		return undeliverable{"invalid email job payload"}
	}
	var recipientID, to, event, title, body, targetType, targetID, itemID string
	err := w.Store.Pool.QueryRow(ctx, `SELECT u.id,u.email,n.event_type,n.title,n.body,n.target_type,n.target_id,COALESCE(n.item_id,'') FROM notifications n JOIN users u ON u.id=n.recipient_id WHERE n.id=$1`, payload.NotificationID).Scan(&recipientID, &to, &event, &title, &body, &targetType, &targetID, &itemID)
	if errors.Is(err, pgx.ErrNoRows) {
		return undeliverable{"the notification this job refers to no longer exists"}
	}
	if err != nil {
		return err
	}
	cfg, err := w.config(ctx)
	if err != nil {
		return err
	}
	if targetType == "REVIEW_REQUEST" {
		if link := itemLink(cfg, targetID, itemID); link != "" {
			body = body + "\n\n" + link
		}
	}
	record := mail.Delivery{Event: event, RecipientID: recipientID, NotificationID: payload.NotificationID, Attempt: j.Attempt}
	subject := "[SecCheck] " + title
	if _, err = netmail.ParseAddress(to); err != nil {
		return w.skip(ctx, record, to, subject, "recipient has no valid email address")
	}
	if !cfg.Enabled {
		return w.skip(ctx, record, to, subject, "email delivery is switched off")
	}
	if !cfg.Allows(event) {
		return w.skip(ctx, record, to, subject, "this event type is switched off")
	}
	if readyErr := cfg.Ready(); readyErr != nil {
		// The switch is on but the row is incomplete. Retrying until an
		// administrator fills it in would page them about their own gap.
		return w.skip(ctx, record, to, subject, readyErr.Error())
	}
	if err = w.sendMail(ctx, cfg, record, mail.Message{To: to, Subject: subject, Body: body}); err != nil {
		return err
	}
	// Retrying would send a second copy of a mail that already went out, so
	// this is not an error the job can be failed on -- but leaving the mark
	// off means the daily digest picks the same notification up again.
	if _, err = w.Store.Pool.Exec(ctx, `UPDATE notifications SET emailed_at=COALESCE(emailed_at,now()) WHERE id=$1`, payload.NotificationID); err != nil {
		w.Store.Log(ctx, "ERROR", "", "notification", "email was sent but could not be marked as sent; the digest may repeat it", map[string]any{"notification_id": payload.NotificationID, "error": truncate(err.Error(), 300)})
	}
	w.Store.Log(ctx, "INFO", "", "notification", "email notification delivered", map[string]any{"notification_id": payload.NotificationID})
	return nil
}

// skip records that nothing was tried, and why, and hands the reason back as
// the undeliverable it is -- so the record can answer "it never came" even
// when the relay was never asked.
func (w *Worker) skip(ctx context.Context, d mail.Delivery, to, subject, reason string) error {
	d.Recipient, d.Subject, d.Status, d.Error = to, subject, mail.StatusSkipped, reason
	if err := mail.Record(ctx, w.Store.Pool, store.NewID(), d); err != nil {
		w.Store.Log(ctx, "ERROR", "", "notification", "mail delivery could not be recorded", map[string]any{"event": d.Event, "error": truncate(err.Error(), 300)})
	}
	return undeliverable{reason}
}

// giveUp closes a job that will never succeed. The notification itself stays in
// the recipient's list -- the in-app record is the one that always exists -- and
// the reason is kept on the job so the administrator can see why no mail went
// out without being paged about it.
func (w *Worker) giveUp(ctx context.Context, j job, cause undeliverable) {
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='COMPLETED',locked_at=NULL,last_error=$2,updated_at=now() WHERE id=$1`, j.ID, "not sent: "+cause.reason)
	w.Store.Log(ctx, "WARN", "", "notification", "email notification skipped", map[string]any{"job_id": j.ID, "reason": cause.reason})
}

func (w *Worker) fail(ctx context.Context, j job, cause error) {
	status := "PENDING"
	if j.Attempt >= 5 {
		status = "FAILED"
	}
	delay := time.Duration(1<<min(j.Attempt, 6)) * time.Minute
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status=$2,available_at=now()+$3::interval,locked_at=NULL,last_error=$4,updated_at=now() WHERE id=$1`, j.ID, status, fmt.Sprintf("%d seconds", int(delay.Seconds())), truncate(cause.Error(), 1000))
	w.Store.Log(ctx, "ERROR", "", "notification", "email notification failed", map[string]any{"job_id": j.ID, "attempt": j.Attempt, "terminal": status == "FAILED", "error": truncate(cause.Error(), 500)})
}

func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

// SendTest lets an administrator prove the relay settings before relying on
// them, the way the OIDC discovery button proves the identity provider. It
// is the one send that happens in the request, because the administrator is
// waiting for the answer; the attempt is recorded like any other.
func (w *Worker) SendTest(ctx context.Context, actorID, recipient string) error {
	cfg, err := w.config(ctx)
	if err != nil {
		return err
	}
	if _, err = netmail.ParseAddress(recipient); err != nil {
		return errors.New("받는 주소가 올바르지 않습니다")
	}
	if !cfg.Enabled {
		return errors.New("메일 알림이 꺼져 있습니다. 켜고 저장한 뒤 다시 시도하세요")
	}
	body := "SecCheck 메일 설정 테스트입니다. 이 메일이 도착했다면 사내 릴레이를 통한 알림 발송 경로가 정상입니다."
	if link := cfg.Link("/admin/settings"); link != "" {
		body += "\n\n" + link
	}
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cfg.Timeout()+5*time.Second)
	defer cancel()
	return w.sendMail(sendCtx, cfg, mail.Delivery{Event: mail.EventTest, RecipientID: actorID}, mail.Message{To: recipient, Subject: "[SecCheck] 메일 설정 테스트", Body: body})
}
