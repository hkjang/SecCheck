package notify

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/hkjang/SecCheck/internal/cryptox"
	"github.com/hkjang/SecCheck/internal/store"
	"github.com/jackc/pgx/v5"
)

type Worker struct {
	Store *store.Store
	Box   *cryptox.Box

	// Sender delivers one message. Only the tests replace it; leaving it nil
	// uses SMTP, which is the only thing production ever wants.
	Sender func(ctx context.Context, cfg emailSettings, recipient, subject, body string) error
}

func (w *Worker) sendMail(ctx context.Context, cfg emailSettings, recipient, subject, body string) error {
	if w.Sender != nil {
		return w.Sender(ctx, cfg, recipient, subject, body)
	}
	return send(ctx, cfg, recipient, subject, body)
}

type emailSettings struct {
	Enabled    bool   `json:"email_enabled"`
	Host       string `json:"smtp_host"`
	Port       int    `json:"smtp_port"`
	Username   string `json:"smtp_username"`
	TLSMode    string `json:"smtp_tls_mode"`
	From       string `json:"from"`
	DigestHour int    `json:"digest_hour"`
	Password   string `json:"-"`
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
			if err = w.deliver(ctx, j); err != nil {
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
type digestRecipient struct{ id, email string }

// "Once a day" means once a calendar day where the reader lives. Measuring the
// day in the container's UTC clock sent a second digest as soon as UTC rolled
// over, which for a zone ahead of UTC falls in the middle of the reader's
// working day -- two identical summaries, hours apart.
func (w *Worker) digestRecipients(ctx context.Context, zone string, at time.Time) ([]digestRecipient, error) {
	rows, err := w.Store.Pool.Query(ctx, `SELECT p.user_id,u.email FROM notification_preferences p JOIN users u ON u.id=p.user_id
                WHERE p.digest='DAILY' AND p.email_enabled AND u.active AND u.email<>''
                  AND (p.digest_sent_at IS NULL OR p.digest_sent_at < date_trunc('day', $2::timestamptz AT TIME ZONE $1) AT TIME ZONE $1)
                  AND EXISTS(SELECT 1 FROM notifications n WHERE n.recipient_id=p.user_id AND n.emailed_at IS NULL)`, zone, at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var recipients []digestRecipient
	for rows.Next() {
		var rec digestRecipient
		if rows.Scan(&rec.id, &rec.email) == nil {
			recipients = append(recipients, rec)
		}
	}
	return recipients, rows.Err()
}

func (w *Worker) sendDigests(ctx context.Context) {
	var cfg emailSettings
	encrypted, err := w.Store.Setting(ctx, "notification", &cfg)
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
	if encrypted != "" {
		plain, decryptErr := w.Box.Decrypt(encrypted, []byte("setting:notification"))
		if decryptErr != nil {
			return
		}
		cfg.Password = string(plain)
	}
	recipients, err := w.digestRecipients(ctx, zone.String(), now)
	if err != nil {
		return
	}

	for _, rec := range recipients {
		// The identifiers are carried through so that exactly what was sent is
		// marked as sent. Marking every unsent notification instead swallowed
		// anything that arrived while the digest was being delivered: it was
		// stamped as emailed without ever appearing in one.
		items, err := w.Store.Pool.Query(ctx, `SELECT id,title,body,created_at FROM notifications WHERE recipient_id=$1 AND emailed_at IS NULL ORDER BY created_at LIMIT 200`, rec.id)
		if err != nil {
			continue
		}
		var lines []string
		var included []string
		for items.Next() {
			var id, title, body string
			var at time.Time
			if items.Scan(&id, &title, &body, &at) != nil {
				continue
			}
			included = append(included, id)
			lines = append(lines, fmt.Sprintf("[%s] %s\n%s", at.In(w.Store.Location(ctx)).Format("01-02 15:04"), title, truncate(body, 300)))
		}
		items.Close()
		if len(lines) == 0 {
			continue
		}
		subject := fmt.Sprintf("[SecCheck] 알림 요약 %d건", len(lines))
		body := strings.Join(lines, "\n\n") + "\n\n" + serviceLink(ctx, w.Store, "")
		if err = w.sendMail(ctx, cfg, rec.email, subject, body); err != nil {
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

// serviceLink turns a notification target into an address people can click.
// Without a configured base URL the e-mail simply omits the link rather than
// guessing a hostname.
func serviceLink(ctx context.Context, s *store.Store, targetID string) string {
	var general struct {
		BaseURL string `json:"base_url"`
	}
	if _, err := s.Setting(ctx, "general", &general); err != nil {
		return ""
	}
	base := strings.TrimRight(strings.TrimSpace(general.BaseURL), "/")
	if base == "" {
		return ""
	}
	if targetID == "" {
		return base + "/notifications"
	}
	return base + "/reviews/" + targetID
}

func (w *Worker) claim(ctx context.Context) (job, error) {
	var j job
	err := pgx.BeginFunc(ctx, w.Store.Pool, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `UPDATE jobs SET status='RUNNING',attempts=attempts+1,locked_at=now(),updated_at=now() WHERE id=(SELECT id FROM jobs WHERE type='SEND_EMAIL' AND status='PENDING' AND available_at<=now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,payload,attempts`).Scan(&j.ID, &j.Payload, &j.Attempt)
	})
	return j, err
}

func (w *Worker) deliver(ctx context.Context, j job) error {
	var payload struct {
		NotificationID string `json:"notification_id"`
	}
	if err := json.Unmarshal(j.Payload, &payload); err != nil || payload.NotificationID == "" {
		return errors.New("invalid email job payload")
	}
	var to, title, body, targetType, targetID string
	err := w.Store.Pool.QueryRow(ctx, `SELECT u.email,n.title,n.body,n.target_type,n.target_id FROM notifications n JOIN users u ON u.id=n.recipient_id WHERE n.id=$1`, payload.NotificationID).Scan(&to, &title, &body, &targetType, &targetID)
	if err != nil {
		return err
	}
	if targetType == "REVIEW_REQUEST" {
		if link := serviceLink(ctx, w.Store, targetID); link != "" {
			body = body + "\n\n" + link
		}
	}
	if _, err = mail.ParseAddress(to); err != nil {
		return errors.New("recipient has no valid email address")
	}
	var cfg emailSettings
	encrypted, err := w.Store.Setting(ctx, "notification", &cfg)
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return errors.New("email adapter is disabled")
	}
	if encrypted != "" {
		plain, decryptErr := w.Box.Decrypt(encrypted, []byte("setting:notification"))
		if decryptErr != nil {
			return decryptErr
		}
		cfg.Password = string(plain)
	}
	if err = w.sendMail(ctx, cfg, to, "[SecCheck] "+title, body); err != nil {
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

func (w *Worker) fail(ctx context.Context, j job, cause error) {
	status := "PENDING"
	if j.Attempt >= 5 {
		status = "FAILED"
	}
	delay := time.Duration(1<<min(j.Attempt, 6)) * time.Minute
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status=$2,available_at=now()+$3::interval,locked_at=NULL,last_error=$4,updated_at=now() WHERE id=$1`, j.ID, status, fmt.Sprintf("%d seconds", int(delay.Seconds())), truncate(cause.Error(), 1000))
	w.Store.Log(ctx, "ERROR", "", "notification", "email notification failed", map[string]any{"job_id": j.ID, "attempt": j.Attempt, "terminal": status == "FAILED", "error": truncate(cause.Error(), 500)})
}

func send(ctx context.Context, cfg emailSettings, recipient, subject, body string) error {
	if cfg.Host == "" || cfg.Port < 1 || cfg.Port > 65535 || cfg.From == "" {
		return errors.New("SMTP adapter configuration is incomplete")
	}
	from, err := mail.ParseAddress(cfg.From)
	if err != nil {
		return errors.New("SMTP from address is invalid")
	}
	host := strings.TrimSpace(cfg.Host)
	addr := net.JoinHostPort(host, fmt.Sprint(cfg.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	var client *smtp.Client
	if strings.EqualFold(cfg.TLSMode, "tls") {
		conn, dialErr := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if dialErr != nil {
			return dialErr
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		client, err = smtp.NewClient(conn, host)
	} else {
		conn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			return dialErr
		}
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		client, err = smtp.NewClient(conn, host)
		if err == nil && strings.EqualFold(cfg.TLSMode, "starttls") {
			if ok, _ := client.Extension("STARTTLS"); !ok {
				err = errors.New("SMTP server does not support STARTTLS")
			} else {
				err = client.StartTLS(tlsConfig)
			}
		}
	}
	if err != nil {
		if client != nil {
			_ = client.Close()
		}
		return err
	}
	defer client.Close()
	if cfg.Username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return errors.New("SMTP server does not support authentication")
		}
		if err = client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, host)); err != nil {
			return err
		}
	}
	if err = client.Mail(from.Address); err != nil {
		return err
	}
	if err = client.Rcpt(recipient); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	message := "From: " + sanitizeHeader(from.String()) + "\r\nTo: " + sanitizeHeader(recipient) + "\r\nSubject: " + sanitizeHeader(subject) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body
	if _, err = wc.Write([]byte(message)); err != nil {
		_ = wc.Close()
		return err
	}
	if err = wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func sanitizeHeader(v string) string {
	return strings.ReplaceAll(strings.ReplaceAll(v, "\r", ""), "\n", "")
}
func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	return v[:n]
}

// SendTest lets an administrator prove the SMTP settings before relying on
// them, the way the OIDC discovery button proves the identity provider.
func (w *Worker) SendTest(ctx context.Context, recipient string) error {
	var cfg emailSettings
	encrypted, err := w.Store.Setting(ctx, "notification", &cfg)
	if err != nil {
		return err
	}
	if encrypted != "" {
		plain, decryptErr := w.Box.Decrypt(encrypted, []byte("setting:notification"))
		if decryptErr != nil {
			return decryptErr
		}
		cfg.Password = string(plain)
	}
	if _, err = mail.ParseAddress(recipient); err != nil {
		return errors.New("받는 주소가 올바르지 않습니다")
	}
	body := "SecCheck SMTP 설정 테스트 메일입니다. 이 메일이 도착했다면 알림 발송 경로가 정상입니다."
	if link := serviceLink(ctx, w.Store, ""); link != "" {
		body += "\n\n" + link
	}
	return send(ctx, cfg, recipient, "[SecCheck] SMTP 설정 테스트", body)
}
