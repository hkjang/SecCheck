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
}

type emailSettings struct {
	Enabled  bool   `json:"email_enabled"`
	Host     string `json:"smtp_host"`
	Port     int    `json:"smtp_port"`
	Username string `json:"smtp_username"`
	TLSMode  string `json:"smtp_tls_mode"`
	From     string `json:"from"`
	Password string `json:"-"`
}

type job struct {
	ID      string
	Payload []byte
	Attempt int
}

func New(s *store.Store, box *cryptox.Box) *Worker { return &Worker{Store: s, Box: box} }

func (w *Worker) Run(ctx context.Context) {
	_, _ = w.Store.Pool.Exec(ctx, `UPDATE jobs SET status='PENDING',locked_at=NULL,available_at=now(),updated_at=now() WHERE status='RUNNING' AND locked_at<now()-interval '5 minutes'`)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
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
	var to, title, body string
	err := w.Store.Pool.QueryRow(ctx, `SELECT u.email,n.title,n.body FROM notifications n JOIN users u ON u.id=n.recipient_id WHERE n.id=$1`, payload.NotificationID).Scan(&to, &title, &body)
	if err != nil {
		return err
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
	if err = send(ctx, cfg, to, title, body); err != nil {
		return err
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
