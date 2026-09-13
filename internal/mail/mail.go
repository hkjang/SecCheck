// Package mail sends event notifications through the company's SMTP relay.
//
// It follows the internal mail standard: the settings row is called `mail`
// and its keys are the ones every other service uses (mail.enabled,
// mail.smtp_host, ...), the common relay -- port 25, no credentials, no TLS --
// is the default, mail goes out in the background so no request waits on the
// relay, every attempt is recorded without the body, and the password is
// never read back.
package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strings"
	"time"
)

// SettingKey is the settings row; the keys inside it are the standard's
// `mail.<key>` names with the prefix taken by the row.
const SettingKey = "mail"

// Config is the `mail` settings row. The password lives in the row's
// encrypted column and is only ever filled in by Load.
type Config struct {
	Enabled        bool   `json:"enabled"`
	Host           string `json:"smtp_host"`
	Port           int    `json:"smtp_port"`
	Security       string `json:"security"`
	SkipTLSVerify  bool   `json:"skip_tls_verify"`
	Username       string `json:"username"`
	FromAddress    string `json:"from_address"`
	FromName       string `json:"from_name"`
	BaseURL        string `json:"base_url"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	DigestHour     int    `json:"digest_hour"`
	// The switches are pointers so that a row saved without them -- an API
	// caller sending only the relay fields -- keeps them on, which is their
	// default, instead of silently switching every event off.
	NotifyTurn     *bool  `json:"notify_turn"`
	NotifyDecision *bool  `json:"notify_decision"`
	NotifyDeadline *bool  `json:"notify_deadline"`
	NotifyFailure  *bool  `json:"notify_failure"`
	Password       string `json:"-"`
}

// Bool is a switch value for a literal Config.
func Bool(v bool) *bool { return &v }

func on(p *bool) bool { return p == nil || *p }

// Defaults aim at the common case: an internal relay on port 25 that accepts
// mail from the network without credentials and negotiates TLS if it can.
const (
	DefaultPort     = 25
	DefaultSecurity = "auto"
	DefaultTimeout  = 10
	DefaultFromName = "SecCheck"
)

// Switches are the event switches an administrator can flip, in the order
// the screen and the guide show them. Each one covers a group of
// notification types that share a reason to be mailed at all: somebody is
// waiting for it. Anything not listed under a switch stays on the bell.
var Switches = []Switch{
	{Key: "notify_turn", Label: "내 차례", Description: "심의·항목·결재가 내 손에 왔거나, 보완 요청과 그 조치, 후속조치 이행 보고처럼 내가 다음 일을 해야 할 때",
		Events: []string{"REVIEW_SUBMITTED", "REVIEW_ASSIGNED", "REVIEW_TRANSFERRED", "ITEM_ASSIGNED", "APPROVAL_PENDING", "CHANGE_REQUEST", "CHANGE_DONE", "FOLLOW_UP_REPORTED"}},
	{Key: "notify_decision", Label: "결과", Description: "기다리던 심의의 승인·반려·취소, 결재 회수, 후속조치 종료",
		Events: []string{"APPROVED", "REJECTED", "REVIEW_CANCELLED", "APPROVAL_WITHDRAWN", "FOLLOW_UP_DONE"}},
	{Key: "notify_deadline", Label: "기한", Description: "보완·후속조치 기한, 오픈 예정일, API 키 만료가 다가오거나 지났을 때와 멈춘 심의",
		Events: []string{"CHANGE_REQUEST_DUE", "FOLLOW_UP_DUE", "OPEN_DATE_NEAR", "REVIEW_STALLED", "API_KEY_EXPIRING"}},
	{Key: "notify_failure", Label: "장애", Description: "작업 큐 정체·재시도 소진, 저장 공간, 증적 무결성·악성코드, 감사로그 체인, 계정 잠금처럼 운영자가 조치해야 할 때",
		Events: []string{"JOB_QUEUE_STALLED", "JOB_FAILED", "STORAGE_LOW", "EVIDENCE_UNREADABLE", "EVIDENCE_INFECTED", "AUDIT_CHAIN_BROKEN", "ACCOUNT_LOCKED"}},
}

// Switch groups notification event types under one administrator switch.
type Switch struct {
	Key         string
	Label       string
	Description string
	Events      []string
}

// SwitchFor names the switch that governs an event type, or "" when the
// event is bell-only and never mailed.
func SwitchFor(event string) string {
	for _, sw := range Switches {
		for _, e := range sw.Events {
			if e == event {
				return sw.Key
			}
		}
	}
	return ""
}

// SettingReader is the part of the store the package needs: one row's JSON
// and its encrypted column.
type SettingReader interface {
	Setting(ctx context.Context, key string, out any) (string, error)
}

// Decrypter opens the password column. The store's master-key box is one.
type Decrypter interface {
	Decrypt(encoded string, aad []byte) ([]byte, error)
}

// Load reads the row and, when a password is stored, opens it.
func Load(ctx context.Context, settings SettingReader, box Decrypter) (Config, error) {
	cfg := Config{Port: DefaultPort, Security: DefaultSecurity, TimeoutSeconds: DefaultTimeout, FromName: DefaultFromName, DigestHour: 8}
	encrypted, err := settings.Setting(ctx, SettingKey, &cfg)
	if err != nil {
		return cfg, err
	}
	cfg.normalize()
	if encrypted == "" || box == nil {
		return cfg, nil
	}
	plain, err := box.Decrypt(encrypted, []byte("setting:"+SettingKey))
	if err != nil {
		// The password an installation set before this row existed was
		// sealed under the old row's name. It is carried over as is, and
		// re-sealed under this row the next time an administrator saves one.
		if legacy, legacyErr := box.Decrypt(encrypted, []byte("setting:notification")); legacyErr == nil {
			plain, err = legacy, nil
		}
	}
	if err != nil {
		return cfg, err
	}
	cfg.Password = string(plain)
	return cfg, nil
}

func (c *Config) normalize() {
	c.Host = strings.TrimSpace(c.Host)
	c.Username = strings.TrimSpace(c.Username)
	c.FromAddress = strings.TrimSpace(c.FromAddress)
	c.FromName = strings.TrimSpace(c.FromName)
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.Security = strings.ToLower(strings.TrimSpace(c.Security))
	if c.Security == "" {
		c.Security = DefaultSecurity
	}
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = DefaultTimeout
	}
	if c.FromName == "" {
		c.FromName = DefaultFromName
	}
	// A relay on the implicit TLS port needs no extra configuration.
	if c.Security == DefaultSecurity && c.Port == 465 {
		c.Security = "tls"
	}
}

// Validate answers what the settings screen should say when the row is
// saved, in the words the screen shows; "" means it can be saved.
func (c Config) Validate() string {
	c.normalize()
	switch c.Security {
	case "auto", "none", "starttls", "tls":
	default:
		return "전송 보안은 auto · none · starttls · tls 중 하나여야 합니다."
	}
	if c.Port < 1 || c.Port > 65535 {
		return "SMTP 포트 범위를 확인하세요."
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 300 {
		return "연결 제한 시간은 1~300초여야 합니다."
	}
	if c.DigestHour < 0 || c.DigestHour > 23 {
		return "요약 발송 시각은 0~23시여야 합니다."
	}
	if c.FromAddress != "" {
		if _, err := netmail.ParseAddress(c.FromAddress); err != nil {
			return "발신 주소가 올바른 메일 주소가 아닙니다."
		}
	}
	if c.BaseURL != "" && !strings.HasPrefix(c.BaseURL, "http://") && !strings.HasPrefix(c.BaseURL, "https://") {
		return "서비스 주소는 http(s)로 시작하는 완전한 URL이어야 합니다."
	}
	if c.Enabled && (c.Host == "" || c.FromAddress == "") {
		return "메일 알림 활성화 시 SMTP 호스트와 발신 주소가 필요합니다."
	}
	return ""
}

// Ready says why nothing can be sent right now, or nil. It is the reason the
// delivery record carries when the switch is on but the row is incomplete.
func (c Config) Ready() error {
	if !c.Enabled {
		return errors.New("mail is switched off")
	}
	if c.Host == "" {
		return errors.New("mail.smtp_host is not set")
	}
	if c.FromAddress == "" {
		return errors.New("mail.from_address is not set")
	}
	if _, err := netmail.ParseAddress(c.FromAddress); err != nil {
		return errors.New("mail.from_address is not a valid address")
	}
	return nil
}

// Allows answers whether the administrator has left this event type on.
// Bell-only events answer false: they are never mailed.
func (c Config) Allows(event string) bool {
	switch SwitchFor(event) {
	case "notify_turn":
		return on(c.NotifyTurn)
	case "notify_decision":
		return on(c.NotifyDecision)
	case "notify_deadline":
		return on(c.NotifyDeadline)
	case "notify_failure":
		return on(c.NotifyFailure)
	}
	return false
}

// AboutTheService says whether an event reports on the system rather than
// on somebody's work: an administrator who presses the button that finds
// the broken chain still wants the mail, so these are never withheld from
// the person whose action raised them.
func AboutTheService(event string) bool { return SwitchFor(event) == "notify_failure" }

// AllowedEvents lists every event type the switches currently let through,
// for a query that must leave the others out of a digest.
func (c Config) AllowedEvents() []string {
	var events []string
	for _, sw := range Switches {
		if c.Allows(sw.Events[0]) {
			events = append(events, sw.Events...)
		}
	}
	if events == nil {
		events = []string{}
	}
	return events
}

// Timeout is the relay timeout as a duration.
func (c Config) Timeout() time.Duration { return time.Duration(c.TimeoutSeconds) * time.Second }

// Link builds an address inside this service for a mail body, or "" when no
// base address is configured -- the mail then simply carries no link rather
// than a guessed hostname.
func (c Config) Link(path string) string {
	if c.BaseURL == "" {
		return ""
	}
	return c.BaseURL + path
}

// Message is one mail: a single recipient, a subject, a plain-text body.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Sender delivers one message. Production uses Send; tests substitute.
type Sender func(ctx context.Context, cfg Config, msg Message) error

// Send delivers one message over the relay the configuration names,
// negotiating security the way the configuration asks:
//
//	auto     TLS when the relay advertises STARTTLS, plain otherwise
//	none     plain, even if the relay offers STARTTLS
//	starttls STARTTLS, and a failure if the relay has none
//	tls      implicit TLS from the first byte (port 465)
func Send(ctx context.Context, cfg Config, msg Message) error {
	cfg.normalize()
	if err := cfg.Ready(); err != nil {
		return err
	}
	if _, err := netmail.ParseAddress(msg.To); err != nil {
		return errors.New("recipient has no valid email address")
	}
	from := netmail.Address{Name: cfg.FromName, Address: cfg.FromAddress}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprint(cfg.Port))
	dialer := &net.Dialer{Timeout: cfg.Timeout()}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.Host, InsecureSkipVerify: cfg.SkipTLSVerify} // #nosec G402 -- the operator opts in for a private relay certificate
	var client *smtp.Client
	var err error
	if cfg.Security == "tls" {
		conn, dialErr := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if dialErr != nil {
			return dialErr
		}
		_ = conn.SetDeadline(time.Now().Add(3 * cfg.Timeout()))
		client, err = smtp.NewClient(conn, cfg.Host)
	} else {
		conn, dialErr := dialer.DialContext(ctx, "tcp", addr)
		if dialErr != nil {
			return dialErr
		}
		_ = conn.SetDeadline(time.Now().Add(3 * cfg.Timeout()))
		client, err = smtp.NewClient(conn, cfg.Host)
		if err == nil && cfg.Security != "none" {
			offered, _ := client.Extension("STARTTLS")
			switch {
			case offered:
				err = client.StartTLS(tlsConfig)
			case cfg.Security == "starttls":
				err = errors.New("SMTP server does not support STARTTLS")
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
		if err = client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}
	if err = client.Mail(from.Address); err != nil {
		return err
	}
	if err = client.Rcpt(msg.To); err != nil {
		return err
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	// A Korean subject is encoded the way the From name already is, so a
	// relay that does not speak SMTPUTF8 passes it on unharmed.
	subject := mime.QEncoding.Encode("UTF-8", sanitizeHeader(msg.Subject))
	message := "From: " + sanitizeHeader(from.String()) + "\r\nTo: " + sanitizeHeader(msg.To) + "\r\nSubject: " + subject +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + msg.Body
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
