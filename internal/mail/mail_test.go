package mail

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type rowReader struct {
	row       string
	encrypted string
}

func (r rowReader) Setting(_ context.Context, key string, out any) (string, error) {
	if key != SettingKey {
		return "", errors.New("no such row")
	}
	return r.encrypted, json.Unmarshal([]byte(r.row), out)
}

type aadBox map[string]string

func (b aadBox) Decrypt(encoded string, aad []byte) ([]byte, error) {
	if b[string(aad)] != encoded {
		return nil, errors.New("wrong key")
	}
	return []byte("secret-" + encoded), nil
}

func TestSanitizeHeader(t *testing.T) {
	if got := sanitizeHeader("safe\r\nBcc: attacker@example.com"); got != "safeBcc: attacker@example.com" {
		t.Fatalf("unexpected sanitized header %q", got)
	}
}

// A fresh row is the common internal relay: port 25, no credentials, TLS if
// offered, and switched off.
func TestAFreshRowIsOffAndAimsAtAPlainRelay(t *testing.T) {
	cfg, err := Load(context.Background(), rowReader{row: `{}`}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Error("mail is on by default")
	}
	if cfg.Port != 25 || cfg.Security != "auto" || cfg.TimeoutSeconds != 10 || cfg.FromName != "SecCheck" {
		t.Errorf("defaults are %+v", cfg)
	}
	if cfg.Ready() == nil {
		t.Error("an empty row claims to be ready to send")
	}
	if err := cfg.Ready(); err == nil || !strings.Contains(err.Error(), "switched off") {
		t.Errorf("the reason given is %v", err)
	}
	if cfg.Link("/x") != "" {
		t.Error("a link was built without a base address")
	}
}

func TestThePasswordComesFromTheSealedColumnAndTheOldRowsSealStillOpens(t *testing.T) {
	box := aadBox{"setting:mail": "new", "setting:notification": "old"}
	cfg, err := Load(context.Background(), rowReader{row: `{"username":"relay"}`, encrypted: "new"}, box)
	if err != nil || cfg.Password != "secret-new" {
		t.Fatalf("password %q, err %v", cfg.Password, err)
	}
	cfg, err = Load(context.Background(), rowReader{row: `{"username":"relay"}`, encrypted: "old"}, box)
	if err != nil || cfg.Password != "secret-old" {
		t.Fatalf("a password sealed under the old row's name: %q, err %v", cfg.Password, err)
	}
	if _, err = Load(context.Background(), rowReader{row: `{}`, encrypted: "other"}, box); err == nil {
		t.Error("an unopenable password was not reported")
	}
	// The password never travels in the JSON the settings API returns.
	b, _ := json.Marshal(Config{Password: "hunter2", Host: "relay"})
	if strings.Contains(string(b), "hunter2") {
		t.Errorf("the password is in the row JSON: %s", b)
	}
}

func TestValidateSpeaksTheScreensLanguage(t *testing.T) {
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{}, ""},
		{Config{Enabled: true}, "SMTP 호스트와 발신 주소"},
		{Config{Enabled: true, Host: "relay", FromAddress: "a@b.c"}, ""},
		{Config{Security: "ssl"}, "전송 보안"},
		{Config{Port: 70000}, "포트"},
		{Config{TimeoutSeconds: 900}, "제한 시간"},
		{Config{DigestHour: 24}, "요약 발송 시각"},
		{Config{FromAddress: "not an address"}, "발신 주소"},
		{Config{BaseURL: "seccheck.internal"}, "서비스 주소"},
	}
	for _, c := range cases {
		got := c.cfg.Validate()
		if (c.want == "" && got != "") || (c.want != "" && !strings.Contains(got, c.want)) {
			t.Errorf("%+v: got %q, want %q", c.cfg, got, c.want)
		}
	}
	// The implicit-TLS port needs no extra configuration.
	cfg := Config{Port: 465}
	cfg.normalize()
	if cfg.Security != "tls" {
		t.Errorf("port 465 with auto negotiates %s", cfg.Security)
	}
}

func TestEverySwitchCoversItsEventsAndNothingElseIsMailed(t *testing.T) {
	all := Config{NotifyTurn: Bool(true), NotifyDecision: Bool(true), NotifyDeadline: Bool(true), NotifyFailure: Bool(true)}
	seen := map[string]bool{}
	for _, sw := range Switches {
		if len(sw.Events) == 0 {
			t.Errorf("%s covers nothing", sw.Key)
		}
		for _, e := range sw.Events {
			if seen[e] {
				t.Errorf("%s is under two switches", e)
			}
			seen[e] = true
			if SwitchFor(e) != sw.Key || !all.Allows(e) {
				t.Errorf("%s is not governed by %s", e, sw.Key)
			}
		}
	}
	if all.Allows("COMMENT_ADDED") || SwitchFor("COMMENT_ADDED") != "" {
		t.Error("a bell-only event is mailed")
	}
	// A row saved without the switches -- an API caller sending only the
	// relay fields -- keeps every group on; only an explicit false turns
	// one off, and only that one.
	if !(Config{}).Allows("REVIEW_ASSIGNED") || !(Config{}).Allows("STORAGE_LOW") {
		t.Error("an absent switch is read as off")
	}
	one := Config{NotifyTurn: Bool(false), NotifyDecision: Bool(false), NotifyFailure: Bool(false)}
	if one.Allows("REVIEW_ASSIGNED") || !one.Allows("OPEN_DATE_NEAR") {
		t.Error("switching a group off did not stop only that group")
	}
	if got := one.AllowedEvents(); len(got) != len(Switches[2].Events) {
		t.Errorf("AllowedEvents with one switch on lists %v", got)
	}
	none := Config{NotifyTurn: Bool(false), NotifyDecision: Bool(false), NotifyDeadline: Bool(false), NotifyFailure: Bool(false)}
	if got := none.AllowedEvents(); got == nil || len(got) != 0 {
		t.Errorf("AllowedEvents with nothing on is %v, want an empty list a query can bind", got)
	}
	if !AboutTheService("AUDIT_CHAIN_BROKEN") || AboutTheService("APPROVED") {
		t.Error("the events about the service itself are not the failure group")
	}
}

// relay is the smallest SMTP server that can take one message: it answers
// the greeting, EHLO, MAIL, RCPT, DATA and QUIT and keeps what it was given.
func relay(t *testing.T, offerStartTLS bool) (addr string, got func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var received strings.Builder
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		w := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		w("220 relay.test ESMTP")
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					w("250 queued")
					continue
				}
				received.WriteString(line + "\n")
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				if offerStartTLS {
					w("250-relay.test")
					w("250 STARTTLS")
				} else {
					w("250 relay.test")
				}
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				received.WriteString(line + "\n")
				w("250 ok")
			case strings.HasPrefix(line, "DATA"):
				inData = true
				w("354 go ahead")
			case strings.HasPrefix(line, "QUIT"):
				w("221 bye")
				return
			default:
				w("500 what")
			}
		}
	}()
	return ln.Addr().String(), func() string {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the relay never finished the conversation")
		}
		return received.String()
	}
}

func TestSendSpeaksSMTPToAPlainRelayWithoutCredentials(t *testing.T) {
	addr, got := relay(t, false)
	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{Enabled: true, Host: host, FromAddress: "seccheck@example.internal", FromName: "보안 심의", TimeoutSeconds: 5}
	if _, err := json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Port = atoi(port)
	err := Send(context.Background(), cfg, Message{To: "reader@example.internal", Subject: "제목\r\nBcc: x", Body: "본문"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	transcript := got()
	for _, want := range []string{"MAIL FROM:<seccheck@example.internal>", "RCPT TO:<reader@example.internal>", "Subject: =?UTF-8?q?", "본문", "Content-Type: text/plain; charset=UTF-8"} {
		if !strings.Contains(transcript, want) {
			t.Errorf("the relay did not receive %q:\n%s", want, transcript)
		}
	}
	if strings.Contains(transcript, "\nBcc:") {
		t.Error("a header injected through the subject reached the relay")
	}
}

func TestSendRefusesWhatItCannotDo(t *testing.T) {
	addr, _ := relay(t, false)
	host, port, _ := net.SplitHostPort(addr)
	cfg := Config{Enabled: true, Host: host, Port: atoi(port), FromAddress: "seccheck@example.internal", Security: "starttls", TimeoutSeconds: 5}
	if err := Send(context.Background(), cfg, Message{To: "reader@example.internal"}); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("starttls against a relay without it: %v", err)
	}
	cfg.Security = "auto"
	if err := Send(context.Background(), cfg, Message{To: "no address"}); err == nil {
		t.Error("an unparseable recipient was accepted")
	}
	cfg.Enabled = false
	if err := Send(context.Background(), cfg, Message{To: "reader@example.internal"}); err == nil {
		t.Error("mail went out while switched off")
	}
	// A relay that is not there is an error, not a hang: the timeout holds.
	dead := Config{Enabled: true, Host: "127.0.0.1", Port: 1, FromAddress: "seccheck@example.internal", TimeoutSeconds: 1}
	start := time.Now()
	if err := Send(context.Background(), dead, Message{To: "reader@example.internal"}); err == nil {
		t.Error("a closed port was reported as delivered")
	}
	if time.Since(start) > 5*time.Second {
		t.Error("a dead relay held the caller for longer than the timeout")
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
