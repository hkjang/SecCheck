package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The relay settings follow the company standard: off until an administrator
// turns them on, the password sealed and never read back, a test button
// that says what happened, and a record of every attempt.
func TestMailSettingsKeepThePasswordAndRecordTheTestSend(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	admin := h.login(adminOf(h))
	admin.do(http.MethodPatch, "/api/v1/me", map[string]string{"display_name": "관리자", "email": "admin@example.test", "department": ""})

	// A fresh install: the row is there, off, aimed at a plain relay, and
	// the old row is gone.
	rows := admin.do(http.MethodGet, "/api/v1/admin/settings", nil)
	var settings []struct {
		Key              string         `json:"key"`
		Value            map[string]any `json:"value"`
		SecretConfigured bool           `json:"secret_configured"`
	}
	if err := json.Unmarshal([]byte(rows.body), &settings); err != nil {
		t.Fatalf("settings: %v: %s", err, rows.body)
	}
	find := func(key string) (map[string]any, bool, bool) {
		for _, s := range settings {
			if s.Key == key {
				return s.Value, s.SecretConfigured, true
			}
		}
		return nil, false, false
	}
	mailRow, secret, ok := find("mail")
	if !ok {
		t.Fatal("no mail settings row")
	}
	if _, _, old := find("notification"); old {
		t.Error("the old notification row is still served")
	}
	if enabled, _ := mailRow["enabled"].(bool); enabled || secret {
		t.Errorf("a fresh install has mail on or a password set: %v", mailRow)
	}
	if port, _ := mailRow["smtp_port"].(float64); port != 25 || mailRow["security"] != "auto" || mailRow["username"] != "" {
		t.Errorf("the defaults are not the plain internal relay: %v", mailRow)
	}
	for _, key := range []string{"notify_turn", "notify_decision", "notify_deadline", "notify_failure"} {
		if on, _ := mailRow[key].(bool); !on {
			t.Errorf("%s starts off", key)
		}
	}
	if _, has := mailRow["password"]; has {
		t.Error("the row carries a password key")
	}

	// Saving with a password: the answer and every later read say only
	// that one is configured.
	saved := admin.do(http.MethodPut, "/api/v1/admin/settings/mail", map[string]any{
		"enabled": true, "smtp_host": "127.0.0.1", "smtp_port": 1, "security": "none", "username": "relay", "password": "hunter2-relay-secret",
		"from_address": "seccheck@example.test", "from_name": "보안 심의", "base_url": "https://seccheck.example.test", "timeout_seconds": 1,
	})
	if saved.status != http.StatusOK {
		t.Fatalf("save: %d %s", saved.status, saved.body)
	}
	if strings.Contains(saved.body, "hunter2") {
		t.Errorf("the save response returns the password: %s", saved.body)
	}
	if configured, _ := saved.json()["secret_configured"].(bool); !configured {
		t.Errorf("the save response does not say a password is configured: %s", saved.body)
	}
	again := admin.do(http.MethodGet, "/api/v1/admin/settings", nil)
	if strings.Contains(again.body, "hunter2") {
		t.Error("reading the settings back returns the password")
	}
	var stored string
	if err := h.db.Pool.QueryRow(ctx, `SELECT value_json::text FROM settings WHERE key='mail'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "hunter2") || strings.Contains(stored, "password") {
		t.Errorf("the password landed in the JSON row: %s", stored)
	}
	var logged int
	if err := h.db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE canonical_payload LIKE '%hunter2%'`).Scan(&logged); err != nil {
		t.Fatal(err)
	}
	if logged != 0 {
		t.Error("the password is in the audit record")
	}

	// The test button against a port nothing listens on: the request itself
	// succeeds in saying so, and the attempt is on record as failed.
	test := admin.do(http.MethodPost, "/api/v1/admin/settings/mail/test", nil)
	if test.status != http.StatusBadGateway || test.errorCode() != "SMTP_FAILED" {
		t.Fatalf("test send against a dead relay: %d %s", test.status, test.body)
	}
	record := admin.do(http.MethodGet, "/api/v1/admin/mail/deliveries", nil)
	if record.status != http.StatusOK {
		t.Fatalf("deliveries: %d %s", record.status, record.body)
	}
	var page struct {
		Items []struct {
			Event, Recipient, Subject, Status, Error string
		}
		Summary map[string]int
	}
	if err := json.Unmarshal([]byte(record.body), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Event != "TEST" || page.Items[0].Recipient != "admin@example.test" || page.Items[0].Status != "FAILED" || page.Items[0].Error == "" {
		t.Errorf("the test send is recorded as %+v", page.Items)
	}
	if page.Summary["FAILED"] != 1 {
		t.Errorf("the summary reads %v", page.Summary)
	}
	if strings.Contains(record.body, "hunter2") {
		t.Error("the delivery record carries the password")
	}

	// Only somebody with the role sees the record or presses the button.
	h.user("mail-reader", "REQUESTER")
	reader := h.login("mail-reader")
	if res := reader.do(http.MethodGet, "/api/v1/admin/mail/deliveries", nil); res.status != http.StatusForbidden {
		t.Errorf("a requester read the delivery record: %d", res.status)
	}

	// A row that cannot be sent from is refused before it is saved.
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/mail", map[string]any{"enabled": true, "smtp_host": "", "from_address": ""}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("mail switched on without a relay was accepted: %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/mail", map[string]any{"enabled": false, "security": "ssl"}); res.status != http.StatusUnprocessableEntity {
		t.Errorf("an unknown security mode was accepted: %d %s", res.status, res.body)
	}
}

// The test button sends where the screen says. The address box starts as
// the administrator's own, but the bootstrap administrator often has none,
// and the relay that accepts only one domain is found by naming an address
// in it -- so the address in the body wins, and without either the answer
// is a validation error rather than a delivery attempt to nobody.
func TestTheTestMailGoesToTheAddressTheScreenNames(t *testing.T) {
	h := newHarness(t)
	admin := h.login(adminOf(h))
	if res := admin.do(http.MethodPatch, "/api/v1/me", map[string]string{"display_name": "관리자", "email": "", "department": ""}); res.status != http.StatusOK {
		t.Fatalf("clearing the profile address: %d %s", res.status, res.body)
	}
	if res := admin.do(http.MethodPut, "/api/v1/admin/settings/mail", map[string]any{
		"enabled": true, "smtp_host": "127.0.0.1", "smtp_port": 1, "security": "none", "from_address": "seccheck@example.test", "timeout_seconds": 1,
	}); res.status != http.StatusOK {
		t.Fatalf("save: %d %s", res.status, res.body)
	}

	// No address anywhere: refused before the relay is asked, and nothing
	// is on record.
	if res := admin.do(http.MethodPost, "/api/v1/admin/settings/mail/test", map[string]string{"recipient": ""}); res.status != http.StatusUnprocessableEntity || res.errorCode() != "VALIDATION_FAILED" {
		t.Fatalf("a test send with no address at all: %d %s", res.status, res.body)
	}
	// The address from the screen: the relay is asked (and, being dead,
	// says no), and the record names that address.
	res := admin.do(http.MethodPost, "/api/v1/admin/settings/mail/test", map[string]string{"recipient": "ops@example.test"})
	if res.status != http.StatusBadGateway || res.errorCode() != "SMTP_FAILED" {
		t.Fatalf("a test send to a named address against a dead relay: %d %s", res.status, res.body)
	}
	record := admin.do(http.MethodGet, "/api/v1/admin/mail/deliveries", nil)
	var page struct {
		Items []struct{ Event, Recipient, Status string }
	}
	if err := json.Unmarshal([]byte(record.body), &page); err != nil {
		t.Fatalf("deliveries: %v: %s", err, record.body)
	}
	if len(page.Items) != 1 || page.Items[0].Event != "TEST" || page.Items[0].Recipient != "ops@example.test" || page.Items[0].Status != "FAILED" {
		t.Errorf("the test send is recorded as %+v", page.Items)
	}
}

// An installation that already sends mail keeps sending it: what the old
// notification row and general.base_url held is carried into the new row.
func TestTheOldNotificationRowIsCarriedIntoTheMailRow(t *testing.T) {
	db := newHarness(t).db
	ctx := context.Background()
	// Put the pre-036 shape back and run the migration's carry-over again.
	if _, err := db.Pool.Exec(ctx, `INSERT INTO settings(key,value_json,sensitive,encrypted_value) VALUES('notification','{"email_enabled":true,"smtp_host":"relay.old","smtp_port":587,"smtp_username":"old-user","smtp_tls_mode":"starttls","from":"old@example.test","digest_hour":7}'::jsonb,true,'sealed')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE settings SET value_json = value_json || '{"base_url":"https://old.example.test"}'::jsonb WHERE key='general'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `DELETE FROM settings WHERE key='mail'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version=36`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	var raw []byte
	var encrypted string
	if err := db.Pool.QueryRow(ctx, `SELECT value_json,encrypted_value FROM settings WHERE key='mail'`).Scan(&raw, &encrypted); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &value)
	want := map[string]any{"enabled": true, "smtp_host": "relay.old", "smtp_port": float64(587), "username": "old-user", "security": "starttls", "from_address": "old@example.test", "digest_hour": float64(7), "base_url": "https://old.example.test", "notify_turn": true}
	for key, expected := range want {
		if value[key] != expected {
			t.Errorf("%s carried over as %v, want %v", key, value[key], expected)
		}
	}
	if encrypted != "sealed" {
		t.Errorf("the sealed password was not carried: %q", encrypted)
	}
	var leftovers int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM settings WHERE key='notification' OR (key='general' AND value_json ? 'base_url')`).Scan(&leftovers); err != nil {
		t.Fatal(err)
	}
	if leftovers != 0 {
		t.Error("the old row or general.base_url survived the migration")
	}
}
