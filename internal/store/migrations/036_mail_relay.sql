-- The mail relay gets its own settings row, named the way every service in
-- the company names it (mail.enabled, mail.smtp_host, ...): an operator who
-- has set up one of them has nothing new to learn here. The defaults are the
-- common internal relay -- port 25, no credentials, TLS only if the relay
-- offers it -- and the switch is off, so a fresh install sends nothing.
--
-- What the old `notification` row and `general.base_url` held is carried
-- across when a relay had been set up, so an installation that already sends
-- mail keeps sending it with the same relay after this migration; an
-- installation that never named a relay gets the standard's defaults. The
-- password stays sealed under the old row's name until an administrator
-- saves a new one; the loader knows.
INSERT INTO settings(key,value_json,sensitive) VALUES
 ('mail', '{"enabled":false,"smtp_host":"","smtp_port":25,"security":"auto","skip_tls_verify":false,"username":"","from_address":"","from_name":"SecCheck","base_url":"","timeout_seconds":10,"digest_hour":8,"notify_turn":true,"notify_decision":true,"notify_deadline":true,"notify_failure":true}'::jsonb, false)
ON CONFLICT (key) DO NOTHING;

UPDATE settings m SET
  value_json = m.value_json || jsonb_build_object(
    'enabled',      COALESCE((n.value_json->>'email_enabled')::boolean, false),
    'smtp_host',    COALESCE(n.value_json->>'smtp_host', ''),
    'smtp_port',    COALESCE((n.value_json->>'smtp_port')::int, 25),
    'security',     CASE n.value_json->>'smtp_tls_mode' WHEN 'tls' THEN 'tls' WHEN 'none' THEN 'none' WHEN 'starttls' THEN 'starttls' ELSE 'auto' END,
    'username',     COALESCE(n.value_json->>'smtp_username', ''),
    'from_address', COALESCE(n.value_json->>'from', ''),
    'digest_hour',  COALESCE((n.value_json->>'digest_hour')::int, 8),
    'base_url',     COALESCE(g.value_json->>'base_url', '')),
  encrypted_value = n.encrypted_value,
  sensitive = n.sensitive
FROM settings n, settings g
WHERE m.key='mail' AND n.key='notification' AND g.key='general' AND COALESCE(n.value_json->>'smtp_host','') <> '';

DELETE FROM settings WHERE key='notification';
UPDATE settings SET value_json = value_json - 'base_url' WHERE key='general';

-- Every attempt to hand a message to the relay, so that "it never came" can
-- be answered: when, for which event, to whom, with what subject, and what
-- the relay said. Never the body -- that would make this table a second copy
-- of everything the service ever wrote to anyone.
CREATE TABLE IF NOT EXISTS mail_deliveries (
  id text PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  event_type text NOT NULL,
  recipient_id text NOT NULL DEFAULT '',
  recipient text NOT NULL,
  subject text NOT NULL,
  status text NOT NULL,
  attempt int NOT NULL DEFAULT 1,
  error text NOT NULL DEFAULT '',
  notification_id text NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_mail_deliveries_created ON mail_deliveries(created_at DESC);
