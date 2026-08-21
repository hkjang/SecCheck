-- Time-based one-time passwords for local accounts. The shared secret is
-- stored encrypted under the master key, like every other secret.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enrolled_at timestamptz;

-- Malware scanning moved off the upload request, so evidence now waits in
-- PENDING until the background scanner clears it.
ALTER TABLE evidences ADD COLUMN IF NOT EXISTS scan_detail text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_jobs_type_status ON jobs(type, status, available_at);

-- Change-request reminders need to know what has already been sent so a due
-- date does not generate one notification per worker tick.
ALTER TABLE change_requests ADD COLUMN IF NOT EXISTS reminded_at timestamptz;

INSERT INTO settings(key,value_json,sensitive) VALUES
 ('security','{}'::jsonb,false)
ON CONFLICT (key) DO NOTHING;
UPDATE settings SET value_json = '{"require_totp_for_admins":false}'::jsonb || value_json WHERE key='security';
