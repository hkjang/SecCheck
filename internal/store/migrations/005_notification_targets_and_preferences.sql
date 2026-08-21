-- Notifications carried a title and a body and nothing to click. Recording
-- what the event is about lets the list link straight to the review.
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS target_type text NOT NULL DEFAULT '';
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS target_id text NOT NULL DEFAULT '';

-- Backfill the ones whose body starts with the review number, so existing
-- notifications become clickable too. This is an equality join on an indexed
-- column rather than a scan of every body against every review.
UPDATE notifications n SET target_type='REVIEW_REQUEST', target_id=r.id
FROM review_requests r
WHERE n.target_id='' AND r.review_number = split_part(n.body, ' ', 1);

-- Every notification was e-mailed to everyone whenever the global switch was
-- on. People need to say which events reach their inbox, and whether they
-- want them as they happen or once a day.
CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  email_enabled boolean NOT NULL DEFAULT true,
  digest text NOT NULL DEFAULT 'IMMEDIATE' CHECK(digest IN ('IMMEDIATE','DAILY')),
  muted_events text[] NOT NULL DEFAULT '{}',
  digest_sent_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- The daily digest collects the notifications a person has not been e-mailed
-- about yet.
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS emailed_at timestamptz;
CREATE INDEX IF NOT EXISTS idx_notifications_pending_digest ON notifications(recipient_id, created_at) WHERE emailed_at IS NULL;

-- E-mails link back into the service, which has to know its own address.
UPDATE settings SET value_json = '{"base_url":""}'::jsonb || value_json WHERE key='general';
UPDATE settings SET value_json = '{"digest_hour":8}'::jsonb || value_json WHERE key='notification';
