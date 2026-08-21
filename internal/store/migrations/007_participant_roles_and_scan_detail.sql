-- review_participants.participant_role has existed since the first schema with
-- a CONTRIBUTOR default that nothing ever read or wrote, so adding anyone to a
-- review — including someone meant only to look at it — granted full write
-- access to the checklist. The column now means what its name says.
UPDATE review_participants SET participant_role='CONTRIBUTOR' WHERE participant_role NOT IN ('CONTRIBUTOR','VIEWER');
ALTER TABLE review_participants DROP CONSTRAINT IF EXISTS review_participants_role_check;
ALTER TABLE review_participants ADD CONSTRAINT review_participants_role_check CHECK (participant_role IN ('CONTRIBUTOR','VIEWER'));
CREATE INDEX IF NOT EXISTS idx_review_participants_role ON review_participants(review_request_id, participant_role);

-- notifications.channel defaulted to IN_APP and was never read. Whether a
-- notification was e-mailed is recorded by emailed_at, so the column was
-- describing a distinction the code does not make. Dropping it is safe for a
-- rollback because no version ever named it in an INSERT.
ALTER TABLE notifications DROP COLUMN IF EXISTS channel;
