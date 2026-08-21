-- Deleting evidence only ever set deleted_at. The encrypted blob stayed on the
-- volume for the life of the installation, and the code comment claiming the
-- files were "kept under the configured retention policy" described a policy
-- that did not exist. The metadata rows are kept — they are part of the audit
-- record that the evidence existed and was removed — but the blobs are
-- reclaimed and marked so.
ALTER TABLE evidences ADD COLUMN IF NOT EXISTS purged_at timestamptz;
ALTER TABLE evidence_versions ADD COLUMN IF NOT EXISTS purged_at timestamptz;
CREATE INDEX IF NOT EXISTS idx_evidences_purgeable ON evidences(deleted_at) WHERE deleted_at IS NOT NULL AND purged_at IS NULL;

UPDATE settings SET value_json = '{"deleted_evidence_retention_days":90}'::jsonb || value_json WHERE key='upload';
