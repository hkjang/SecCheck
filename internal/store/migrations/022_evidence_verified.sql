-- The evidence volume is the one thing this service exists to keep, and until
-- now nothing read it back on its own: a file lost to a failed disk, a restore
-- that missed the volume, or a power cut that dropped a directory entry was
-- found when somebody tried to download it, which for evidence means during an
-- audit. The column records when a blob was last read back and matched.
ALTER TABLE evidences ADD COLUMN IF NOT EXISTS verified_at timestamptz;
CREATE INDEX IF NOT EXISTS idx_evidences_verified ON evidences(verified_at NULLS FIRST) WHERE deleted_at IS NULL AND purged_at IS NULL;
