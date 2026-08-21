-- Search and every list filter use ILIKE '%term%', which no btree index can
-- serve. pg_trgm turns them into index scans.
--
-- Three things have to hold. Creating an extension needs rights a hardened,
-- least-privilege role may not have, so failure degrades to sequential scans
-- instead of refusing to start. Two instances migrating at once would race on
-- the same CREATE, so the work is serialised on an advisory lock. And the
-- operator class is resolved through the schema the extension actually landed
-- in, rather than trusting search_path.
DO $$
DECLARE
  ext_schema text;
  target record;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('seccheck:pg_trgm'));
  BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;
  EXCEPTION
    WHEN insufficient_privilege OR feature_not_supported OR invalid_schema_name OR unique_violation OR duplicate_object THEN
      RAISE NOTICE 'pg_trgm is unavailable; text search will fall back to sequential scans';
  END;

  SELECT n.nspname INTO ext_schema
  FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
  WHERE e.extname = 'pg_trgm';
  IF ext_schema IS NULL THEN
    RETURN;
  END IF;

  FOR target IN
    SELECT * FROM (VALUES
      ('idx_review_requests_number_trgm', 'review_requests', 'review_number'),
      ('idx_review_requests_service_trgm', 'review_requests', 'service_name'),
      ('idx_review_requests_department_trgm', 'review_requests', 'department'),
      ('idx_submission_items_code_trgm', 'submission_items', 'item_code'),
      ('idx_submission_items_title_trgm', 'submission_items', 'title'),
      ('idx_evidences_filename_trgm', 'evidences', 'original_filename'),
      ('idx_users_display_name_trgm', 'users', 'display_name'),
      ('idx_security_controls_code_trgm', 'security_controls', 'code'),
      ('idx_security_controls_title_trgm', 'security_controls', 'title'),
      ('idx_audit_logs_user_name_trgm', 'audit_logs', 'user_name'),
      ('idx_application_logs_message_trgm', 'application_logs', 'message')
    ) AS t(index_name, table_name, column_name)
  LOOP
    EXECUTE format('CREATE INDEX IF NOT EXISTS %I ON %I USING gin (%I %I.gin_trgm_ops)',
      target.index_name, target.table_name, target.column_name, ext_schema);
  END LOOP;
END $$;

-- Verifying the hash chain used to re-read and re-hash every event ever
-- written. Remembering how far the chain has already been proved makes the
-- routine check proportional to what is new, while a full pass stays
-- available on demand.
ALTER TABLE audit_chain_state ADD COLUMN IF NOT EXISTS verified_sequence bigint NOT NULL DEFAULT 0;
ALTER TABLE audit_chain_state ADD COLUMN IF NOT EXISTS verified_hash text NOT NULL DEFAULT '';
ALTER TABLE audit_chain_state ADD COLUMN IF NOT EXISTS verified_at timestamptz;

-- Failed background jobs are retried from the administration screen, which
-- needs to list them by age.
CREATE INDEX IF NOT EXISTS idx_jobs_status_updated ON jobs(status, updated_at DESC);
