-- The baseline is version 1, and version 1 is the number the very first
-- release recorded after applying its own schema.sql. Everything the baseline
-- file gained after that release -- login lockout's two columns, three
-- indexes -- reaches a fresh install through 001_baseline.sql and reaches an
-- installation from that first release through nothing at all: 001 is already
-- recorded, so it is skipped forever. Those databases lost the ability to log
-- in, because every attempt writes failed_login_count.
--
-- This file re-asserts the difference. It is idempotent, so a database that
-- already has the columns takes no change, and the guard test in
-- migrate_test.go fails the build if the baseline ever drifts again.
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count integer NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until timestamptz;
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_oidc_states_expiry ON oidc_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_jobs_retention ON jobs(status,updated_at);
