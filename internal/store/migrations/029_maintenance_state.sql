-- Housekeeping runs in a goroutine nobody watches: reminders, evidence
-- sampling, retention purges and the audit-chain check all stop together if it
-- dies, and every screen goes on looking normal. Recording each completed run
-- makes its absence something an operator can see.
CREATE TABLE IF NOT EXISTS maintenance_state (
  id integer PRIMARY KEY,
  last_run_at timestamptz,
  last_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  CONSTRAINT maintenance_state_single CHECK (id = 1)
);
INSERT INTO maintenance_state(id) VALUES(1) ON CONFLICT (id) DO NOTHING;
