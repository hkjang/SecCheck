-- A review's own history is assembled by looking up the audit events that
-- point at it and at its items, evidence and change requests. Without an index
-- on the target that is a scan of the whole audit table.
CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_id, timestamp DESC) WHERE target_id <> '';
