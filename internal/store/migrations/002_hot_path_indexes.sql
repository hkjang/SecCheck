-- PostgreSQL does not index foreign-key columns automatically, so every join
-- and every ON DELETE CASCADE on these tables was a sequential scan. The
-- checklist view alone runs four correlated sub-queries per item.
CREATE INDEX IF NOT EXISTS idx_submission_items_submission ON submission_items(submission_id);
CREATE INDEX IF NOT EXISTS idx_submission_items_source ON submission_items(source_item_id);
CREATE INDEX IF NOT EXISTS idx_evidences_item ON evidences(submission_item_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_evidences_scan ON evidences(scan_status) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_evidence_versions_evidence ON evidence_versions(evidence_id);
CREATE INDEX IF NOT EXISTS idx_change_requests_item ON change_requests(submission_item_id);
CREATE INDEX IF NOT EXISTS idx_change_requests_review ON change_requests(review_request_id, status);
CREATE INDEX IF NOT EXISTS idx_change_requests_due ON change_requests(due_date) WHERE status <> 'VERIFIED';
CREATE INDEX IF NOT EXISTS idx_comments_item ON comments(submission_item_id);
CREATE INDEX IF NOT EXISTS idx_submissions_review ON submissions(review_request_id, revision DESC);
CREATE INDEX IF NOT EXISTS idx_rule_overrides_review ON rule_overrides(review_request_id);
CREATE INDEX IF NOT EXISTS idx_approvals_review ON approvals(review_request_id);
CREATE INDEX IF NOT EXISTS idx_review_participants_user ON review_participants(user_id);

-- The unread badge polls once a minute per signed-in user.
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(recipient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_recipient_unread ON notifications(recipient_id) WHERE read_at IS NULL;

-- Audit and log filters added with the admin console search.
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_time ON audit_logs(event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_application_logs_level_time ON application_logs(level, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_application_logs_request ON application_logs(request_id) WHERE request_id <> '';

-- Template administration and the Rule Engine walk these paths on every
-- review creation.
CREATE INDEX IF NOT EXISTS idx_checklist_items_version ON checklist_items(version_id, sort_order);
CREATE INDEX IF NOT EXISTS idx_checklist_items_control ON checklist_items(control_id);
CREATE INDEX IF NOT EXISTS idx_checklist_versions_template ON checklist_versions(template_id, status);
CREATE INDEX IF NOT EXISTS idx_checklist_sections_version ON checklist_sections(version_id);
CREATE INDEX IF NOT EXISTS idx_template_changes_version ON template_changes(version_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_code);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_data_keys_user ON user_data_keys(user_id, version DESC);

-- Reviews are listed newest-first with a keyset cursor.
CREATE INDEX IF NOT EXISTS idx_review_requests_updated ON review_requests(updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_review_requests_status_updated ON review_requests(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_review_requests_requester ON review_requests(requester_id);
CREATE INDEX IF NOT EXISTS idx_review_requests_reviewer ON review_requests(reviewer_id);
CREATE INDEX IF NOT EXISTS idx_review_requests_approver ON review_requests(approver_id);
