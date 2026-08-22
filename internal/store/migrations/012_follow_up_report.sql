-- The register was closable only by a security reviewer, but the remediation
-- is the service team's work: they had no way to say they had done it and had
-- to tell somebody out of band. Change requests have long worked as report
-- then verify, and this brings the actions attached to a verdict into line --
-- the team reports, the security side confirms, and the register stays
-- trustworthy because only the security side marks something discharged.
ALTER TABLE review_results ADD COLUMN IF NOT EXISTS follow_up_reported_at timestamptz;
ALTER TABLE review_results ADD COLUMN IF NOT EXISTS follow_up_reported_by text REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_review_results_follow_up_reported_by ON review_results(follow_up_reported_by) WHERE follow_up_reported_by IS NOT NULL;
