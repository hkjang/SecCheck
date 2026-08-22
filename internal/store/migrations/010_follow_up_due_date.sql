-- A commitment with no date is not trackable. The register could say an
-- action was outstanding but never that it was late, so "3개월 내 보완"
-- written at review time meant nothing to the service afterwards. Change
-- requests have carried a due date from the start; the actions attached to a
-- verdict, which outlive the review, did not.
ALTER TABLE review_results ADD COLUMN IF NOT EXISTS follow_up_due_date date;

-- The register orders by what is late first over a table that grows with
-- every judged item.
CREATE INDEX IF NOT EXISTS idx_review_results_follow_up_due ON review_results(follow_up_due_date) WHERE btrim(follow_up) <> '' AND follow_up_done_at IS NULL;
