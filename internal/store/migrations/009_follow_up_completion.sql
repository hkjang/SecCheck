-- A conditional pass records what the team promised to do afterwards, and the
-- report collects those promises across every review. Listing them is only
-- half of it: without somewhere to record that an action was carried out, the
-- register can only ever grow, and an old entry looks the same whether it was
-- done last year or forgotten.
ALTER TABLE review_results ADD COLUMN IF NOT EXISTS follow_up_done_at timestamptz;
ALTER TABLE review_results ADD COLUMN IF NOT EXISTS follow_up_done_by text REFERENCES users(id);
ALTER TABLE review_results ADD COLUMN IF NOT EXISTS follow_up_note text NOT NULL DEFAULT '';

-- The register reads outstanding actions first and by date, over a table that
-- grows with every judged item.
CREATE INDEX IF NOT EXISTS idx_review_results_follow_up ON review_results(follow_up_done_at) WHERE btrim(follow_up) <> '';

-- Deleting a user must not scan every judged item to find the ones they
-- closed.
CREATE INDEX IF NOT EXISTS idx_review_results_follow_up_done_by ON review_results(follow_up_done_by) WHERE follow_up_done_by IS NOT NULL;
