-- evidence_touched_at() answers "when did this item's evidence last move",
-- which has to include files that were deleted -- removing a file after a
-- verdict is exactly what it exists to catch. The only index on the column
-- excludes deleted rows (idx_evidences_item is partial), so that lookup could
-- not use it and fell back to a scan of the whole table, once per checklist
-- item, every time a review was opened.
CREATE INDEX IF NOT EXISTS idx_evidences_item_all ON evidences(submission_item_id);
