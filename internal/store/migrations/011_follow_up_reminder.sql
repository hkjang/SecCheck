-- A due date nobody is told about is only marginally better than no date: it
-- is found by opening the report, which is exactly what does not happen
-- between reviews. Change requests have been reminded on since the beginning;
-- this lets the actions attached to a verdict be reminded on the same way,
-- and once each rather than every hour the worker runs.
ALTER TABLE review_results ADD COLUMN IF NOT EXISTS follow_up_reminded_at timestamptz;
