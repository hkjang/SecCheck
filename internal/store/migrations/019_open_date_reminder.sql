-- The planned open date is the date the service goes live, reviewed or not. It
-- was recorded, sorted by and shown on the dashboard, and nothing ever acted
-- on it: a review could sit in progress while its launch date arrived, and the
-- first person to notice was whoever tried to launch.
--
-- This records when the people who can still do something about it were told.
ALTER TABLE review_requests ADD COLUMN IF NOT EXISTS open_date_reminded_at timestamptz;
