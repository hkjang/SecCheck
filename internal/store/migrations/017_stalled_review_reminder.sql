-- Every other kind of waiting in this service is chased: a change request has
-- a due date, a follow-up has one, a stopped queue raises an alert. The one
-- state nobody was reminded about is the one where the ball is with the
-- reviewer or the approver -- a review submitted and not picked up, started
-- and left, or waiting for a signature. The requester sees no movement and has
-- nowhere to push.
--
-- This records when the people whose turn it is were last told, so a review
-- that stays stuck does not send the same reminder every hour.
ALTER TABLE review_requests ADD COLUMN IF NOT EXISTS stalled_reminded_at timestamptz;
