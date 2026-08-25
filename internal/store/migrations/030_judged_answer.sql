-- A verdict is a judgement of a particular answer. The service already knows
-- when the answer moved on afterwards -- the item is flagged "판정 후 답변
-- 변경" -- but not what it used to say, and neither does the audit log, which
-- records that a response was updated without keeping its text. The reviewer
-- re-checking a resubmission had to remember. The answer as judged is kept
-- with the verdict, one snapshot per judgement.
ALTER TABLE review_results ADD COLUMN IF NOT EXISTS judged_answer jsonb;
