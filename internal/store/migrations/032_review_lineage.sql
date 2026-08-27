-- A service is identified across reviews by its name, which is free text a
-- team is free to change: "결제 서비스" becomes "페이먼트 서비스" and every
-- earlier verdict, and every file that could have been carried forward,
-- silently stops being found. 재심의 복사 already knows which review a new one
-- came from, so the link is recorded and the lineage follows it as well as the
-- name.
ALTER TABLE review_requests ADD COLUMN IF NOT EXISTS copied_from text REFERENCES review_requests(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_review_requests_copied_from ON review_requests(copied_from);

-- review_lineage answers "which reviews are the same service as this one".
-- Reviews reached through the copy chain in either direction, plus anything
-- still carrying the same name -- a service that was never renamed keeps
-- exactly the behaviour it had before this existed.
CREATE OR REPLACE FUNCTION review_lineage(review_id text) RETURNS TABLE(id text)
LANGUAGE sql STABLE AS $$
        WITH RECURSIVE chain AS (
                SELECT r.id, r.copied_from FROM review_requests r WHERE r.id = review_id
                UNION
                SELECT r.id, r.copied_from
                FROM review_requests r
                JOIN chain c ON r.id = c.copied_from OR r.copied_from = c.id
        )
        SELECT c.id FROM chain c
        UNION
        SELECT r.id FROM review_requests r
        WHERE r.service_name = (SELECT s.service_name FROM review_requests s WHERE s.id = review_id);
$$;
