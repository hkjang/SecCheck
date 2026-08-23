-- Completing a review refuses verdicts older than the answer they judged, but
-- an item's evidence is judged too: evidence adequacy is part of the verdict.
-- A file added, replaced with a new version, or deleted after the verdict
-- leaves the same stale judgement, so the check needs one timestamp covering
-- every way the evidence of an item can move.
CREATE OR REPLACE FUNCTION evidence_touched_at(item_id text) RETURNS timestamptz
LANGUAGE sql STABLE AS $$
        SELECT max(touched_at) FROM (
                SELECT GREATEST(e.created_at, COALESCE(e.deleted_at, e.created_at)) AS touched_at
                FROM evidences e WHERE e.submission_item_id = item_id
                UNION ALL
                SELECT v.created_at FROM evidence_versions v
                JOIN evidences e ON e.id = v.evidence_id WHERE e.submission_item_id = item_id
        ) touched;
$$;
