-- "How was this control judged before" is asked from every item panel: once
-- for the same service's earlier reviews, once for every other service's. Both
-- look items up by their code across every submission ever taken, and the only
-- indexes on the table are the submission and the source item, so each lookup
-- fell back to a scan of the whole table -- which grows by a hundred and
-- thirty rows for every review the installation has ever created.
CREATE INDEX IF NOT EXISTS idx_submission_items_code ON submission_items(item_code);
