-- A re-review copies last year's answers into the new checklist, which is the
-- point of the feature: most of them are still true. But a copied answer looked
-- exactly like one somebody had just written, so a cycle where nobody
-- re-examined anything was indistinguishable from a cycle where everybody did
-- -- which is the classic way a periodic review turns into a rubber stamp.
-- The timestamp says the answer came from the previous review and has not been
-- touched since; any save clears it.
ALTER TABLE responses ADD COLUMN IF NOT EXISTS carried_at timestamptz;
