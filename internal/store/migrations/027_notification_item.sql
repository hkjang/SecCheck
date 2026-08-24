-- A notice about one checklist item -- a comment, a correction, an assignment
-- -- could only link to the review it belongs to, so the reader arrived at a
-- list of a few hundred items with no idea which one was meant.
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS item_id text REFERENCES submission_items(id) ON DELETE SET NULL;
-- Deleting an item has to find the notices that point at it, so the foreign
-- key gets the index the rest of the schema keeps for the same reason.
CREATE INDEX IF NOT EXISTS notifications_item_idx ON notifications(item_id) WHERE item_id IS NOT NULL;
