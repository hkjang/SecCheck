-- Every replacement of an evidence file was kept, encrypted, with its own hash
-- and uploader -- and none of it could be read back: the evidences row carries
-- only the current file, and nothing listed the versions behind it. A reviewer
-- could see that a file was on its third version without being able to ask
-- what the first two were.
--
-- The name the uploader gave the file was the one piece the history did not
-- record, because the evidences row was overwritten in place. Versions
-- uploaded from here on carry their own; the current version of existing
-- evidence is backfilled from the row that still holds its name, and older
-- versions keep an empty name because it was never written down.
ALTER TABLE evidence_versions ADD COLUMN IF NOT EXISTS original_filename text NOT NULL DEFAULT '';

UPDATE evidence_versions v SET original_filename = e.original_filename
  FROM evidences e
 WHERE e.id = v.evidence_id AND v.version = e.current_version AND v.original_filename = '';
