-- Whether a stored file still matches its record is state, not an event: a
-- notification is read once and swept away by retention, and after that
-- nothing on any screen says the volume is missing a file. The reason lives on
-- the row so the system screen can list what is broken until it is fixed.
ALTER TABLE evidences ADD COLUMN IF NOT EXISTS verify_error text NOT NULL DEFAULT '';
