-- A password an administrator typed for somebody else is a shared secret: the
-- person who set it knows a working credential for that account, and until now
-- nothing ever required it to be replaced. The flag makes it temporary.
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password boolean NOT NULL DEFAULT false;
