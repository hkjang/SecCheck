-- Somebody already signed in at Keycloak should not have to pass this
-- service's login screen too. With auto_login on, the browser asks the
-- provider once with prompt=none, which answers from an existing session or
-- comes straight back refused; the row that holds a sign-in in flight now
-- remembers which kind it was, because a refused silent attempt is the
-- ordinary answer for a signed-out person and must land on the login screen
-- marked so the browser does not ask again.
--
-- Off. A fresh install and an upgraded one show the login screen exactly as
-- before until an administrator turns the setting on.
ALTER TABLE oidc_states ADD COLUMN IF NOT EXISTS silent boolean NOT NULL DEFAULT false;
UPDATE settings SET value_json = '{"auto_login":false}'::jsonb || value_json WHERE key='oidc';
