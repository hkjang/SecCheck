-- Every internal application counts "what is actually used" its own way, and
-- the answers land nowhere. This row lets an administrator attach a visitor
-- tracking snippet from the settings screen, the same shape in every service.
--
-- It is off. A fresh install and an upgraded one serve exactly the pages they
-- served before: no script, and the same content security policy. Momento is
-- the in-house collector and is proxied through this origin by default, so
-- turning it on adds no external address to that policy either.
INSERT INTO settings(key,value_json,sensitive) VALUES
 ('analytics', '{"enabled":false,"provider":"none","momento_url":"","momento_site_id":"","momento_proxy":true,"measurement_id":"","matomo_url":"","matomo_site_id":"","custom_snippet":"","allowed_hosts":"","include_admin":false,"placement":"head"}'::jsonb, false)
ON CONFLICT (key) DO NOTHING;
