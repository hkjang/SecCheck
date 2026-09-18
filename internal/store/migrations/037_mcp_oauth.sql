-- MCP over SSO: the personal key stays, and a Keycloak access token opens
-- /mcp as well once an administrator turns this on. The keys follow the
-- company's MCP OAuth standard (mcp.oauth.enabled, .resource, .audience,
-- .scopes); a settings row here is one flat JSON object, so they are the
-- oauth_* keys of the mcp row. The issuer and username claim are the web
-- sign-in's (settings.oidc) and are not asked for twice.
--
-- Off. A fresh install and an upgraded one serve no metadata document, add
-- no header to a refusal, and refuse a token the way they refuse a wrong
-- key, until the switch is turned on.
INSERT INTO settings(key,value_json,sensitive) VALUES
 ('mcp', '{"oauth_enabled":false,"oauth_resource":"","oauth_audience":"","oauth_scopes":"read"}'::jsonb, false)
ON CONFLICT (key) DO NOTHING;
