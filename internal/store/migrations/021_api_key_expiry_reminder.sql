-- An API key carries an expiry date that nothing ever mentioned again: the
-- screen did not show it and nobody was told before it passed. An integration
-- built on the key -- a nightly export, an agent over MCP -- simply started
-- failing with 401 one morning. The column records when the owner was warned.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS expiry_reminded_at timestamptz;
