-- Additive migration: retains all existing CyberGuard data.
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS agent_id text;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS event_source text;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS metadata jsonb;
CREATE TABLE IF NOT EXISTS monitoring_agents (
  id text PRIMARY KEY,
  owner_id text NOT NULL,
  device_id text NOT NULL,
  token_hash text NOT NULL UNIQUE,
  os text NOT NULL,
  version text NOT NULL,
  status text NOT NULL DEFAULT 'online',
  config jsonb NOT NULL DEFAULT '{"intervalSeconds":15,"enabled":true}'::jsonb,
  last_heartbeat timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS monitoring_agents_owner_idx ON monitoring_agents(owner_id);
