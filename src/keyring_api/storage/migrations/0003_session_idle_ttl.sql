-- Stamp the idle TTL used at session create so a later settings change does not
-- reshape an existing session. NULL means the session predates the stamp and
-- resolve_session keeps using the deployment TTL.

ALTER TABLE sessions ADD COLUMN idle_ttl_seconds INTEGER;
