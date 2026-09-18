-- A grant is a handle bound to one service, never a stand-alone credential.
CREATE TABLE offline_grants (
    grant_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    profile TEXT NOT NULL,
    service TEXT NOT NULL,
    audiences TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (account_id, profile) REFERENCES profiles(account_id, name) ON DELETE CASCADE
) STRICT;
CREATE INDEX offline_grants_owner ON offline_grants(account_id, profile, created_at, grant_id);
