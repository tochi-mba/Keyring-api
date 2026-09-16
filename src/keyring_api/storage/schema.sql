CREATE INDEX account_roles_by_role ON account_roles(role_name);
CREATE INDEX audit_by_actor ON audit(actor_id, sequence);
CREATE INDEX grants_by_account ON grants(account_id);
CREATE INDEX sessions_by_account ON sessions(account_id, created_at);
CREATE TABLE account_roles (
    account_id TEXT    NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    role_name  TEXT    NOT NULL REFERENCES roles(name)          ON DELETE RESTRICT,
    position   INTEGER NOT NULL,
    PRIMARY KEY (account_id, role_name)
) STRICT;
CREATE TABLE accounts (
    account_id      TEXT    NOT NULL PRIMARY KEY,
    -- No COLLATE NOCASE: addresses are lowercased by domain.accounts.normalize_email
    -- before they ever reach here, so the normalization is the guarantee. NOCASE would
    -- be a second, ASCII-only guarantee that disagrees with the first on any address
    -- outside ASCII.
    email           TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT
) STRICT;
CREATE TABLE audit (
    sequence  INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    entry_id  TEXT    NOT NULL UNIQUE,
    at        TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    actor_id  TEXT    NOT NULL,
    target_id TEXT,
    detail    TEXT    NOT NULL
) STRICT;
CREATE TABLE connections (
    account_id       TEXT    NOT NULL,
    profile_name     TEXT    NOT NULL,
    service          TEXT    NOT NULL,
    kind             TEXT    NOT NULL,
    status           TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    expires_at       TEXT,
    scopes           TEXT    NOT NULL,  -- JSON array
    stores_totp_seed INTEGER NOT NULL,
    last_error       TEXT,
    PRIMARY KEY (account_id, profile_name, service),
    FOREIGN KEY (account_id, profile_name)
        REFERENCES profiles(account_id, name) ON DELETE CASCADE
) STRICT;
CREATE TABLE grants (
    grant_id    TEXT    NOT NULL PRIMARY KEY,
    purpose     TEXT    NOT NULL,
    token_hash  TEXT    NOT NULL UNIQUE,
    created_at  TEXT    NOT NULL,
    expires_at  TEXT    NOT NULL,
    email       TEXT,
    account_id  TEXT    REFERENCES accounts(account_id) ON DELETE CASCADE,
    redeemed_at TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0,
    -- Mirrors Grant.__post_init__. A grant that names neither an address nor an account
    -- authorises nothing and can never be matched to anybody.
    CHECK (email IS NOT NULL OR account_id IS NOT NULL)
) STRICT;
CREATE TABLE profiles (
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    profile_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (account_id, name)
) STRICT;
CREATE TABLE roles (
    name        TEXT    NOT NULL PRIMARY KEY,
    description TEXT    NOT NULL,
    permissions TEXT    NOT NULL,  -- JSON array of permission values
    builtin     INTEGER NOT NULL,
    created_at  TEXT,
    updated_at  TEXT
) STRICT;
CREATE TABLE schema_version (
    version    INTEGER NOT NULL PRIMARY KEY,
    applied_at TEXT    NOT NULL
) STRICT
;
CREATE TABLE "secrets" (
    account_id   TEXT    NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    profile_name TEXT    NOT NULL,
    service      TEXT    NOT NULL,
    version      INTEGER NOT NULL,
    wrapped_key  BLOB    NOT NULL,
    key_nonce    BLOB    NOT NULL,
    nonce        BLOB    NOT NULL,
    ciphertext   BLOB    NOT NULL,
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    PRIMARY KEY (account_id, profile_name, service)
) STRICT;
CREATE TABLE sessions (
    session_id          TEXT NOT NULL PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    token_hash          TEXT NOT NULL UNIQUE,
    created_at          TEXT NOT NULL,
    last_used_at        TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL
, idle_ttl_seconds INTEGER) STRICT;
CREATE TABLE sqlite_sequence(name,seq);
