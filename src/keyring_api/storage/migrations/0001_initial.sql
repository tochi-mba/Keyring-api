-- The whole schema, as one migration.
--
-- STRICT on every table. Without it SQLite will happily store a string in an INTEGER
-- column, and a row-mapper bug becomes data that reads back as the wrong type months
-- later rather than a failure at the write.
--
-- Datetimes are TEXT in the fixed-width format keyring_api.storage.times writes, chosen
-- so that ORDER BY on the column is chronological. See that module for why.

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

CREATE TABLE roles (
    name        TEXT    NOT NULL PRIMARY KEY,
    description TEXT    NOT NULL,
    permissions TEXT    NOT NULL,  -- JSON array of permission values
    builtin     INTEGER NOT NULL,
    created_at  TEXT,
    updated_at  TEXT
) STRICT;

-- Which account holds which role.
--
-- ON DELETE RESTRICT on role_name is load-bearing: it is what makes "a role still held
-- by somebody cannot be deleted" one statement instead of a count followed by a delete,
-- which two administrators can interleave.
--
-- position preserves the order the roles were assigned in, so an account reads back
-- holding exactly what it was given rather than an arbitrary permutation of it.
CREATE TABLE account_roles (
    account_id TEXT    NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    role_name  TEXT    NOT NULL REFERENCES roles(name)          ON DELETE RESTRICT,
    position   INTEGER NOT NULL,
    PRIMARY KEY (account_id, role_name)
) STRICT;

CREATE INDEX account_roles_by_role ON account_roles(role_name);

CREATE TABLE sessions (
    session_id          TEXT NOT NULL PRIMARY KEY,
    account_id          TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    token_hash          TEXT NOT NULL UNIQUE,
    created_at          TEXT NOT NULL,
    last_used_at        TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    absolute_expires_at TEXT NOT NULL
) STRICT;

CREATE INDEX sessions_by_account ON sessions(account_id, created_at);

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

CREATE INDEX grants_by_account ON grants(account_id);

CREATE TABLE profiles (
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    profile_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (account_id, name)
) STRICT;

-- A connection is a row rather than a field inside its profile.
--
-- That is the whole point of this table. Held inside the profile, adding a connection
-- was read-modify-write on the entire profile, and two requests adding two different
-- connections lost one of them. As a row with its own key, adding one is an INSERT.
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

-- Encrypted credential material. Three BLOBs and nothing readable.
--
-- Deliberately *not* foreign-keyed to profiles. The secret store is addressed by an
-- (account, profile, service) triple rather than by a profile row, and that
-- independence is the port's design -- every method names an account, so no call can
-- reach across one. Emptying it when a profile goes is the credential service's
-- explicit job, and there is a test that says so.
CREATE TABLE secrets (
    account_id   TEXT    NOT NULL,
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

-- The audit log has no foreign keys, on purpose.
--
-- Deleting an account must not delete the record that it was deleted. The consequence
-- is that an entry has to be self-describing: actor_id and target_id are opaque ids
-- whose rows may already be gone, and nothing here joins back to them.
--
-- sequence is the ordering, not `at`. The clock is injectable and two entries recorded
-- in the same tick share a timestamp, so "newest first" has to be insertion order to be
-- an order at all.
CREATE TABLE audit (
    sequence  INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    entry_id  TEXT    NOT NULL UNIQUE,
    at        TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    actor_id  TEXT    NOT NULL,
    target_id TEXT,
    detail    TEXT    NOT NULL
) STRICT;

CREATE INDEX audit_by_actor ON audit(actor_id, sequence);
