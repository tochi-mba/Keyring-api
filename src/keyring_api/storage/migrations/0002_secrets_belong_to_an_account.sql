-- Give credential material a foreign key to the account that owns it.
--
-- 0001 left `secrets` unreferenced so that deleting an account meant deleting the row,
-- then sweeping the vault, then hoping the second half happened. That sequence had a
-- documented "lesser harm": if the sweep failed, encrypted material was left with
-- nothing pointing at it -- unreachable through the API, invisible to every later
-- delete, and still decryptable by anyone holding the master key and the file.
--
-- With everything in one database that is no longer a trade worth making. The cascade
-- makes the whole deletion one transaction, and the harm becomes impossible rather than
-- merely lesser.
--
-- Deliberately still NOT keyed to `profiles`. The secret store is addressed by an
-- (account, profile, service) triple rather than by a profile row, and that independence
-- is the port's design; emptying a profile is the credential service's explicit job.

CREATE TABLE secrets_new (
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

-- Rows whose account is already gone are dropped rather than carried over. They are the
-- exact orphans this key exists to prevent, and copying them would fail the migration
-- and refuse to start the service over material nobody can reach anyway.
INSERT INTO secrets_new
SELECT * FROM secrets WHERE account_id IN (SELECT account_id FROM accounts);

DROP TABLE secrets;

ALTER TABLE secrets_new RENAME TO secrets;
