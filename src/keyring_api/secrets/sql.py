"""Encrypted credential material, as rows.

One row per ``(account, profile, service)`` triple, holding the four opaque byte strings
:mod:`keyring_api.secrets.envelope` produces and nothing else. A row is worthless to
anyone who reads the database without the master key, which is the same guarantee the
file store gave and the reason none of the crypto changed when the storage did.

**Why the triple is the primary key rather than a check.** Every method takes an
``account_id``, and it is half the key rather than something compared afterwards. There
is no call that *could* reach across an account, so the isolation is in the shape of the
table rather than in a condition somebody has to remember to write.

**Why there is no foreign key to profiles.** The port is addressed by a triple, not by a
profile row, and keeping it independent is deliberate: this store must be usable without
the profile table agreeing, and the credential service is the thing that knows a deleted
profile means deleted material. That cascade is explicit, and there is a test that says
so.

**Why there is no identifier validation.** The file store checked every segment for
``..`` and separators, because each became a path. Nothing here becomes a path and every
value is a bound parameter, so the class of bug that check existed for cannot be
expressed -- it is gone rather than unguarded.

**What is deliberately not defended against.** The server can decrypt everything, because
unattended OAuth refresh requires it -- see ADR-0006. Moving the ciphertext from files
into a database changes nothing about that.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keyring_api.secrets.envelope import Envelope, open_envelope, require_master, seal
from keyring_api.storage.times import to_column

if TYPE_CHECKING:
    import sqlite3

    from keyring_api.core.clock import Clock
    from keyring_api.secrets.base import Secret
    from keyring_api.storage.database import Database


class SqlSecretStore:
    """Envelope-encrypted secrets, one row each."""

    def __init__(self, *, database: Database, master_key: bytes | None, clock: Clock) -> None:
        self._db = database
        self._master = AESGCM(master_key) if master_key is not None else None
        self._clock = clock

    @property
    def is_sealed(self) -> bool:
        return self._master is None

    async def get(self, account_id: str, profile: str, service: str) -> Secret | None:
        master = require_master(self._master)

        row = await self._db.fetch_one(
            "SELECT version, wrapped_key, key_nonce, nonce, ciphertext FROM secrets "
            "WHERE account_id = ? AND profile_name = ? AND service = ?",
            (account_id, profile, service),
        )
        if row is None:
            return None

        return open_envelope(_envelope_of(row), master=master)

    async def put(self, account_id: str, profile: str, service: str, secret: Secret) -> None:
        master = require_master(self._master)
        envelope = seal(secret, master=master)
        now = to_column(self._clock.now())

        # Replacing rather than updating: a rewrite gets a fresh data key and a fresh
        # nonce, so no key or nonce is ever reused across two different plaintexts.
        await self._db.execute(
            "INSERT INTO secrets"
            " (account_id, profile_name, service, version, wrapped_key, key_nonce, nonce,"
            "  ciphertext, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (account_id, profile_name, service) DO UPDATE SET"
            "   version = excluded.version,"
            "   wrapped_key = excluded.wrapped_key,"
            "   key_nonce = excluded.key_nonce,"
            "   nonce = excluded.nonce,"
            "   ciphertext = excluded.ciphertext,"
            "   updated_at = excluded.updated_at",
            (
                account_id,
                profile,
                service,
                envelope.version,
                envelope.wrapped_key,
                envelope.key_nonce,
                envelope.nonce,
                envelope.ciphertext,
                now,
                now,
            ),
        )

    async def delete(self, account_id: str, profile: str, service: str) -> bool:
        deleted = await self._db.execute(
            "DELETE FROM secrets WHERE account_id = ? AND profile_name = ? AND service = ?",
            (account_id, profile, service),
        )
        return deleted > 0

    async def delete_profile(self, account_id: str, profile: str) -> int:
        return await self._db.execute(
            "DELETE FROM secrets WHERE account_id = ? AND profile_name = ?",
            (account_id, profile),
        )

    async def delete_account(self, account_id: str) -> int:
        return await self._db.execute("DELETE FROM secrets WHERE account_id = ?", (account_id,))


def _envelope_of(row: sqlite3.Row) -> Envelope:
    return Envelope(
        version=row["version"],
        wrapped_key=row["wrapped_key"],
        key_nonce=row["key_nonce"],
        nonce=row["nonce"],
        ciphertext=row["ciphertext"],
    )
