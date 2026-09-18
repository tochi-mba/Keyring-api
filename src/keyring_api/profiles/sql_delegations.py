"""Offline grant writes and revocation use the database's single writer."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from keyring_api.domain.delegation import OfflineGrant
from keyring_api.domain.errors import LimitExceededError, ProfileNotFoundError
from keyring_api.storage.times import from_column, from_column_optional, to_column

if TYPE_CHECKING:
    import sqlite3
    from datetime import datetime

    from keyring_api.storage.database import Database


class SqlDelegationStore:
    """Every account-facing lookup is explicitly bound to its account and profile."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def add(self, grant: OfflineGrant, *, cap: int, now: datetime) -> None:
        def write(connection: sqlite3.Connection) -> None:
            found = connection.execute(
                "SELECT 1 FROM profiles WHERE account_id = ? AND name = ?",
                (grant.account_id, grant.profile),
            ).fetchone()
            if found is None:
                msg = "no profile of that name"
                raise ProfileNotFoundError(msg)
            count = connection.execute(
                "SELECT count(*) FROM offline_grants WHERE account_id = ? AND profile = ? "
                "AND revoked_at IS NULL AND expires_at > ?",
                (grant.account_id, grant.profile, to_column(now)),
            ).fetchone()[0]
            if count >= cap:
                msg = "the offline grant limit for this profile was reached"
                raise LimitExceededError(msg)
            connection.execute(
                "INSERT INTO offline_grants "
                "(grant_id, account_id, profile, service, audiences, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    grant.grant_id,
                    grant.account_id,
                    grant.profile,
                    grant.service,
                    json.dumps(grant.audiences),
                    to_column(grant.created_at),
                    to_column(grant.expires_at),
                ),
            )

        await self._db.transact(write)

    async def for_exchange(self, grant_id: str, service: str) -> OfflineGrant | None:
        rows = await self._db.fetch_all(
            "SELECT * FROM offline_grants WHERE grant_id = ? AND service = ?",
            (grant_id, service),
        )
        return _grant(rows[0]) if rows else None

    async def list_for_profile(self, account_id: str, profile: str) -> list[OfflineGrant]:
        rows = await self._db.fetch_all(
            "SELECT * FROM offline_grants WHERE account_id = ? AND profile = ? "
            "ORDER BY created_at, grant_id",
            (account_id, profile),
        )
        return [_grant(row) for row in rows]

    async def revoke(self, account_id: str, profile: str, grant_id: str, *, now: datetime) -> bool:
        rows = await self._db.execute(
            "UPDATE offline_grants SET revoked_at = COALESCE(revoked_at, ?) "
            "WHERE account_id = ? AND profile = ? AND grant_id = ?",
            (to_column(now), account_id, profile, grant_id),
        )
        return rows > 0


def _grant(row: sqlite3.Row) -> OfflineGrant:
    return OfflineGrant(
        grant_id=row["grant_id"],
        account_id=row["account_id"],
        profile=row["profile"],
        service=row["service"],
        audiences=tuple(json.loads(row["audiences"])),
        created_at=from_column(row["created_at"]),
        expires_at=from_column(row["expires_at"]),
        revoked_at=from_column_optional(row["revoked_at"]),
    )
