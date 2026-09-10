"""Profiles and their connections, as rows.

The change worth reading is that **a connection is a row rather than a field inside its
profile**. Held inside the profile, adding one was read-modify-write on the whole record:
two requests connecting two different services each read the profile, each added their
own connection to what they had read, and each wrote back a profile missing the other's.
A lost update, and it lost a credential's metadata while the credential itself sat in the
vault with nothing pointing at it.

As a row with its own key, adding a connection is an ``INSERT``. There is nothing to lose.

Account isolation is unchanged and is still structural: every method takes an
``account_id``, it is part of the primary key rather than something compared afterwards,
and a profile belonging to somebody else reads back as absent -- exactly like one that was
never created, because a distinguishable "not yours" tells one person that another person
has a profile by that name.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from keyring_api.domain.errors import (
    LimitExceededError,
    ProfileExistsError,
    ProfileNotFoundError,
)
from keyring_api.domain.profiles import (
    Connection,
    ConnectionStatus,
    CredentialKind,
    Profile,
)
from keyring_api.storage.times import (
    from_column,
    from_column_optional,
    to_column,
    to_column_optional,
)

if TYPE_CHECKING:
    import sqlite3
    from datetime import datetime

    from keyring_api.storage.database import Database

PROFILE_COLUMNS = "account_id, name, profile_id, created_at, updated_at"

CONNECTION_COLUMNS = (
    "account_id, profile_name, service, kind, status, created_at, updated_at, "
    "expires_at, scopes, stores_totp_seed, last_error"
)


class SqlProfileStore:
    """Profiles in one table, their connections in another."""

    def __init__(self, *, database: Database) -> None:
        self._db = database

    async def add(self, profile: Profile, *, cap: int) -> None:
        def write(connection: sqlite3.Connection) -> None:
            taken = connection.execute(
                "SELECT 1 FROM profiles WHERE account_id = ? AND name = ?",
                (profile.account_id, profile.name),
            ).fetchone()
            if taken is not None:
                msg = f"a profile named {profile.name!r} already exists"
                raise ProfileExistsError(msg)

            held = connection.execute(
                "SELECT count(*) AS total FROM profiles WHERE account_id = ?",
                (profile.account_id,),
            ).fetchone()["total"]
            if held >= cap:
                msg = f"at most {cap} profiles per account"
                raise LimitExceededError(msg)

            _insert_profile(connection, profile)
            for item in profile.connections:
                _upsert_connection(connection, profile.account_id, profile.name, item)

        await self._db.transact(write)

    async def get(self, account_id: str, name: str) -> Profile | None:
        # The account is half the key rather than something checked afterwards, so a
        # cross-account read is not a bug that can be introduced -- it cannot be
        # expressed.
        return await self._db.run(
            lambda connection: _read_one(
                connection, "WHERE account_id = ? AND name = ?", (account_id, name)
            )
        )

    async def list_for_account(self, account_id: str) -> list[Profile]:
        return await self._db.run(
            lambda connection: _read_many(
                connection,
                "WHERE account_id = ? ORDER BY created_at, name",
                (account_id,),
            )
        )

    async def put_connection(
        self, account_id: str, name: str, connection: Connection, *, cap: int, now: datetime
    ) -> Connection:
        def write(handle: sqlite3.Connection) -> Connection:
            touched = handle.execute(
                "UPDATE profiles SET updated_at = ? WHERE account_id = ? AND name = ?",
                (to_column(now), account_id, name),
            ).rowcount
            if not touched:
                # Reached after a network round trip, where the profile may have been
                # deleted while the provider was being called. The token just obtained is
                # discarded, which is right -- it was obtained for something gone.
                msg = "the profile this connection belongs to no longer exists"
                raise ProfileNotFoundError(msg)

            _check_connection_cap(handle, account_id, name, connection.service, cap=cap)
            _upsert_connection(handle, account_id, name, connection)

            stored = handle.execute(
                f"SELECT {CONNECTION_COLUMNS} FROM connections "  # noqa: S608
                "WHERE account_id = ? AND profile_name = ? AND service = ?",
                (account_id, name, connection.service),
            ).fetchone()
            return _connection_of(stored)

        return await self._db.transact(write)

    async def remove_connection(
        self, account_id: str, name: str, service: str, *, now: datetime
    ) -> bool:
        def write(handle: sqlite3.Connection) -> bool:
            gone = handle.execute(
                "DELETE FROM connections WHERE account_id = ? AND profile_name = ? AND service = ?",
                (account_id, name, service),
            ).rowcount
            if gone:
                handle.execute(
                    "UPDATE profiles SET updated_at = ? WHERE account_id = ? AND name = ?",
                    (to_column(now), account_id, name),
                )
            return gone > 0

        return await self._db.transact(write)

    async def delete(self, account_id: str, name: str) -> bool:
        # The connections go with it through the foreign key, not through a second
        # statement somebody has to remember to write.
        deleted = await self._db.execute(
            "DELETE FROM profiles WHERE account_id = ? AND name = ?", (account_id, name)
        )
        return deleted > 0

    async def count_for_account(self, account_id: str) -> int:
        return await self._db.count(
            "SELECT count(*) AS total FROM profiles WHERE account_id = ?", (account_id,)
        )

    async def all_profiles(self) -> list[Profile]:
        """Every profile, across every account.

        The one method that is not account-scoped, and it exists for exactly one caller:
        the health check, which reports *counts* of unwell connections and never names an
        account, a profile, or a service.
        """
        return await self._db.run(lambda connection: _read_many(connection, "", ()))


def _insert_profile(connection: sqlite3.Connection, profile: Profile) -> None:
    connection.execute(
        f"INSERT INTO profiles ({PROFILE_COLUMNS}) VALUES (?, ?, ?, ?, ?)",  # noqa: S608
        (
            profile.account_id,
            profile.name,
            profile.profile_id,
            to_column(profile.created_at),
            to_column(profile.updated_at),
        ),
    )


def _check_connection_cap(
    handle: sqlite3.Connection, account_id: str, name: str, service: str, *, cap: int
) -> None:
    """Refuse a new connection past the cap, but never refuse replacing one."""
    held = handle.execute(
        "SELECT count(*) AS total FROM connections WHERE account_id = ? AND profile_name = ?",
        (account_id, name),
    ).fetchone()["total"]
    replacing = handle.execute(
        "SELECT 1 FROM connections WHERE account_id = ? AND profile_name = ? AND service = ?",
        (account_id, name, service),
    ).fetchone()

    if replacing is None and held >= cap:
        msg = f"at most {cap} connections per profile"
        raise LimitExceededError(msg)


def _upsert_connection(
    handle: sqlite3.Connection, account_id: str, name: str, item: Connection
) -> None:
    """Write one connection, leaving ``created_at`` alone if there already was one.

    Not updating created_at is the point of doing this as an upsert rather than a delete
    and an insert: a refresh replaces a connection several times a day, and each one
    would otherwise reset how long the service had been connected.
    """
    handle.execute(
        f"INSERT INTO connections ({CONNECTION_COLUMNS})"  # noqa: S608
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT (account_id, profile_name, service) DO UPDATE SET"
        "   kind = excluded.kind,"
        "   status = excluded.status,"
        "   updated_at = excluded.updated_at,"
        "   expires_at = excluded.expires_at,"
        "   scopes = excluded.scopes,"
        "   stores_totp_seed = excluded.stores_totp_seed,"
        "   last_error = excluded.last_error",
        (
            account_id,
            name,
            item.service,
            item.kind.value,
            item.status.value,
            to_column(item.created_at),
            to_column(item.updated_at),
            to_column_optional(item.expires_at),
            json.dumps(list(item.scopes)),
            int(item.stores_totp_seed),
            item.last_error,
        ),
    )


def _read_one(
    connection: sqlite3.Connection, where: str, parameters: tuple[object, ...]
) -> Profile | None:
    found = _read_many(connection, where, parameters)
    return found[0] if found else None


def _read_many(
    connection: sqlite3.Connection, where: str, parameters: tuple[object, ...]
) -> list[Profile]:
    rows = connection.execute(
        f"SELECT {PROFILE_COLUMNS} FROM profiles {where}",  # noqa: S608
        parameters,
    ).fetchall()
    return [
        _profile_of(row, connections=_connections_of(connection, row["account_id"], row["name"]))
        for row in rows
    ]


def _connections_of(
    connection: sqlite3.Connection, account_id: str, profile_name: str
) -> tuple[Connection, ...]:
    rows = connection.execute(
        f"SELECT {CONNECTION_COLUMNS} FROM connections "  # noqa: S608
        "WHERE account_id = ? AND profile_name = ? ORDER BY created_at, service",
        (account_id, profile_name),
    ).fetchall()
    return tuple(_connection_of(row) for row in rows)


def _profile_of(row: sqlite3.Row, *, connections: tuple[Connection, ...]) -> Profile:
    return Profile(
        profile_id=row["profile_id"],
        account_id=row["account_id"],
        name=row["name"],
        created_at=from_column(row["created_at"]),
        updated_at=from_column(row["updated_at"]),
        connections=connections,
    )


def _connection_of(row: sqlite3.Row) -> Connection:
    return Connection(
        service=row["service"],
        kind=CredentialKind(row["kind"]),
        status=ConnectionStatus(row["status"]),
        created_at=from_column(row["created_at"]),
        updated_at=from_column(row["updated_at"]),
        expires_at=from_column_optional(row["expires_at"]),
        scopes=tuple(json.loads(row["scopes"])),
        stores_totp_seed=bool(row["stores_totp_seed"]),
        last_error=row["last_error"],
    )
