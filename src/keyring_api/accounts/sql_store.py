"""Accounts, sessions and grants, as rows.

The CRUD is uninteresting. What is worth reading is where three guarantees moved to,
because none of them survives a naive translation of the code they replace.

**The last owner survives.** In memory this was a count and a write under one lock. The
naive port is ``SELECT count(*)`` and then ``UPDATE``, and it is wrong: two administrators
demoting the two remaining owners both read "there are two", both proceed, and the
deployment ends with none and no way to appoint one. Here the check and the write are one
``BEGIN IMMEDIATE`` transaction, submitted as a single callable -- so there is no instant
between them at which anything else can run. It stays correct if a connection pool ever
replaces the single connection, because SQLite's immediate transactions are serializable
among writers.

**A grant is redeemed once.** In memory this was an atomic ``pop``. Here it is one
statement -- ``UPDATE ... WHERE redeemed_at IS NULL RETURNING *`` -- so the loser of a
race gets an empty result rather than a second redemption.

**The session cap holds.** In memory the caller ran ``while count >= max: drop_oldest``,
which two concurrent logins interleave and overshoot. Here inserting and trimming are one
transaction, and the trim is a single ``DELETE`` with an ``OFFSET``.

Expired sessions stay invisible on read, as before: enforcing expiry only in the sweeper
would leave a session working between its deadline and the next sweep.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

from keyring_api.accounts.store import NO_SUCH_ACCOUNT
from keyring_api.domain.accounts import Account, AccountStatus
from keyring_api.domain.errors import (
    AccountExistsError,
    AccountNotFoundError,
    LastOwnerError,
    RoleNotFoundError,
)
from keyring_api.domain.grants import Grant, GrantPurpose
from keyring_api.domain.rbac import OWNER
from keyring_api.domain.sessions import Session
from keyring_api.storage.times import (
    from_column,
    from_column_optional,
    to_column,
    to_column_optional,
)

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.core.clock import Clock
    from keyring_api.storage.database import Database

LAST_OWNER = "this is the last owner; appoint another owner first"

ACCOUNT_COLUMNS = (
    "account_id, email, password_hash, created_at, updated_at, status, "
    "failed_attempts, locked_until"
)

SESSION_COLUMNS = (
    "session_id, account_id, token_hash, created_at, last_used_at, expires_at, absolute_expires_at"
)

GRANT_COLUMNS = (
    "grant_id, purpose, token_hash, created_at, expires_at, email, account_id, redeemed_at, revoked"
)


class SqlAccountStore:
    """Accounts, with their roles in a side table."""

    def __init__(self, *, database: Database) -> None:
        self._db = database

    async def add(self, account: Account) -> None:
        def write(connection: sqlite3.Connection) -> None:
            taken = connection.execute(
                "SELECT 1 FROM accounts WHERE email = ?", (account.email,)
            ).fetchone()
            if taken is not None:
                msg = f"an account already exists for {account.email!r}"
                raise AccountExistsError(msg)
            _insert_account(connection, account)

        await self._db.transact(write)

    async def get(self, account_id: str) -> Account | None:
        return await self._db.run(
            lambda connection: _read_one(connection, "WHERE account_id = ?", (account_id,))
        )

    async def get_by_email(self, email: str) -> Account | None:
        return await self._db.run(
            lambda connection: _read_one(connection, "WHERE email = ?", (email,))
        )

    async def save(self, account: Account) -> None:
        def write(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE accounts SET email = ?, password_hash = ?, updated_at = ?, "
                "status = ?, failed_attempts = ?, locked_until = ? WHERE account_id = ?",
                (
                    account.email,
                    account.password_hash,
                    to_column(account.updated_at),
                    account.status.value,
                    account.failed_attempts,
                    to_column_optional(account.locked_until),
                    account.account_id,
                ),
            )
            _write_roles(connection, account.account_id, account.roles)

        await self._db.transact(write)

    async def delete(self, account_id: str) -> bool:
        def write(connection: sqlite3.Connection) -> bool:
            if not _exists(connection, account_id):
                return False

            _check_owner_survives(
                connection,
                account_id,
                keeping_owner=False,
                roles=_roles_of(connection, account_id),
            )

            # The cascade is the schema's: sessions, grants, profiles, connections and
            # account_roles all go with it. Nothing here has to remember the order.
            connection.execute("DELETE FROM accounts WHERE account_id = ?", (account_id,))
            return True

        return await self._db.transact(write)

    async def count(self) -> int:
        return await self._db.count("SELECT count(*) AS total FROM accounts")

    async def list_all(self) -> list[Account]:
        return await self._db.run(
            lambda connection: _read_many(connection, "ORDER BY created_at, account_id", ())
        )

    async def count_holding(self, role: str) -> int:
        return await self._db.count(
            "SELECT count(*) AS total FROM account_roles WHERE role_name = ?", (role,)
        )

    async def set_roles(self, account_id: str, roles: tuple[str, ...], *, now: datetime) -> Account:
        def write(connection: sqlite3.Connection) -> Account:
            current = _read_one(connection, "WHERE account_id = ?", (account_id,))
            if current is None:
                raise AccountNotFoundError(NO_SUCH_ACCOUNT)

            _check_owner_survives(
                connection, account_id, keeping_owner=OWNER in roles, roles=current.roles
            )

            connection.execute(
                "UPDATE accounts SET updated_at = ? WHERE account_id = ?",
                (to_column(now), account_id),
            )
            _write_roles(connection, account_id, roles)
            return current.with_roles(roles, now=now)

        return await self._db.transact(write)


class SqlSessionStore:
    """Login sessions, with expiry applied on every read."""

    def __init__(self, *, database: Database, clock: Clock) -> None:
        self._db = database
        self._clock = clock

    async def add(self, session: Session) -> None:
        await self._db.execute(
            f"INSERT INTO sessions ({SESSION_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)",  # noqa: S608
            (
                session.session_id,
                session.account_id,
                session.token_hash,
                to_column(session.created_at),
                to_column(session.last_used_at),
                to_column(session.expires_at),
                to_column(session.absolute_expires_at),
            ),
        )

    async def get_by_token_hash(self, token_hash: str) -> Session | None:
        now = to_column(self._clock.now())
        # Expiry is in the WHERE clause rather than checked afterwards, so there is no
        # window in which a caller reads an expired session and decides for itself.
        row = await self._db.fetch_one(
            f"SELECT {SESSION_COLUMNS} FROM sessions "  # noqa: S608
            "WHERE token_hash = ? AND expires_at > ? AND absolute_expires_at > ?",
            (token_hash, now, now),
        )
        return None if row is None else _session_of(row)

    async def save(self, session: Session) -> None:
        await self._db.execute(
            "UPDATE sessions SET last_used_at = ?, expires_at = ?, absolute_expires_at = ? "
            "WHERE session_id = ?",
            (
                to_column(session.last_used_at),
                to_column(session.expires_at),
                to_column(session.absolute_expires_at),
                session.session_id,
            ),
        )

    async def revoke(self, session_id: str) -> bool:
        return (
            await self._db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,)) > 0
        )

    async def revoke_all(self, account_id: str, *, except_session_id: str | None = None) -> int:
        return await self._db.execute(
            "DELETE FROM sessions WHERE account_id = ? AND session_id IS NOT ?",
            (account_id, except_session_id),
        )

    async def count_for_account(self, account_id: str) -> int:
        now = to_column(self._clock.now())
        return await self._db.count(
            "SELECT count(*) AS total FROM sessions "
            "WHERE account_id = ? AND expires_at > ? AND absolute_expires_at > ?",
            (account_id, now, now),
        )

    async def drop_oldest(self, account_id: str) -> int:
        return await self._db.execute(
            "DELETE FROM sessions WHERE session_id = ("
            "  SELECT session_id FROM sessions WHERE account_id = ?"
            "  ORDER BY created_at, session_id LIMIT 1)",
            (account_id,),
        )

    async def add_within_cap(self, session: Session, *, cap: int) -> int:
        """Store a session and trim the account back to ``cap``, as one transaction.

        The caller used to loop -- count, drop the oldest, count again -- which two
        concurrent logins interleave, each seeing room the other is about to take. Here
        the insert and the trim cannot be separated, so the cap holds no matter how many
        logins arrive at once. Returns how many older sessions went.
        """

        def write(connection: sqlite3.Connection) -> int:
            connection.execute(
                f"INSERT INTO sessions ({SESSION_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)",  # noqa: S608
                (
                    session.session_id,
                    session.account_id,
                    session.token_hash,
                    to_column(session.created_at),
                    to_column(session.last_used_at),
                    to_column(session.expires_at),
                    to_column(session.absolute_expires_at),
                ),
            )
            return connection.execute(
                "DELETE FROM sessions WHERE session_id IN ("
                "  SELECT session_id FROM sessions WHERE account_id = ?"
                "  ORDER BY created_at DESC, session_id DESC LIMIT -1 OFFSET ?)",
                (session.account_id, cap),
            ).rowcount

        return await self._db.transact(write)

    async def purge_expired(self) -> int:
        now = to_column(self._clock.now())
        return await self._db.execute(
            "DELETE FROM sessions WHERE expires_at <= ? OR absolute_expires_at <= ?",
            (now, now),
        )


class SqlGrantStore:
    """Invites and password resets, redeemed by a single conditional update."""

    def __init__(self, *, database: Database) -> None:
        self._db = database

    async def add(self, grant: Grant) -> None:
        await self._db.execute(
            f"INSERT INTO grants ({GRANT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",  # noqa: S608
            (
                grant.grant_id,
                grant.purpose.value,
                grant.token_hash,
                to_column(grant.created_at),
                to_column(grant.expires_at),
                grant.email,
                grant.account_id,
                to_column_optional(grant.redeemed_at),
                int(grant.revoked),
            ),
        )

    async def get_by_token_hash(self, token_hash: str) -> Grant | None:
        row = await self._db.fetch_one(
            f"SELECT {GRANT_COLUMNS} FROM grants WHERE token_hash = ?",  # noqa: S608
            (token_hash,),
        )
        return None if row is None else _grant_of(row)

    async def redeem(self, token_hash: str, *, now: datetime) -> Grant | None:
        """One statement, so exactly one caller can win.

        Every failure -- unknown, expired, revoked, already redeemed -- lands in the same
        empty result, because a caller holding a guessed token must not learn which.
        """
        stamp = to_column(now)
        row = await self._db.transact(
            lambda connection: connection.execute(
                f"UPDATE grants SET redeemed_at = ? "  # noqa: S608
                "WHERE token_hash = ? AND redeemed_at IS NULL AND revoked = 0 "
                "AND expires_at > ? "
                f"RETURNING {GRANT_COLUMNS}",
                (stamp, token_hash, stamp),
            ).fetchone()
        )
        return None if row is None else _grant_of(row)

    async def revoke_all_for_account(self, account_id: str, purpose: GrantPurpose) -> int:
        return await self._db.execute(
            "UPDATE grants SET revoked = 1 WHERE account_id = ? AND purpose = ? AND revoked = 0",
            (account_id, purpose.value),
        )

    async def delete_for_account(self, account_id: str) -> int:
        return await self._db.execute("DELETE FROM grants WHERE account_id = ?", (account_id,))

    async def purge_expired(self, *, now: datetime) -> int:
        return await self._db.execute("DELETE FROM grants WHERE expires_at <= ?", (to_column(now),))


def _exists(connection: sqlite3.Connection, account_id: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM accounts WHERE account_id = ?", (account_id,)
    ).fetchone()
    return row is not None


def _insert_account(connection: sqlite3.Connection, account: Account) -> None:
    connection.execute(
        f"INSERT INTO accounts ({ACCOUNT_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",  # noqa: S608
        (
            account.account_id,
            account.email,
            account.password_hash,
            to_column(account.created_at),
            to_column(account.updated_at),
            account.status.value,
            account.failed_attempts,
            to_column_optional(account.locked_until),
        ),
    )
    _write_roles(connection, account.account_id, account.roles)


def _write_roles(connection: sqlite3.Connection, account_id: str, roles: tuple[str, ...]) -> None:
    """Replace an account's roles, keeping the order they were given in.

    Duplicates are collapsed to their first appearance. Holding a role twice means
    nothing -- the union of permissions is identical either way -- so it is normalized on
    the way in rather than stored and left for a reader of the listing to wonder at.
    """
    connection.execute("DELETE FROM account_roles WHERE account_id = ?", (account_id,))
    try:
        connection.executemany(
            "INSERT INTO account_roles (account_id, role_name, position) VALUES (?, ?, ?)",
            [(account_id, role, index) for index, role in enumerate(dict.fromkeys(roles))],
        )
    except sqlite3.IntegrityError as exc:
        # The foreign key refusing a role that does not exist. Callers check first, so
        # reaching here means the role was deleted between their check and this write --
        # a real race, and one whose answer is the domain's word for it rather than a
        # driver exception surfacing as a 500.
        msg = "one of those roles no longer exists"
        raise RoleNotFoundError(msg) from exc


def _roles_of(connection: sqlite3.Connection, account_id: str) -> tuple[str, ...]:
    rows = connection.execute(
        "SELECT role_name FROM account_roles WHERE account_id = ? ORDER BY position",
        (account_id,),
    ).fetchall()
    return tuple(row["role_name"] for row in rows)


def _check_owner_survives(
    connection: sqlite3.Connection,
    account_id: str,
    *,
    keeping_owner: bool,
    roles: tuple[str, ...],
) -> None:
    """Refuse a change that would leave the deployment with no owner.

    Called inside the transaction that performs the write, which is the entire point --
    see the module docstring for what happens when this check and its write are
    separated.
    """
    if keeping_owner or OWNER not in roles:
        return

    remaining = connection.execute(
        "SELECT count(*) AS total FROM account_roles WHERE role_name = ? AND account_id IS NOT ?",
        (OWNER, account_id),
    ).fetchone()["total"]
    if not remaining:
        raise LastOwnerError(LAST_OWNER)


def _read_one(
    connection: sqlite3.Connection, where: str, parameters: tuple[object, ...]
) -> Account | None:
    found = _read_many(connection, where, parameters)
    return found[0] if found else None


def _read_many(
    connection: sqlite3.Connection, where: str, parameters: tuple[object, ...]
) -> list[Account]:
    rows = connection.execute(
        f"SELECT {ACCOUNT_COLUMNS} FROM accounts {where}",  # noqa: S608
        parameters,
    ).fetchall()
    return [_account_of(row, roles=_roles_of(connection, row["account_id"])) for row in rows]


def _account_of(row: sqlite3.Row, *, roles: tuple[str, ...]) -> Account:
    return Account(
        account_id=row["account_id"],
        email=row["email"],
        password_hash=row["password_hash"],
        created_at=from_column(row["created_at"]),
        updated_at=from_column(row["updated_at"]),
        status=AccountStatus(row["status"]),
        failed_attempts=row["failed_attempts"],
        locked_until=from_column_optional(row["locked_until"]),
        roles=roles,
    )


def _session_of(row: sqlite3.Row) -> Session:
    return Session(
        session_id=row["session_id"],
        account_id=row["account_id"],
        token_hash=row["token_hash"],
        created_at=from_column(row["created_at"]),
        last_used_at=from_column(row["last_used_at"]),
        expires_at=from_column(row["expires_at"]),
        absolute_expires_at=from_column(row["absolute_expires_at"]),
    )


def _grant_of(row: sqlite3.Row) -> Grant:
    return Grant(
        grant_id=row["grant_id"],
        purpose=GrantPurpose(row["purpose"]),
        token_hash=row["token_hash"],
        created_at=from_column(row["created_at"]),
        expires_at=from_column(row["expires_at"]),
        email=row["email"],
        account_id=row["account_id"],
        redeemed_at=from_column_optional(row["redeemed_at"]),
        revoked=bool(row["revoked"]),
    )
