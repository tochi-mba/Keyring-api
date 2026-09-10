"""Roles as rows, and the refusal that is now a foreign key.

The interesting change from the in-memory adapter is what happens when somebody tries to
delete a role an account still holds. That used to be a count taken by the caller and
passed in -- two calls, two locks, and a window between them in which the role could be
granted to somebody and then deleted out from under them. Here it is
``ON DELETE RESTRICT`` on ``account_roles.role_name``: one statement, and the database
refuses it. The ``held_by`` argument survives only because it is in the port; nothing
reads it.

**The built-in roles are rows too.** The port says a built-in name counts as taken, and
warns that an adapter keeping built-ins out of its table would lose that property
silently -- a custom role shadowing ``member`` would change what every account holds
without any account's roles changing. Seeding them into the table makes the primary key
the guarantee.

They are seeded from :mod:`keyring_api.domain.rbac` rather than written into the
migration, so there is one definition of what ``admin`` means rather than two that drift.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from keyring_api.accounts.roles import NO_SUCH_ROLE
from keyring_api.domain.errors import (
    InvalidRoleError,
    RoleExistsError,
    RoleInUseError,
    RoleNotFoundError,
)
from keyring_api.domain.rbac import BUILTIN_ROLES, Permission, Role, builtin_role, permissions_of
from keyring_api.storage.times import from_column_optional, to_column_optional

if TYPE_CHECKING:
    import sqlite3

    from keyring_api.storage.database import Database

ROLE_COLUMNS = "name, description, permissions, builtin, created_at, updated_at"


def seed_builtin_roles(database: Database) -> None:
    """Make sure every built-in role exists. Idempotent, and runs at startup.

    Synchronous, like the migration it follows: it happens once, in the composition root,
    before there is an event loop to keep responsive.

    Built-ins are upserted rather than inserted-if-absent, so a deployment that upgrades
    to a release which adds a permission to ``admin`` gets it. That is the point of them
    being code rather than data: they are what this version of the service says they are.
    """
    database.run_sync(
        lambda connection: connection.executemany(
            "INSERT INTO roles (name, description, permissions, builtin) VALUES (?, ?, ?, 1) "
            "ON CONFLICT (name) DO UPDATE SET "
            "  description = excluded.description, permissions = excluded.permissions",
            [
                (role.name, role.description, _dump(role.permissions))
                for role in (builtin_role(name) for name in BUILTIN_ROLES)
            ],
        )
    )


class SqlRoleStore:
    """Roles in a table, with the built-ins among them."""

    def __init__(self, *, database: Database) -> None:
        self._db = database

    async def get(self, name: str) -> Role | None:
        row = await self._db.fetch_one(
            f"SELECT {ROLE_COLUMNS} FROM roles WHERE name = ?",  # noqa: S608
            (name,),
        )
        return None if row is None else _role_of(row)

    async def require(self, name: str) -> Role:
        role = await self.get(name)
        if role is None:
            raise RoleNotFoundError(NO_SUCH_ROLE)
        return role

    async def list_all(self) -> list[Role]:
        # Built-ins first: they are the ones a reader needs to understand before the
        # custom roles that were defined in terms of them.
        rows = await self._db.fetch_all(
            f"SELECT {ROLE_COLUMNS} FROM roles ORDER BY builtin DESC, name"  # noqa: S608
        )
        return [_role_of(row) for row in rows]

    async def add(self, role: Role) -> None:
        def write(connection: sqlite3.Connection) -> None:
            taken = connection.execute(
                "SELECT 1 FROM roles WHERE name = ?", (role.name,)
            ).fetchone()
            if taken is not None:
                msg = f"a role named {role.name!r} already exists"
                raise RoleExistsError(msg)
            connection.execute(
                f"INSERT INTO roles ({ROLE_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)",  # noqa: S608
                (
                    role.name,
                    role.description,
                    _dump(role.permissions),
                    int(role.builtin),
                    to_column_optional(role.created_at),
                    to_column_optional(role.updated_at),
                ),
            )

        await self._db.transact(write)

    async def save(self, role: Role) -> None:
        await self._db.execute(
            "UPDATE roles SET description = ?, permissions = ?, updated_at = ? WHERE name = ?",
            (
                role.description,
                _dump(role.permissions),
                to_column_optional(role.updated_at),
                role.name,
            ),
        )

    async def delete(self, name: str, *, held_by: int) -> None:  # noqa: ARG002
        """Remove a custom role.

        ``held_by`` is ignored. It is in the port because the in-memory adapter needed the
        caller to count first; here the foreign key answers the same question inside the
        one statement that does the delete, which is the only way the answer cannot go
        stale between the check and the write.
        """

        def write(connection: sqlite3.Connection) -> None:
            row = connection.execute("SELECT builtin FROM roles WHERE name = ?", (name,)).fetchone()
            if row is None:
                raise RoleNotFoundError(NO_SUCH_ROLE)

            if row["builtin"]:
                msg = f"{name!r} is a built-in role and cannot be deleted"
                raise InvalidRoleError(msg)

            holders = connection.execute(
                "SELECT count(*) AS total FROM account_roles WHERE role_name = ?", (name,)
            ).fetchone()["total"]
            if holders:
                # Refused rather than cascaded. Silently stripping a permission from
                # everybody who had it is the kind of change nobody notices until
                # somebody cannot do their job. ON DELETE RESTRICT would refuse this
                # anyway; the count is here to say how many, in the message.
                msg = f"{holders} account(s) still hold {name!r}; revoke it first"
                raise RoleInUseError(msg)

            connection.execute("DELETE FROM roles WHERE name = ?", (name,))

        await self._db.transact(write)

    async def resolve(self, names: tuple[str, ...]) -> frozenset[Permission]:
        if not names:
            return frozenset()

        placeholders = ", ".join("?" for _ in names)
        rows = await self._db.fetch_all(
            f"SELECT {ROLE_COLUMNS} FROM roles WHERE name IN ({placeholders})",  # noqa: S608
            names,
        )
        # A name with no role behind it contributes nothing rather than raising -- it
        # simply matches no row. Roles cannot be deleted while held, so this only happens
        # if a database is restored from an inconsistent state, where the safe reading is
        # "no permissions".
        return permissions_of(_role_of(row) for row in rows)


def _dump(permissions: frozenset[Permission]) -> str:
    """Render a permission set as JSON, sorted so the column is stable to diff."""
    return json.dumps(sorted(permission.value for permission in permissions))


def _role_of(row: sqlite3.Row) -> Role:
    return Role(
        name=row["name"],
        permissions=frozenset(Permission(value) for value in json.loads(row["permissions"])),
        description=row["description"],
        builtin=bool(row["builtin"]),
        created_at=from_column_optional(row["created_at"]),
        updated_at=from_column_optional(row["updated_at"]),
    )
