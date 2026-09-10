"""Numbered SQL files, applied in order, recorded as they go.

Hand-rolled rather than Alembic. What a migration tool buys is autogeneration from an
ORM and support for a dozen engines; there is no ORM here and there is one engine, so
what would be left is "run these files in order", which is this module. The same
reasoning that made RFC 6238 hand-written in :mod:`keyring_api.credentials.totp`.

Each file is applied inside its own transaction, with the version recorded in the same
transaction. SQLite has transactional DDL, so a migration that fails halfway leaves the
schema exactly as it was rather than half-changed with nothing to say so.

One driver wrinkle worth knowing before editing this: ``executescript`` **commits any
open transaction before it runs**, so a migration cannot be wrapped in a ``BEGIN`` issued
from outside it. The ``BEGIN IMMEDIATE`` is therefore prepended to the script text, where
``executescript`` runs it as part of the script and leaves the transaction open for the
version row that follows.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

from keyring_api.core.logging import get_logger
from keyring_api.storage.times import to_column

if TYPE_CHECKING:
    import sqlite3
    from datetime import datetime

    from keyring_api.storage.database import Database

logger = get_logger(__name__)

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

SCHEMA_VERSION_DDL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER NOT NULL PRIMARY KEY,
    applied_at TEXT    NOT NULL
) STRICT
"""


class Migration:
    """One numbered SQL file."""

    __slots__ = ("path", "version")

    def __init__(self, path: Path) -> None:
        self.path = path
        self.version = int(path.name.split("_", 1)[0])

    @property
    def name(self) -> str:
        """The file's name, for the log line and for failure messages."""
        return self.path.name


def discover(directory: Path = MIGRATIONS_DIR) -> list[Migration]:
    """Every migration in a directory, oldest first.

    Ordered by the number rather than by the filename, so a tenth migration does not sort
    between the first and the second.
    """
    migrations = [Migration(path) for path in directory.glob("*.sql")]
    return sorted(migrations, key=lambda migration: migration.version)


async def migrate(database: Database, *, now: datetime, directory: Path = MIGRATIONS_DIR) -> int:
    """Bring the schema up to date. Returns how many migrations were applied.

    Idempotent: running it against an up-to-date database applies nothing and returns
    zero, which is what makes it safe to call on every start.
    """
    await database.transact(lambda connection: connection.execute(SCHEMA_VERSION_DDL))

    applied = {
        row["version"] for row in await database.fetch_all("SELECT version FROM schema_version")
    }
    pending = [migration for migration in discover(directory) if migration.version not in applied]

    for migration in pending:
        await database.run(
            partial(_apply, migration=migration, script=migration.path.read_text(), now=now)
        )
        logger.info("migration_applied", version=migration.version, name=migration.name)

    return len(pending)


def _apply(
    connection: sqlite3.Connection, *, migration: Migration, script: str, now: datetime
) -> None:
    """Run one migration and record it, as a single transaction.

    The rollback covers the script as well as the version row. A script that fails
    partway leaves its transaction *open* rather than unwinding it, so without this a
    broken migration would hold a write lock and leave half a schema behind.
    """
    try:
        # The SQL is a file shipped inside this package, not anything a caller supplies.
        connection.executescript(f"BEGIN IMMEDIATE;\n{script}")
        connection.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (migration.version, to_column(now)),
        )
    except BaseException:
        connection.rollback()
        raise
    connection.commit()
