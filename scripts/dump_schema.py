"""Regenerate the checked-in schema snapshot.

The snapshot is what the schema-drift test compares against. Run this after changing a
migration, look at the diff, and commit it with the migration -- the diff is the point,
because it is the review of what the migration actually did.
"""

from __future__ import annotations

import asyncio
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from keyring_api.storage.database import Database
from keyring_api.storage.migrator import MIGRATIONS_DIR, migrate

SNAPSHOT = MIGRATIONS_DIR.parent / "schema.sql"


async def dump() -> str:
    """Build a database from the migrations and render every object in it."""
    with tempfile.TemporaryDirectory() as scratch:
        database = Database(Path(scratch) / "schema.db")
        try:
            await migrate(database, now=datetime(2026, 1, 1, tzinfo=UTC))
            rows = await database.fetch_all(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE sql IS NOT NULL ORDER BY type, name"
            )
        finally:
            await database.aclose()

    return "".join(f"{row['sql']};\n" for row in rows)


def main() -> None:
    SNAPSHOT.write_text(asyncio.run(dump()))
    print(f"wrote {SNAPSHOT}")


if __name__ == "__main__":
    main()
