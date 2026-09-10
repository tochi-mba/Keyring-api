"""Applying numbered SQL files, once each, atomically.

The snapshot test at the bottom is the one that earns its keep. Hand-rolled migrations
have exactly one characteristic failure -- the DDL and the row-mappers drifting apart --
and comparing the built schema against a checked-in copy is what catches it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from keyring_api.storage.database import Database
from keyring_api.storage.migrator import MIGRATIONS_DIR, discover, migrate
from keyring_api.storage.times import from_column
from tests.fakes.clock import EPOCH

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path


@pytest.fixture
async def blank(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(tmp_path / "blank.db")
    try:
        yield database
    finally:
        await database.aclose()


async def table_names(database: Database) -> set[str]:
    rows = await database.fetch_all(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    )
    return {row["name"] for row in rows}


class TestDiscovery:
    def test_it_finds_the_shipped_migrations(self) -> None:
        found = discover()

        assert found
        assert found[0].version == 1
        assert found[0].name == "0001_initial.sql"

    def test_it_orders_by_number_not_by_name(self, tmp_path: Path) -> None:
        # "0010" sorts before "0002" as a string only if the padding is wrong, but a
        # migration written as "10_" would, which is why the number is what orders them.
        for name in ("2_second.sql", "10_tenth.sql", "1_first.sql"):
            (tmp_path / name).write_text("SELECT 1;")

        assert [migration.version for migration in discover(tmp_path)] == [1, 2, 10]


class TestApplying:
    async def test_it_builds_the_schema(self, blank: Database) -> None:
        applied = await migrate(blank, now=EPOCH)

        assert applied == 1
        assert "accounts" in await table_names(blank)

    async def test_it_records_what_it_applied(self, blank: Database) -> None:
        await migrate(blank, now=EPOCH)

        row = await blank.fetch_one("SELECT version, applied_at FROM schema_version")

        assert row is not None
        assert row["version"] == 1
        assert from_column(row["applied_at"]) == EPOCH

    async def test_running_it_again_applies_nothing(self, blank: Database) -> None:
        await migrate(blank, now=EPOCH)

        assert await migrate(blank, now=EPOCH) == 0

    async def test_running_it_again_changes_nothing(self, blank: Database) -> None:
        await migrate(blank, now=EPOCH)
        before = await table_names(blank)

        await migrate(blank, now=EPOCH)

        assert await table_names(blank) == before

    async def test_it_applies_only_what_is_missing(self, blank: Database, tmp_path: Path) -> None:
        directory = tmp_path / "steps"
        directory.mkdir()
        (directory / "0001_one.sql").write_text("CREATE TABLE one (x TEXT NOT NULL) STRICT;")
        await migrate(blank, now=EPOCH, directory=directory)

        (directory / "0002_two.sql").write_text("CREATE TABLE two (x TEXT NOT NULL) STRICT;")

        assert await migrate(blank, now=EPOCH, directory=directory) == 1
        assert {"one", "two"} <= await table_names(blank)


class TestAtomicity:
    async def test_a_migration_that_fails_partway_leaves_nothing_behind(
        self, blank: Database, tmp_path: Path
    ) -> None:
        """SQLite has transactional DDL, and this is the test that says we use it.

        Without the rollback the first table would exist, unrecorded, and the next start
        would try to create it again and fail forever.
        """
        directory = tmp_path / "broken"
        directory.mkdir()
        (directory / "0001_half.sql").write_text(
            "CREATE TABLE good (x TEXT NOT NULL) STRICT;\nCREATE TABLE bad (;"
        )

        with pytest.raises(Exception, match="syntax error"):
            await migrate(blank, now=EPOCH, directory=directory)

        assert "good" not in await table_names(blank)
        assert await blank.fetch_all("SELECT version FROM schema_version") == []

    async def test_a_failed_version_row_rolls_the_schema_back_too(
        self, blank: Database, tmp_path: Path
    ) -> None:
        """The version row and the DDL commit together or not at all.

        Forced here by making the migration insert its own conflicting version row, so
        the failure lands on the INSERT rather than on the script.
        """
        directory = tmp_path / "conflict"
        directory.mkdir()
        (directory / "0001_clash.sql").write_text(
            "CREATE TABLE good (x TEXT NOT NULL) STRICT;\n"
            "INSERT INTO schema_version (version, applied_at) VALUES (1, 'earlier');"
        )
        await blank.transact(
            lambda connection: connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_version ("
                "  version INTEGER NOT NULL PRIMARY KEY, applied_at TEXT NOT NULL) STRICT"
            )
        )

        with pytest.raises(Exception, match="UNIQUE constraint"):
            await migrate(blank, now=EPOCH, directory=directory)

        assert "good" not in await table_names(blank)

    async def test_the_database_is_usable_after_a_failed_migration(
        self, blank: Database, tmp_path: Path
    ) -> None:
        """A held write lock would make every later call hang or fail."""
        directory = tmp_path / "broken"
        directory.mkdir()
        (directory / "0001_half.sql").write_text("CREATE TABLE bad (;")

        with pytest.raises(Exception, match="syntax error"):
            await migrate(blank, now=EPOCH, directory=directory)

        assert await migrate(blank, now=EPOCH) == 1


class TestSchemaSnapshot:
    """The built schema, compared against a checked-in copy.

    When this fails, either the migration changed and the snapshot needs regenerating --
    ``make schema`` -- or something changed the schema that did not mean to.
    """

    async def test_it_matches_the_checked_in_snapshot(self, database: Database) -> None:
        snapshot = (MIGRATIONS_DIR.parent / "schema.sql").read_text()

        assert await dump_schema(database) == snapshot


async def dump_schema(database: Database) -> str:
    """Every object in the database, in a stable order."""
    rows = await database.fetch_all(
        "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name"
    )
    return "".join(f"{row['sql']};\n" for row in rows)
