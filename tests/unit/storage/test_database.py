"""The connection wrapper, and the two hazards it exists to remove.

The interesting tests here are not the CRUD ones. They are:

* :class:`TestCancellation`, which is the reason this is a single-worker executor rather
  than ``asyncio.to_thread`` under an ``asyncio.Lock``.
* :class:`TestForeignKeys`, because ``PRAGMA foreign_keys`` can report success and do
  nothing, and a vault whose cascades silently stopped happening looks fine until an
  account is deleted.
"""

from __future__ import annotations

import asyncio
import gc
import sqlite3
import threading
import warnings
from functools import partial
from typing import TYPE_CHECKING

import pytest

from keyring_api.storage.database import (
    CONNECT_PRAGMAS,
    DATABASE_FILE_MODE,
    Database,
    StorageError,
    make_private,
    require_foreign_keys,
)
from tests.support.filemode import assert_mode

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path


@pytest.fixture
async def db(tmp_path: Path) -> AsyncIterator[Database]:
    database = Database(tmp_path / "scratch.db")
    await database.execute("CREATE TABLE t (x INTEGER NOT NULL PRIMARY KEY, y TEXT) STRICT")
    try:
        yield database
    finally:
        await database.aclose()


class TestReadsAndWrites:
    async def test_it_writes_and_reads_back(self, db: Database) -> None:
        await db.execute("INSERT INTO t (x, y) VALUES (?, ?)", (1, "one"))

        row = await db.fetch_one("SELECT y FROM t WHERE x = ?", (1,))

        assert row is not None
        assert row["y"] == "one"

    async def test_fetch_one_is_none_when_there_is_no_row(self, db: Database) -> None:
        assert await db.fetch_one("SELECT y FROM t WHERE x = ?", (404,)) is None

    async def test_fetch_all_returns_every_row(self, db: Database) -> None:
        await db.execute("INSERT INTO t (x, y) VALUES (1, 'a'), (2, 'b')")

        rows = await db.fetch_all("SELECT x FROM t ORDER BY x")

        assert [row["x"] for row in rows] == [1, 2]

    async def test_execute_reports_how_many_rows_it_touched(self, db: Database) -> None:
        await db.execute("INSERT INTO t (x, y) VALUES (1, 'a'), (2, 'b')")

        assert await db.execute("DELETE FROM t WHERE x > 0") == 2

    async def test_it_remembers_where_the_file_is(self, tmp_path: Path, db: Database) -> None:
        assert db.path == tmp_path / "scratch.db"

    async def test_it_creates_the_directory_it_was_pointed_at(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "nested" / "deeper" / "keyring.db")
        try:
            assert (tmp_path / "nested" / "deeper").is_dir()
        finally:
            await database.aclose()


class TestTransactions:
    async def test_a_failed_transaction_leaves_nothing_behind(self, db: Database) -> None:
        def write_then_fail(connection: sqlite3.Connection) -> None:
            connection.execute("INSERT INTO t (x, y) VALUES (1, 'a')")
            msg = "changed my mind"
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="changed my mind"):
            await db.transact(write_then_fail)

        assert await db.fetch_all("SELECT x FROM t") == []

    async def test_a_transaction_that_returns_commits(self, db: Database) -> None:
        def write_two(connection: sqlite3.Connection) -> int:
            connection.execute("INSERT INTO t (x, y) VALUES (1, 'a')")
            connection.execute("INSERT INTO t (x, y) VALUES (2, 'b')")
            return 2

        assert await db.transact(write_two) == 2
        assert len(await db.fetch_all("SELECT x FROM t")) == 2

    async def test_the_connection_is_usable_after_a_rollback(self, db: Database) -> None:
        await db.execute("INSERT INTO t (x, y) VALUES (1, 'a')")

        with pytest.raises(sqlite3.IntegrityError):
            await db.execute("INSERT INTO t (x, y) VALUES (1, 'again')")

        await db.execute("INSERT INTO t (x, y) VALUES (2, 'b')")

        rows = await db.fetch_all("SELECT y FROM t ORDER BY x")
        assert [row["y"] for row in rows] == ["a", "b"]


class TestCancellation:
    """Why this is an executor and not a lock.

    Under ``asyncio.to_thread`` guarded by an ``asyncio.Lock``, cancelling the awaiting
    task releases the lock while the thread is still inside the transaction, and the next
    caller enters the same connection from a second thread. These tests say that cannot
    happen here.
    """

    async def test_a_cancelled_write_still_completes(self, db: Database) -> None:
        """The documented cost of the design, asserted rather than assumed.

        Cancelling the awaiting task does not cancel work the thread has already picked
        up. That is deliberate -- it is what makes a transaction indivisible -- and it
        means a request abandoned mid-write can still land. The in-memory stores behaved
        the same way, having no ``await`` inside their locks.
        """
        started = threading.Event()
        release = threading.Event()

        def slow_insert(connection: sqlite3.Connection) -> None:
            started.set()
            release.wait(timeout=5)
            connection.execute("INSERT INTO t (x, y) VALUES (1, 'first')")

        task = asyncio.create_task(db.transact(slow_insert))
        for _ in range(1000):
            if started.is_set():
                break
            await asyncio.sleep(0.001)
        assert started.is_set(), "the write never reached the worker thread"

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        release.set()
        # Queued behind the write still in flight, so awaiting this is also how we wait
        # for that one to finish -- which is itself the serialization under test.
        await db.execute("INSERT INTO t (x, y) VALUES (2, 'second')")

        rows = await db.fetch_all("SELECT y FROM t ORDER BY x")
        assert [row["y"] for row in rows] == ["first", "second"]

    async def test_concurrent_callers_never_overlap(self, db: Database) -> None:
        """Two transactions submitted at once run one after the other, never together.

        The counter is the assertion: if a second call ever entered the connection while
        a first was inside it, ``depth`` would reach two.
        """
        depth = 0
        deepest = 0

        def nested(connection: sqlite3.Connection, *, value: int) -> None:
            nonlocal depth, deepest
            depth += 1
            deepest = max(deepest, depth)
            connection.execute("INSERT INTO t (x, y) VALUES (?, 'x')", (value,))
            depth -= 1

        await asyncio.gather(*(db.transact(partial(nested, value=value)) for value in range(20)))

        assert deepest == 1
        assert len(await db.fetch_all("SELECT x FROM t")) == 20


class TestForeignKeys:
    async def test_they_are_on(self, db: Database) -> None:
        row = await db.fetch_one("PRAGMA foreign_keys")

        assert row is not None
        assert row[0] == 1

    async def test_a_violating_write_actually_raises(self, db: Database) -> None:
        """Reading the pragma back is not enough on its own -- this is the other half.

        A build where the pragma reported ``1`` but the cascade never fired would pass
        the test above and fail this one.
        """
        await db.execute("CREATE TABLE parent (id TEXT NOT NULL PRIMARY KEY) STRICT")
        await db.execute(
            "CREATE TABLE child ("
            "  id TEXT NOT NULL PRIMARY KEY,"
            "  parent_id TEXT NOT NULL REFERENCES parent(id) ON DELETE CASCADE"
            ") STRICT"
        )

        with pytest.raises(sqlite3.IntegrityError):
            await db.execute("INSERT INTO child (id, parent_id) VALUES ('c', 'nobody')")

    async def test_a_cascade_actually_cascades(self, db: Database) -> None:
        await db.execute("CREATE TABLE parent (id TEXT NOT NULL PRIMARY KEY) STRICT")
        await db.execute(
            "CREATE TABLE child ("
            "  id TEXT NOT NULL PRIMARY KEY,"
            "  parent_id TEXT NOT NULL REFERENCES parent(id) ON DELETE CASCADE"
            ") STRICT"
        )
        await db.execute("INSERT INTO parent (id) VALUES ('p')")
        await db.execute("INSERT INTO child (id, parent_id) VALUES ('c', 'p')")

        await db.execute("DELETE FROM parent WHERE id = 'p'")

        assert await db.fetch_all("SELECT id FROM child") == []

    def test_the_guard_refuses_a_connection_without_them(self) -> None:
        connection = sqlite3.connect(":memory:")

        with pytest.raises(StorageError, match="foreign keys are not enabled"):
            require_foreign_keys(connection)

    def test_the_guard_accepts_a_connection_with_them(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.execute("PRAGMA foreign_keys = ON")

        require_foreign_keys(connection)

    async def test_opening_a_database_refuses_when_the_pragma_does_not_take(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The startup guard, exercised by removing the pragma that satisfies it."""
        monkeypatch.setattr(
            "keyring_api.storage.database.CONNECT_PRAGMAS",
            tuple(p for p in CONNECT_PRAGMAS if "foreign_keys" not in p),
        )

        threads_before = threading.active_count()

        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            with pytest.raises(StorageError, match="foreign keys are not enabled"):
                Database(tmp_path / "unsafe.db")

        # A refused connection is closed by the code that opened it. Anything dropped on
        # the floor is collected here, inside the filter that would make it an error rather
        # than a line on stderr -- which is how Python 3.13 first reported this leak.
        with warnings.catch_warnings():
            warnings.simplefilter("error", ResourceWarning)
            gc.collect()
        assert threading.active_count() == threads_before, "the worker thread was given back"


class TestJournalMode:
    async def test_it_is_wal(self, db: Database) -> None:
        row = await db.fetch_one("PRAGMA journal_mode")

        assert row is not None
        assert row[0] == "wal"

    async def test_writes_are_synchronous(self, db: Database) -> None:
        row = await db.fetch_one("PRAGMA synchronous")

        assert row is not None
        assert row[0] == 2  # FULL


class TestClosing:
    async def test_closing_twice_is_harmless(self, tmp_path: Path) -> None:
        database = Database(tmp_path / "twice.db")

        await database.aclose()
        await database.aclose()

    async def test_data_survives_the_close(self, tmp_path: Path) -> None:
        path = tmp_path / "survivor.db"
        first = Database(path)
        await first.execute("CREATE TABLE t (x TEXT NOT NULL) STRICT")
        await first.execute("INSERT INTO t (x) VALUES ('kept')")
        await first.aclose()

        second = Database(path)
        try:
            rows = await second.fetch_all("SELECT x FROM t")
        finally:
            await second.aclose()

        assert [row["x"] for row in rows] == ["kept"]


class TestFileMode:
    """The protection the file store had and SQLite does not give by default.

    SQLite creates its files 0644. The credential material in them is encrypted, but the
    password hashes, session token hashes and addresses are not, and never were going to
    be -- so the mode is doing real work here rather than belt-and-braces.
    """

    async def test_the_database_is_readable_only_by_its_owner(self, db: Database) -> None:
        assert_mode(db.path, DATABASE_FILE_MODE)

    async def test_the_write_ahead_log_is_too(self, db: Database) -> None:
        # It holds committed rows that have not been checkpointed yet, so a readable WAL
        # is a readable database with extra steps.
        await db.execute("INSERT INTO t (x, y) VALUES (1, 'a')")
        wal = db.path.with_name(db.path.name + "-wal")

        assert wal.exists()
        assert_mode(wal, DATABASE_FILE_MODE)

    async def test_reopening_does_not_loosen_it(self, tmp_path: Path) -> None:
        path = tmp_path / "reopened.db"
        first = Database(path)
        await first.execute("CREATE TABLE t (x TEXT NOT NULL) STRICT")
        await first.aclose()
        path.chmod(0o644)

        second = Database(path)
        try:
            assert_mode(path, DATABASE_FILE_MODE)
        finally:
            await second.aclose()

    async def test_a_directory_it_creates_is_owner_only(self, tmp_path: Path) -> None:
        # A world-readable directory says which files exist even when none can be read.
        database = Database(tmp_path / "fresh" / "keyring.db")
        try:
            assert_mode(tmp_path / "fresh", 0o700)
        finally:
            await database.aclose()

    async def test_it_leaves_an_existing_directory_alone(self, tmp_path: Path) -> None:
        # The configured path names a file, so its parent may be somewhere shared that
        # this service has no business tightening -- /var/lib, at the extreme.
        existing = tmp_path / "shared"
        existing.mkdir(mode=0o755)

        database = Database(existing / "keyring.db")
        try:
            assert_mode(existing, 0o755)
        finally:
            await database.aclose()

    def test_the_helper_skips_sidecars_that_are_not_there(self, tmp_path: Path) -> None:
        # Called on a database with no WAL yet -- which is what happens if the journal
        # mode did not take -- and must not fail for the file it cannot find.
        lonely = tmp_path / "lonely.db"
        lonely.touch()

        make_private(lonely)

        assert_mode(lonely, DATABASE_FILE_MODE)
