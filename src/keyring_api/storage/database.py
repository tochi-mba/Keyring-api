"""One SQLite connection, owned by one thread, reached only through this class.

## Why a single thread and not a lock

The obvious design is ``asyncio.to_thread`` guarded by an ``asyncio.Lock``::

    async with self._lock:                    # DO NOT
        return await asyncio.to_thread(work)

It is broken. Cancelling the task while it awaits ``to_thread`` unwinds the ``async
with`` and releases the lock, but **does not cancel the thread**: ``work`` is still
running on the shared connection, mid-transaction, when the next task takes the lock and
calls into that same connection from a different thread. A client disconnecting cancels
its request task, so this is an ordinary Tuesday rather than a thought experiment.

A single-worker executor removes the failure instead of patching it. Serialization stops
depending on a lock that cancellation can drop, and becomes a property of there being
exactly one thread that may touch the connection at all.

## What that buys, and what it costs

Every database call is submitted as *one whole callable*, so a transaction is indivisible
by construction rather than by convention -- which is what the invariants above this
layer are built on. It is strictly stronger than the per-store ``asyncio.Lock``\\ s it
replaces: those let calls to different stores interleave, and nothing interleaves here.
Exactly one thread ever exists, so there is no pool to exhaust.

The cost, and it belongs in the open: **a cancelled request's write may still commit**,
because the queued callable runs to completion regardless of who is still waiting for it.
That is not new -- the in-memory stores had no ``await`` inside their locks either, so
their bodies always ran to completion once entered -- but it is now worth knowing.

## The pragma that lies

``PRAGMA foreign_keys`` defaults to **off**, is per-connection rather than stored in the
file, and -- the part that costs an afternoon -- is a **silent no-op when a transaction
is open**. Issued through a driver that opens implicit transactions around DML, it can
report success and do nothing, leaving every foreign key in the schema decorative and
every cascade absent. That is why the connection is opened with ``isolation_level=None``
(this class issues its own ``BEGIN IMMEDIATE``) and why the setting is read back and
verified rather than assumed.

``BEGIN IMMEDIATE`` rather than a deferred ``BEGIN`` that upgrades to a write lock
partway through: the deferred form is where ``SQLITE_BUSY`` and writer deadlock live, and
the immediate form is what makes a check-then-write pair serializable even if a
connection pool ever replaces the single connection here.

## The file mode matters as much as the cipher

SQLite creates its files 0644, which would put every password hash, session token hash
and address in this service in a file any user on the machine can read. Encryption
defends against a stolen disk; the mode defends against every other process on the box,
which is by far the likelier reader. The credential material is encrypted either way --
but the rest of the database is not, and never was going to be.
"""

from __future__ import annotations

import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from keyring_api.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

logger = get_logger(__name__)

DATABASE_FILE_MODE = 0o600
"""Owner-only. SQLite would otherwise create these 0644; see the module docstring."""

SIDECARS = ("-wal", "-shm")
"""The write-ahead log and its shared-memory index, which hold data like the file does.

SQLite gives a WAL file the permissions of the database it belongs to, so these only need
setting for sidecars that already exist by the time the mode is applied.
"""

CONNECT_PRAGMAS: tuple[str, ...] = (
    "PRAGMA journal_mode = WAL",
    "PRAGMA foreign_keys = ON",
    "PRAGMA synchronous = FULL",
    "PRAGMA busy_timeout = 5000",
)
"""Applied to the connection, in this order, before anything else runs on it.

``synchronous = FULL`` rather than the ``NORMAL`` usually paired with WAL. ``NORMAL`` can
lose the most recently committed transactions on power loss, and here a lost transaction
is a credential somebody believes is saved and is not. One fsync per commit, at a volume
of a few writes a minute, is not a cost worth optimising.
"""


class StorageError(RuntimeError):
    """The database cannot be used as configured.

    Deliberately not a :class:`~keyring_api.domain.errors.DomainError`: nothing here is
    about accounts or credentials, and nothing above should be catching it. It means the
    process should not have started.
    """


def require_foreign_keys(connection: sqlite3.Connection) -> None:
    """Refuse a connection whose foreign keys did not actually come on.

    Read back rather than trusted. See the module docstring for how a ``PRAGMA
    foreign_keys`` can succeed and do nothing; the consequence is a vault whose cascades
    and whose "this role is still held" refusal both quietly stop happening.
    """
    (enabled,) = connection.execute("PRAGMA foreign_keys").fetchone()
    if not enabled:
        msg = "foreign keys are not enabled on this connection; refusing to continue"
        raise StorageError(msg)


def make_private(path: Path) -> None:
    """Make the database and its sidecars readable only by the account running us.

    Applied after opening rather than before, because there is nothing to chmod until
    SQLite has created the file -- which leaves a window where a fresh database exists at
    0644. It is one open() wide, on a file with nothing in it yet, and closing it properly
    would mean pre-creating the file ourselves and hoping SQLite agreed with the result.
    """
    path.chmod(DATABASE_FILE_MODE)
    for suffix in SIDECARS:
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            sidecar.chmod(DATABASE_FILE_MODE)


class Database:
    """The one way into the SQLite file.

    Constructing this opens the connection. Nothing is migrated -- see
    :func:`keyring_api.storage.migrator.migrate`.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="keyring-db")
        self._closed = False
        # Submitted rather than called, so the connection is created on the worker
        # thread and is therefore only ever touched by it.
        try:
            self._connection: sqlite3.Connection = self._executor.submit(self._connect).result()
        except BaseException:
            # `_connect` has already closed a connection that failed its own startup
            # checks. The thread that opened it still has to be given back here, or a
            # process that refused to start keeps a worker alive while it tries to exit.
            self._executor.shutdown(wait=True)
            raise

    @property
    def path(self) -> Path:
        """Where the file is. For diagnostics and for the backup instructions."""
        return self._path

    def _connect(self) -> sqlite3.Connection:
        # mode applies only to directories this creates; an existing one is left alone,
        # because the configured path names a file and its parent may not be ours.
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self._path, isolation_level=None)
        # Everything after the open is a startup check that may refuse the
        # connection. A refused connection has to be closed here, because nothing
        # above holds a reference to it yet: the file handle and the WAL sidecars
        # would otherwise stay open in a process that is refusing to start, and
        # Python 3.13 reports exactly that as a ResourceWarning at collection.
        try:
            connection.row_factory = sqlite3.Row

            journal_mode = "unknown"
            for pragma in CONNECT_PRAGMAS:
                row = connection.execute(pragma).fetchone()
                if row is not None and pragma.startswith("PRAGMA journal_mode"):
                    journal_mode = str(row[0])

            require_foreign_keys(connection)
            # After the pragmas, because switching to WAL is what creates the sidecars.
            make_private(self._path)
            logger.info("database_opened", journal_mode=journal_mode)
        except BaseException:
            connection.close()
            raise
        return connection

    def run_sync[T](self, work: Callable[[sqlite3.Connection], T]) -> T:
        """Run ``work`` on the worker thread, blocking the caller until it finishes.

        For startup only -- opening the database and migrating it happen before there is
        an event loop to keep responsive, and the composition root is synchronous. Inside
        a request this would block the loop, which is what :meth:`run` is for.
        """
        return self._executor.submit(work, self._connection).result()

    async def run[T](self, work: Callable[[sqlite3.Connection], T]) -> T:
        """Run ``work`` on the worker thread, outside any transaction.

        For reads. A single SQLite statement is atomic by itself, so a read needs no
        explicit transaction; a *sequence* of reads that must agree with each other does,
        and belongs in :meth:`transact`.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, work, self._connection)

    async def transact[T](self, work: Callable[[sqlite3.Connection], T]) -> T:
        """Run ``work`` as one ``BEGIN IMMEDIATE`` transaction.

        The whole transaction is one submitted callable, which is what makes it
        indivisible: there is no point inside it at which another caller can be
        interleaved, because there is no other thread that could run one.

        Anything ``work`` raises -- a domain error refusing the write included -- rolls
        the transaction back and propagates.
        """
        return await self.run(lambda connection: _in_transaction(connection, work))

    async def fetch_all(self, sql: str, parameters: Sequence[object] = ()) -> list[sqlite3.Row]:
        """Run one read statement and return every row."""
        return await self.run(lambda connection: connection.execute(sql, parameters).fetchall())

    async def fetch_one(self, sql: str, parameters: Sequence[object] = ()) -> sqlite3.Row | None:
        """Run one read statement and return the first row, or ``None``."""
        row: sqlite3.Row | None = await self.run(
            lambda connection: connection.execute(sql, parameters).fetchone()
        )
        return row

    async def count(self, sql: str, parameters: Sequence[object] = ()) -> int:
        """Run a ``SELECT count(*) AS total`` and return the number.

        Indexes into the result rather than testing for a missing row. An aggregate with
        no GROUP BY always returns exactly one row, so a "what if it did not" branch
        would be unreachable code -- which the coverage gate could then never cover, and
        which somebody would eventually satisfy by weakening the gate.
        """
        rows = await self.fetch_all(sql, parameters)
        return int(rows[0]["total"])

    async def execute(self, sql: str, parameters: Sequence[object] = ()) -> int:
        """Run one write statement in its own transaction. Returns rows affected."""
        return await self.transact(lambda connection: connection.execute(sql, parameters).rowcount)

    async def aclose(self) -> None:
        """Close the connection and stop the worker thread. Safe to call twice."""
        if self._closed:
            return
        self._closed = True

        await self.run(lambda connection: connection.close())
        # The queue is empty by now -- the close above was the last thing on it -- so
        # this returns immediately rather than blocking the event loop.
        self._executor.shutdown(wait=True)


def _in_transaction[T](
    connection: sqlite3.Connection, work: Callable[[sqlite3.Connection], T]
) -> T:
    """Run ``work`` between ``BEGIN IMMEDIATE`` and ``COMMIT``, rolling back on anything."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        result = work(connection)
    except BaseException:
        connection.rollback()
        raise
    connection.commit()
    return result
