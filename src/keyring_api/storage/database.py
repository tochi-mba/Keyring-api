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
"""

from __future__ import annotations

import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, TypeVar

from keyring_api.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

logger = get_logger(__name__)

T = TypeVar("T")

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
        self._connection: sqlite3.Connection = self._executor.submit(self._connect).result()

    @property
    def path(self) -> Path:
        """Where the file is. For diagnostics and for the backup instructions."""
        return self._path

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self._path, isolation_level=None)
        connection.row_factory = sqlite3.Row

        journal_mode = "unknown"
        for pragma in CONNECT_PRAGMAS:
            row = connection.execute(pragma).fetchone()
            if row is not None and pragma.startswith("PRAGMA journal_mode"):
                journal_mode = str(row[0])

        require_foreign_keys(connection)
        logger.info("database_opened", journal_mode=journal_mode)
        return connection

    async def run(self, work: Callable[[sqlite3.Connection], T]) -> T:
        """Run ``work`` on the worker thread, outside any transaction.

        For reads. A single SQLite statement is atomic by itself, so a read needs no
        explicit transaction; a *sequence* of reads that must agree with each other does,
        and belongs in :meth:`transact`.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, work, self._connection)

    async def transact(self, work: Callable[[sqlite3.Connection], T]) -> T:
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


def _in_transaction(connection: sqlite3.Connection, work: Callable[[sqlite3.Connection], T]) -> T:
    """Run ``work`` between ``BEGIN IMMEDIATE`` and ``COMMIT``, rolling back on anything."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        result = work(connection)
    except BaseException:
        connection.rollback()
        raise
    connection.commit()
    return result
