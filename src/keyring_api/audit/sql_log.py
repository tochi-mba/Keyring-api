"""The audit log, as rows with no foreign keys.

**No foreign keys, on purpose.** Deleting an account must not delete the record that it
was deleted. ``actor_id`` and ``target_id`` are opaque ids whose rows may already be
gone, and nothing here joins back to them -- which is also why an entry has to be
self-describing: what it says is all that will be left.

**Ordered by insertion, not by timestamp.** The clock is injectable, and two entries
recorded in the same tick share one. "Newest first" has to be an order rather than an
approximation of one, so it is the autoincrementing sequence.

The cap is kept from the in-memory adapter, for a different reason than it had there. It
was memory; here it is disk, and an audit log driven by request volume is still something
that grows without anybody deciding it should.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from keyring_api.audit.log import MAX_ENTRIES, AuditAction, AuditEntry
from keyring_api.storage.times import from_column, to_column

if TYPE_CHECKING:
    import sqlite3

    from keyring_api.core.clock import Clock
    from keyring_api.storage.database import Database

ENTRY_COLUMNS = "entry_id, at, action, actor_id, target_id, detail"


class SqlAuditLog:
    """An append-only table, trimmed to a bound."""

    def __init__(self, *, database: Database, clock: Clock, max_entries: int = MAX_ENTRIES) -> None:
        self._db = database
        self._clock = clock
        self._max_entries = max_entries

    async def record(
        self,
        action: AuditAction,
        *,
        actor_id: str,
        target_id: str | None = None,
        detail: str = "",
    ) -> AuditEntry:
        entry = AuditEntry(
            entry_id=uuid.uuid4().hex,
            at=self._clock.now(),
            action=action,
            actor_id=actor_id,
            target_id=target_id,
            detail=detail,
        )

        def write(connection: sqlite3.Connection) -> None:
            connection.execute(
                f"INSERT INTO audit ({ENTRY_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?)",  # noqa: S608
                (
                    entry.entry_id,
                    to_column(entry.at),
                    entry.action.value,
                    entry.actor_id,
                    entry.target_id,
                    entry.detail,
                ),
            )
            # Trimmed in the same transaction as the insert, so the bound is a bound
            # rather than something a sweeper gets round to.
            connection.execute(
                "DELETE FROM audit WHERE sequence <= (SELECT max(sequence) FROM audit) - ?",
                (self._max_entries,),
            )

        await self._db.transact(write)
        return entry

    async def recent(self, *, limit: int = 100, actor_id: str | None = None) -> list[AuditEntry]:
        # Newest first: the question being asked is almost always "what just happened".
        rows = await self._db.fetch_all(
            f"SELECT {ENTRY_COLUMNS} FROM audit "  # noqa: S608
            "WHERE ? IS NULL OR actor_id = ? "
            "ORDER BY sequence DESC LIMIT ?",
            (actor_id, actor_id, limit),
        )
        return [_entry_of(row) for row in rows]

    async def count(self) -> int:
        return await self._db.count("SELECT count(*) AS total FROM audit")


def _entry_of(row: sqlite3.Row) -> AuditEntry:
    return AuditEntry(
        entry_id=row["entry_id"],
        at=from_column(row["at"]),
        action=AuditAction(row["action"]),
        actor_id=row["actor_id"],
        target_id=row["target_id"],
        detail=row["detail"],
    )
