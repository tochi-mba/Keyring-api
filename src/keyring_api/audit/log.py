"""An append-only record of privileged actions.

Every action one account takes *on another* is recorded: who, what, to whom, and when.
Actions on your own account are not -- reading your own profiles is not an audit event,
and recording it would bury the entries that matter under everything that does not.

Three rules about content, all the same rule really:

**Never a secret.** Not a token, not a password, not a credential value, not even the
name of a service somebody connected. An audit log is read by more people than the vault
is, and kept for longer.

**Never an email address.** Actor and target are opaque account ids. The log answers
"which account did this" without spreading personal data into a file that outlives the
account.

**Details are for humans, not for reconstruction.** A short string saying what changed.
If an entry would need a secret to be useful, it is the wrong entry.

The log is capped. It is in memory like everything else in v1 (ADR-0004), and an
uncapped list of entries driven by request volume is a memory leak with an audit-shaped
excuse.
"""

from __future__ import annotations

import asyncio
import uuid
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.core.clock import Clock

MAX_ENTRIES = 10_000
"""Oldest entries are dropped past this. See the module docstring."""


class AuditAction(StrEnum):
    """What was done. A closed set, so the log can be filtered reliably."""

    ACCOUNT_INVITED = "account.invited"
    ACCOUNT_DELETED = "account.deleted"
    ACCOUNT_DISABLED = "account.disabled"
    ACCOUNT_ENABLED = "account.enabled"
    ACCOUNT_SESSIONS_REVOKED = "account.sessions_revoked"
    ACCOUNT_PASSWORD_RESET_ISSUED = "account.password_reset_issued"  # noqa: S105
    ROLES_ASSIGNED = "roles.assigned"
    ROLE_CREATED = "role.created"
    ROLE_UPDATED = "role.updated"
    ROLE_DELETED = "role.deleted"
    PROFILE_DELETED_BY_ADMIN = "profile.deleted_by_admin"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One privileged action."""

    entry_id: str
    at: datetime
    action: AuditAction
    actor_id: str
    """The account that acted, or ``"break-glass"`` for the admin token."""

    target_id: str | None = None
    """The account acted upon, when there is one."""

    detail: str = ""
    """A short human-readable summary. Never contains a secret."""


BREAK_GLASS_ACTOR = "break-glass"
"""Recorded when the admin token was used instead of an account.

Deliberately conspicuous. Break-glass access is legitimate and should be rare, and an
audit log full of it is telling you something.
"""


@runtime_checkable
class AuditLog(Protocol):
    """Records privileged actions and reads them back."""

    async def record(
        self,
        action: AuditAction,
        *,
        actor_id: str,
        target_id: str | None = None,
        detail: str = "",
    ) -> AuditEntry:
        """Append an entry."""
        ...

    async def recent(self, *, limit: int = 100, actor_id: str | None = None) -> list[AuditEntry]:
        """Read entries newest first, optionally for one actor."""
        ...

    async def count(self) -> int:
        """How many entries are held."""
        ...


class InMemoryAuditLog:
    """A bounded deque of entries."""

    def __init__(self, *, clock: Clock, max_entries: int = MAX_ENTRIES) -> None:
        self._clock = clock
        self._entries: deque[AuditEntry] = deque(maxlen=max_entries)
        self._lock = asyncio.Lock()

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
        async with self._lock:
            self._entries.append(entry)
        return entry

    async def recent(self, *, limit: int = 100, actor_id: str | None = None) -> list[AuditEntry]:
        async with self._lock:
            entries = list(self._entries)

        if actor_id is not None:
            entries = [entry for entry in entries if entry.actor_id == actor_id]

        # Newest first: the question being asked is almost always "what just happened".
        return entries[::-1][:limit]

    async def count(self) -> int:
        async with self._lock:
            return len(self._entries)
