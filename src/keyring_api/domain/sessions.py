"""Login sessions.

Sessions are opaque tokens, stored hashed, not JWTs. A JWT cannot be revoked without a
blocklist, and a blocklist is a session table with extra steps and worse ergonomics.
Keeping the session in a table is what makes "log out everywhere" and "revoke every
session when the password changes" actually work rather than approximately work.

Two deadlines, because they answer different questions. The idle deadline ends a session
nobody is using -- the laptop left in a cafe. The absolute deadline ends a session that
has been kept alive forever by being used, which is the one an attacker with a stolen
token relies on.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

SESSION_ID_PREFIX = "sess_"


def new_session_id() -> str:
    """Return a fresh session id.

    Distinct from the session *token*: this identifies the row, is safe to log, and is
    what a "revoke this session" request names. The token is never stored.
    """
    return f"{SESSION_ID_PREFIX}{uuid.uuid4().hex}"


@dataclass(frozen=True, slots=True)
class Session:
    """One login, on one device.

    ``token_hash`` is all that is kept of the token itself. A database dump therefore
    yields no usable sessions, which is the entire reason the token is hashed at rest
    even though it is high-entropy and short-lived.
    """

    session_id: str
    account_id: str
    token_hash: str
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    absolute_expires_at: datetime
    idle_ttl_seconds: float | None = None
    """The idle TTL stamped at create. ``None`` on sessions that predate the stamp."""

    def is_expired(self, *, now: datetime) -> bool:
        """Whether either deadline has passed."""
        return now >= self.expires_at or now >= self.absolute_expires_at

    def touched(
        self,
        *,
        now: datetime,
        idle_ttl_seconds: float,
        absolute_expires_at: datetime | None,
    ) -> Session:
        """Record use, extending the idle window but never the absolute one.

        Args:
            now: when the session was used.
            idle_ttl_seconds: how long a session may sit unused.
            absolute_expires_at: ignored unless given; present so a caller that has
                already computed the ceiling need not recompute it.
        """
        ceiling = absolute_expires_at or self.absolute_expires_at
        # min(), so a session touched a minute before its ceiling does not come away
        # with a fresh full idle window and outlive the ceiling by an idle period.
        expires_at = min(now + timedelta(seconds=idle_ttl_seconds), ceiling)
        return replace(self, last_used_at=now, expires_at=expires_at, absolute_expires_at=ceiling)
