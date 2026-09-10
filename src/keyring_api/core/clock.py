"""Time as an injectable dependency.

Nothing in this codebase calls :func:`datetime.now` or :func:`time.monotonic` directly.
That matters more here than in most services: a session, an invite, a reset token and an
OAuth access token are each defined by when they stop being valid, so every one of those
rules is only testable if time is something a test can move.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Reads the current time.

    Two readings are exposed because they answer different questions: :meth:`now` is a
    timestamp fit to record and compare against an expiry, while :meth:`monotonic`
    measures elapsed duration and is immune to system clock adjustments.
    """

    def now(self) -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""
        ...

    def monotonic(self) -> float:
        """Return a monotonically increasing number of seconds from an arbitrary origin."""
        ...


class SystemClock:
    """The real clock, used everywhere outside tests."""

    __slots__ = ()

    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()
