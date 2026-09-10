"""A clock that only moves when a test tells it to."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

EPOCH = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class FakeClock:
    """Deterministic :class:`~keyring_api.core.clock.Clock` implementation."""

    def __init__(self, start: datetime = EPOCH) -> None:
        self._start = start
        self._now = start

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return (self._now - self._start).total_seconds()

    def advance(self, delta: timedelta | float) -> None:
        """Move time forward by a timedelta or a number of seconds."""
        if not isinstance(delta, timedelta):
            delta = timedelta(seconds=delta)
        self._now += delta
