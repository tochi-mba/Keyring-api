"""Time as an injectable dependency.

Every rule in this library that depends on time -- a token's expiry, the age of a cached key
set, the window between two fetches an unknown key id may provoke -- reads the clock it was
handed. With the wall clock those rules could only be tested by waiting, and a rule that is
tested by waiting is a rule that is not tested.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Reads the current time.

    Two readings, because they answer different questions: :meth:`now` is a timestamp fit to
    compare against an expiry, and :meth:`monotonic` measures elapsed duration and is immune
    to the system clock being adjusted.
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
