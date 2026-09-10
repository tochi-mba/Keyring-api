"""Rate limiting for the endpoints an unauthenticated stranger can reach.

This is the *endpoint's* defence, and it is deliberately separate from the per-account
lockout in :class:`~keyring_api.domain.accounts.Account`. The two protect different
things and are keyed differently on purpose:

* The **lockout** is keyed by account and stops someone guessing one person's password.
* The **rate limit** is keyed by caller and stops someone working through a list of
  addresses, or hammering the reset endpoint to send mail.

Keying the rate limit by account instead would hand an attacker a way to lock a real
person out of logging in at all, simply by failing on their behalf.

The window slides. A fixed window resets on a boundary, which lets an attacker spend the
whole budget just before it and the whole budget just after -- twice the limit, back to
back, which is exactly the burst the limit exists to prevent.
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from keyring_api.domain.errors import RateLimitedError

if TYPE_CHECKING:
    from keyring_api.core.clock import Clock

MAX_TIMESTAMPS_PER_CALLER = 128
"""Cap on the history kept per caller.

Only the most recent `limit` attempts can ever matter, so anything beyond a generous
multiple of that is memory an unauthenticated caller gets to allocate for free.
"""


@runtime_checkable
class RateLimiter(Protocol):
    """Counts attempts and refuses the ones past a budget."""

    async def check(self, scope: str, caller: str, *, limit: int, window_seconds: float) -> None:
        """Record an attempt and refuse it if the budget is spent.

        Raises:
            RateLimitedError: carrying how long to wait.
        """
        ...

    async def reset(self, scope: str, caller: str) -> None:
        """Forget a caller's attempts, after an outcome that proves they are not guessing."""
        ...

    async def purge_expired(self, *, window_seconds: float) -> int:
        """Forget callers whose attempts have all aged out. Returns how many went."""
        ...


class InMemoryRateLimiter:
    """A sliding window of attempt timestamps per (scope, caller)."""

    def __init__(self, *, clock: Clock) -> None:
        self._clock = clock
        self._attempts: dict[tuple[str, str], deque[float]] = {}
        self._lock = asyncio.Lock()

    async def check(self, scope: str, caller: str, *, limit: int, window_seconds: float) -> None:
        now = self._clock.monotonic()
        retry_after = await self._record(scope, caller, now=now, limit=limit, window=window_seconds)

        # Raised outside the lock: the verdict is computed under it, but holding a lock
        # while unwinding an exception is a good way to build a deadlock later.
        if retry_after is not None:
            msg = f"too many {scope} attempts; try again later"
            raise RateLimitedError(msg, retry_after_seconds=retry_after)

    async def _record(
        self, scope: str, caller: str, *, now: float, limit: int, window: float
    ) -> float | None:
        """Record an attempt. Returns how long to wait, or ``None`` if it is allowed."""
        async with self._lock:
            timestamps = self._attempts.setdefault((scope, caller), deque())
            self._evict_before(timestamps, now - window)

            # Recorded before the verdict, so an attacker who keeps hammering keeps
            # extending their own window rather than draining it while they attack.
            timestamps.append(now)
            if len(timestamps) > MAX_TIMESTAMPS_PER_CALLER:
                timestamps.popleft()

            if len(timestamps) <= limit:
                return None
            return max(window - (now - timestamps[0]), 1.0)

    async def reset(self, scope: str, caller: str) -> None:
        async with self._lock:
            self._attempts.pop((scope, caller), None)

    async def purge_expired(self, *, window_seconds: float) -> int:
        cutoff = self._clock.monotonic() - window_seconds

        async with self._lock:
            doomed = [
                key
                for key, timestamps in self._attempts.items()
                if not timestamps or timestamps[-1] <= cutoff
            ]
            for key in doomed:
                del self._attempts[key]
            return len(doomed)

    async def tracked_callers(self) -> int:
        """How many callers are currently remembered. Reported by ``/healthy``."""
        async with self._lock:
            return len(self._attempts)

    @staticmethod
    def _evict_before(timestamps: deque[float], cutoff: float) -> None:
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
