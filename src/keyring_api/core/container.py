"""The composition root.

Every adapter is chosen and wired here, once, and handed to the app. Nothing else
constructs its own dependencies -- which is what makes the whole service testable by
substitution, and what keeps "which store" and "which hasher" configuration decisions
rather than code.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from keyring_api.accounts.hashing import Argon2PasswordHasher
from keyring_api.accounts.ratelimit import InMemoryRateLimiter
from keyring_api.accounts.service import AccountService
from keyring_api.accounts.store import (
    InMemoryAccountStore,
    InMemoryGrantStore,
    InMemorySessionStore,
)
from keyring_api.core.clock import SystemClock
from keyring_api.core.logging import get_logger

if TYPE_CHECKING:
    from keyring_api.core.clock import Clock
    from keyring_api.core.config import Settings

logger = get_logger(__name__)

SWEEP_INTERVAL_SECONDS = 300.0
"""How often expired sessions, grants and rate-limit records are evicted."""


@dataclass(slots=True)
class Container:
    """Everything the API needs, already wired together."""

    settings: Settings
    clock: Clock
    accounts: InMemoryAccountStore
    sessions: InMemorySessionStore
    grants: InMemoryGrantStore
    limiter: InMemoryRateLimiter
    account_service: AccountService
    started_monotonic: float
    _sweeper: asyncio.Task[None] | None = None

    @classmethod
    def build(cls, settings: Settings, *, clock: Clock | None = None) -> Container:
        """Construct every adapter named by ``settings``."""
        clock = clock or SystemClock()
        accounts = InMemoryAccountStore()
        sessions = InMemorySessionStore(clock=clock)
        grants = InMemoryGrantStore()
        limiter = InMemoryRateLimiter(clock=clock)

        return cls(
            settings=settings,
            clock=clock,
            accounts=accounts,
            sessions=sessions,
            grants=grants,
            limiter=limiter,
            account_service=AccountService(
                accounts=accounts,
                sessions=sessions,
                grants=grants,
                hasher=Argon2PasswordHasher(settings.argon2),
                limiter=limiter,
                clock=clock,
                settings=settings,
            ),
            started_monotonic=clock.monotonic(),
        )

    @property
    def uptime_seconds(self) -> float:
        return self.clock.monotonic() - self.started_monotonic

    def start_sweeper(self) -> None:
        """Begin evicting expired sessions, grants and rate-limit records."""
        self._sweeper = asyncio.create_task(self._sweep_forever(), name="retention-sweeper")

    async def aclose(self) -> None:
        """Shut everything down in dependency order."""
        if self._sweeper is not None:
            self._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sweeper
            self._sweeper = None

    async def _sweep_forever(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
            await self._sweep_guarded()

    async def _sweep_guarded(self) -> None:
        """Run one sweep, surviving any failure.

        A sweep failure must not kill the sweeper: the next tick tries again. Without
        this the first transient error would silently stop all retention, and expired
        sessions would accumulate until someone noticed the memory.
        """
        try:
            swept = await self.account_service.sweep_once()
        except Exception:
            logger.exception("sweep_failed")
            return

        if swept.sessions or swept.grants:
            logger.info("swept", sessions=swept.sessions, grants=swept.grants)
