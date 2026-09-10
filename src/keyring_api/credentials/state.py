"""The ``state`` parameter of an OAuth authorization-code flow.

State is kept server-side rather than signed and handed to the browser. Both designs
give tamper-resistance; only this one gives **single use**, and single use is what stops
a captured callback URL being replayed. A signed stateless token would need a
server-side record of what had already been redeemed anyway -- which is this, with an
extra signature layer on top.

Each record binds the flow to one account, profile and service. That binding is checked
on the way back, so a callback cannot attach a credential to a profile the person who
started the flow does not own.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from keyring_api.accounts.tokens import hash_token, new_token

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.core.clock import Clock
    from keyring_api.domain.profiles import CredentialKind


@dataclass(frozen=True, slots=True)
class FlowBinding:
    """What a state parameter is bound to.

    One value rather than five arguments, because it is one idea: this flow, and no
    other, may attach a credential to this account's profile for this service. Every
    field is checked on the way back.
    """

    account_id: str
    profile: str
    service: str
    kind: CredentialKind
    redirect_uri: str


@dataclass(frozen=True, slots=True)
class OAuthFlow:
    """One authorization attempt in progress."""

    binding: FlowBinding
    expires_at: datetime
    """Short. An unfinished flow is a loose end, and the window in which a leaked
    callback URL is worth anything to somebody else."""

    def is_live(self, *, now: datetime) -> bool:
        return now < self.expires_at


@runtime_checkable
class OAuthStateStore(Protocol):
    """Issues and redeems the ``state`` parameter."""

    async def issue(self, binding: FlowBinding, *, ttl_seconds: float) -> str:
        """Start a flow. Returns the opaque state to send to the provider."""
        ...

    async def redeem(self, state: str) -> OAuthFlow | None:
        """Consume a state exactly once.

        ``None`` covers unknown, expired and already-redeemed alike: an attacker who
        forges a callback must not learn which of those it was.
        """
        ...

    async def purge_expired(self) -> int:
        """Drop abandoned flows. Returns how many went."""
        ...


class InMemoryOAuthStateStore:
    """Flows in a dictionary keyed by the hash of the state token."""

    def __init__(self, *, clock: Clock) -> None:
        self._clock = clock
        self._flows: dict[str, OAuthFlow] = {}
        self._lock = asyncio.Lock()

    async def issue(self, binding: FlowBinding, *, ttl_seconds: float) -> str:
        state = new_token()
        flow = OAuthFlow(
            binding=binding,
            expires_at=self._clock.now() + timedelta(seconds=ttl_seconds),
        )

        async with self._lock:
            # Stored by hash, like every other token here. The state travels through the
            # provider and through the person's browser history; what is kept on this
            # side should not be usable if it is read.
            self._flows[hash_token(state)] = flow
        return state

    async def redeem(self, state: str) -> OAuthFlow | None:
        now = self._clock.now()

        async with self._lock:
            # Popped, not read: consumption and lookup are one operation, so two
            # callbacks racing the same state cannot both proceed.
            flow = self._flows.pop(hash_token(state), None)

        if flow is None or not flow.is_live(now=now):
            return None
        return flow

    async def purge_expired(self) -> int:
        now = self._clock.now()

        async with self._lock:
            doomed = [key for key, flow in self._flows.items() if not flow.is_live(now=now)]
            for key in doomed:
                del self._flows[key]
            return len(doomed)
