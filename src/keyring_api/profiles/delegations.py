"""Persistence port for profile-scoped offline grants."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.domain.delegation import OfflineGrant


@runtime_checkable
class DelegationStore(Protocol):
    """Grants survive restarts and disappear with their owning profile."""

    async def add(self, grant: OfflineGrant, *, cap: int, now: datetime) -> None: ...

    async def for_exchange(self, grant_id: str, service: str) -> OfflineGrant | None: ...

    async def list_for_profile(self, account_id: str, profile: str) -> list[OfflineGrant]: ...

    async def revoke(
        self, account_id: str, profile: str, grant_id: str, *, now: datetime
    ) -> bool: ...
