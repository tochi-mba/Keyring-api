"""Where profiles live.

Every method takes an ``account_id``, and it is not optional on any of them. That is the
mechanism behind account isolation: there is no call that *could* read across accounts,
so isolation is not a check somebody has to remember to write in a handler.

A profile that belongs to somebody else reads back as absent, exactly like one that was
never created. The alternative -- a distinguishable "not yours" -- would tell one person
that another person has a profile by that name.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from keyring_api.domain.errors import ProfileExistsError

if TYPE_CHECKING:
    from keyring_api.domain.profiles import Profile


@runtime_checkable
class ProfileStore(Protocol):
    """Persistence for profiles and their connections."""

    async def add(self, profile: Profile) -> None:
        """Store a new profile.

        Raises:
            ProfileExistsError: if this account already has one by that name.
        """
        ...

    async def get(self, account_id: str, name: str) -> Profile | None:
        """Return one of this account's profiles, or ``None``.

        ``None`` covers both "no such profile" and "somebody else's profile".
        """
        ...

    async def list_for_account(self, account_id: str) -> list[Profile]:
        """Every profile this account owns, oldest first."""
        ...

    async def save(self, profile: Profile) -> None:
        """Record a change to a profile."""
        ...

    async def delete(self, account_id: str, name: str) -> bool:
        """Remove a profile. Returns whether there was one."""
        ...

    async def delete_for_account(self, account_id: str) -> int:
        """Remove every profile an account owns, for a cascading delete."""
        ...

    async def count_for_account(self, account_id: str) -> int:
        """How many profiles this account has, for the per-account cap."""
        ...


class InMemoryProfileStore:
    """Profiles in a dictionary keyed by account and name."""

    def __init__(self) -> None:
        self._profiles: dict[tuple[str, str], Profile] = {}
        self._lock = asyncio.Lock()

    async def add(self, profile: Profile) -> None:
        key = (profile.account_id, profile.name)

        async with self._lock:
            if key in self._profiles:
                msg = f"a profile named {profile.name!r} already exists"
                raise ProfileExistsError(msg)
            self._profiles[key] = profile

    async def get(self, account_id: str, name: str) -> Profile | None:
        async with self._lock:
            # The account is half the key rather than something checked afterwards, so
            # a cross-account read is not a bug that can be introduced -- it simply
            # cannot be expressed.
            return self._profiles.get((account_id, name))

    async def list_for_account(self, account_id: str) -> list[Profile]:
        async with self._lock:
            owned = [
                profile for (owner, _), profile in self._profiles.items() if owner == account_id
            ]
        return sorted(owned, key=lambda profile: profile.created_at)

    async def save(self, profile: Profile) -> None:
        async with self._lock:
            self._profiles[(profile.account_id, profile.name)] = profile

    async def delete(self, account_id: str, name: str) -> bool:
        async with self._lock:
            return self._profiles.pop((account_id, name), None) is not None

    async def delete_for_account(self, account_id: str) -> int:
        async with self._lock:
            doomed = [key for key in self._profiles if key[0] == account_id]
            for key in doomed:
                del self._profiles[key]
            return len(doomed)

    async def count_for_account(self, account_id: str) -> int:
        async with self._lock:
            return sum(1 for owner, _ in self._profiles if owner == account_id)
