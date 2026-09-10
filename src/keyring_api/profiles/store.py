"""What a profile store promises. The adapter is :mod:`keyring_api.profiles.sql_store`.

Every method takes an ``account_id``, and it is not optional on any of them. That is the
mechanism behind account isolation: there is no call that *could* read across accounts,
so isolation is not a check somebody has to remember to write in a handler.

A profile that belongs to somebody else reads back as absent, exactly like one that was
never created. The alternative -- a distinguishable "not yours" -- would tell one person
that another person has a profile by that name.

There is no ``save(profile)``. Writing a whole profile back means writing back everything
a caller read some time ago, and two requests connecting two different services each
wrote back a record missing the other's. Connections are therefore written one at a time,
by name, through :meth:`ProfileStore.put_connection` -- so a write says what it changes
rather than restating everything it did not.

The caps live here for the same reason. A caller that counts and then writes has a
window in between; a store that counts and writes in one operation does not.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.domain.profiles import Connection, Profile


@runtime_checkable
class ProfileStore(Protocol):
    """Persistence for profiles and their connections."""

    async def add(self, profile: Profile, *, cap: int) -> None:
        """Store a new profile, refusing to take the account past ``cap``.

        Args:
            profile: the profile to store.
            cap: the most profiles one account may hold. Enforced here rather than by
                the caller, because a count taken before the write can go stale.

        Raises:
            ProfileExistsError: if this account already has one by that name.
            LimitExceededError: if this account is already at ``cap``.
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

    async def put_connection(
        self, account_id: str, name: str, connection: Connection, *, cap: int, now: datetime
    ) -> Connection:
        """Add or replace one connection, and return it as stored.

        Returns what is stored rather than what was passed, because replacing a
        connection keeps the ``created_at`` it already had -- saying otherwise would make
        "connected since" jump every time a token was refreshed.

        Args:
            account_id: whose profile.
            name: which profile.
            connection: the connection to write.
            cap: the most connections one profile may hold. Replacing an existing
                connection is never refused, however full the profile is.
            now: what to set the profile's ``updated_at`` to.

        Raises:
            ProfileNotFoundError: no such profile for this account. Callers reach this
                after a network round trip, where the profile may have been deleted while
                the provider was being called.
            LimitExceededError: adding a new connection would pass ``cap``.
        """
        ...

    async def remove_connection(
        self, account_id: str, name: str, service: str, *, now: datetime
    ) -> bool:
        """Remove one connection. Returns whether there was one."""
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

    async def all_profiles(self) -> list[Profile]:
        """Every profile, across every account.

        The one method that is not account-scoped, and it exists for exactly one caller:
        the health check, which reports *counts* of unwell connections and never names
        an account, a profile, or a service. Anything else that reaches for this is
        almost certainly a cross-account read wearing a disguise.
        """
        ...
