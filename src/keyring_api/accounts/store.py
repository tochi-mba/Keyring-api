"""Where accounts, sessions and grants live.

Three ports and three in-memory adapters. The adapters are honest about their limit --
everything dies with the process and nothing spans replicas (ADR-0004) -- but the ports
are the contract, and the tests are written against the ports, so the Postgres adapter
that eventually replaces these has a suite waiting for it.

Two behaviours are in the store rather than the caller, on purpose:

* **Expired sessions are invisible on read.** Enforcing expiry only in a sweeper would
  mean a session keeps working between its deadline and the next sweep.
* **Redeeming a grant is one atomic operation.** Read-then-write in a caller cannot stop
  two clicks on the same reset link both succeeding.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from keyring_api.domain.errors import AccountExistsError

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.core.clock import Clock
    from keyring_api.domain.accounts import Account
    from keyring_api.domain.grants import Grant, GrantPurpose
    from keyring_api.domain.sessions import Session


@runtime_checkable
class AccountStore(Protocol):
    """Persistence for accounts."""

    async def add(self, account: Account) -> None:
        """Store a new account.

        Raises:
            AccountExistsError: if the address is already taken.
        """
        ...

    async def get(self, account_id: str) -> Account | None:
        """Return an account, or ``None``."""
        ...

    async def get_by_email(self, email: str) -> Account | None:
        """Return the account for a normalized address, or ``None``.

        Absent rather than raising: at a login, "no such account" has to be
        indistinguishable from "wrong password", and an exception is harder to keep
        indistinguishable than a ``None``.
        """
        ...

    async def save(self, account: Account) -> None:
        """Record a change to an account."""
        ...

    async def delete(self, account_id: str) -> bool:
        """Remove an account. Returns whether there was one."""
        ...

    async def count(self) -> int:
        """How many accounts exist."""
        ...


@runtime_checkable
class SessionStore(Protocol):
    """Persistence for login sessions."""

    async def add(self, session: Session) -> None:
        """Store a new session."""
        ...

    async def get_by_token_hash(self, token_hash: str) -> Session | None:
        """Return a live session for this token hash, or ``None`` if there is none.

        Expired sessions are not returned. A session must stop working the moment it
        passes its deadline, not the next time something sweeps.
        """
        ...

    async def save(self, session: Session) -> None:
        """Record a change to a session, such as its last use."""
        ...

    async def revoke(self, session_id: str) -> bool:
        """Drop one session. Returns whether there was one."""
        ...

    async def revoke_all(self, account_id: str, *, except_session_id: str | None = None) -> int:
        """Drop every session for an account. Returns how many went."""
        ...

    async def count_for_account(self, account_id: str) -> int:
        """How many live sessions this account has."""
        ...

    async def drop_oldest(self, account_id: str) -> int:
        """Drop this account's oldest session, to make room under the cap."""
        ...

    async def purge_expired(self) -> int:
        """Drop sessions past either deadline. Returns how many went."""
        ...


@runtime_checkable
class GrantStore(Protocol):
    """Persistence for invites and password resets."""

    async def add(self, grant: Grant) -> None:
        """Store a new grant."""
        ...

    async def get_by_token_hash(self, token_hash: str) -> Grant | None:
        """Return a grant for this token hash, expired or not."""
        ...

    async def redeem(self, token_hash: str, *, now: datetime) -> Grant | None:
        """Atomically mark a redeemable grant used, and return it.

        ``None`` covers every way this can fail -- unknown, expired, revoked, already
        redeemed -- because a caller holding a guessed token must not learn which.
        """
        ...

    async def revoke_all_for_account(self, account_id: str, purpose: GrantPurpose) -> int:
        """Invalidate every outstanding grant of one purpose for an account."""
        ...

    async def delete_for_account(self, account_id: str) -> int:
        """Remove every grant belonging to an account, for a cascading delete."""
        ...

    async def purge_expired(self, *, now: datetime) -> int:
        """Drop grants past their expiry. Returns how many went."""
        ...


class InMemoryAccountStore:
    """Accounts in two dictionaries -- by id, and by address -- under one lock."""

    def __init__(self) -> None:
        self._by_id: dict[str, Account] = {}
        self._id_by_email: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def add(self, account: Account) -> None:
        async with self._lock:
            if account.email in self._id_by_email:
                msg = f"an account already exists for {account.email!r}"
                raise AccountExistsError(msg)
            self._by_id[account.account_id] = account
            self._id_by_email[account.email] = account.account_id

    async def get(self, account_id: str) -> Account | None:
        async with self._lock:
            return self._by_id.get(account_id)

    async def get_by_email(self, email: str) -> Account | None:
        async with self._lock:
            account_id = self._id_by_email.get(email)
            return None if account_id is None else self._by_id.get(account_id)

    async def save(self, account: Account) -> None:
        async with self._lock:
            self._by_id[account.account_id] = account

    async def delete(self, account_id: str) -> bool:
        async with self._lock:
            account = self._by_id.pop(account_id, None)
            if account is None:
                return False
            # The address index is a second copy of the same fact. Leaving it behind
            # would make that address permanently un-invitable.
            self._id_by_email.pop(account.email, None)
            return True

    async def count(self) -> int:
        async with self._lock:
            return len(self._by_id)


class InMemorySessionStore:
    """Sessions keyed by token hash, with expiry applied on every read."""

    def __init__(self, *, clock: Clock) -> None:
        self._clock = clock
        self._by_id: dict[str, Session] = {}
        self._lock = asyncio.Lock()

    async def add(self, session: Session) -> None:
        async with self._lock:
            self._by_id[session.session_id] = session

    async def get_by_token_hash(self, token_hash: str) -> Session | None:
        now = self._clock.now()
        async with self._lock:
            for session in self._by_id.values():
                if session.token_hash == token_hash:
                    return None if session.is_expired(now=now) else session
            return None

    async def save(self, session: Session) -> None:
        async with self._lock:
            self._by_id[session.session_id] = session

    async def revoke(self, session_id: str) -> bool:
        async with self._lock:
            return self._by_id.pop(session_id, None) is not None

    async def revoke_all(self, account_id: str, *, except_session_id: str | None = None) -> int:
        async with self._lock:
            doomed = [
                session_id
                for session_id, session in self._by_id.items()
                if session.account_id == account_id and session_id != except_session_id
            ]
            for session_id in doomed:
                del self._by_id[session_id]
            return len(doomed)

    async def count_for_account(self, account_id: str) -> int:
        now = self._clock.now()
        async with self._lock:
            return sum(
                1
                for session in self._by_id.values()
                if session.account_id == account_id and not session.is_expired(now=now)
            )

    async def drop_oldest(self, account_id: str) -> int:
        async with self._lock:
            owned = [
                session for session in self._by_id.values() if session.account_id == account_id
            ]
            if not owned:
                return 0
            oldest = min(owned, key=lambda session: session.created_at)
            del self._by_id[oldest.session_id]
            return 1

    async def purge_expired(self) -> int:
        now = self._clock.now()
        async with self._lock:
            doomed = [
                session_id
                for session_id, session in self._by_id.items()
                if session.is_expired(now=now)
            ]
            for session_id in doomed:
                del self._by_id[session_id]
            return len(doomed)


class InMemoryGrantStore:
    """Invites and resets, with redemption performed under the lock."""

    def __init__(self) -> None:
        self._by_id: dict[str, Grant] = {}
        self._lock = asyncio.Lock()

    async def add(self, grant: Grant) -> None:
        async with self._lock:
            self._by_id[grant.grant_id] = grant

    async def get_by_token_hash(self, token_hash: str) -> Grant | None:
        async with self._lock:
            return self._find_locked(token_hash)

    async def redeem(self, token_hash: str, *, now: datetime) -> Grant | None:
        async with self._lock:
            grant = self._find_locked(token_hash)
            if grant is None or not grant.is_redeemable(now=now):
                return None
            redeemed = grant.redeemed(now=now)
            self._by_id[grant.grant_id] = redeemed
            return redeemed

    async def revoke_all_for_account(self, account_id: str, purpose: GrantPurpose) -> int:
        async with self._lock:
            # Collected first rather than reassigned mid-iteration: rebinding an
            # existing key during iteration happens to be legal, which is exactly why it
            # survives review and then breaks when someone adds a delete beside it.
            doomed = [
                grant_id
                for grant_id, grant in self._by_id.items()
                if grant.account_id == account_id and grant.purpose is purpose and not grant.revoked
            ]
            for grant_id in doomed:
                self._by_id[grant_id] = self._by_id[grant_id].revoked_now()
            return len(doomed)

    async def delete_for_account(self, account_id: str) -> int:
        async with self._lock:
            doomed = [
                grant_id
                for grant_id, grant in self._by_id.items()
                if grant.account_id == account_id
            ]
            for grant_id in doomed:
                del self._by_id[grant_id]
            return len(doomed)

    async def purge_expired(self, *, now: datetime) -> int:
        async with self._lock:
            doomed = [
                grant_id for grant_id, grant in self._by_id.items() if now >= grant.expires_at
            ]
            for grant_id in doomed:
                del self._by_id[grant_id]
            return len(doomed)

    def _find_locked(self, token_hash: str) -> Grant | None:
        for grant in self._by_id.values():
            if grant.token_hash == token_hash:
                return grant
        return None
