"""What accounts, sessions and grants promise, independent of where they are kept.

Three ports. The adapter is :mod:`keyring_api.accounts.sql_store`; a Postgres one would
slot in here unchanged, which is the reason these are written as protocols rather than as
base classes.

Three behaviours are in the store rather than the caller, on purpose, and each is a race
that a caller doing it in two steps would lose:

* **Expired sessions are invisible on read.** Enforcing expiry only in a sweeper would
  mean a session keeps working between its deadline and the next sweep.
* **Redeeming a grant is one atomic operation.** Read-then-write in a caller cannot stop
  two clicks on the same reset link both succeeding.
* **The last owner check and the write are one operation.** Two administrators demoting
  the two remaining owners at the same moment would otherwise both read "there are two".
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

NO_SUCH_ACCOUNT = "no account with that id"

if TYPE_CHECKING:
    from datetime import datetime

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
        """Remove an account and everything that belongs to it. Returns whether there was one.

        The cascade is part of the contract, not an implementation detail: sessions,
        grants, profiles, connections, roles and stored credential material all go, and
        they go in the same operation. A caller doing it in steps has a middle, and a
        failure in that middle leaves credential material with no account referencing it
        -- unreachable through the API, invisible to every later delete, and still
        decryptable by anyone holding the master key.

        Raises:
            LastOwnerError: if it holds the last owner role.
        """
        ...

    async def count(self) -> int:
        """How many accounts exist."""
        ...

    async def list_all(self) -> list[Account]:
        """Every account, oldest first. For the administrative listing."""
        ...

    async def count_holding(self, role: str) -> int:
        """How many accounts hold a role. Used to refuse deleting one still in use."""
        ...

    async def set_roles(self, account_id: str, roles: tuple[str, ...], *, now: datetime) -> Account:
        """Replace an account's roles, refusing to remove the last owner.

        The check and the write are one operation on purpose. Performed by a caller
        instead, two administrators demoting the two remaining owners at the same moment
        would both read "there are two" and both proceed.

        Raises:
            AccountNotFoundError: no such account.
            LastOwnerError: this would leave the deployment with no owner.
        """
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

    async def add_within_cap(self, session: Session, *, cap: int) -> int:
        """Store a session and trim the account back to ``cap``, as one operation.

        One operation on purpose. Performed by a caller as a count-then-drop loop, two
        logins arriving together each see room the other is about to take, and the cap
        that bounds how much memory an authenticated caller can allocate stops bounding
        it. Returns how many older sessions went.
        """
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

    async def purge_expired(self, *, now: datetime) -> int:
        """Drop grants past their expiry. Returns how many went."""
        ...
