"""What a role store promises. The adapter is :mod:`keyring_api.accounts.sql_roles`.

The interesting part of this port is not the CRUD. It is that two operations -- removing
a role from an account, and deleting an account -- have to check "is this the last
owner?" and act on the answer **as one atomic step**.

Checked in the caller instead, two administrators demoting the two remaining owners at
the same moment both read "there are two owners", both proceed, and the deployment ends
with none. It is a narrow window and a permanent consequence: nobody can appoint an
owner, because appointing one requires being one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from keyring_api.domain.rbac import Permission, Role

NO_SUCH_ROLE = "no role by that name"


@runtime_checkable
class RoleStore(Protocol):
    """Persistence for roles."""

    async def get(self, name: str) -> Role | None:
        """Return a role, or ``None``."""
        ...

    async def require(self, name: str) -> Role:
        """Return a role.

        Raises:
            RoleNotFoundError: if there is none.
        """
        ...

    async def list_all(self) -> list[Role]:
        """Every role, built-in first, then custom ones alphabetically."""
        ...

    async def add(self, role: Role) -> None:
        """Store a new custom role.

        A built-in name counts as taken. That matters more than it looks: a custom role
        shadowing ``member`` would change what every account holds without any account's
        roles changing. Stated here rather than left to the adapter, because an adapter
        that kept built-ins out of its table would lose the property silently.

        Raises:
            RoleExistsError: if the name is taken, built-in or otherwise.
        """
        ...

    async def save(self, role: Role) -> None:
        """Record a change to a custom role."""
        ...

    async def delete(self, name: str, *, held_by: int) -> None:
        """Remove a custom role.

        Args:
            held_by: how many accounts currently hold it. An adapter that can answer the
                question inside the statement that does the delete -- a foreign key --
                should ignore this and do that instead, because a count taken by the
                caller can go stale between the two calls.

        Raises:
            RoleNotFoundError: no such role.
            RoleInUseError: accounts still hold it.
            InvalidRoleError: it is built in.
        """
        ...

    async def resolve(self, names: tuple[str, ...]) -> frozenset[Permission]:
        """The union of these roles' permissions, ignoring names that no longer exist."""
        ...
