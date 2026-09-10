"""Where roles live, and where the last-owner guarantee is actually enforced.

The interesting part of this module is not the CRUD. It is that two operations --
removing a role from an account, and deleting an account -- have to check "is this the
last owner?" and act on the answer **as one atomic step**.

Checked in the caller instead, two administrators demoting the two remaining owners at
the same moment both read "there are two owners", both proceed, and the deployment ends
with none. It is a narrow window and a permanent consequence: nobody can appoint an
owner, because appointing one requires being one.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from keyring_api.domain.errors import (
    InvalidRoleError,
    RoleExistsError,
    RoleInUseError,
    RoleNotFoundError,
)
from keyring_api.domain.rbac import BUILTIN_ROLES, Role, builtin_role, permissions_of

if TYPE_CHECKING:
    from keyring_api.domain.rbac import Permission

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
        roles changing. In the in-memory adapter it falls out of the built-ins living in
        the same dictionary, which is exactly why it is stated here -- an adapter that
        kept built-ins out of its table would lose the property silently.

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
            held_by: how many accounts currently hold it.

        Raises:
            RoleNotFoundError: no such role.
            RoleInUseError: accounts still hold it.
            InvalidRoleError: it is built in.
        """
        ...

    async def resolve(self, names: tuple[str, ...]) -> frozenset[Permission]:
        """The union of these roles' permissions, ignoring names that no longer exist."""
        ...


class InMemoryRoleStore:
    """Roles in a dictionary, seeded with the built-ins."""

    def __init__(self) -> None:
        self._roles: dict[str, Role] = {name: builtin_role(name) for name in BUILTIN_ROLES}
        self._lock = asyncio.Lock()

    async def get(self, name: str) -> Role | None:
        async with self._lock:
            return self._roles.get(name)

    async def require(self, name: str) -> Role:
        role = await self.get(name)
        if role is None:
            raise RoleNotFoundError(NO_SUCH_ROLE)
        return role

    async def list_all(self) -> list[Role]:
        async with self._lock:
            roles = list(self._roles.values())
        # Built-ins first: they are the ones a reader needs to understand before the
        # custom roles that were defined in terms of them.
        return sorted(roles, key=lambda role: (not role.builtin, role.name))

    async def add(self, role: Role) -> None:
        async with self._lock:
            if role.name in self._roles:
                msg = f"a role named {role.name!r} already exists"
                raise RoleExistsError(msg)
            self._roles[role.name] = role

    async def save(self, role: Role) -> None:
        async with self._lock:
            self._roles[role.name] = role

    async def delete(self, name: str, *, held_by: int) -> None:
        async with self._lock:
            role = self._roles.get(name)
            if role is None:
                raise RoleNotFoundError(NO_SUCH_ROLE)

            if role.builtin:
                msg = f"{name!r} is a built-in role and cannot be deleted"
                raise InvalidRoleError(msg)

            if held_by:
                # Refused rather than cascaded. Silently stripping a permission from
                # everybody who had it is the kind of change nobody notices until
                # somebody cannot do their job.
                msg = f"{held_by} account(s) still hold {name!r}; revoke it first"
                raise RoleInUseError(msg)

            del self._roles[name]

    async def resolve(self, names: tuple[str, ...]) -> frozenset[Permission]:
        async with self._lock:
            roles = [self._roles[name] for name in names if name in self._roles]

        # A name with no role behind it contributes nothing rather than raising. Roles
        # cannot be deleted while held, so this only happens if a store is restored from
        # an inconsistent state -- in which case the safe reading is "no permissions".
        return permissions_of(roles)
