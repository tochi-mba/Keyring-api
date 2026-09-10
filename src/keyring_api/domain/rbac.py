"""Roles and permissions.

Real RBAC: permissions are a closed enum, roles are sets of them, and roles are data --
so a deployment can define whatever it needs rather than living with three hardcoded
tiers. Built-in roles exist so a fresh deployment works, and are immutable so that
"member" cannot quietly be edited into "owner".

## The line this module does not cross

**No permission grants access to another account's credentials.** There is no
``credentials:read_any``, and adding one would be a change of kind rather than degree.
The operator can already decrypt the vault, because they hold the master key
(ADR-0006) -- but that requires shell access on the box, leaves the credential in one
place, and cannot be delegated. A *permission* that produced somebody else's token would
be remote, silent, grantable to anyone, and usable from a browser. Administration here
means managing accounts, not becoming them.

## The two rules that stop privilege escalation

Both are the same idea, and between them they close every path by which a role could be
used to acquire a permission its holder does not already have:

1. **You cannot grant a role whose permissions exceed your own.** Otherwise "assign
   roles" is a synonym for "give yourself every permission".
2. **You cannot create or edit a role whose permissions exceed your own.** Otherwise
   rule 1 is bypassed by writing the role first and granting it second.

## The rule that stops lockout

**The last owner cannot be demoted or deleted.** A deployment with no owner has no way
to appoint one, and the only way back in is the break-glass admin token -- which is
exactly the situation that token exists for and exactly the situation nobody wants to be
in at two in the morning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

from keyring_api.domain.errors import InsufficientPermissionError, InvalidRoleError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

MAX_ROLE_NAME_LENGTH = 64
MAX_ROLE_DESCRIPTION_LENGTH = 200
MAX_ROLES_PER_ACCOUNT = 16
"""A cap, because roles are unioned on every authenticated request."""

_ROLE_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")


class Permission(StrEnum):
    """Everything a role can allow.

    A closed enum rather than free strings. A typo in a free-string permission is a role
    that silently grants nothing -- or, in a check, a gate that silently allows everyone.

    Named ``resource:verb`` so a role's contents read as a sentence, and so a future
    grouping by resource does not require renaming anything.
    """

    ACCOUNTS_READ = "accounts:read"
    """List accounts and read one. Metadata only -- address, status, roles."""

    ACCOUNTS_INVITE = "accounts:invite"
    ACCOUNTS_DISABLE = "accounts:disable"
    """Disable or re-enable an account. Disabling ends its live sessions."""

    ACCOUNTS_DELETE = "accounts:delete"
    """Delete an account and everything it owns. Irreversible."""

    ACCOUNTS_REVOKE_SESSIONS = "accounts:revoke_sessions"
    """Sign somebody out everywhere. The gentler answer to a lost laptop."""

    ACCOUNTS_RESET_PASSWORD = "accounts:reset_password"  # noqa: S105 -- a permission name
    """Mint a reset token for somebody else.

    Deliberately separate from ACCOUNTS_DISABLE: it is close to an account takeover,
    since whoever holds the token sets the password. A role can have one without the
    other.
    """

    ROLES_READ = "roles:read"
    ROLES_WRITE = "roles:write"
    """Create, edit and delete custom roles -- bounded by your own permissions."""

    ROLES_ASSIGN = "roles:assign"
    """Grant and revoke roles -- bounded by your own permissions."""

    PROFILES_READ_ANY = "profiles:read_any"
    """See which profiles and connections another account has.

    Metadata only, and that is the whole point: which services somebody has connected and
    whether each is working, never the credential. There is no permission for the latter.
    """

    PROFILES_DELETE_ANY = "profiles:delete_any"
    """Delete another account's profile or connection. Destroys, never reads."""

    AUDIT_READ = "audit:read"
    """Read the record of privileged actions."""


ALL_PERMISSIONS = frozenset(Permission)

OWNER = "owner"
ADMIN = "admin"
AUDITOR = "auditor"
MEMBER = "member"

BUILTIN_ROLES: dict[str, frozenset[Permission]] = {
    OWNER: ALL_PERMISSIONS,
    ADMIN: frozenset(
        {
            Permission.ACCOUNTS_READ,
            Permission.ACCOUNTS_INVITE,
            Permission.ACCOUNTS_DISABLE,
            Permission.ACCOUNTS_DELETE,
            Permission.ACCOUNTS_REVOKE_SESSIONS,
            Permission.ACCOUNTS_RESET_PASSWORD,
            Permission.ROLES_READ,
            Permission.ROLES_ASSIGN,
            Permission.PROFILES_READ_ANY,
            Permission.PROFILES_DELETE_ANY,
            Permission.AUDIT_READ,
        }
    ),
    AUDITOR: frozenset({Permission.ACCOUNTS_READ, Permission.ROLES_READ, Permission.AUDIT_READ}),
    MEMBER: frozenset(),
}
"""Roles every deployment starts with. Immutable, so ``member`` stays what it says.

``admin`` deliberately lacks ``roles:write``. An admin can hand out the roles that exist;
minting a *new* permission set is an owner's job. The subset rule would prevent an admin
from creating anything more powerful than themselves anyway -- this is the belt to that
braces, and it keeps the blast radius of a compromised admin session smaller.
"""

DEFAULT_ROLE = MEMBER
"""What a newly redeemed invite gets. Nothing administrative, ever, by default."""


def normalize_role_name(raw: str) -> str:
    """Reduce a role name to the one form it is stored and compared as.

    Raises:
        InvalidRoleError: if it cannot be stored or addressed.
    """
    name = raw.strip().lower()

    if not name:
        msg = "role name must not be empty"
        raise InvalidRoleError(msg)

    if len(name) > MAX_ROLE_NAME_LENGTH:
        msg = f"role name must be at most {MAX_ROLE_NAME_LENGTH} characters"
        raise InvalidRoleError(msg)

    if not _ROLE_NAME.match(name):
        msg = (
            "role name may contain only lowercase letters, digits, dot, dash and "
            "underscore, and must start and end with a letter or digit"
        )
        raise InvalidRoleError(msg)

    return name


def parse_permissions(values: Iterable[str]) -> frozenset[Permission]:
    """Turn wire strings into permissions, refusing anything unrecognised.

    Refused rather than ignored. A typo'd permission that is silently dropped produces a
    role which looks right in the response and does nothing, and the discovery happens
    when somebody cannot do their job.

    Raises:
        InvalidRoleError: naming every unrecognised value at once.
    """
    # Materialised first, because the parameter is an Iterable and a generator is a legal
    # argument. Scanning for unknown values would consume it, leaving the pass that builds
    # the result with nothing to read -- and the caller would get a role with no
    # permissions at all: the same "looks right, does nothing" failure this function
    # exists to prevent, arriving through a different door.
    requested = list(values)

    known = {permission.value: permission for permission in Permission}
    unknown = sorted({value for value in requested if value not in known})

    if unknown:
        msg = f"unknown permissions: {', '.join(unknown)}"
        raise InvalidRoleError(msg)

    return frozenset(known[value] for value in requested)


@dataclass(frozen=True, slots=True)
class Role:
    """A named set of permissions."""

    name: str
    permissions: frozenset[Permission]
    description: str = ""
    builtin: bool = False
    """Built-in roles cannot be edited or deleted, so ``member`` stays what it says."""

    created_at: datetime | None = None
    updated_at: datetime | None = None

    def with_permissions(
        self, permissions: frozenset[Permission], *, description: str, now: datetime
    ) -> Role:
        """Return this role with a new permission set."""
        return replace(self, permissions=permissions, description=description, updated_at=now)


def builtin_role(name: str) -> Role:
    """Build one of the roles every deployment starts with."""
    return Role(
        name=name,
        permissions=BUILTIN_ROLES[name],
        description=_BUILTIN_DESCRIPTIONS[name],
        builtin=True,
    )


_BUILTIN_DESCRIPTIONS = {
    OWNER: "Every permission, including managing roles. At least one must always exist.",
    ADMIN: "Manage accounts and assign existing roles. Cannot mint new roles.",
    AUDITOR: "Read-only: accounts, roles and the audit log.",
    MEMBER: "No administrative permissions. What every new account gets.",
}


def permissions_of(roles: Iterable[Role]) -> frozenset[Permission]:
    """The union of several roles' permissions.

    A union rather than a precedence order: roles are additive, so holding both
    ``auditor`` and ``member`` is exactly ``auditor``, and there is no rule anyone has to
    remember about which role "wins".

    No empty-input guard: ``frozenset().union()`` with nothing to union is already the
    empty set. The guard that was here truthiness-tested an ``Iterable``, which is always
    ``True`` for a generator -- the same latent bug as iterating one twice, and worth
    removing rather than leaving as decoration.
    """
    return frozenset().union(*(role.permissions for role in roles))


def check_can_grant(*, holder: frozenset[Permission], granted: frozenset[Permission]) -> None:
    """Refuse to hand out a permission the grantor does not hold.

    The rule that makes every other permission check meaningful. Without it, anyone with
    ``roles:assign`` effectively holds every permission, because they can grant
    themselves a role that has them.

    Raises:
        InsufficientPermissionError: naming the permissions that were not held, so the
            caller can see what they would need rather than guessing.
    """
    excess = granted - holder
    if excess:
        names = ", ".join(sorted(permission.value for permission in excess))
        msg = f"you cannot grant permissions you do not hold: {names}"
        raise InsufficientPermissionError(msg)
