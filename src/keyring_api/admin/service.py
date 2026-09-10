"""Administrative operations, and the guards that keep them from being an escalation path.

Every method takes an ``Actor`` -- who is asking, and what they are allowed to do -- and
every one of them is written on the assumption that the actor is trying to acquire a
permission they do not have. That is not paranoia about your family; it is that an
account with an administrative role is now the most valuable thing to steal in this
service, and the code has to be right regardless of who is holding it.

The four guards, and what each closes:

**Permission before existence.** Every method checks the permission first and looks the
target up second. The other order turns a 403/404 difference into an oracle: a caller
with no permissions could enumerate account ids by watching which ones came back 404.

**No granting above yourself.** Assigning a role, and creating or editing one, both
require that the resulting permission set is a subset of the actor's own. Either alone is
bypassed by doing the other first.

**The last owner survives.** Enforced in the store, under its lock, because the check and
the write have to be one step.

**Never another account's credentials.** There is no method here that returns one, and no
permission that would allow it. Administration means managing accounts, not becoming
them -- see the module docstring of :mod:`keyring_api.domain.rbac`.

**No acting upwards.** The granting rule alone does not close escalation, because
resetting a password is close to becoming somebody. Every action *against a person* --
reset, disable, sign out, delete -- additionally requires that the target holds no
permission the actor lacks. Without it, an ``admin`` who cannot grant themselves
``roles:write`` simply resets the owner's password instead.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from keyring_api.audit.log import BREAK_GLASS_ACTOR, AuditAction
from keyring_api.core.logging import get_logger
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.errors import (
    AccountNotFoundError,
    InsufficientPermissionError,
    InvalidRoleError,
    ProfileNotFoundError,
    RoleExistsError,
    RoleNotFoundError,
)
from keyring_api.domain.rbac import (
    MAX_ROLE_DESCRIPTION_LENGTH,
    MAX_ROLES_PER_ACCOUNT,
    Permission,
    Role,
    check_can_grant,
    normalize_role_name,
    parse_permissions,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from keyring_api.accounts.roles import RoleStore
    from keyring_api.accounts.service import AccountService, IssuedGrant
    from keyring_api.accounts.store import AccountStore
    from keyring_api.audit.log import AuditEntry, AuditLog
    from keyring_api.core.clock import Clock
    from keyring_api.credentials.service import CredentialService
    from keyring_api.domain.accounts import Account
    from keyring_api.domain.profiles import Profile

logger = get_logger(__name__)

NO_SUCH_ACCOUNT = "no account with that id"
NO_SUCH_PROFILE = "no profile by that name"


@dataclass(frozen=True, slots=True)
class Actor:
    """Who is making an administrative request, and what they may do.

    Built fresh from the account on every request rather than carried in a token, so
    revoking a role takes effect on the caller's very next request rather than whenever
    they next log in.
    """

    account_id: str
    permissions: frozenset[Permission]
    is_break_glass: bool = False
    """True when the deployment's admin token was used instead of an account.

    Holds every permission, bypasses the subset rule (there is no "own" permission set to
    be a subset of), and is recorded conspicuously in the audit log.
    """

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions

    def require(self, permission: Permission) -> None:
        """Raise unless this actor holds ``permission``.

        Raises:
            InsufficientPermissionError: naming what was needed, because a caller who
                cannot tell which permission they lack cannot ask for the right one.
        """
        if permission not in self.permissions:
            msg = f"this action requires the {permission.value!r} permission"
            raise InsufficientPermissionError(msg)


class AdminService:
    """Administrative operations over accounts and roles."""

    def __init__(  # noqa: PLR0913 -- six injected collaborators; see AccountService
        self,
        *,
        accounts: AccountStore,
        roles: RoleStore,
        audit: AuditLog,
        account_service: AccountService,
        credential_service: CredentialService,
        clock: Clock,
    ) -> None:
        self._accounts = accounts
        self._roles = roles
        self._audit = audit
        self._account_service = account_service
        self._credential_service = credential_service
        self._clock = clock

    # -- Reading -----------------------------------------------------------------------

    async def list_accounts(self, actor: Actor) -> list[Account]:
        """Every account. Metadata only -- never a credential, never a password hash."""
        actor.require(Permission.ACCOUNTS_READ)
        return await self._accounts.list_all()

    async def get_account(self, actor: Actor, account_id: str) -> Account:
        """One account.

        Raises:
            InsufficientPermissionError: checked first, so a caller without the
                permission cannot learn whether the id exists.
            AccountNotFoundError: no such account.
        """
        actor.require(Permission.ACCOUNTS_READ)
        return await self._require_account(account_id)

    async def list_profiles(self, actor: Actor, account_id: str) -> list[Profile]:
        """Which profiles and connections an account has.

        Metadata only, and that is the whole point of the permission: an administrator
        can see that somebody's Spotify connection has expired without being able to use
        it. There is no method here, and no permission, that returns a credential.
        """
        actor.require(Permission.PROFILES_READ_ANY)
        await self._require_account(account_id)
        return await self._credential_service.list_profiles(account_id)

    async def read_audit(self, actor: Actor, *, limit: int = 100) -> list[AuditEntry]:
        """The record of privileged actions."""
        actor.require(Permission.AUDIT_READ)
        return await self._audit.recent(limit=limit)

    # -- Acting on accounts ------------------------------------------------------------

    async def invite(self, actor: Actor, *, email: str) -> IssuedGrant:
        """Mint an invite for a new account."""
        actor.require(Permission.ACCOUNTS_INVITE)
        grant = await self._account_service.issue_invite(email=email)
        await self._record(actor, AuditAction.ACCOUNT_INVITED, detail=f"grant {grant.grant_id}")
        return grant

    async def set_status(self, actor: Actor, account_id: str, status: AccountStatus) -> Account:
        """Disable or re-enable an account.

        Disabling ends its live sessions as well as stopping new logins -- otherwise the
        person just disabled stays signed in wherever they already are, which is the one
        thing disabling is for.
        """
        actor.require(Permission.ACCOUNTS_DISABLE)
        account = await self._require_account(account_id)
        await self._check_can_act_on(actor, account)

        await self._account_service.set_status(account_id, status)
        if status is not AccountStatus.ACTIVE:
            await self._account_service.logout_everywhere(account_id)

        action = (
            AuditAction.ACCOUNT_ENABLED
            if status is AccountStatus.ACTIVE
            else AuditAction.ACCOUNT_DISABLED
        )
        await self._record(actor, action, target_id=account_id)

        updated = await self._accounts.get(account_id)
        return updated if updated is not None else account

    async def revoke_sessions(self, actor: Actor, account_id: str) -> int:
        """Sign an account out everywhere. The gentler answer to a lost laptop."""
        actor.require(Permission.ACCOUNTS_REVOKE_SESSIONS)
        await self._check_can_act_on(actor, await self._require_account(account_id))

        revoked = await self._account_service.logout_everywhere(account_id)
        await self._record(
            actor,
            AuditAction.ACCOUNT_SESSIONS_REVOKED,
            target_id=account_id,
            detail=f"{revoked} session(s)",
        )
        return revoked

    async def issue_password_reset(self, actor: Actor, account_id: str) -> IssuedGrant:
        """Mint a reset token for somebody else.

        Its own permission, separate from disabling, because it is close to an account
        takeover: whoever holds the token sets the password. A role can reasonably have
        the power to disable an account without having the power to walk into it.

        And for exactly that reason it is bounded by :meth:`_check_can_act_on`. Without
        that, this method is a hole straight through the escalation guards: an ``admin``
        who cannot grant themselves ``roles:write`` can instead reset the *owner's*
        password and log in as somebody who already has it.
        """
        actor.require(Permission.ACCOUNTS_RESET_PASSWORD)
        account = await self._require_account(account_id)
        await self._check_can_act_on(actor, account)

        grant = await self._account_service.issue_reset_for(account)
        await self._record(actor, AuditAction.ACCOUNT_PASSWORD_RESET_ISSUED, target_id=account_id)
        return grant

    async def delete_account(self, actor: Actor, account_id: str) -> None:
        """Delete an account and everything it owns.

        Everything goes together: sessions, grants, profiles, connections, roles and
        stored credential material. Nothing is destroyed if the deletion is refused.

        Raises:
            InsufficientPermissionError / AccountNotFoundError: as above.
            LastOwnerError: from the store, atomically -- the last owner cannot go.
        """
        actor.require(Permission.ACCOUNTS_DELETE)
        await self._check_can_act_on(actor, await self._require_account(account_id))

        # One operation, not a sequence. It used to be two -- delete the account, then
        # sweep the vault -- with the order chosen so that a refused deletion could not
        # destroy anything first, and a documented lesser harm if the second half failed:
        # credential material left with nothing referencing it. The store cascades now,
        # so the refusal and the destruction are the same transaction and neither half
        # can happen alone.
        await self._account_service.delete_account(account_id)
        await self._record(actor, AuditAction.ACCOUNT_DELETED, target_id=account_id)

    async def delete_profile(self, actor: Actor, account_id: str, name: str) -> None:
        """Delete another account's profile and the credentials in it.

        Destroys, never reads. That asymmetry is deliberate: cleaning up after somebody
        who has left should not require the ability to use what they left behind.
        """
        actor.require(Permission.PROFILES_DELETE_ANY)
        await self._check_can_act_on(actor, await self._require_account(account_id))

        if not await self._credential_service.delete_profile(account_id, name):
            raise ProfileNotFoundError(NO_SUCH_PROFILE)

        await self._record(
            actor,
            AuditAction.PROFILE_DELETED_BY_ADMIN,
            target_id=account_id,
            detail=f"profile {name!r}",
        )

    # -- Roles -------------------------------------------------------------------------

    async def list_roles(self, actor: Actor) -> list[Role]:
        """Every role and what it allows."""
        actor.require(Permission.ROLES_READ)
        return await self._roles.list_all()

    async def create_role(
        self, actor: Actor, *, name: str, permissions: Iterable[str], description: str = ""
    ) -> Role:
        """Define a new role.

        Bounded by the actor's own permissions. Without that bound, ``roles:write`` alone
        would be every permission: write a role containing them, then grant it.
        """
        actor.require(Permission.ROLES_WRITE)

        role_name = normalize_role_name(name)
        wanted = parse_permissions(permissions)
        self._check_grantable(actor, wanted)
        _check_description(description)

        if await self._roles.get(role_name) is not None:
            msg = f"a role named {role_name!r} already exists"
            raise RoleExistsError(msg)

        now = self._clock.now()
        role = Role(
            name=role_name,
            permissions=wanted,
            description=description,
            created_at=now,
            updated_at=now,
        )
        await self._roles.add(role)
        await self._record(actor, AuditAction.ROLE_CREATED, detail=f"role {role_name!r}")
        return role

    async def update_role(
        self, actor: Actor, name: str, *, permissions: Iterable[str], description: str = ""
    ) -> Role:
        """Change what a role allows.

        Built-in roles are immutable. Otherwise ``member`` could be edited into something
        every account already holds, which is the quietest possible privilege escalation:
        nobody's roles changed.
        """
        actor.require(Permission.ROLES_WRITE)

        role = await self._roles.require(normalize_role_name(name))
        if role.builtin:
            msg = f"{role.name!r} is a built-in role and cannot be edited"
            raise InvalidRoleError(msg)

        wanted = parse_permissions(permissions)
        self._check_grantable(actor, wanted)
        _check_description(description)

        updated = role.with_permissions(wanted, description=description, now=self._clock.now())
        await self._roles.save(updated)
        await self._record(actor, AuditAction.ROLE_UPDATED, detail=f"role {role.name!r}")
        return updated

    async def delete_role(self, actor: Actor, name: str) -> None:
        """Remove a custom role that nobody holds."""
        actor.require(Permission.ROLES_WRITE)

        role_name = normalize_role_name(name)
        held_by = await self._accounts.count_holding(role_name)
        await self._roles.delete(role_name, held_by=held_by)
        await self._record(actor, AuditAction.ROLE_DELETED, detail=f"role {role_name!r}")

    async def set_account_roles(
        self, actor: Actor, account_id: str, roles: Iterable[str]
    ) -> Account:
        """Replace an account's roles.

        The escalation guard is the whole method. Every role being granted is resolved to
        its permissions, and the union must be a subset of the actor's own -- otherwise
        ``roles:assign`` is a synonym for "give yourself everything", including to
        yourself.

        Raises:
            InsufficientPermissionError: lacking ``roles:assign``, or granting above
                yourself.
            RoleNotFoundError: one of the names does not exist.
            LastOwnerError: this would leave the deployment with no owner.
        """
        actor.require(Permission.ROLES_ASSIGN)
        account = await self._require_account(account_id)

        wanted = tuple(dict.fromkeys(normalize_role_name(name) for name in roles))
        if len(wanted) > MAX_ROLES_PER_ACCOUNT:
            msg = f"an account may hold at most {MAX_ROLES_PER_ACCOUNT} roles"
            raise InvalidRoleError(msg)

        granted: frozenset[Permission] = frozenset()
        for name in wanted:
            role = await self._roles.get(name)
            if role is None:
                missing = f"no role named {name!r}"
                raise RoleNotFoundError(missing)
            granted |= role.permissions

        self._check_grantable(actor, granted)

        updated = await self._accounts.set_roles(account.account_id, wanted, now=self._clock.now())
        await self._record(
            actor,
            AuditAction.ROLES_ASSIGNED,
            target_id=account_id,
            detail=f"roles {', '.join(wanted) or '(none)'}",
        )
        return updated

    # -- Internals ---------------------------------------------------------------------

    async def _check_can_act_on(self, actor: Actor, target: Account) -> None:
        """Refuse to act on an account whose permissions exceed the actor's own.

        The counterpart to :meth:`_check_grantable`, and it exists because the granting
        rule alone does not close escalation. Resetting somebody's password is close to
        becoming them -- whoever holds the token sets the password -- so an ``admin``
        who cannot grant themselves ``roles:write`` could simply reset the *owner's*
        password, redeem the token, and log in as somebody who has it. Every guard on
        the granting path is then irrelevant.

        The same reasoning covers disabling, signing out, and deleting: each is an action
        against a person, and being able to take it against somebody more privileged than
        you is a way to remove the people who could stop you.

        Acting on yourself is always allowed -- your own permissions are trivially a
        subset of your own -- so this never blocks somebody managing their own account.

        Raises:
            InsufficientPermissionError: naming what the target holds that you do not.
        """
        if actor.is_break_glass or target.account_id == actor.account_id:
            return

        held_by_target = await self._roles.resolve(target.roles)
        excess = held_by_target - actor.permissions
        if excess:
            names = ", ".join(sorted(permission.value for permission in excess))
            msg = f"you cannot act on an account that holds permissions you do not: {names}"
            raise InsufficientPermissionError(msg)

    def _check_grantable(self, actor: Actor, permissions: frozenset[Permission]) -> None:
        """Refuse to hand out or define a permission the actor does not hold.

        Break-glass is exempt: it is the deployment's own token, it already holds every
        permission, and there is no "own set" for it to exceed.
        """
        if actor.is_break_glass:
            return
        check_can_grant(holder=actor.permissions, granted=permissions)

    async def _require_account(self, account_id: str) -> Account:
        account = await self._accounts.get(account_id)
        if account is None:
            raise AccountNotFoundError(NO_SUCH_ACCOUNT)
        return account

    async def _record(
        self,
        actor: Actor,
        action: AuditAction,
        *,
        target_id: str | None = None,
        detail: str = "",
    ) -> None:
        await self._audit.record(
            action,
            actor_id=BREAK_GLASS_ACTOR if actor.is_break_glass else actor.account_id,
            target_id=target_id,
            detail=detail,
        )


def _check_description(description: str) -> None:
    """Bound a field that is stored and echoed back."""
    if len(description) > MAX_ROLE_DESCRIPTION_LENGTH:
        msg = f"description must be at most {MAX_ROLE_DESCRIPTION_LENGTH} characters"
        raise InvalidRoleError(msg)
