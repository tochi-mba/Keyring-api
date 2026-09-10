"""Privilege escalation, attempted every way this service allows.

Every test here is written from the attacker's side: an account that already holds one
administrative permission and wants a second one it was never given. The subject is the
guards in :mod:`keyring_api.admin.service`, so actors are built by hand rather than logged
in over HTTP -- an ``Actor`` is precisely what a request has been reduced to by the time
any of this code runs, and constructing one directly is how a test can hold an attacker's
permission set still and vary nothing else.

The three shapes of attack, and where each is stopped:

* **Grant it to somebody** -- including to yourself, which is the case people forget.
* **Write the role first, grant it second**, which is why creating and editing a role are
  bounded by the author's own permissions too.
* **Edit a role that already exists**, especially a built-in one, which changes what an
  account may do without anybody's roles changing.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import pytest

from keyring_api.admin.service import Actor, AdminService
from keyring_api.audit.log import BREAK_GLASS_ACTOR
from keyring_api.core.container import Container
from keyring_api.domain.accounts import Account, AccountStatus, new_account_id
from keyring_api.domain.errors import (
    AccountNotFoundError,
    InsufficientPermissionError,
    InvalidRoleError,
    RoleNotFoundError,
)
from keyring_api.domain.rbac import (
    ADMIN,
    ALL_PERMISSIONS,
    AUDITOR,
    BUILTIN_ROLES,
    MAX_ROLE_DESCRIPTION_LENGTH,
    MAX_ROLES_PER_ACCOUNT,
    MEMBER,
    OWNER,
    Permission,
    Role,
)
from tests.fakes.clock import EPOCH, FakeClock

if TYPE_CHECKING:
    from keyring_api.core.config import Settings

NOWHERE = "acct_never_existed"
"""An account id nothing will ever hand out, for the 403-before-404 tests."""

ATTACKER_EMAIL = "attacker@example.com"
TARGET_EMAIL = "target@example.com"

AdminCall = Callable[[AdminService, Actor, str], Awaitable[object]]
"""One administrative method, called as ``(service, actor, account_id)``.

The account id is passed to every one of them, including the methods that do not take
one, so a single table can be replayed against a real id and an imaginary one.
"""

ADMIN_CALLS: dict[str, AdminCall] = {
    "list_accounts": lambda service, who, _: service.list_accounts(who),
    "get_account": lambda service, who, target: service.get_account(who, target),
    "list_profiles": lambda service, who, target: service.list_profiles(who, target),
    "read_audit": lambda service, who, _: service.read_audit(who),
    "invite": lambda service, who, _: service.invite(who, email="invited@example.com"),
    "set_status": lambda service, who, target: service.set_status(
        who, target, AccountStatus.DISABLED
    ),
    "revoke_sessions": lambda service, who, target: service.revoke_sessions(who, target),
    "issue_password_reset": lambda service, who, target: service.issue_password_reset(who, target),
    "delete_account": lambda service, who, target: service.delete_account(who, target),
    "delete_profile": lambda service, who, target: service.delete_profile(who, target, "personal"),
    "list_roles": lambda service, who, _: service.list_roles(who),
    "create_role": lambda service, who, _: service.create_role(who, name="minted", permissions=[]),
    "update_role": lambda service, who, _: service.update_role(who, MEMBER, permissions=[]),
    "delete_role": lambda service, who, _: service.delete_role(who, MEMBER),
    "set_account_roles": lambda service, who, target: service.set_account_roles(who, target, []),
}
"""Every public method of the service, called the cheapest way that reaches its guard."""

ACCOUNT_ID_CALLS = [
    "get_account",
    "list_profiles",
    "set_status",
    "revoke_sessions",
    "issue_password_reset",
    "delete_account",
    "delete_profile",
    "set_account_roles",
]
"""The subset that names an account, and so could otherwise answer "does this id exist?"."""


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def container(settings: Settings, clock: FakeClock) -> Container:
    return Container.build(settings, clock=clock)


@pytest.fixture
def admin(container: Container) -> AdminService:
    return container.admin_service


def actor(*permissions: Permission, account_id: str = "acct_attacker") -> Actor:
    """An ordinary administrative caller holding exactly these permissions."""
    return Actor(account_id=account_id, permissions=frozenset(permissions))


def break_glass(*permissions: Permission) -> Actor:
    """The deployment's own admin token, as the request layer builds it."""
    return Actor(
        account_id=BREAK_GLASS_ACTOR, permissions=frozenset(permissions), is_break_glass=True
    )


def names(*permissions: Permission) -> list[str]:
    """Permissions as they arrive from the wire: strings, not enum members."""
    return [permission.value for permission in permissions]


async def add_account(
    container: Container, email: str = TARGET_EMAIL, *, roles: tuple[str, ...] = (MEMBER,)
) -> Account:
    """Put an account in the store without going near a password or an invite."""
    account = Account(
        account_id=new_account_id(),
        email=email,
        password_hash="$argon2id$fake",
        created_at=EPOCH,
        updated_at=EPOCH,
        roles=roles,
    )
    await container.accounts.add(account)
    return account


async def define_role(container: Container, name: str, *permissions: Permission) -> Role:
    """Put a custom role in the store directly, as an owner would have created it."""
    role = Role(name=name, permissions=frozenset(permissions), description=f"the {name} role")
    await container.roles.add(role)
    return role


async def roles_of(container: Container, account_id: str) -> tuple[str, ...]:
    """Re-read an account's roles from the store, to check an attack changed nothing."""
    stored = await container.accounts.get(account_id)
    assert stored is not None
    return stored.roles


class TestGrantingARole:
    async def test_a_role_holding_a_permission_the_assigner_lacks_cannot_be_granted(
        self, admin: AdminService, container: Container
    ) -> None:
        # roles:assign is not a synonym for "every permission". Without this bound it
        # would be, because the roles worth granting are exactly the powerful ones.
        await define_role(container, "deleter", Permission.ACCOUNTS_DELETE)
        target = await add_account(container)

        with pytest.raises(InsufficientPermissionError, match="cannot grant"):
            await admin.set_account_roles(
                actor(Permission.ROLES_ASSIGN), target.account_id, ["deleter"]
            )

        assert await roles_of(container, target.account_id) == (MEMBER,)

    async def test_the_assigner_cannot_grant_that_role_to_themselves_either(
        self, admin: AdminService, container: Container
    ) -> None:
        # The guard is on the permissions being handed out, not on who is receiving them.
        # A rule that only inspected *other* accounts would leave the shortest path to
        # every permission wide open: grant it to yourself.
        await define_role(container, "assigner", Permission.ROLES_ASSIGN)
        await define_role(container, "deleter", Permission.ACCOUNTS_DELETE)
        attacker = await add_account(container, ATTACKER_EMAIL, roles=("assigner",))

        with pytest.raises(InsufficientPermissionError, match="cannot grant"):
            await admin.set_account_roles(
                actor(Permission.ROLES_ASSIGN, account_id=attacker.account_id),
                attacker.account_id,
                ["assigner", "deleter"],
            )

        assert await roles_of(container, attacker.account_id) == ("assigner",)

    async def test_a_role_within_the_assigners_own_permissions_can_be_granted(
        self, admin: AdminService, container: Container
    ) -> None:
        await define_role(container, "reader", Permission.ACCOUNTS_READ)
        target = await add_account(container)

        updated = await admin.set_account_roles(
            actor(Permission.ROLES_ASSIGN, Permission.ACCOUNTS_READ, Permission.AUDIT_READ),
            target.account_id,
            ["reader"],
        )

        assert updated.roles == ("reader",)

    async def test_a_role_equal_to_the_assigners_own_permissions_can_be_granted(
        self, admin: AdminService, container: Container
    ) -> None:
        # The boundary of the subset rule, asserted from the inside: equal is allowed, and
        # the previous tests establish that one permission more is not.
        own = frozenset({Permission.ROLES_ASSIGN, Permission.ACCOUNTS_READ})
        await define_role(container, "twin", *own)
        target = await add_account(container)

        updated = await admin.set_account_roles(
            Actor(account_id="acct_granter", permissions=own), target.account_id, ["twin"]
        )

        assert updated.roles == ("twin",)

    async def test_an_actor_holding_every_permission_can_appoint_an_owner(
        self, admin: AdminService, container: Container
    ) -> None:
        target = await add_account(container)

        updated = await admin.set_account_roles(
            Actor(account_id="acct_owner", permissions=ALL_PERMISSIONS),
            target.account_id,
            [OWNER],
        )

        assert updated.roles == (OWNER,)

    async def test_a_builtin_admin_cannot_appoint_an_owner(
        self, admin: AdminService, container: Container
    ) -> None:
        # admin is every permission except roles:write, so owner is exactly one permission
        # above it -- and the refusal names that permission, because a caller who cannot
        # tell what they lack cannot ask for the right thing.
        target = await add_account(container)

        with pytest.raises(InsufficientPermissionError, match="roles:write"):
            await admin.set_account_roles(
                Actor(account_id="acct_admin", permissions=BUILTIN_ROLES[ADMIN]),
                target.account_id,
                [OWNER],
            )

        assert await roles_of(container, target.account_id) == (MEMBER,)

    async def test_a_role_nobody_has_defined_cannot_be_granted(
        self, admin: AdminService, container: Container
    ) -> None:
        target = await add_account(container)

        with pytest.raises(RoleNotFoundError):
            await admin.set_account_roles(
                actor(Permission.ROLES_ASSIGN), target.account_id, ["ghost"]
            )

    async def test_the_same_role_named_twice_is_held_once(
        self, admin: AdminService, container: Container
    ) -> None:
        target = await add_account(container)

        updated = await admin.set_account_roles(
            actor(Permission.ROLES_ASSIGN, *BUILTIN_ROLES[AUDITOR]),
            target.account_id,
            [AUDITOR, AUDITOR],
        )

        assert updated.roles == (AUDITOR,)

    async def test_more_roles_than_the_cap_are_refused(
        self, admin: AdminService, container: Container
    ) -> None:
        # The cap is not cosmetic: an account's roles are resolved and unioned on every
        # authenticated request, so the list is work done per request, by anyone.
        target = await add_account(container)
        too_many = [f"role-{index}" for index in range(MAX_ROLES_PER_ACCOUNT + 1)]

        with pytest.raises(InvalidRoleError):
            await admin.set_account_roles(
                actor(Permission.ROLES_ASSIGN), target.account_id, too_many
            )

        assert await roles_of(container, target.account_id) == (MEMBER,)


class TestWritingARole:
    async def test_a_role_cannot_be_created_holding_a_permission_its_author_lacks(
        self, admin: AdminService, container: Container
    ) -> None:
        # Bounding assignment alone would achieve nothing: the attacker would write the
        # role first and grant it second, and the assign guard would see a role whose
        # permissions it is comparing against an actor who has just widened them.
        with pytest.raises(InsufficientPermissionError, match="accounts:delete"):
            await admin.create_role(
                actor(Permission.ROLES_WRITE),
                name="backdoor",
                permissions=names(Permission.ACCOUNTS_DELETE),
            )

        assert await container.roles.get("backdoor") is None

    async def test_a_role_within_the_authors_own_permissions_can_be_created(
        self, admin: AdminService, container: Container
    ) -> None:
        role = await admin.create_role(
            actor(Permission.ROLES_WRITE, Permission.ACCOUNTS_READ, Permission.AUDIT_READ),
            name="support",
            permissions=names(Permission.ACCOUNTS_READ),
        )

        assert role.permissions == frozenset({Permission.ACCOUNTS_READ})
        assert not role.builtin
        stored = await container.roles.get("support")
        assert stored is not None
        assert stored.permissions == frozenset({Permission.ACCOUNTS_READ})

    async def test_an_existing_role_cannot_be_widened_beyond_its_editors_permissions(
        self, admin: AdminService, container: Container
    ) -> None:
        await define_role(container, "support", Permission.ACCOUNTS_READ)

        with pytest.raises(InsufficientPermissionError, match="accounts:delete"):
            await admin.update_role(
                actor(Permission.ROLES_WRITE, Permission.ACCOUNTS_READ),
                "support",
                permissions=names(Permission.ACCOUNTS_READ, Permission.ACCOUNTS_DELETE),
            )

        stored = await container.roles.get("support")
        assert stored is not None
        assert stored.permissions == frozenset({Permission.ACCOUNTS_READ})

    async def test_the_create_then_grant_attack_is_stopped_at_the_first_step(
        self, admin: AdminService, container: Container
    ) -> None:
        # The whole attack, end to end, by the actor best placed to run it: roles:write to
        # mint the role and roles:assign to hand it over, and nothing else. It fails at
        # step one, so step two has no role to name.
        await define_role(container, "role-editor", Permission.ROLES_WRITE, Permission.ROLES_ASSIGN)
        attacker = await add_account(container, ATTACKER_EMAIL, roles=("role-editor",))
        who = actor(Permission.ROLES_WRITE, Permission.ROLES_ASSIGN, account_id=attacker.account_id)

        with pytest.raises(InsufficientPermissionError, match="cannot grant"):
            await admin.create_role(
                who, name="backdoor", permissions=names(Permission.ACCOUNTS_DELETE)
            )

        with pytest.raises(RoleNotFoundError):
            await admin.set_account_roles(who, attacker.account_id, ["backdoor"])

        assert await roles_of(container, attacker.account_id) == ("role-editor",)

    async def test_editing_a_role_you_already_hold_cannot_widen_what_you_may_do(
        self, admin: AdminService, container: Container
    ) -> None:
        # The subtler version of the same attack. Nothing about the account changes -- the
        # attacker keeps the role they were given -- so the escalation would leave no
        # trace in anybody's roles, only in what that role now means.
        await define_role(
            container, "support", Permission.ROLES_WRITE, Permission.PROFILES_READ_ANY
        )
        attacker = await add_account(container, ATTACKER_EMAIL, roles=("support",))

        with pytest.raises(InsufficientPermissionError, match="profiles:delete_any"):
            await admin.update_role(
                actor(
                    Permission.ROLES_WRITE,
                    Permission.PROFILES_READ_ANY,
                    account_id=attacker.account_id,
                ),
                "support",
                permissions=names(
                    Permission.ROLES_WRITE,
                    Permission.PROFILES_READ_ANY,
                    Permission.PROFILES_DELETE_ANY,
                ),
            )

        stored = await container.roles.get("support")
        assert stored is not None
        assert stored.permissions == frozenset(
            {Permission.ROLES_WRITE, Permission.PROFILES_READ_ANY}
        )

    @pytest.mark.parametrize("name", [OWNER, ADMIN, AUDITOR, MEMBER])
    async def test_a_builtin_role_cannot_be_edited(
        self, admin: AdminService, container: Container, name: str
    ) -> None:
        # Editing "member" into something powerful is the quietest escalation available:
        # every account already holds it, so nobody's roles change and no assignment is
        # recorded. Refused even for an actor holding every permission, who is the only
        # actor the subset rule would have let through.
        owner = Actor(account_id="acct_owner", permissions=ALL_PERMISSIONS)

        with pytest.raises(InvalidRoleError):
            await admin.update_role(owner, name, permissions=names(Permission.ACCOUNTS_DELETE))

        stored = await container.roles.get(name)
        assert stored is not None
        assert stored.permissions == BUILTIN_ROLES[name]

    @pytest.mark.parametrize("name", [OWNER, ADMIN, AUDITOR, MEMBER])
    async def test_a_builtin_role_cannot_be_deleted(
        self, admin: AdminService, container: Container, name: str
    ) -> None:
        # Deleting a built-in is the same attack from the other side: resolve() treats a
        # name with no role behind it as no permissions, so deleting "owner" would strip
        # every owner rather than raising anywhere anybody would notice.
        owner = Actor(account_id="acct_owner", permissions=ALL_PERMISSIONS)

        with pytest.raises(InvalidRoleError):
            await admin.delete_role(owner, name)

        stored = await container.roles.get(name)
        assert stored is not None
        assert stored.permissions == BUILTIN_ROLES[name]

    async def test_a_permission_that_does_not_exist_is_refused_by_name(
        self, admin: AdminService, container: Container
    ) -> None:
        # credentials:read_any is the permission this service deliberately does not have.
        # Asked for, it is refused as unknown rather than quietly dropped -- a role that
        # silently ignored it would read as though the boundary had moved.
        with pytest.raises(InvalidRoleError, match="credentials:read_any"):
            await admin.create_role(
                Actor(account_id="acct_owner", permissions=ALL_PERMISSIONS),
                name="thief",
                permissions=["accounts:read", "credentials:read_any"],
            )

        assert await container.roles.get("thief") is None

    async def test_an_over_long_description_is_refused(self, admin: AdminService) -> None:
        # Stored and echoed back to every reader of the role list, so it is bounded.
        with pytest.raises(InvalidRoleError):
            await admin.create_role(
                Actor(account_id="acct_owner", permissions=ALL_PERMISSIONS),
                name="wordy",
                permissions=[],
                description="x" * (MAX_ROLE_DESCRIPTION_LENGTH + 1),
            )


class TestBreakGlass:
    async def test_break_glass_can_appoint_an_owner(
        self, admin: AdminService, container: Container
    ) -> None:
        # The recovery path exists for the deployment that has no owner able to log in.
        # If it could not appoint one, it would not be a recovery path.
        target = await add_account(container)

        updated = await admin.set_account_roles(
            break_glass(*ALL_PERMISSIONS), target.account_id, [OWNER]
        )

        assert updated.roles == (OWNER,)

    async def test_the_break_glass_flag_is_what_exempts_it_from_the_subset_rule(
        self, admin: AdminService, container: Container
    ) -> None:
        # Built with a deliberately narrow permission set, which an ordinary actor could
        # never grant owner with. The exemption is a property of the flag, not of the fact
        # that the real token happens to arrive holding everything: there is no "own"
        # permission set for a deployment token to be a subset of.
        target = await add_account(container)

        updated = await admin.set_account_roles(
            break_glass(Permission.ROLES_ASSIGN), target.account_id, [OWNER]
        )

        assert updated.roles == (OWNER,)

    async def test_break_glass_is_audited_as_itself_rather_than_as_an_account(
        self, admin: AdminService, container: Container
    ) -> None:
        # Conspicuous on purpose. Break-glass use is legitimate and should be rare, and an
        # audit log full of it is telling the operator something.
        target = await add_account(container)

        await admin.set_account_roles(break_glass(*ALL_PERMISSIONS), target.account_id, [AUDITOR])

        entries = await container.audit.recent(limit=1)
        assert entries[0].actor_id == BREAK_GLASS_ACTOR
        assert entries[0].target_id == target.account_id


class TestPermissionIsCheckedBeforeAnythingElse:
    @pytest.mark.parametrize("name", list(ADMIN_CALLS))
    async def test_an_actor_with_no_permissions_is_refused_by_every_method(
        self, admin: AdminService, name: str
    ) -> None:
        # A member holds no permissions at all, and every method has to say so. A single
        # method that forgot its check is a hole nothing else in the design covers.
        with pytest.raises(InsufficientPermissionError):
            await ADMIN_CALLS[name](admin, actor(), NOWHERE)

    @pytest.mark.parametrize("name", ACCOUNT_ID_CALLS)
    async def test_an_account_that_exists_is_refused_identically_to_one_that_does_not(
        self, admin: AdminService, container: Container, name: str
    ) -> None:
        # Permission first, existence second. Together with the previous test this is the
        # whole property: a caller with no permissions gets the same refusal for a real id
        # and an imaginary one, so the difference cannot be walked to enumerate accounts.
        existing = await add_account(container)

        with pytest.raises(InsufficientPermissionError):
            await ADMIN_CALLS[name](admin, actor(), existing.account_id)

    @pytest.mark.parametrize("name", ACCOUNT_ID_CALLS)
    async def test_an_actor_who_does_hold_the_permission_learns_the_id_is_unknown(
        self, admin: AdminService, name: str
    ) -> None:
        # The other half of the pair, and the reason the previous ones mean anything: the
        # id really is absent, so a permitted caller is told so. Only who is asking
        # changes the answer.
        permitted = Actor(account_id="acct_owner", permissions=ALL_PERMISSIONS)

        with pytest.raises(AccountNotFoundError):
            await ADMIN_CALLS[name](admin, permitted, NOWHERE)


class TestTheActorItself:
    def test_an_actor_reports_the_permissions_it_holds_and_no_others(self) -> None:
        who = actor(Permission.ACCOUNTS_READ)

        assert who.has(Permission.ACCOUNTS_READ)
        assert not who.has(Permission.ACCOUNTS_DELETE)

    def test_a_refusal_names_the_permission_that_was_missing(self) -> None:
        # A caller who cannot tell which permission they lack cannot ask for the right
        # one, and will be given something broader than they needed.
        with pytest.raises(InsufficientPermissionError, match="accounts:delete"):
            actor(Permission.ACCOUNTS_READ).require(Permission.ACCOUNTS_DELETE)
