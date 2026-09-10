"""You cannot act on an account more privileged than you.

Its own file because it is a distinct guard from the granting rule, and because the hole
it closes went unnoticed through a full suite at 100% coverage.

The granting rule stops an actor handing themselves a permission. It does nothing about
an actor *becoming* somebody who already has it -- and resetting a password is close to
exactly that, since whoever holds the token sets the password. An `admin` who cannot
grant themselves `roles:write` could reset the `owner`'s password, redeem it at the
unauthenticated reset endpoint, and log in as somebody who has it. Every guard on the
granting path is then decoration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from keyring_api.admin.service import Actor
from keyring_api.core.container import Container
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.errors import InsufficientPermissionError
from keyring_api.domain.rbac import ADMIN, ALL_PERMISSIONS, BUILTIN_ROLES, MEMBER, OWNER
from tests.fakes.clock import FakeClock

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from keyring_api.core.config import Settings

PASSWORD = "correct horse battery staple"


@pytest.fixture
async def container(settings: Settings) -> AsyncIterator[Container]:
    built = Container.build(settings, clock=FakeClock())
    try:
        yield built
    finally:
        await built.aclose()


async def make_account(container: Container, email: str, roles: list[str]) -> str:
    """Create an account through the real invite flow and set its roles."""
    invite = await container.account_service.issue_invite(email=email)
    account = await container.account_service.redeem_invite(
        token=invite.token, password=PASSWORD, caller="1.2.3.4"
    )
    await container.accounts.set_roles(account.account_id, tuple(roles), now=container.clock.now())
    return account.account_id


def admin_actor(account_id: str) -> Actor:
    """An actor holding exactly the built-in admin permissions."""
    return Actor(account_id=account_id, permissions=BUILTIN_ROLES[ADMIN])


class TestTheTakeoverPath:
    async def test_an_admin_cannot_reset_an_owner_s_password(self, container: Container) -> None:
        # THE test. Without this guard the whole escalation story is undone in one call:
        # with mail disabled the reset token comes back in the response body, and the
        # unauthenticated reset endpoint turns it into the owner's password.
        owner_id = await make_account(container, "owner@example.com", [OWNER])
        admin_id = await make_account(container, "admin@example.com", [ADMIN])

        with pytest.raises(InsufficientPermissionError, match="roles:write"):
            await container.admin_service.issue_password_reset(admin_actor(admin_id), owner_id)

    async def test_an_admin_can_still_reset_an_ordinary_account(self, container: Container) -> None:
        # The guard must not break the thing the permission is for. Helping somebody
        # who is locked out is the entire point of accounts:reset_password.
        await make_account(container, "owner@example.com", [OWNER])
        admin_id = await make_account(container, "admin@example.com", [ADMIN])
        member_id = await make_account(container, "member@example.com", [MEMBER])

        grant = await container.admin_service.issue_password_reset(admin_actor(admin_id), member_id)

        assert grant.token

    async def test_anyone_can_act_on_themselves(self, container: Container) -> None:
        # Your own permissions are trivially a subset of your own, so this never blocks
        # somebody managing their own account -- including an owner.
        await make_account(container, "other@example.com", [OWNER])
        owner_id = await make_account(container, "owner@example.com", [OWNER])

        grant = await container.admin_service.issue_password_reset(
            Actor(account_id=owner_id, permissions=ALL_PERMISSIONS), owner_id
        )

        assert grant.token

    async def test_break_glass_is_exempt(self, container: Container) -> None:
        # It holds every permission and has no permission set of its own to be a subset
        # of. It is also the way back in when no owner can log in, which is precisely the
        # situation this guard would otherwise make unrecoverable.
        owner_id = await make_account(container, "owner@example.com", [OWNER])

        grant = await container.admin_service.issue_password_reset(
            Actor(account_id="break-glass", permissions=ALL_PERMISSIONS, is_break_glass=True),
            owner_id,
        )

        assert grant.token


class TestEveryActionAgainstAPerson:
    """Reset is the sharpest case, but the same reasoning covers the rest.

    Being able to disable, sign out or delete somebody more privileged than you is a way
    to remove the people who could stop you.
    """

    async def test_an_admin_cannot_disable_an_owner(self, container: Container) -> None:
        owner_id = await make_account(container, "owner@example.com", [OWNER])
        admin_id = await make_account(container, "admin@example.com", [ADMIN])

        with pytest.raises(InsufficientPermissionError):
            await container.admin_service.set_status(
                admin_actor(admin_id), owner_id, AccountStatus.DISABLED
            )

    async def test_an_admin_cannot_sign_an_owner_out(self, container: Container) -> None:
        owner_id = await make_account(container, "owner@example.com", [OWNER])
        admin_id = await make_account(container, "admin@example.com", [ADMIN])

        with pytest.raises(InsufficientPermissionError):
            await container.admin_service.revoke_sessions(admin_actor(admin_id), owner_id)

    async def test_an_admin_cannot_delete_an_owner(self, container: Container) -> None:
        # Even a non-last owner, which the last-owner guard would have allowed.
        await make_account(container, "first@example.com", [OWNER])
        owner_id = await make_account(container, "owner@example.com", [OWNER])
        admin_id = await make_account(container, "admin@example.com", [ADMIN])

        with pytest.raises(InsufficientPermissionError):
            await container.admin_service.delete_account(admin_actor(admin_id), owner_id)

    async def test_an_admin_cannot_delete_an_owner_s_profile(self, container: Container) -> None:
        owner_id = await make_account(container, "owner@example.com", [OWNER])
        admin_id = await make_account(container, "admin@example.com", [ADMIN])
        await container.credential_service.create_profile(owner_id, "personal")

        with pytest.raises(InsufficientPermissionError):
            await container.admin_service.delete_profile(
                admin_actor(admin_id), owner_id, "personal"
            )

    async def test_an_admin_can_do_all_of_it_to_an_ordinary_account(
        self, container: Container
    ) -> None:
        # The guard bounds who, not what. An admin remains fully able to administer.
        await make_account(container, "owner@example.com", [OWNER])
        admin_id = await make_account(container, "admin@example.com", [ADMIN])
        member_id = await make_account(container, "member@example.com", [MEMBER])
        actor = admin_actor(admin_id)

        await container.admin_service.set_status(actor, member_id, AccountStatus.DISABLED)
        await container.admin_service.revoke_sessions(actor, member_id)
        await container.admin_service.delete_account(actor, member_id)

        assert await container.accounts.get(member_id) is None


class TestPeerLevelActions:
    async def test_an_admin_can_act_on_another_admin(self, container: Container) -> None:
        # Equal, not greater. The rule is a subset check, not a hierarchy, so peers can
        # cover for each other -- which is the reason to have two administrators.
        await make_account(container, "owner@example.com", [OWNER])
        first_id = await make_account(container, "admin-a@example.com", [ADMIN])
        second_id = await make_account(container, "admin-b@example.com", [ADMIN])

        grant = await container.admin_service.issue_password_reset(admin_actor(first_id), second_id)

        assert grant.token

    async def test_the_error_names_what_the_target_holds(self, container: Container) -> None:
        # So an administrator can see why they were refused rather than guessing, and so
        # the refusal is not itself confusing enough to be worked around.
        owner_id = await make_account(container, "owner@example.com", [OWNER])
        admin_id = await make_account(container, "admin@example.com", [ADMIN])

        with pytest.raises(InsufficientPermissionError) as caught:
            await container.admin_service.revoke_sessions(admin_actor(admin_id), owner_id)

        assert "roles:write" in str(caught.value)
