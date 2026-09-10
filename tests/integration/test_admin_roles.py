"""The role half of ``/v1/admin``, over HTTP.

The unit tests hold the escalation guards still and poke at them directly. These cover
what a caller with a real session can actually observe: which status code each refusal
produces, that a role edit is felt by its holders without them logging in again, and
that the subset rule survives the trip through the router rather than living only in the
service it was written in.

Two properties are the reason this file exists:

* **A member can reach none of it.** Every route here is parametrised into one test, so
  a new route that forgets its permission fails a test rather than shipping.
* **Nobody can grant above themselves**, including to themselves, and the refusal leaves
  the attacker's roles exactly as they were.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient, Response

from keyring_api.domain.rbac import ADMIN, ALL_PERMISSIONS, AUDITOR, MEMBER, OWNER, Permission
from tests.conftest import (
    ADMIN_TOKEN,
    account_id_of,
    auth,
    grant_roles,
    onboard,
    onboard_with_roles,
)

OTHER_EMAIL = "other@example.com"
THIRD_EMAIL = "third@example.com"

SUPPORT = "support"
"""The custom role most tests build. Nothing built-in is named this."""

ASSIGNER = "assigner"
NO_SUCH_ROLE = "never-defined"

ACCOUNTS_READ = Permission.ACCOUNTS_READ.value
AUDIT_READ = Permission.AUDIT_READ.value
ROLES_ASSIGN = Permission.ROLES_ASSIGN.value
ROLES_WRITE = Permission.ROLES_WRITE.value

INVENTED_PERMISSION = "credentials:read_any"
"""A permission this service deliberately does not have. See ADR-0010."""

ROLE_ROUTES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("GET", "/v1/admin/permissions", None),
    ("GET", "/v1/admin/roles", None),
    ("POST", "/v1/admin/roles", {"name": SUPPORT, "permissions": []}),
    ("PUT", f"/v1/admin/roles/{AUDITOR}", {"permissions": []}),
    ("DELETE", f"/v1/admin/roles/{AUDITOR}", None),
    ("PUT", "/v1/admin/accounts/{account_id}/roles", {"roles": []}),
]
"""Every route in the role half, with a body that would validate if it got that far."""


async def create_role(
    client: AsyncClient,
    token: str,
    *,
    permissions: list[str],
    name: str = SUPPORT,
    description: str = "For the people who answer the phone.",
) -> Response:
    """Attempt to define a custom role. Returns the raw response, refusals included."""
    return await client.post(
        "/v1/admin/roles",
        json={"name": name, "permissions": permissions, "description": description},
        headers=auth(token),
    )


async def update_role(
    client: AsyncClient, token: str, name: str, *, permissions: list[str]
) -> Response:
    """Attempt to replace a role's permission set."""
    return await client.put(
        f"/v1/admin/roles/{name}",
        json={"permissions": permissions, "description": "Changed."},
        headers=auth(token),
    )


async def put_roles(client: AsyncClient, token: str, account_id: str, roles: list[str]) -> Response:
    """Attempt to replace an account's roles. Unlike ``grant_roles``, asserts nothing."""
    return await client.put(
        f"/v1/admin/accounts/{account_id}/roles", json={"roles": roles}, headers=auth(token)
    )


async def role_names(client: AsyncClient, token: str) -> list[str]:
    """Every role name, in the order the service lists them."""
    response = await client.get("/v1/admin/roles", headers=auth(token))
    assert response.status_code == 200, response.text
    names: list[str] = [role["name"] for role in response.json()["roles"]]
    return names


async def roles_of(client: AsyncClient, token: str, account_id: str) -> list[str]:
    """Which roles an account holds, read back over HTTP."""
    response = await client.get(f"/v1/admin/accounts/{account_id}", headers=auth(token))
    assert response.status_code == 200, response.text
    held: list[str] = response.json()["roles"]
    return held


class TestThePermissionCatalogue:
    async def test_every_permission_is_listed_with_a_description(self, client: AsyncClient) -> None:
        # An administrator building a custom role has to be able to see the vocabulary;
        # guessing at strings produces a role that is rejected or, worse, one that is
        # accepted and does nothing.
        owner = await onboard(client)

        response = await client.get("/v1/admin/permissions", headers=auth(owner))

        assert response.status_code == 200
        listed = response.json()["permissions"]
        assert [entry["name"] for entry in listed] == sorted(
            permission.value for permission in ALL_PERMISSIONS
        )
        assert all(len(entry["description"]) > 0 for entry in listed)

    async def test_reading_the_catalogue_needs_only_roles_read(self, client: AsyncClient) -> None:
        # auditor is read-only, and reading which permissions exist is reading.
        await onboard(client)
        auditor = await onboard_with_roles(client, OTHER_EMAIL, [AUDITOR])

        response = await client.get("/v1/admin/permissions", headers=auth(auditor))

        assert response.status_code == 200


class TestAMemberReachesNoneOfIt:
    @pytest.mark.parametrize(("method", "path", "body"), ROLE_ROUTES)
    async def test_an_account_with_no_permissions_is_refused(
        self, client: AsyncClient, method: str, path: str, body: dict[str, Any] | None
    ) -> None:
        # The second account onboarded gets `member`, which holds nothing. Parametrised
        # rather than written out so that a route added without a permission check has
        # to be added here too before this test will pass.
        await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        account_id = await account_id_of(client, member)

        response = await client.request(
            method, path.format(account_id=account_id), json=body, headers=auth(member)
        )

        assert response.status_code == 403
        # The detail, not just the status: a 403 produced by anything other than the
        # missing permission would satisfy the status code and prove nothing.
        assert "permission" in response.json()["detail"]


class TestListingRoles:
    async def test_builtin_roles_come_first_with_their_permissions(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)

        response = await client.get("/v1/admin/roles", headers=auth(owner))

        assert response.status_code == 200
        roles = response.json()["roles"]
        assert [role["name"] for role in roles] == [ADMIN, AUDITOR, MEMBER, OWNER]
        by_name = {role["name"]: role for role in roles}
        assert by_name[OWNER]["permissions"] == sorted(
            permission.value for permission in ALL_PERMISSIONS
        )
        assert ROLES_WRITE not in by_name[ADMIN]["permissions"]
        assert by_name[MEMBER]["permissions"] == []
        assert all(role["builtin"] is True for role in roles)


class TestCreatingARole:
    async def test_a_new_role_is_created_and_listed_after_the_builtins(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)

        response = await create_role(client, owner, permissions=[ACCOUNTS_READ, AUDIT_READ])

        assert response.status_code == 201
        body = response.json()
        assert body["name"] == SUPPORT
        assert body["permissions"] == sorted([ACCOUNTS_READ, AUDIT_READ])
        assert body["builtin"] is False
        assert await role_names(client, owner) == [ADMIN, AUDITOR, MEMBER, OWNER, SUPPORT]

    async def test_a_second_role_of_the_same_name_conflicts(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        await create_role(client, owner, permissions=[ACCOUNTS_READ])

        response = await create_role(client, owner, permissions=[AUDIT_READ])

        assert response.status_code == 409

    async def test_an_unknown_permission_is_rejected_and_named(self, client: AsyncClient) -> None:
        # Rejected rather than dropped: a role that silently ignores a typo looks correct
        # in the response and does nothing, and the discovery happens when somebody
        # cannot do their job. The value used here is one this service deliberately does
        # not define -- there is no permission that returns another account's credential.
        owner = await onboard(client)

        response = await create_role(
            client, owner, permissions=[ACCOUNTS_READ, INVENTED_PERMISSION]
        )

        assert response.status_code == 422
        assert INVENTED_PERMISSION in response.json()["detail"]
        assert await role_names(client, owner) == [ADMIN, AUDITOR, MEMBER, OWNER]


class TestUpdatingARole:
    async def test_updating_replaces_the_permission_set_rather_than_merging(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)
        await create_role(client, owner, permissions=[ACCOUNTS_READ, AUDIT_READ])

        response = await update_role(client, owner, SUPPORT, permissions=[ACCOUNTS_READ])

        assert response.status_code == 200
        assert response.json()["permissions"] == [ACCOUNTS_READ]
        assert AUDIT_READ not in response.json()["permissions"]

    async def test_a_permission_removed_from_a_role_is_gone_on_the_holders_next_request(
        self, client: AsyncClient
    ) -> None:
        # The property the whole design rests on: an actor is rebuilt from the account's
        # roles on every single request, so permissions are never cached on the session
        # and never baked into a token. The holder here keeps the same session token
        # throughout, and still loses the permission the moment the role changes.
        owner = await onboard(client)
        await create_role(client, owner, permissions=[ACCOUNTS_READ])
        holder = await onboard_with_roles(client, OTHER_EMAIL, [SUPPORT])
        assert (await client.get("/v1/admin/accounts", headers=auth(holder))).status_code == 200

        await update_role(client, owner, SUPPORT, permissions=[AUDIT_READ])

        response = await client.get("/v1/admin/accounts", headers=auth(holder))
        assert response.status_code == 403

    @pytest.mark.parametrize("name", [OWNER, ADMIN, AUDITOR, MEMBER])
    async def test_a_builtin_role_cannot_be_edited(self, client: AsyncClient, name: str) -> None:
        # Editing "member" into something powerful is the quietest privilege escalation
        # available: every account already holds it, so nobody's roles change and no
        # assignment is recorded anywhere.
        owner = await onboard(client)

        response = await update_role(client, owner, name, permissions=[ACCOUNTS_READ])

        assert response.status_code == 422
        assert "built-in" in response.json()["detail"]


class TestDeletingARole:
    async def test_a_role_an_account_still_holds_cannot_be_deleted(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)
        await create_role(client, owner, permissions=[ACCOUNTS_READ])
        await onboard_with_roles(client, OTHER_EMAIL, [SUPPORT])

        response = await client.delete(f"/v1/admin/roles/{SUPPORT}", headers=auth(owner))

        assert response.status_code == 409

    async def test_it_can_be_deleted_once_nobody_holds_it(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        await create_role(client, owner, permissions=[ACCOUNTS_READ])
        holder = await onboard_with_roles(client, OTHER_EMAIL, [SUPPORT])
        await grant_roles(client, await account_id_of(client, holder), [MEMBER])

        response = await client.delete(f"/v1/admin/roles/{SUPPORT}", headers=auth(owner))

        assert response.status_code == 204
        assert await role_names(client, owner) == [ADMIN, AUDITOR, MEMBER, OWNER]

    @pytest.mark.parametrize("name", [OWNER, ADMIN, AUDITOR, MEMBER])
    async def test_a_builtin_role_cannot_be_deleted(self, client: AsyncClient, name: str) -> None:
        # The same attack from the other side: a role name with nothing behind it
        # resolves to no permissions, so deleting "owner" would quietly strip every
        # owner rather than failing anywhere anybody would look.
        owner = await onboard(client)

        response = await client.delete(f"/v1/admin/roles/{name}", headers=auth(owner))

        assert response.status_code == 422
        assert "built-in" in response.json()["detail"]
        assert name in await role_names(client, owner)

    async def test_deleting_a_role_that_never_existed_is_not_found(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)

        response = await client.delete(f"/v1/admin/roles/{NO_SUCH_ROLE}", headers=auth(owner))

        assert response.status_code == 404


class TestAssigningRoles:
    async def test_assigning_replaces_the_whole_set_and_the_response_shows_it(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        account_id = await account_id_of(client, member)

        response = await put_roles(client, owner, account_id, [AUDITOR])

        assert response.status_code == 200
        assert response.json()["roles"] == [AUDITOR]
        assert await roles_of(client, owner, account_id) == [AUDITOR]

    async def test_an_unknown_role_name_is_not_found(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        account_id = await account_id_of(client, member)

        response = await put_roles(client, owner, account_id, [NO_SUCH_ROLE])

        assert response.status_code == 404
        assert await roles_of(client, owner, account_id) == [MEMBER]

    async def test_an_admin_cannot_mint_a_role_but_can_hand_out_an_existing_one(
        self, client: AsyncClient
    ) -> None:
        # `admin` deliberately lacks roles:write. Handing out the roles that exist is an
        # administrator's job; deciding what a role means is an owner's.
        await onboard(client)
        administrator = await onboard_with_roles(client, OTHER_EMAIL, [ADMIN])
        subject = await onboard(client, THIRD_EMAIL)
        subject_id = await account_id_of(client, subject)

        minted = await create_role(client, administrator, permissions=[ACCOUNTS_READ])
        assigned = await put_roles(client, administrator, subject_id, [AUDITOR])

        assert minted.status_code == 403
        assert assigned.status_code == 200
        assert assigned.json()["roles"] == [AUDITOR]


class TestGrantingAboveYourself:
    async def test_an_assigner_cannot_grant_itself_owner(self, client: AsyncClient) -> None:
        # The attack the subset rule exists for: roles:assign without the rule is a
        # synonym for "hold every permission", because the holder can simply award
        # themselves the role that has them. Granting to yourself is the case people
        # forget, so it is the one written here.
        owner = await onboard(client)
        await create_role(client, owner, name=ASSIGNER, permissions=[ROLES_ASSIGN, ACCOUNTS_READ])
        attacker = await onboard_with_roles(client, OTHER_EMAIL, [ASSIGNER])
        attacker_id = await account_id_of(client, attacker)

        response = await put_roles(client, attacker, attacker_id, [OWNER])

        assert response.status_code == 403
        assert await roles_of(client, attacker, attacker_id) == [ASSIGNER]

    async def test_an_assigner_cannot_grant_owner_to_somebody_else_either(
        self, client: AsyncClient
    ) -> None:
        # The bound is on the permissions leaving the actor's hands, not on who catches
        # them -- an accomplice account would be the same escalation with one more step.
        owner = await onboard(client)
        await create_role(client, owner, name=ASSIGNER, permissions=[ROLES_ASSIGN, ACCOUNTS_READ])
        attacker = await onboard_with_roles(client, OTHER_EMAIL, [ASSIGNER])
        accomplice = await onboard(client, THIRD_EMAIL)
        accomplice_id = await account_id_of(client, accomplice)

        response = await put_roles(client, attacker, accomplice_id, [OWNER])

        assert response.status_code == 403
        assert await roles_of(client, attacker, accomplice_id) == [MEMBER]

    async def test_a_role_within_the_actors_own_permissions_is_allowed(
        self, client: AsyncClient
    ) -> None:
        # The other half of the rule, and the reason the refusals above mean something:
        # the bound is the actor's own permission set, not a hardcoded list of roles.
        owner = await onboard(client)
        await create_role(client, owner, name=ASSIGNER, permissions=[ROLES_ASSIGN, ACCOUNTS_READ])
        await create_role(client, owner, permissions=[ACCOUNTS_READ])
        assigner = await onboard_with_roles(client, OTHER_EMAIL, [ASSIGNER])
        subject_id = await account_id_of(client, await onboard(client, THIRD_EMAIL))

        response = await put_roles(client, assigner, subject_id, [SUPPORT])

        assert response.status_code == 200
        assert response.json()["roles"] == [SUPPORT]


class TestBreakGlass:
    async def test_the_admin_token_can_work_the_whole_role_surface(
        self, client: AsyncClient
    ) -> None:
        # The recovery path, for a deployment whose owner cannot log in. It holds every
        # permission and is exempt from the subset rule, so it can hand out `owner`.
        await onboard(client)
        subject = await onboard(client, OTHER_EMAIL)
        subject_id = await account_id_of(client, subject)

        created = await create_role(client, ADMIN_TOKEN, permissions=[ACCOUNTS_READ])
        updated = await update_role(client, ADMIN_TOKEN, SUPPORT, permissions=[AUDIT_READ])
        granted = await put_roles(client, ADMIN_TOKEN, subject_id, [SUPPORT, OWNER])
        revoked = await put_roles(client, ADMIN_TOKEN, subject_id, [OWNER])
        deleted = await client.delete(f"/v1/admin/roles/{SUPPORT}", headers=auth(ADMIN_TOKEN))

        assert created.status_code == 201
        assert updated.json()["permissions"] == [AUDIT_READ]
        assert granted.json()["roles"] == [SUPPORT, OWNER]
        assert revoked.json()["roles"] == [OWNER]
        assert deleted.status_code == 204

    async def test_the_admin_token_reads_the_catalogue_and_the_role_list(
        self, client: AsyncClient
    ) -> None:
        permissions = await client.get("/v1/admin/permissions", headers=auth(ADMIN_TOKEN))

        assert permissions.status_code == 200
        assert len(permissions.json()["permissions"]) == len(ALL_PERMISSIONS)
        assert await role_names(client, ADMIN_TOKEN) == [ADMIN, AUDITOR, MEMBER, OWNER]
