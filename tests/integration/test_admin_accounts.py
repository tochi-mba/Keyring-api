"""The account half of ``/v1/admin``, over HTTP.

The unit tests hold the service guards still and poke at them directly. These cover what
an operator with a real session can observe: which status code each refusal produces,
that disabling somebody actually signs them out, and that the two routes which reach
into another account's profiles show metadata and destroy secrets without ever
returning one.

Three properties are why this file exists:

* **Nothing here carries password material or a credential.** Asserted on the response
  text rather than field by field, so a field added later that does carry one fails a
  test instead of shipping.
* **403 is answered before 404.** A caller lacking the permission gets the same refusal
  for an id that exists and one that never did, which is the only reason 403 is safe on
  this surface at all.
* **Everything done to another account lands in the audit log**, with opaque ids and no
  address in it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from httpx import AsyncClient, Response

from keyring_api.audit.log import BREAK_GLASS_ACTOR
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.rbac import AUDITOR, MEMBER, OWNER
from tests.conftest import (
    ADMIN_TOKEN,
    EMAIL,
    PASSWORD,
    account_id_of,
    auth,
    grant_roles,
    log_in,
    make_profile,
    onboard,
    put_api_key,
    stored_secret_count,
)

if TYPE_CHECKING:
    from fastapi import FastAPI


OTHER_EMAIL = "other@example.com"
NEW_PASSWORD = "an entirely different passphrase"

PROFILE = "personal"
SERVICE = "tmdb"
API_KEY = "the-api-key"
"""What :func:`tests.conftest.put_api_key` stores, so tests can hunt for it in a body."""

NO_SUCH_ACCOUNT = "acct_never_existed"
NO_SUCH_PROFILE = "never-created"

ACCOUNT_ROUTES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("GET", "/v1/admin/accounts", None),
    ("GET", "/v1/admin/accounts/{account_id}", None),
    ("PUT", "/v1/admin/accounts/{account_id}/status", {"status": "disabled"}),
    ("POST", "/v1/admin/accounts/{account_id}/revoke-sessions", None),
    ("POST", "/v1/admin/accounts/{account_id}/password-reset", None),
    ("GET", "/v1/admin/accounts/{account_id}/profiles", None),
    ("DELETE", f"/v1/admin/accounts/{{account_id}}/profiles/{PROFILE}", None),
    ("GET", "/v1/admin/audit", None),
]
"""Every account-half route, with a body that would validate if it got that far.

Deletion of a whole account has its own file -- see tests/integration/test_admin.py.
"""

TARGETED_ROUTES = [route for route in ACCOUNT_ROUTES if "{account_id}" in route[1]]
"""The subset that names an account, and so could leak which ids exist."""


def assert_carries_no_secret(body: str) -> None:
    """Refuse any administrative response that could carry password or key material.

    Checked over the whole body rather than field by field: a field added to one of
    these models later has to pass this too.
    """
    lowered = body.lower()
    assert "argon2" not in lowered
    assert "hash" not in lowered
    assert "password" not in lowered
    assert API_KEY not in body


async def set_status(
    client: AsyncClient, token: str, account_id: str, status: AccountStatus
) -> Response:
    """Attempt to disable or re-enable an account. Returns the raw response."""
    return await client.put(
        f"/v1/admin/accounts/{account_id}/status",
        json={"status": status.value},
        headers=auth(token),
    )


async def set_roles(client: AsyncClient, token: str, account_id: str, roles: list[str]) -> Response:
    """Replace an account's roles as a named actor, rather than via break-glass."""
    return await client.put(
        f"/v1/admin/accounts/{account_id}/roles", json={"roles": roles}, headers=auth(token)
    )


async def profile_names(client: AsyncClient, token: str, account_id: str) -> list[str]:
    """Which profiles an account has, read through the administrative route."""
    response = await client.get(f"/v1/admin/accounts/{account_id}/profiles", headers=auth(token))
    assert response.status_code == 200, response.text
    names: list[str] = [profile["name"] for profile in response.json()]
    return names


async def audit_entries(client: AsyncClient, token: str) -> list[dict[str, Any]]:
    """The audit log, newest first."""
    response = await client.get("/v1/admin/audit", headers=auth(token))
    assert response.status_code == 200, response.text
    entries: list[dict[str, Any]] = response.json()["entries"]
    return entries


async def attempt_login(client: AsyncClient, email: str, password: str) -> int:
    """Log in without asserting anything. Returns the status code."""
    response = await client.post("/v1/auth/login", json={"email": email, "password": password})
    return response.status_code


class TestReadingAccounts:
    async def test_the_listing_shows_metadata_and_no_password_material(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        await make_profile(client, member)
        await put_api_key(client, member)

        response = await client.get("/v1/admin/accounts", headers=auth(owner))

        assert response.status_code == 200
        listed = response.json()["accounts"]
        assert [account["email"] for account in listed] == [EMAIL, OTHER_EMAIL]
        assert listed[0]["roles"] == [OWNER]
        assert listed[1]["roles"] == [MEMBER]
        assert listed[1]["status"] == AccountStatus.ACTIVE.value
        assert listed[1]["locked"] is False
        assert_carries_no_secret(response.text)

    async def test_reading_one_account_shows_metadata_and_no_password_material(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)
        await make_profile(client, member)
        await put_api_key(client, member)

        response = await client.get(f"/v1/admin/accounts/{member_id}", headers=auth(owner))

        assert response.status_code == 200
        body = response.json()
        assert body["account_id"] == member_id
        assert body["email"] == OTHER_EMAIL
        assert body["roles"] == [MEMBER]
        assert_carries_no_secret(response.text)

    @pytest.mark.parametrize(("method", "path", "body"), ACCOUNT_ROUTES)
    async def test_an_account_with_no_permissions_is_refused(
        self, client: AsyncClient, method: str, path: str, body: dict[str, Any] | None
    ) -> None:
        # The second account onboarded gets `member`, which holds nothing at all.
        # Parametrised rather than written out so a route added without a permission
        # check has to be added here before this test will pass.
        await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)

        response = await client.request(
            method, path.format(account_id=member_id), json=body, headers=auth(member)
        )

        assert response.status_code == 403


class TestPermissionIsAnsweredBeforeExistence:
    """403 first, 404 second, on every route that names an account.

    The other order is an oracle: a caller with no permissions would learn which ids
    exist by watching which ones came back 404, and account ids are the input to every
    other administrative route.
    """

    @pytest.mark.parametrize(("method", "path", "body"), TARGETED_ROUTES)
    async def test_an_invented_id_is_refused_exactly_like_a_real_one(
        self, client: AsyncClient, method: str, path: str, body: dict[str, Any] | None
    ) -> None:
        await onboard(client)
        member = await onboard(client, OTHER_EMAIL)

        response = await client.request(
            method, path.format(account_id=NO_SUCH_ACCOUNT), json=body, headers=auth(member)
        )

        assert response.status_code == 403

    @pytest.mark.parametrize(("method", "path", "body"), TARGETED_ROUTES)
    async def test_the_same_id_is_not_found_for_a_caller_who_holds_the_permission(
        self, client: AsyncClient, method: str, path: str, body: dict[str, Any] | None
    ) -> None:
        # Safe to be explicit here, and only here: this caller already holds the
        # permission, so telling them the id is unknown reveals nothing they could not
        # find in the listing.
        owner = await onboard(client)

        response = await client.request(
            method, path.format(account_id=NO_SUCH_ACCOUNT), json=body, headers=auth(owner)
        )

        assert response.status_code == 404


class TestDisablingAnAccount:
    async def test_a_disabled_accounts_live_session_stops_working_at_once(
        self, client: AsyncClient
    ) -> None:
        # Disabling that left the person signed in wherever they already are would not
        # be disabling: the session they hold is the thing being taken away.
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)

        response = await set_status(client, owner, member_id, AccountStatus.DISABLED)

        assert response.status_code == 200
        assert response.json()["status"] == AccountStatus.DISABLED.value
        assert (await client.get("/v1/auth/me", headers=auth(member))).status_code == 401

    async def test_a_disabled_account_cannot_log_in_again(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)

        await set_status(client, owner, member_id, AccountStatus.DISABLED)

        assert await attempt_login(client, OTHER_EMAIL, PASSWORD) == 401

    async def test_re_enabling_lets_the_account_back_in(self, client: AsyncClient) -> None:
        # Reversible, unlike deletion. That is the whole reason the two are separate
        # permissions on separate routes.
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)
        await set_status(client, owner, member_id, AccountStatus.DISABLED)

        response = await set_status(client, owner, member_id, AccountStatus.ACTIVE)

        assert response.status_code == 200
        assert await attempt_login(client, OTHER_EMAIL, PASSWORD) == 200


class TestRevokingSessions:
    async def test_revoking_ends_the_sessions_without_disabling_the_account(
        self, client: AsyncClient
    ) -> None:
        # The gentler answer to a lost laptop: signed out everywhere, not locked out.
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)

        response = await client.post(
            f"/v1/admin/accounts/{member_id}/revoke-sessions", headers=auth(owner)
        )

        assert response.status_code == 200
        assert response.json()["revoked"] == 1
        assert (await client.get("/v1/auth/me", headers=auth(member))).status_code == 401
        fresh = await log_in(client, OTHER_EMAIL)
        assert (await client.get("/v1/auth/me", headers=auth(fresh))).status_code == 200


class TestIssuingAPasswordReset:
    async def test_the_issued_token_actually_sets_a_new_password(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)

        issued = await client.post(
            f"/v1/admin/accounts/{member_id}/password-reset", headers=auth(owner)
        )

        assert issued.status_code == 200
        # Mail is off in the test settings, so the token comes back here for the
        # operator to carry. With delivery configured it exists only in the inbox.
        assert issued.json()["delivered"] is False
        redeemed = await client.post(
            "/v1/auth/password/reset",
            json={"token": issued.json()["token"], "password": NEW_PASSWORD},
        )
        assert redeemed.status_code == 204
        assert await attempt_login(client, OTHER_EMAIL, NEW_PASSWORD) == 200
        assert await attempt_login(client, OTHER_EMAIL, PASSWORD) == 401


class TestAnotherAccountsProfiles:
    async def test_the_listing_shows_connections_and_never_the_credential(
        self, client: AsyncClient
    ) -> None:
        # This asymmetry is what makes profiles:read_any safe to hand out: an operator
        # can see that somebody's connection exists and whether it works, and cannot use
        # it. There is deliberately no permission that returns the value.
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)
        await make_profile(client, member)
        await put_api_key(client, member, profile=PROFILE, service=SERVICE, key=API_KEY)

        response = await client.get(f"/v1/admin/accounts/{member_id}/profiles", headers=auth(owner))

        assert response.status_code == 200
        listed = response.json()
        assert [profile["name"] for profile in listed] == [PROFILE]
        assert listed[0]["connections"] == [
            {"service": SERVICE, "kind": "api_key", "status": "active"}
        ]
        assert API_KEY not in response.text

    async def test_deleting_a_profile_takes_its_stored_credential_with_it(
        self, client: AsyncClient, app: FastAPI
    ) -> None:
        # A profile record is a row. Leftover credential material is decryptable and
        # nothing knows it is there, so nothing will ever collect it.
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)
        await make_profile(client, member)
        await put_api_key(client, member, profile=PROFILE, service=SERVICE, key=API_KEY)
        assert await stored_secret_count(app, member_id, PROFILE) == 1

        response = await client.delete(
            f"/v1/admin/accounts/{member_id}/profiles/{PROFILE}", headers=auth(owner)
        )

        assert response.status_code == 204
        assert await stored_secret_count(app, member_id, PROFILE) == 0
        assert await profile_names(client, owner, member_id) == []

    async def test_deleting_a_profile_nobody_has_is_not_found(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)
        await make_profile(client, member)

        response = await client.delete(
            f"/v1/admin/accounts/{member_id}/profiles/{NO_SUCH_PROFILE}", headers=auth(owner)
        )

        assert response.status_code == 404
        assert await profile_names(client, owner, member_id) == [PROFILE]


class TestTheAuditLog:
    async def test_it_records_who_did_what_to_whom(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        owner_id = await account_id_of(client, owner)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)

        await set_status(client, owner, member_id, AccountStatus.DISABLED)
        assert (await set_roles(client, owner, member_id, [AUDITOR])).status_code == 200

        entries = await audit_entries(client, owner)

        # Newest first, so the role change precedes the disable it followed.
        assert [entry["action"] for entry in entries[:2]] == ["roles.assigned", "account.disabled"]
        assert [entry["actor_id"] for entry in entries[:2]] == [owner_id, owner_id]
        assert [entry["target_id"] for entry in entries[:2]] == [member_id, member_id]
        assert AUDITOR in entries[0]["detail"]

    async def test_a_member_cannot_read_it(self, client: AsyncClient) -> None:
        # Who acted on whom is administrative information in its own right, and the
        # people it is about are the ones most interested in reading it.
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        await set_roles(client, owner, await account_id_of(client, member), [MEMBER])

        response = await client.get("/v1/admin/audit", headers=auth(member))

        assert response.status_code == 403

    async def test_no_address_ever_reaches_it(self, client: AsyncClient) -> None:
        # An audit log is read by more people, and kept for longer, than the vault is.
        # Actor and target are opaque account ids for exactly that reason.
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)
        await set_status(client, owner, member_id, AccountStatus.DISABLED)
        await set_roles(client, owner, member_id, [AUDITOR])

        response = await client.get("/v1/admin/audit", headers=auth(owner))

        assert response.status_code == 200
        assert "@" not in response.text
        assert_carries_no_secret(response.text)

    async def test_break_glass_is_recorded_as_itself(self, client: AsyncClient) -> None:
        # Conspicuously, and not as an account id. Break-glass is legitimate and should
        # be rare; a log full of it is telling the operator something.
        owner = await onboard(client)
        member = await onboard(client, OTHER_EMAIL)
        member_id = await account_id_of(client, member)

        assert (
            await set_status(client, ADMIN_TOKEN, member_id, AccountStatus.DISABLED)
        ).status_code == 200

        entries = await audit_entries(client, owner)
        assert entries[0]["action"] == "account.disabled"
        assert entries[0]["actor_id"] == BREAK_GLASS_ACTOR


class TestTheLastOwner:
    async def test_the_only_owner_cannot_delete_themselves(self, client: AsyncClient) -> None:
        # A deployment with no owner has no way to appoint one; the only way back is the
        # break-glass token, which is the situation nobody wants to be in.
        owner = await onboard(client)
        owner_id = await account_id_of(client, owner)

        response = await client.delete(f"/v1/admin/accounts/{owner_id}", headers=auth(owner))

        assert response.status_code == 409
        assert (await client.get("/v1/auth/me", headers=auth(owner))).status_code == 200

    async def test_a_refused_deletion_destroys_nothing(
        self, client: AsyncClient, app: FastAPI
    ) -> None:
        # A refusal has to arrive before anything is destroyed. A 409 that has already
        # emptied the account's vault is data loss wearing a refusal's response: the
        # caller is told the deletion did not happen.
        owner = await onboard(client)
        owner_id = await account_id_of(client, owner)
        await make_profile(client, owner)
        await put_api_key(client, owner, profile=PROFILE, service=SERVICE, key=API_KEY)

        response = await client.delete(f"/v1/admin/accounts/{owner_id}", headers=auth(owner))

        assert response.status_code == 409
        assert await stored_secret_count(app, owner_id) == 1
        assert await profile_names(client, owner, owner_id) == [PROFILE]

    async def test_an_owner_can_go_once_a_second_owner_exists(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        owner_id = await account_id_of(client, owner)
        successor = await onboard(client, OTHER_EMAIL)
        await grant_roles(client, await account_id_of(client, successor), [OWNER])

        response = await client.delete(f"/v1/admin/accounts/{owner_id}", headers=auth(owner))

        assert response.status_code == 204
        assert await attempt_login(client, EMAIL, PASSWORD) == 401
