"""The authentication endpoints over HTTP.

The unit tests cover the service's rules. These cover what a caller can actually
observe: status codes, bodies, headers, and -- most of all -- whether two situations
that must look identical do.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from keyring_api.api.schemas.common import PROBLEM_CONTENT_TYPE
from keyring_api.core.config import RateLimitSettings
from tests.conftest import (
    ADMIN_TOKEN,
    EMAIL,
    PASSWORD,
    auth,
    build_settings,
    container_of,
    invite,
    log_in,
    onboard,
)

if TYPE_CHECKING:
    from pathlib import Path


class TestInviteIssuance:
    async def test_an_administrator_can_mint_an_invite(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/admin/invites", json={"email": EMAIL}, headers=auth(ADMIN_TOKEN)
        )

        assert response.status_code == 201
        assert response.json()["token"]

    async def test_a_session_without_the_permission_does_not_authorise_administration(
        self, client: AsyncClient
    ) -> None:
        # The first account onboarded becomes the owner, so this uses a second one --
        # which gets `member`, and `member` has no administrative permissions at all.
        # A compromised ordinary account must not be able to mint accounts.
        await onboard(client)
        ordinary = await onboard(client, "ordinary@example.com")

        response = await client.post(
            "/v1/admin/invites", json={"email": "third@example.com"}, headers=auth(ordinary)
        )

        assert response.status_code == 403

    async def test_a_session_holding_the_permission_does_authorise_it(
        self, client: AsyncClient
    ) -> None:
        owner = await onboard(client)

        response = await client.post(
            "/v1/admin/invites", json={"email": "other@example.com"}, headers=auth(owner)
        )

        assert response.status_code == 201

    async def test_no_token_is_refused(self, client: AsyncClient) -> None:
        response = await client.post("/v1/admin/invites", json={"email": EMAIL})

        assert response.status_code == 401

    async def test_a_wrong_admin_token_is_refused(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/admin/invites", json={"email": EMAIL}, headers=auth("not-the-token")
        )

        assert response.status_code == 401

    async def test_a_deployment_with_no_admin_token_refuses_break_glass(
        self, tmp_path: Path
    ) -> None:
        # Refused, never waved through. An admin route that falls back to "no token
        # required" when none is configured is how a service ships with an
        # unauthenticated account factory.
        settings = build_settings(tmp_path, admin_token=None)

        async with (
            LifespanManager(create_app(settings)) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            response = await http.post(
                "/v1/admin/invites", json={"email": EMAIL}, headers=auth("anything")
            )

        assert response.status_code == 401

    async def test_inviting_an_address_that_already_has_an_account_conflicts(
        self, client: AsyncClient
    ) -> None:
        await onboard(client)

        response = await client.post(
            "/v1/admin/invites", json={"email": EMAIL}, headers=auth(ADMIN_TOKEN)
        )

        assert response.status_code == 409

    async def test_an_unusable_address_is_rejected(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/admin/invites", json={"email": "nonsense"}, headers=auth(ADMIN_TOKEN)
        )

        assert response.status_code == 422


class TestRegistration:
    async def test_there_is_no_public_registration_endpoint(self, client: AsyncClient) -> None:
        # Invite-only is a design decision, not a configuration one. Nothing here should
        # ever accept an account creation from a stranger.
        paths = (await client.get("/openapi.json")).json()["paths"]

        assert "/v1/auth/register" not in paths
        assert "/v1/accounts" not in paths

    async def test_redeeming_an_invite_creates_an_account(self, client: AsyncClient) -> None:
        token = await invite(client)

        response = await client.post(
            "/v1/auth/invites/redeem", json={"token": token, "password": PASSWORD}
        )

        assert response.status_code == 201
        assert response.json()["email"] == EMAIL

    async def test_the_response_carries_no_password_material(self, client: AsyncClient) -> None:
        token = await invite(client)

        body = (
            await client.post(
                "/v1/auth/invites/redeem", json={"token": token, "password": PASSWORD}
            )
        ).text

        assert PASSWORD not in body
        assert "argon2" not in body
        assert "hash" not in body

    async def test_a_redeemed_invite_cannot_be_used_again(self, client: AsyncClient) -> None:
        token = await invite(client)
        await client.post("/v1/auth/invites/redeem", json={"token": token, "password": PASSWORD})

        response = await client.post(
            "/v1/auth/invites/redeem", json={"token": token, "password": PASSWORD}
        )

        assert response.status_code == 400

    async def test_an_invented_token_fails_the_same_way_a_used_one_does(
        self, client: AsyncClient
    ) -> None:
        used = await invite(client)
        await client.post("/v1/auth/invites/redeem", json={"token": used, "password": PASSWORD})

        spent = await client.post(
            "/v1/auth/invites/redeem", json={"token": used, "password": PASSWORD}
        )
        invented = await client.post(
            "/v1/auth/invites/redeem", json={"token": "never-existed", "password": PASSWORD}
        )

        assert spent.status_code == invented.status_code
        assert spent.json()["detail"] == invented.json()["detail"]

    async def test_a_short_password_is_rejected(self, client: AsyncClient) -> None:
        token = await invite(client)

        response = await client.post(
            "/v1/auth/invites/redeem", json={"token": token, "password": "short"}
        )

        assert response.status_code == 422

    async def test_a_rejected_password_does_not_burn_the_invite(self, client: AsyncClient) -> None:
        # Otherwise a typo costs a round trip to the administrator.
        token = await invite(client)
        await client.post("/v1/auth/invites/redeem", json={"token": token, "password": "short"})

        response = await client.post(
            "/v1/auth/invites/redeem", json={"token": token, "password": PASSWORD}
        )

        assert response.status_code == 201

    async def test_the_address_cannot_be_chosen_by_the_redeemer(self, client: AsyncClient) -> None:
        # There is no email field on this request, and inventing one is rejected rather
        # than ignored -- otherwise a caller could believe they had chosen an address.
        token = await invite(client)

        response = await client.post(
            "/v1/auth/invites/redeem",
            json={"token": token, "password": PASSWORD, "email": "attacker@example.com"},
        )

        assert response.status_code == 422


class TestLogin:
    async def test_a_correct_password_returns_a_session_token(self, client: AsyncClient) -> None:
        await onboard(client)

        response = await client.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})

        assert response.status_code == 200
        assert response.json()["token"]

    async def test_an_unknown_address_and_a_wrong_password_are_indistinguishable(
        self, client: AsyncClient
    ) -> None:
        # The single most important test in this file. Status, body and content type
        # must match exactly -- any difference tells a stranger who has an account here.
        await onboard(client)

        unknown = await client.post(
            "/v1/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}
        )
        wrong = await client.post(
            "/v1/auth/login", json={"email": EMAIL, "password": "wrong password"}
        )

        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json() | {"request_id": None} == wrong.json() | {"request_id": None}
        assert unknown.headers["content-type"] == wrong.headers["content-type"]

    async def test_a_malformed_address_is_also_indistinguishable(self, client: AsyncClient) -> None:
        # A 422 here would be a smaller oracle than a 404, but still an oracle: it tells
        # a caller which address shapes this service considers real.
        await onboard(client)

        malformed = await client.post(
            "/v1/auth/login", json={"email": "not-an-address", "password": PASSWORD}
        )
        wrong = await client.post(
            "/v1/auth/login", json={"email": EMAIL, "password": "wrong password"}
        )

        assert malformed.status_code == wrong.status_code

    async def test_a_failure_is_rendered_as_problem_json(self, client: AsyncClient) -> None:
        response = await client.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})

        assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)
        assert response.json()["request_id"]

    async def test_the_password_is_never_echoed_back(self, client: AsyncClient) -> None:
        # FastAPI's raw validation errors include the offending input, which on this
        # endpoint is a password. The handler copies only the location and the message.
        response = await client.post("/v1/auth/login", json={"email": EMAIL, "password": 12345})

        assert response.status_code == 422
        assert "12345" not in response.text

    async def test_a_short_password_is_not_rejected_at_login(self, client: AsyncClient) -> None:
        # Enforcing the policy here would tell a caller that the stored password is
        # longer than what they sent, and would lock out every account whose password
        # predates a raised minimum.
        await onboard(client)

        response = await client.post("/v1/auth/login", json={"email": EMAIL, "password": "x"})

        assert response.status_code == 401

    async def test_login_is_rate_limited(self, tmp_path: Path) -> None:
        settings = build_settings(tmp_path, rate_limit=RateLimitSettings(login_attempts=3))

        async with (
            LifespanManager(create_app(settings)) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            for _ in range(3):
                await http.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})

            response = await http.post(
                "/v1/auth/login", json={"email": EMAIL, "password": PASSWORD}
            )

        assert response.status_code == 429
        assert int(response.headers["retry-after"]) > 0


class TestSessions:
    async def test_a_session_token_authenticates_a_request(self, client: AsyncClient) -> None:
        token = await onboard(client)

        response = await client.get("/v1/auth/me", headers=auth(token))

        assert response.status_code == 200
        assert response.json()["email"] == EMAIL

    async def test_no_token_is_refused_as_problem_json(self, client: AsyncClient) -> None:
        # FastAPI's own HTTPBearer would raise a bare 403 with a plain JSON body -- a
        # different status and a different shape from every other failure here.
        response = await client.get("/v1/auth/me")

        assert response.status_code == 401
        assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)

    async def test_an_invented_token_is_refused(self, client: AsyncClient) -> None:
        response = await client.get("/v1/auth/me", headers=auth("not-a-real-token"))

        assert response.status_code == 401

    async def test_logging_out_ends_that_session(self, client: AsyncClient) -> None:
        token = await onboard(client)

        assert (await client.post("/v1/auth/logout", headers=auth(token))).status_code == 204

        assert (await client.get("/v1/auth/me", headers=auth(token))).status_code == 401

    async def test_logging_out_leaves_other_devices_signed_in(self, client: AsyncClient) -> None:
        laptop = await onboard(client)
        phone = await log_in(client)

        await client.post("/v1/auth/logout", headers=auth(laptop))

        assert (await client.get("/v1/auth/me", headers=auth(phone))).status_code == 200

    async def test_logging_out_everywhere_ends_every_session(self, client: AsyncClient) -> None:
        laptop = await onboard(client)
        phone = await log_in(client)

        response = await client.post("/v1/auth/logout-everywhere", headers=auth(laptop))

        assert response.json()["revoked"] == 2
        assert (await client.get("/v1/auth/me", headers=auth(phone))).status_code == 401


class TestPasswordChange:
    async def test_the_current_password_is_required(self, client: AsyncClient) -> None:
        token = await onboard(client)

        response = await client.post(
            "/v1/auth/password",
            json={"current_password": "wrong", "new_password": "a new passphrase"},
            headers=auth(token),
        )

        assert response.status_code == 401

    async def test_the_new_password_takes_effect(self, client: AsyncClient) -> None:
        token = await onboard(client)

        response = await client.post(
            "/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": "a new passphrase"},
            headers=auth(token),
        )

        assert response.status_code == 204
        assert await log_in(client, EMAIL, "a new passphrase")

    async def test_other_sessions_die_but_the_calling_one_survives(
        self, client: AsyncClient
    ) -> None:
        current = await onboard(client)
        other = await log_in(client)

        await client.post(
            "/v1/auth/password",
            json={"current_password": PASSWORD, "new_password": "a new passphrase"},
            headers=auth(current),
        )

        assert (await client.get("/v1/auth/me", headers=auth(other))).status_code == 401
        assert (await client.get("/v1/auth/me", headers=auth(current))).status_code == 200


class TestPasswordReset:
    async def test_a_reset_request_for_a_real_account_is_acknowledged(
        self, client: AsyncClient
    ) -> None:
        await onboard(client)

        response = await client.post("/v1/auth/password/reset-request", json={"email": EMAIL})

        assert response.status_code == 200

    async def test_a_reset_request_answers_identically_for_an_unknown_address(
        self, client: AsyncClient
    ) -> None:
        # Byte-for-byte, apart from the request id. Anything that varies here -- a
        # different message, a different status, even a different length -- is a way to
        # test which addresses have accounts.
        await onboard(client)

        known = await client.post("/v1/auth/password/reset-request", json={"email": EMAIL})
        unknown = await client.post(
            "/v1/auth/password/reset-request", json={"email": "nobody@example.com"}
        )

        assert known.status_code == unknown.status_code
        assert known.json() == unknown.json()

    async def test_a_reset_request_for_a_malformed_address_answers_identically_too(
        self, client: AsyncClient
    ) -> None:
        known = await client.post("/v1/auth/password/reset-request", json={"email": EMAIL})
        malformed = await client.post("/v1/auth/password/reset-request", json={"email": "nonsense"})

        assert known.status_code == malformed.status_code
        assert known.json() == malformed.json()

    async def test_the_response_never_contains_the_reset_token(self, client: AsyncClient) -> None:
        # The token goes to the operator to deliver, never back over the wire to
        # whoever asked -- which would make the reset flow a takeover flow.
        await onboard(client)

        body = (await client.post("/v1/auth/password/reset-request", json={"email": EMAIL})).json()

        assert set(body) == {"detail"}

    async def test_a_reset_token_sets_the_new_password_and_ends_every_session(
        self, client: AsyncClient, app: FastAPI
    ) -> None:
        session = await onboard(client)
        container = container_of(app)
        grant = await container.account_service.request_password_reset(email=EMAIL, caller="test")

        response = await client.post(
            "/v1/auth/password/reset",
            json={"token": grant.token, "password": "a new passphrase"},
        )

        assert response.status_code == 204
        assert (await client.get("/v1/auth/me", headers=auth(session))).status_code == 401
        assert await log_in(client, EMAIL, "a new passphrase")

    async def test_an_invented_reset_token_is_refused(self, client: AsyncClient) -> None:
        response = await client.post(
            "/v1/auth/password/reset",
            json={"token": "never-existed", "password": "a new passphrase"},
        )

        assert response.status_code == 400


class TestContract:
    """Operation ids and descriptions become MCP tool names and tool descriptions."""

    async def test_every_operation_id_is_declared_and_stable(self, client: AsyncClient) -> None:
        # Renaming one of these is a breaking change for every MCP client that has a
        # tool bound to it, so the set is pinned here rather than left to drift.
        schema = (await client.get("/openapi.json")).json()

        operation_ids = {
            operation["operationId"]
            for path in schema["paths"].values()
            for operation in path.values()
        }
        assert operation_ids == {
            # health and keys
            "get_health",
            "get_jwks",
            # authentication
            "login",
            "logout",
            "logout_everywhere",
            "get_current_account",
            "redeem_invite",
            "change_password",
            "request_password_reset",
            "redeem_password_reset",
            "issue_service_token",
            # profiles and connections
            "list_profiles",
            "create_profile",
            "get_profile",
            "delete_profile",
            "put_api_key",
            "put_password",
            "authorize_connection",
            "delete_connection",
            "complete_authorization",
            # service-to-service
            "resolve_credential",
            "resolve_form_secrets",
            # administration
            "issue_invite",
            "delete_account",
            "get_account",
            "list_accounts",
            "set_account_roles",
            "set_account_status",
            "revoke_account_sessions",
            "issue_account_password_reset",
            "list_account_profiles",
            "delete_account_profile",
            "list_roles",
            "create_role",
            "update_role",
            "delete_role",
            "list_permissions",
            "read_audit_log",
        }

    async def test_every_operation_describes_itself(self, client: AsyncClient) -> None:
        schema = (await client.get("/openapi.json")).json()

        for path, operations in schema["paths"].items():
            for method, operation in operations.items():
                assert operation.get("summary"), f"{method} {path} has no summary"
                assert len(operation.get("description", "")) > 40, f"{method} {path}"

    async def test_failures_are_documented_where_they_can_happen(self, client: AsyncClient) -> None:
        schema = (await client.get("/openapi.json")).json()

        assert "401" in schema["paths"]["/v1/auth/login"]["post"]["responses"]
        assert "429" in schema["paths"]["/v1/auth/login"]["post"]["responses"]

    async def test_request_bodies_carry_an_example(self, client: AsyncClient) -> None:
        schema = (await client.get("/openapi.json")).json()

        assert schema["components"]["schemas"]["LoginRequest"]["examples"]

    @pytest.mark.parametrize(
        "schema_name",
        ["SessionResponse", "AccountResponse", "AcknowledgedResponse", "RevokedResponse"],
    )
    async def test_no_response_schema_exposes_stored_credential_material(
        self, client: AsyncClient, schema_name: str
    ) -> None:
        # Walks the declared contract rather than one sampled response, so a field added
        # later is caught by this test rather than by whoever reads the logs.
        schema = (await client.get("/openapi.json")).json()
        fields = schema["components"]["schemas"][schema_name].get("properties", {})

        forbidden = ("password", "hash", "secret", "refresh")
        assert not [name for name in fields if any(bad in name.lower() for bad in forbidden)]
