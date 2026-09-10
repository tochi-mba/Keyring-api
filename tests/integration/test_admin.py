"""The operator surface, and above all the delete cascade.

A vault that half-deletes an account leaves credential material on disk that nothing
knows about and nothing will ever clean up. Every test in the cascade section asserts one
specific thing is gone -- and one asserts that somebody else's is not.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from tests.conftest import (
    ADMIN_TOKEN,
    PASSWORD,
    auth,
    build_settings,
    container_of,
    make_profile,
    onboard,
    put_api_key,
)

if TYPE_CHECKING:
    from pathlib import Path

    from fastapi import FastAPI

    from keyring_api.core.config import Settings

OTHER_EMAIL = "other@example.com"
EMAIL_TO_DELETE = "doomed@example.com"


async def account_id_of(client: AsyncClient, token: str) -> str:
    """Read the calling account's id."""
    response = await client.get("/v1/auth/me", headers=auth(token))
    assert response.status_code == 200, response.text
    account_id: str = response.json()["account_id"]
    return account_id


async def delete(client: AsyncClient, account_id: str) -> int:
    """Delete an account as the operator. Returns the status code."""
    response = await client.delete(f"/v1/admin/accounts/{account_id}", headers=auth(ADMIN_TOKEN))
    return response.status_code


class TestAuthorization:
    async def test_a_session_without_the_permission_does_not_authorise_deletion(
        self, client: AsyncClient
    ) -> None:
        # A compromised ordinary account must not be able to delete accounts -- its own
        # or anybody else's. The second account onboarded gets `member`, which has no
        # administrative permissions at all.
        owner = await onboard(client)
        ordinary = await onboard(client, OTHER_EMAIL)
        victim = await account_id_of(client, owner)

        response = await client.delete(f"/v1/admin/accounts/{victim}", headers=auth(ordinary))

        assert response.status_code == 403

    async def test_no_token_is_refused(self, client: AsyncClient) -> None:
        assert (await client.delete("/v1/admin/accounts/acct_anything")).status_code == 401

    async def test_deleting_an_unknown_account_is_not_found(self, client: AsyncClient) -> None:
        # Safe to be explicit here: only the operator can reach this path, so there is no
        # stranger to leak the answer to.
        assert await delete(client, "acct_never_existed") == 404

    async def test_a_deployment_with_no_admin_token_refuses_break_glass(
        self, tmp_path: Path
    ) -> None:
        # Refused, never waved through. A fallback to "no token required" is how a
        # service ships with an unauthenticated account factory.
        settings = build_settings(tmp_path, admin_token=None)

        async with (
            LifespanManager(create_app(settings)) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            response = await http.delete("/v1/admin/accounts/acct_1", headers=auth("anything"))

        assert response.status_code == 401


class TestCascade:
    """Deleting an account leaves nothing behind.

    Every test here deletes the *second* account. The first one onboarded becomes the
    owner, and the last-owner guard refuses to delete it -- which is its own test, in
    TestLastOwner.
    """

    async def test_the_account_can_no_longer_log_in(self, client: AsyncClient) -> None:
        await onboard(client)
        session = await onboard(client, EMAIL_TO_DELETE)
        account_id = await account_id_of(client, session)

        assert await delete(client, account_id) == 204

        response = await client.post(
            "/v1/auth/login", json={"email": EMAIL_TO_DELETE, "password": PASSWORD}
        )
        assert response.status_code == 401

    async def test_its_sessions_stop_working(self, client: AsyncClient) -> None:
        await onboard(client)
        session = await onboard(client, EMAIL_TO_DELETE)
        account_id = await account_id_of(client, session)

        await delete(client, account_id)

        assert (await client.get("/v1/auth/me", headers=auth(session))).status_code == 401

    async def test_its_outstanding_reset_token_stops_working(
        self, client: AsyncClient, app: FastAPI
    ) -> None:
        # A reset link is a password until it expires. One that survived its account's
        # deletion would be a live credential for an account that no longer exists.
        await onboard(client)
        session = await onboard(client, EMAIL_TO_DELETE)
        account_id = await account_id_of(client, session)
        grant = await container_of(app).account_service.request_password_reset(
            email=EMAIL_TO_DELETE, caller="test"
        )

        await delete(client, account_id)

        response = await client.post(
            "/v1/auth/password/reset",
            json={"token": grant.token, "password": "a new passphrase"},
        )
        assert response.status_code == 400

    async def test_its_profiles_are_gone(self, client: AsyncClient, app: FastAPI) -> None:
        await onboard(client)
        session = await onboard(client, EMAIL_TO_DELETE)
        await make_profile(client, session)
        account_id = await account_id_of(client, session)

        await delete(client, account_id)

        assert await container_of(app).profiles.list_for_account(account_id) == []

    async def test_its_encrypted_credential_files_are_gone_from_disk(
        self, client: AsyncClient, settings: Settings
    ) -> None:
        # The one that matters most. A profile record is a row; a leftover secret file is
        # decryptable credential material sitting on disk that nothing will collect.
        await onboard(client)
        session = await onboard(client, EMAIL_TO_DELETE)
        await make_profile(client, session)
        await put_api_key(client, session, profile="personal", service="tmdb")
        account_id = await account_id_of(client, session)
        stored = settings.secret_dir / account_id
        assert stored.exists()

        await delete(client, account_id)

        assert not stored.exists()

    async def test_the_address_can_be_invited_again(self, client: AsyncClient) -> None:
        # The address index is a second copy of the same fact. Leaving it behind would
        # make that address permanently un-invitable.
        await onboard(client)
        session = await onboard(client, EMAIL_TO_DELETE)
        account_id = await account_id_of(client, session)

        await delete(client, account_id)

        response = await client.post(
            "/v1/admin/invites", json={"email": EMAIL_TO_DELETE}, headers=auth(ADMIN_TOKEN)
        )
        assert response.status_code == 201


class TestCascadeIsNotOverBroad:
    async def test_another_account_keeps_its_session(self, client: AsyncClient) -> None:
        survivor = await onboard(client)
        doomed = await onboard(client, EMAIL_TO_DELETE)

        await delete(client, await account_id_of(client, doomed))

        assert (await client.get("/v1/auth/me", headers=auth(survivor))).status_code == 200

    async def test_another_account_keeps_its_profiles(self, client: AsyncClient) -> None:
        survivor = await onboard(client)
        doomed = await onboard(client, EMAIL_TO_DELETE)
        await make_profile(client, survivor)

        await delete(client, await account_id_of(client, doomed))

        response = await client.get("/v1/profiles/personal", headers=auth(survivor))
        assert response.status_code == 200

    async def test_another_account_keeps_its_credential_files(
        self, client: AsyncClient, settings: Settings
    ) -> None:
        survivor = await onboard(client)
        doomed = await onboard(client, EMAIL_TO_DELETE)
        await make_profile(client, survivor)
        await put_api_key(client, survivor, profile="personal", service="tmdb")
        survivor_id = await account_id_of(client, survivor)

        await delete(client, await account_id_of(client, doomed))

        assert (settings.secret_dir / survivor_id).exists()
