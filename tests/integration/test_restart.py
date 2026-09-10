"""What survives stopping the service and starting it again.

The point of the whole migration, and a test that could not exist before it: every one of
these assertions was false a few commits ago, because an account, its sessions, its
profiles and its roles all died with the process while the encrypted credential material
outlived them -- unreachable, because nothing was left that knew whose it was.

Each test runs two apps in sequence over one database file, exactly as a restart does.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from tests.conftest import (
    ADMIN_TOKEN,
    EMAIL,
    PASSWORD,
    SERVICE_TOKEN,
    account_id_of,
    auth,
    build_settings,
    grant_roles,
    log_in,
    make_profile,
    onboard,
    put_api_key,
    service_call,
    service_token,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from keyring_api.core.config import Settings


@pytest.fixture
def durable(tmp_path: Path) -> Settings:
    """One settings object, and therefore one database file, for both runs."""
    return build_settings(tmp_path)


@contextlib.asynccontextmanager
async def running(settings: Settings) -> AsyncIterator[AsyncClient]:
    """One run of the service, lifespan and all, over the given settings.

    Entering it twice with the same settings is a restart: a new process, a new container,
    a new connection, and the same file underneath.
    """
    async with (
        LifespanManager(create_app(settings)) as managed,
        AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
    ):
        yield http


async def test_an_account_survives(durable: Settings) -> None:
    async with running(durable) as first:
        await onboard(first, EMAIL)

    async with running(durable) as second:
        # Logging in is the whole assertion: the account, its address and its password
        # hash all had to come back.
        assert await log_in(second, EMAIL, PASSWORD)


async def test_a_session_survives(durable: Settings) -> None:
    async with running(durable) as first:
        token = await onboard(first, EMAIL)

    async with running(durable) as second:
        # A restart used to be a forced logout for everybody at once.
        response = await second.get("/v1/auth/me", headers=auth(token))

        assert response.status_code == 200


async def test_a_stored_credential_survives_and_is_still_usable(durable: Settings) -> None:
    async with running(durable) as first:
        token = await onboard(first, EMAIL)
        await make_profile(first, token)
        await put_api_key(first, token, key="the-real-key")

    async with running(durable) as second:
        # The one that mattered most. The ciphertext always survived; what did not was
        # the account, the profile and the connection that said whose it was and how to
        # ask for it, so the material was unreachable and no delete would ever find it.
        session = await log_in(second, EMAIL, PASSWORD)
        minted = await service_token(second, session)
        response = await second.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=minted),
        )

        assert response.status_code == 200
        assert response.json()["headers"] == {"Authorization": "Bearer the-real-key"}


async def test_roles_survive(durable: Settings) -> None:
    async with running(durable) as first:
        owner = await onboard(first, EMAIL)
        session = await onboard(first, "admin@example.com")
        await grant_roles(first, await account_id_of(first, session), ["admin"])
        assert owner

    async with running(durable) as second:
        promoted = await log_in(second, "admin@example.com", PASSWORD)

        response = await second.get("/v1/admin/accounts", headers=auth(promoted))

        assert response.status_code == 200


async def test_a_custom_role_survives(durable: Settings) -> None:
    async with running(durable) as first:
        await onboard(first, EMAIL)
        created = await first.post(
            "/v1/admin/roles",
            json={
                "name": "support",
                "description": "answers the phone",
                "permissions": ["accounts:read"],
            },
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert created.status_code == 201, created.text

    async with running(durable) as second:
        response = await second.get(
            "/v1/admin/roles", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
        )

        assert "support" in [role["name"] for role in response.json()["roles"]]


async def test_the_audit_log_survives(durable: Settings) -> None:
    async with running(durable) as first:
        await onboard(first, EMAIL)
        doomed = await onboard(first, "doomed@example.com")
        doomed_id = await account_id_of(first, doomed)
        deleted = await first.delete(
            f"/v1/admin/accounts/{doomed_id}",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert deleted.status_code == 204, deleted.text

    async with running(durable) as second:
        # An audit log that does not survive a restart is not an audit log. This entry
        # is also the one whose subject no longer exists, which is why the table has no
        # foreign keys.
        response = await second.get(
            "/v1/admin/audit", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
        )

        entries = response.json()["entries"]
        assert [entry["action"] for entry in entries][-1] == "account.invited"
        assert "account.deleted" in [entry["action"] for entry in entries]


async def test_an_outstanding_invite_survives(durable: Settings) -> None:
    async with running(durable) as first:
        await onboard(first, EMAIL)
        invited = await first.post(
            "/v1/admin/invites",
            json={"email": "newcomer@example.com"},
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        token = invited.json()["token"]

    async with running(durable) as second:
        # A restart used to silently invalidate every invite in somebody's inbox.
        response = await second.post(
            "/v1/auth/invites/redeem", json={"token": token, "password": PASSWORD}
        )

        assert response.status_code == 201


async def test_a_deleted_account_stays_deleted(durable: Settings) -> None:
    async with running(durable) as first:
        await onboard(first, EMAIL)
        doomed = await onboard(first, "doomed@example.com")
        doomed_id = await account_id_of(first, doomed)
        await first.delete(
            f"/v1/admin/accounts/{doomed_id}",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )

    async with running(durable) as second:
        response = await second.post(
            "/v1/auth/login", json={"email": "doomed@example.com", "password": PASSWORD}
        )

        assert response.status_code == 401
