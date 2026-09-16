"""Per-person settings over HTTP: what somebody chose is what their session is stamped with.

settings-api is its shared fake here, wired in through the composition root the way the
real client is.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from keyring_api.core.preferences import NAMESPACE, REFUSED, SECONDS_PER_DAY
from settings_client.testing import FakeSettingsClient
from tests.conftest import EMAIL, PASSWORD, build_settings, invite

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

OTHER_EMAIL = "other@example.com"


class RecordingFake(FakeSettingsClient):
    """Records the user token presented on each resolve, so a test can inspect the JWT."""

    def __init__(self) -> None:
        super().__init__()
        self.user_tokens: list[str] = []

    async def resolve(self, namespace: str, *, user_token: str) -> Any:
        self.user_tokens.append(user_token)
        return await super().resolve(namespace, user_token=user_token)


@pytest.fixture
def chosen() -> RecordingFake:
    return RecordingFake()


@pytest.fixture
def app(tmp_path: Path, chosen: RecordingFake) -> Any:
    return create_app(build_settings(tmp_path), settings_client=chosen)


@pytest.fixture
async def client(app: Any) -> AsyncIterator[AsyncClient]:
    async with (
        LifespanManager(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://keyring.test") as http,
    ):
        yield http


async def create_account(client: AsyncClient, email: str) -> None:
    """Invite and redeem without logging in, so a test can control the first settings read."""
    token = await invite(client, email)
    created = await client.post(
        "/v1/auth/invites/redeem", json={"token": token, "password": PASSWORD}
    )
    assert created.status_code == 201, created.text


def expires_at(response: Any) -> datetime:
    raw: str = response.json()["expires_at"]
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def audience_of(token: str) -> str:
    claims = jwt.decode(token, algorithms=["RS256"], options={"verify_signature": False})
    audience: str = claims["aud"]
    return audience


class TestChoicesReachLogin:
    async def test_two_accounts_get_different_idle_timeouts(
        self, client: AsyncClient, chosen: RecordingFake
    ) -> None:
        await create_account(client, EMAIL)
        await create_account(client, OTHER_EMAIL)

        chosen.seed(NAMESPACE, {"session_ttl_days": 1})
        first = await client.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})
        chosen.seed(NAMESPACE, {"session_ttl_days": 7})
        second = await client.post(
            "/v1/auth/login", json={"email": OTHER_EMAIL, "password": PASSWORD}
        )

        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        gap = (expires_at(second) - expires_at(first)).total_seconds()
        assert gap == pytest.approx(6 * SECONDS_PER_DAY, abs=5)
        assert {audience_of(token) for token in chosen.user_tokens} == {NAMESPACE}

    async def test_a_failed_login_never_asks_settings_api(
        self, client: AsyncClient, chosen: RecordingFake
    ) -> None:
        await create_account(client, EMAIL)

        response = await client.post(
            "/v1/auth/login", json={"email": EMAIL, "password": "wrong password"}
        )

        assert response.status_code == 401
        assert chosen.resolves == 0
        assert chosen.user_tokens == []


class TestWhenSettingsApiIsUnwell:
    async def test_an_outage_leaves_the_deployment_idle_timeout(
        self, client: AsyncClient, chosen: RecordingFake
    ) -> None:
        await create_account(client, EMAIL)
        chosen.unavailable = True

        response = await client.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})

        assert response.status_code == 200, response.text

    async def test_settings_api_refusing_this_service_is_a_503(
        self, client: AsyncClient, chosen: RecordingFake
    ) -> None:
        await create_account(client, EMAIL)
        chosen.rejects[NAMESPACE] = (403, "keyring-api was not granted keyring")

        response = await client.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})

        assert response.status_code == 503
        assert response.headers["content-type"].startswith("application/problem+json")
        problem = response.json()
        assert problem["detail"] == REFUSED
        assert "granted" not in problem["detail"]
        assert "keyring-api" not in problem["detail"]
        assert "8003" not in response.text
