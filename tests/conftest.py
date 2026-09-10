"""Shared fixtures.

Every test that touches the app builds its own, so nothing leaks between cases.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from keyring_api.core.config import Argon2Settings, LogFormat, RateLimitSettings, Settings

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from fastapi import FastAPI

ADMIN_TOKEN = "test-admin-token"
EMAIL = "person@example.com"
PASSWORD = "correct horse battery staple"
MASTER_KEY = base64.b64encode(bytes(range(32))).decode()


def build_settings(tmp_path: Path, **overrides: Any) -> Settings:
    """Test settings, built through validation.

    Overrides go through the constructor rather than ``model_copy(update=...)``, which
    skips validators -- so a base64 master key would stay a plain string and fail only
    at the point of use.
    """
    defaults: dict[str, Any] = {
        "_env_file": None,
        "secret_dir": tmp_path / "secrets",
        "signing_key_path": tmp_path / "keys" / "signing.pem",
        "log_format": LogFormat.CONSOLE,
        "admin_token": ADMIN_TOKEN,
        "master_key": MASTER_KEY,
        # Argon2 at production cost is ~50ms a call by design; the suite does hundreds.
        "argon2": Argon2Settings(time_cost=1, memory_cost_kib=8, parallelism=1),
        # High enough that ordinary cases never trip a limit by accident. Tests that are
        # *about* a limit build their own settings with a low one.
        "lockout_threshold": 50,
        "rate_limit": RateLimitSettings(
            login_attempts=100, reset_attempts=100, invite_attempts=100
        ),
    }
    return Settings(**{**defaults, **overrides})


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings pointed at a scratch directory, with costs and limits tuned for tests."""
    return build_settings(tmp_path)


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """An HTTP client wired straight to the ASGI app, with lifespan run for real."""
    async with (
        LifespanManager(app) as managed,
        AsyncClient(
            transport=ASGITransport(app=managed.app), base_url="http://keyring.test"
        ) as http,
    ):
        yield http


def container_of(app: FastAPI) -> Any:
    """Reach the wired container, for tests that need to inspect or substitute an adapter."""
    return app.state.container


async def invite(client: AsyncClient, email: str = EMAIL) -> str:
    """Mint an invite as the administrator and return its token."""
    response = await client.post(
        "/v1/admin/invites",
        json={"email": email},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert response.status_code == 201, response.text
    token: str = response.json()["token"]
    return token


async def onboard(client: AsyncClient, email: str = EMAIL, password: str = PASSWORD) -> str:
    """Invite an address, redeem it, log in, and return the session token."""
    token = await invite(client, email)
    created = await client.post(
        "/v1/auth/invites/redeem", json={"token": token, "password": password}
    )
    assert created.status_code == 201, created.text

    return await log_in(client, email, password)


async def log_in(client: AsyncClient, email: str = EMAIL, password: str = PASSWORD) -> str:
    """Log in and return the session token."""
    response = await client.post("/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    token: str = response.json()["token"]
    return token


def auth(token: str) -> dict[str, str]:
    """The Authorization header for a session token."""
    return {"Authorization": f"Bearer {token}"}
