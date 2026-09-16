"""Shared fixtures.

Every test that touches the app builds its own, so nothing leaks between cases.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keyring_api.accounts.sql_roles import seed_builtin_roles
from keyring_api.api.app import create_app
from keyring_api.api.routers.internal import USER_TOKEN_HEADER
from keyring_api.core.config import Argon2Settings, LogFormat, RateLimitSettings, Settings
from keyring_api.storage.database import Database
from keyring_api.storage.migrator import migrate
from tests.fakes.clock import EPOCH

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from fastapi import FastAPI

ADMIN_TOKEN = "test-admin-token"
EMAIL = "person@example.com"
PASSWORD = "correct horse battery staple"
MASTER_KEY = base64.b64encode(bytes(range(32))).decode()
SERVICE_NAME = "media-tool"
SERVICE_TOKEN = "media-tool-service-token-0123456789abcdef"
"""At least 32 characters, because configuration refuses anything shorter."""


def build_settings(tmp_path: Path, **overrides: Any) -> Settings:
    """Test settings, built through validation.

    Overrides go through the constructor rather than ``model_copy(update=...)``, which
    skips validators -- so a base64 master key would stay a plain string and fail only
    at the point of use.
    """
    defaults: dict[str, Any] = {
        "_env_file": None,
        "database_path": tmp_path / "keyring.db",
        "signing_key_path": tmp_path / "keys" / "signing.pem",
        "log_format": LogFormat.CONSOLE,
        "admin_token": ADMIN_TOKEN,
        "master_key": MASTER_KEY,
        "service_tokens": {SERVICE_NAME: SERVICE_TOKEN},
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
async def database(tmp_path: Path) -> AsyncIterator[Database]:
    """A migrated database on a real file.

    A real file rather than ``:memory:`` on purpose: durability is the property this
    storage exists for, so the tests exercise the journal mode a deployment actually
    runs on.
    """
    db = Database(tmp_path / "keyring.db")
    migrate(db, now=EPOCH)
    seed_builtin_roles(db)
    try:
        yield db
    finally:
        await db.aclose()


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


async def stored_secret_count(app: FastAPI, account_id: str, profile: str | None = None) -> int:
    """How much encrypted credential material this account still has.

    The successor to the tests that used to stat the secrets directory. What they were
    really asking -- is there decryptable material left that nothing knows about -- is
    now a row count.
    """
    database = container_of(app).database
    if profile is None:
        rows = await database.fetch_all(
            "SELECT service FROM secrets WHERE account_id = ?", (account_id,)
        )
    else:
        rows = await database.fetch_all(
            "SELECT service FROM secrets WHERE account_id = ? AND profile_name = ?",
            (account_id, profile),
        )
    count: int = len(rows)
    return count


async def invite(client: AsyncClient, email: str = EMAIL, *, as_token: str = ADMIN_TOKEN) -> str:
    """Mint an invite and return its token.

    Defaults to the break-glass admin token, which is how a fresh deployment gets its
    first account -- there is nobody to authorise it yet.
    """
    response = await client.post(
        "/v1/admin/invites",
        json={"email": email},
        headers={"Authorization": f"Bearer {as_token}"},
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


async def make_profile(client: AsyncClient, token: str, name: str = "personal") -> str:
    """Create a profile and return its name."""
    response = await client.post("/v1/profiles", json={"name": name}, headers=auth(token))
    assert response.status_code == 201, response.text
    created: str = response.json()["name"]
    return created


async def put_api_key(
    client: AsyncClient,
    token: str,
    *,
    profile: str = "personal",
    service: str = "tmdb",
    key: str = "the-api-key",
) -> None:
    """Store an API key credential."""
    response = await client.put(
        f"/v1/profiles/{profile}/connections/{service}/api-key",
        json={"api_key": key},
        headers=auth(token),
    )
    assert response.status_code == 200, response.text


async def service_token(client: AsyncClient, token: str, audience: str = SERVICE_NAME) -> str:
    """Exchange a session for a short-lived token scoped to one service."""
    response = await client.post(
        "/v1/auth/service-token", json={"audience": audience}, headers=auth(token)
    )
    assert response.status_code == 200, response.text
    minted: str = response.json()["token"]
    return minted


async def grant_roles(
    client: AsyncClient, account_id: str, roles: list[str], *, as_token: str = ADMIN_TOKEN
) -> None:
    """Set an account's roles, by default via break-glass."""
    response = await client.put(
        f"/v1/admin/accounts/{account_id}/roles",
        json={"roles": roles},
        headers={"Authorization": f"Bearer {as_token}"},
    )
    assert response.status_code == 200, response.text


async def account_id_of(client: AsyncClient, token: str) -> str:
    """Read the calling account's own id."""
    response = await client.get("/v1/auth/me", headers=auth(token))
    assert response.status_code == 200, response.text
    account_id: str = response.json()["account_id"]
    return account_id


async def onboard_with_roles(
    client: AsyncClient, email: str, roles: list[str], password: str = PASSWORD
) -> str:
    """Onboard an account and grant it roles. Returns its session token."""
    session = await onboard(client, email, password)
    await grant_roles(client, await account_id_of(client, session), roles)
    return session


def service_call(*, service_token_value: str, user_token: str) -> dict[str, str]:
    """The two headers an internal call must carry: which service, and for whom."""
    return {
        "Authorization": f"Bearer {service_token_value}",
        USER_TOKEN_HEADER: user_token,
    }
