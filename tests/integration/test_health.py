"""GET /healthy over HTTP."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from keyring_api.core.config import Settings
from tests.conftest import build_settings

if TYPE_CHECKING:
    from pathlib import Path


async def test_a_healthy_service_reports_ok(client: AsyncClient) -> None:
    response = await client.get("/healthy")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


async def test_it_needs_no_authentication(client: AsyncClient) -> None:
    # A load balancer cannot hold a session. This is the one route that is open, and
    # everything it reports is written on the assumption a stranger is reading it.
    response = await client.get("/healthy")

    assert response.status_code == 200


async def test_it_reports_a_version_and_an_uptime(client: AsyncClient) -> None:
    body = (await client.get("/healthy")).json()

    assert body["version"].count(".") == 2
    assert body["uptime_seconds"] >= 0


async def test_it_names_every_dependency_it_checked(client: AsyncClient) -> None:
    body = (await client.get("/healthy")).json()

    assert set(body["checks"]) == {"accounts", "vault"}


async def test_it_leaks_no_personal_data(client: AsyncClient) -> None:
    # Counts and yes/no answers only -- never an address, a profile name, or a path.
    await client.post(
        "/v1/admin/invites",
        json={"email": "person@example.com"},
        headers={"Authorization": "Bearer test-admin-token"},
    )

    body = (await client.get("/healthy")).text

    assert "person@example.com" not in body


async def test_a_sealed_vault_reports_degraded_with_the_fix(tmp_path: Path) -> None:
    # Degraded rather than dead: people can still log in and see which connections
    # exist, they just cannot use one. Reporting it healthy would hide the
    # misconfiguration until the first credential request failed for no visible reason.
    sealed = build_settings(tmp_path, master_key=None)

    async with (
        LifespanManager(create_app(sealed)) as managed,
        AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
    ):
        response = await http.get("/healthy")

    assert response.status_code == 503
    assert response.json()["status"] == "degraded"
    assert response.json()["checks"]["vault"]["detail"]["fix"] == "set KEYRING_MASTER_KEY"


async def test_an_open_vault_reports_ok(settings: Settings) -> None:
    async with (
        LifespanManager(create_app(settings)) as managed,
        AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
    ):
        response = await http.get("/healthy")

    assert response.status_code == 200
    assert response.json()["checks"]["vault"]["detail"]["sealed"] is False


@pytest.mark.parametrize("path", ["/docs", "/openapi.json"])
async def test_the_api_documents_itself(client: AsyncClient, path: str) -> None:
    assert (await client.get(path)).status_code == 200
