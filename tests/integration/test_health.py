"""GET /healthy and GET /ready over HTTP."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from keyring_api.core.config import Settings
from tests.conftest import build_settings

if TYPE_CHECKING:
    from pathlib import Path


class TestLiveness:
    async def test_a_running_process_reports_alive(self, client: AsyncClient) -> None:
        response = await client.get("/healthy")

        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    async def test_it_needs_no_authentication(self, client: AsyncClient) -> None:
        # A load balancer cannot hold a session. This route and /ready are the open ones,
        # and everything they report is written assuming a stranger is reading it.
        assert (await client.get("/healthy")).status_code == 200

    async def test_it_reports_a_version_and_an_uptime(self, client: AsyncClient) -> None:
        body = (await client.get("/healthy")).json()

        assert body["version"].count(".") == 2
        assert body["uptime_seconds"] >= 0

    async def test_it_stays_alive_while_the_vault_is_sealed(self, tmp_path: Path) -> None:
        # The point of the split. An orchestrator restarts a container whose liveness
        # check fails; a sealed vault is a configuration problem that restarting cannot
        # fix, so it belongs in readiness and nowhere near here.
        sealed = build_settings(tmp_path, master_key=None)

        async with (
            LifespanManager(create_app(sealed)) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            response = await http.get("/healthy")

        assert response.status_code == 200
        assert response.json()["status"] == "alive"

    async def test_it_reports_no_dependency_detail_at_all(self, client: AsyncClient) -> None:
        assert "checks" not in (await client.get("/healthy")).json()


class TestReadiness:
    async def test_a_healthy_service_reports_ok(self, client: AsyncClient) -> None:
        response = await client.get("/ready")

        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    async def test_it_needs_no_authentication(self, client: AsyncClient) -> None:
        assert (await client.get("/ready")).status_code == 200

    async def test_it_names_every_dependency_it_checked(self, client: AsyncClient) -> None:
        body = (await client.get("/ready")).json()

        assert set(body["checks"]) == {"accounts", "vault", "connections"}

    async def test_it_leaks_no_personal_data(self, client: AsyncClient) -> None:
        # Counts and yes/no answers only -- never an address, a profile name, or a path.
        await client.post(
            "/v1/admin/invites",
            json={"email": "person@example.com"},
            headers={"Authorization": "Bearer test-admin-token"},
        )

        body = (await client.get("/ready")).text

        assert "person@example.com" not in body

    async def test_a_sealed_vault_reports_degraded_with_the_fix(self, tmp_path: Path) -> None:
        # Degraded rather than dead: people can still log in and see which connections
        # exist, they just cannot use one. Reporting it healthy would hide the
        # misconfiguration until the first credential request failed for no visible reason.
        sealed = build_settings(tmp_path, master_key=None)

        async with (
            LifespanManager(create_app(sealed)) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            response = await http.get("/ready")

        assert response.status_code == 503
        assert response.json()["status"] == "degraded"
        assert response.json()["checks"]["vault"]["detail"]["fix"] == "set KEYRING_MASTER_KEY"

    async def test_an_open_vault_reports_ok(self, settings: Settings) -> None:
        async with (
            LifespanManager(create_app(settings)) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            response = await http.get("/ready")

        assert response.status_code == 200
        assert response.json()["checks"]["vault"]["detail"]["sealed"] is False

    async def test_it_counts_the_connections_that_exist(self, client: AsyncClient) -> None:
        # This is where the check earns its place: an expired grant shows up here, with
        # the fix, rather than as a job failing mysteriously hours later.
        from tests.conftest import make_profile, onboard, put_api_key

        session = await onboard(client)
        await make_profile(client, session)
        await put_api_key(client, session, profile="personal", service="tmdb")

        body = (await client.get("/ready")).json()

        assert body["checks"]["connections"]["detail"] == {"total": 1, "unusable": 0}
        assert body["status"] == "ok"

    async def test_an_unusable_connection_makes_the_service_degraded(
        self, client: AsyncClient, app: FastAPI
    ) -> None:
        from dataclasses import replace

        from keyring_api.domain.profiles import ConnectionStatus
        from tests.conftest import container_of, make_profile, onboard, put_api_key

        session = await onboard(client)
        await make_profile(client, session)
        await put_api_key(client, session, profile="personal", service="tmdb")

        container = container_of(app)
        profiles = await container.profiles.all_profiles()
        broken = replace(profiles[0].connections[0], status=ConnectionStatus.EXPIRED)
        await container.profiles.put_connection(
            profiles[0].account_id,
            profiles[0].name,
            broken,
            cap=container.settings.max_connections_per_profile,
            now=container.clock.now(),
        )

        response = await client.get("/ready")

        assert response.status_code == 503
        assert response.json()["checks"]["connections"]["detail"]["unusable"] == 1

    async def test_the_connection_count_names_nobody(self, client: AsyncClient) -> None:
        # This endpoint is unauthenticated. It may report how many connections are unwell; it
        # must not report whose, or to what service.
        from tests.conftest import make_profile, onboard, put_api_key

        session = await onboard(client)
        await make_profile(client, session)
        await put_api_key(client, session, profile="personal", service="tmdb")

        body = (await client.get("/ready")).text

        assert "tmdb" not in body
        assert "personal" not in body
        assert "person@example.com" not in body

    async def test_it_publishes_no_counter_that_tracks_reset_requests(
        self, client: AsyncClient
    ) -> None:
        """The subtlest leak this endpoint had, and worth a test that names it.

        /ready is unauthenticated. It used to publish `rate_limited_callers`, the size of
        the rate limiter's map. The per-recipient mail cap only creates a key for an address
        that HAS an account, so a stranger could request a reset for an address and watch
        whether the number rose by one (unknown) or two (real). The identical response body
        was undone by a counter on a different endpoint.
        """
        from tests.conftest import onboard

        await onboard(client)

        before = (await client.get("/ready")).json()["checks"]["accounts"]["detail"]
        await client.post("/v1/auth/password/reset-request", json={"email": "person@example.com"})
        await client.post("/v1/auth/password/reset-request", json={"email": "nobody@example.com"})
        after = (await client.get("/ready")).json()["checks"]["accounts"]["detail"]

        assert "rate_limited_callers" not in after
        assert before == after


@pytest.mark.parametrize("path", ["/docs", "/openapi.json"])
async def test_the_api_documents_itself(client: AsyncClient, path: str) -> None:
    assert (await client.get(path)).status_code == 200
