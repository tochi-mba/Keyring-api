"""The request-context middleware."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from keyring_api.api.middleware import (
    MAX_SUPPLIED_REQUEST_ID,
    REQUEST_ID_HEADER,
    RESPONSE_TIME_HEADER,
)
from keyring_api.api.schemas.common import PROBLEM_CONTENT_TYPE

if TYPE_CHECKING:
    from keyring_api.core.config import Settings


@pytest.fixture
def exploding_app(settings: Settings) -> FastAPI:
    """An app with one route that raises, to exercise the unhandled path."""
    app = create_app(settings)

    @app.get("/boom")
    async def boom() -> None:
        secret_bearing_message = "connection to postgres://user:hunter2@db failed"
        raise RuntimeError(secret_bearing_message)

    return app


async def test_every_response_carries_a_request_id(client: AsyncClient) -> None:
    response = await client.get("/healthy")

    assert response.headers[REQUEST_ID_HEADER]


async def test_every_response_reports_how_long_it_took(client: AsyncClient) -> None:
    response = await client.get("/healthy")

    assert float(response.headers[RESPONSE_TIME_HEADER]) >= 0


async def test_a_caller_supplied_request_id_is_honoured(client: AsyncClient) -> None:
    # So a trace can span services -- downstream-tool's request id and keyring's match.
    response = await client.get("/healthy", headers={REQUEST_ID_HEADER: "from-upstream"})

    assert response.headers[REQUEST_ID_HEADER] == "from-upstream"


async def test_a_caller_supplied_request_id_is_length_capped(client: AsyncClient) -> None:
    # It ends up in every log record for the request, so an unbounded one is a way to
    # write arbitrarily large amounts into the log pipeline.
    response = await client.get("/healthy", headers={REQUEST_ID_HEADER: "x" * 500})

    assert len(response.headers[REQUEST_ID_HEADER]) == MAX_SUPPLIED_REQUEST_ID


class TestUnhandledExceptions:
    async def test_an_unhandled_error_becomes_a_problem_json_500(
        self, exploding_app: FastAPI
    ) -> None:
        async with (
            LifespanManager(exploding_app) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            response = await http.get("/boom")

        assert response.status_code == 500
        assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)

    async def test_the_exception_text_never_reaches_the_caller(
        self, exploding_app: FastAPI
    ) -> None:
        # Exception messages routinely carry connection strings, paths and hostnames.
        # The caller gets a request id to quote instead.
        async with (
            LifespanManager(exploding_app) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            response = await http.get("/boom")

        assert "hunter2" not in response.text
        assert "postgres" not in response.text

    async def test_the_response_still_carries_a_request_id(self, exploding_app: FastAPI) -> None:
        # Handled inside the middleware rather than by Starlette's outermost error
        # handler, which runs after the binding has unwound -- the caller is told to
        # quote an id, so there had better be one.
        async with (
            LifespanManager(exploding_app) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            response = await http.get("/boom")

        assert response.json()["request_id"]
        assert response.headers[REQUEST_ID_HEADER]


async def test_an_account_deleted_mid_request_is_refused_rather_than_crashing(
    client: AsyncClient, app: FastAPI
) -> None:
    # A deletion landing between resolving the session and reading the account is rare,
    # but the answer has to be the same one an expired session gets -- not a 500 that
    # says the handler assumed something it should not have.
    from tests.conftest import auth, container_of, onboard

    # A second account, because the first one created becomes the owner and the
    # last-owner guard refuses to delete it -- correctly, and not what this test is about.
    await onboard(client)
    token = await onboard(client, "second@example.com")
    container = container_of(app)
    account = await container.accounts.get_by_email("second@example.com")
    await container.accounts.delete(account.account_id)

    response = await client.get("/v1/auth/me", headers=auth(token))

    assert response.status_code == 401
