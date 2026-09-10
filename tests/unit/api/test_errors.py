"""Rendering failures as problem+json.

Most error paths are exercised through the endpoints that raise them. These are the two
that no endpoint reaches on purpose: a Starlette-level HTTP error raised before any
handler runs, and an account that vanishes between the two reads a request makes.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient

from keyring_api.api.dependencies import get_actor
from keyring_api.api.schemas.common import PROBLEM_CONTENT_TYPE
from keyring_api.core.container import Container
from keyring_api.domain.errors import AuthenticationError
from keyring_api.domain.sessions import Session, new_session_id
from tests.fakes.clock import EPOCH, FakeClock

if TYPE_CHECKING:
    from keyring_api.core.config import Settings


async def test_an_unrouted_path_is_rendered_as_problem_json(client: AsyncClient) -> None:
    # Starlette raises this one itself, before any handler runs. Without the
    # StarletteHTTPException handler it would come back as FastAPI's plain
    # {"detail": ...} -- a different shape from every other failure this service
    # produces, on the response a scanner is most likely to see.
    response = await client.get("/v1/there-is-no-such-route")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)
    assert response.json()["request_id"]


async def test_a_method_that_is_not_allowed_is_rendered_the_same_way(
    client: AsyncClient,
) -> None:
    response = await client.delete("/healthy")

    assert response.status_code == 405
    assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)


async def test_an_account_deleted_between_the_two_reads_is_refused(
    settings: Settings,
) -> None:
    # get_actor resolves a session and then reads the account. A deletion landing between
    # those is rare and cannot be provoked over HTTP -- resolve_session already refuses a
    # session whose account is gone -- but the answer has to be a 401 rather than an
    # AttributeError on None.
    container = Container.build(settings, clock=FakeClock())
    orphaned = Session(
        session_id=new_session_id(),
        account_id="acct_deleted",
        token_hash="hash",
        created_at=EPOCH,
        last_used_at=EPOCH,
        expires_at=EPOCH + timedelta(hours=1),
        absolute_expires_at=EPOCH + timedelta(days=1),
    )

    async def resolve(_token: str) -> Session:
        return orphaned

    container.account_service.resolve_session = resolve  # type: ignore[assignment,method-assign]

    try:
        with pytest.raises(AuthenticationError):
            await get_actor(
                container, HTTPAuthorizationCredentials(scheme="Bearer", credentials="anything")
            )
    finally:
        await container.aclose()
