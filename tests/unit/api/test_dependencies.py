"""The dependencies that turn a request into an identity."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from keyring_api.api.dependencies import get_current_account, get_current_session
from keyring_api.core.container import Container
from keyring_api.domain.errors import AuthenticationError
from keyring_api.domain.sessions import Session, new_session_id
from tests.fakes.clock import EPOCH, FakeClock

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from keyring_api.core.config import Settings


@pytest.fixture
async def container(settings: Settings) -> AsyncIterator[Container]:
    built = Container.build(settings, clock=FakeClock())
    try:
        yield built
    finally:
        await built.aclose()


def bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


async def test_a_missing_authorization_header_is_refused(container: Container) -> None:
    with pytest.raises(AuthenticationError):
        await get_current_session(container, None)


async def test_an_unknown_token_is_refused(container: Container) -> None:
    with pytest.raises(AuthenticationError):
        await get_current_session(container, bearer("not-a-real-token"))


async def test_an_account_deleted_between_the_two_reads_is_refused(
    container: Container,
) -> None:
    # Exercised directly, because it cannot be provoked over HTTP: resolve_session
    # already refuses a session whose account is gone. It is here because a deletion
    # landing between the two reads is possible, and the answer has to be a 401 rather
    # than an AttributeError on None.
    orphaned = Session(
        session_id=new_session_id(),
        account_id="acct_deleted",
        token_hash="hash",
        created_at=EPOCH,
        last_used_at=EPOCH,
        expires_at=EPOCH + timedelta(hours=1),
        absolute_expires_at=EPOCH + timedelta(days=1),
    )

    with pytest.raises(AuthenticationError):
        await get_current_account(container, orphaned)
