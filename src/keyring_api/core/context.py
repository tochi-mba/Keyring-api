"""Per-request context.

Two facts are attached once, at the edge, and read wherever they are needed without
being threaded through every signature: the request id, and the account the request was
authenticated as. Context variables are task-local, so two people's concurrent requests
can never see each other's identity — which is the mechanism the whole isolation story
rests on, and is tested as such.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

_request_id: ContextVar[str | None] = ContextVar("keyring_request_id", default=None)
_account_id: ContextVar[str | None] = ContextVar("keyring_account_id", default=None)


def new_request_id() -> str:
    """Return a fresh request id."""
    return uuid.uuid4().hex


def get_request_id() -> str | None:
    """Return the current request id, or ``None`` outside a request."""
    return _request_id.get()


def get_account_id() -> str | None:
    """Return the authenticated account, or ``None`` if the request is anonymous."""
    return _account_id.get()


@contextmanager
def bind_request_id(request_id: str) -> Iterator[str]:
    """Bind ``request_id`` for the duration of the block, restoring the previous value after."""
    token = _request_id.set(request_id)
    try:
        yield request_id
    finally:
        _request_id.reset(token)


@contextmanager
def bind_account_id(account_id: str) -> Iterator[str]:
    """Bind ``account_id`` for the duration of the block, restoring the previous value after."""
    token = _account_id.set(account_id)
    try:
        yield account_id
    finally:
        _account_id.reset(token)
