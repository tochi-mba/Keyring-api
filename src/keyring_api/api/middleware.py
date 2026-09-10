"""Request-scoped cross-cutting behaviour.

One middleware, doing what belongs to a single span: give the request an id, make that
id visible to every log record it produces, and record how long it took. The
authenticated account is bound separately, by the dependency that resolves it, because
it is not known until the route's dependencies run.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

from keyring_api.api.errors import unhandled_problem_response
from keyring_api.core.context import bind_request_id, new_request_id
from keyring_api.core.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from starlette.requests import Request
    from starlette.responses import Response

logger = get_logger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"
RESPONSE_TIME_HEADER = "X-Response-Time-Ms"
MAX_SUPPLIED_REQUEST_ID = 64


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Binds a request id and logs the outcome of every request."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # An id supplied by the caller is honoured so a trace can span services, but it
        # is length-capped: it ends up in every log record for this request.
        supplied = request.headers.get(REQUEST_ID_HEADER)
        request_id = supplied[:MAX_SUPPLIED_REQUEST_ID] if supplied else new_request_id()

        started = time.perf_counter()
        with bind_request_id(request_id):
            try:
                response = await call_next(request)
            except Exception as exc:
                # Handled here rather than by Starlette's outermost error middleware,
                # which runs after this binding has unwound and would return a response
                # with no request id on it -- the one thing the caller is told to quote.
                logger.warning(
                    "request_failed",
                    method=request.method,
                    path=request.url.path,
                    duration_ms=_elapsed_ms(started),
                )
                response = unhandled_problem_response(exc)

            duration_ms = _elapsed_ms(started)
            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
            )

        response.headers[REQUEST_ID_HEADER] = request_id
        response.headers[RESPONSE_TIME_HEADER] = f"{duration_ms:.1f}"
        return response


def _elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000
