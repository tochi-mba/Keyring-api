"""Translating exceptions into RFC 9457 problem responses.

This is the only place in the service that maps a failure to a status code, which is
what keeps the handlers thin: they raise domain errors and let this decide what that
means over HTTP.

It is also where the no-enumeration rule is finally enforced. Two decisions matter:

* **Cross-account access is 404, never 403.** A 403 confirms the resource exists, which
  tells one person that another person has a profile by that name. 404 is the same
  answer they would get for a name nobody has used.
* **An unexpected exception's text never reaches the caller.** It can carry a path, a
  hostname, or a fragment of a credential. The caller gets a request id to quote.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from keyring_api.api.schemas.common import PROBLEM_CONTENT_TYPE, FieldError, Problem
from keyring_api.core.context import get_request_id
from keyring_api.core.logging import get_logger
from keyring_api.domain.errors import (
    AccountExistsError,
    AccountNotFoundError,
    AuthenticationError,
    ConnectionNotFoundError,
    CredentialUnavailableError,
    InsufficientPermissionError,
    InvalidEmailError,
    InvalidGrantError,
    InvalidOAuthStateError,
    InvalidPasswordError,
    InvalidProfileNameError,
    InvalidRoleError,
    LastOwnerError,
    LimitExceededError,
    PreferencesUnavailableError,
    ProfileExistsError,
    ProfileNotFoundError,
    RateLimitedError,
    RoleExistsError,
    RoleInUseError,
    RoleNotFoundError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from typing import Any

logger = get_logger(__name__)

PROBLEM_BASE_URI = "https://keyring.invalid/problems"
RETRY_AFTER_HEADER = "Retry-After"

_STATUS_TITLES = {
    status.HTTP_400_BAD_REQUEST: "Bad request",
    status.HTTP_401_UNAUTHORIZED: "Unauthorized",
    status.HTTP_403_FORBIDDEN: "Forbidden",
    status.HTTP_404_NOT_FOUND: "Not found",
    status.HTTP_409_CONFLICT: "Conflict",
    status.HTTP_422_UNPROCESSABLE_CONTENT: "Validation failed",
    status.HTTP_429_TOO_MANY_REQUESTS: "Too many requests",
    status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal server error",
    status.HTTP_503_SERVICE_UNAVAILABLE: "Service unavailable",
}

# Domain errors that map cleanly onto a status code. Anything absent is a bug and
# becomes a 500 with its detail withheld.
_DOMAIN_STATUS: dict[type[Exception], int] = {
    AuthenticationError: status.HTTP_401_UNAUTHORIZED,
    InvalidGrantError: status.HTTP_400_BAD_REQUEST,
    InvalidOAuthStateError: status.HTTP_400_BAD_REQUEST,
    InvalidEmailError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    InvalidPasswordError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    InvalidProfileNameError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    AccountExistsError: status.HTTP_409_CONFLICT,
    AccountNotFoundError: status.HTTP_404_NOT_FOUND,
    # 403 rather than 404, and safe *only* because what is being protected is an
    # administrative capability rather than the existence of a resource. Every admin
    # route checks its permission before looking the target up, so a caller who lacks
    # the permission gets the same 403 whether or not the target exists.
    InsufficientPermissionError: status.HTTP_403_FORBIDDEN,
    InvalidRoleError: status.HTTP_422_UNPROCESSABLE_CONTENT,
    RoleNotFoundError: status.HTTP_404_NOT_FOUND,
    RoleExistsError: status.HTTP_409_CONFLICT,
    RoleInUseError: status.HTTP_409_CONFLICT,
    LastOwnerError: status.HTTP_409_CONFLICT,
    ProfileExistsError: status.HTTP_409_CONFLICT,
    # Not 403. A 403 would confirm the resource exists and belongs to somebody else,
    # which is precisely the fact that must not leak across accounts.
    ProfileNotFoundError: status.HTTP_404_NOT_FOUND,
    ConnectionNotFoundError: status.HTTP_404_NOT_FOUND,
    LimitExceededError: status.HTTP_429_TOO_MANY_REQUESTS,
    CredentialUnavailableError: status.HTTP_503_SERVICE_UNAVAILABLE,
    PreferencesUnavailableError: status.HTTP_503_SERVICE_UNAVAILABLE,
}


# PLR0913: six keyword-only fields, because RFC 9457 has six fields. Grouping them
# into an object would add a type whose only job is to be unpacked one line later.
def problem_response(  # noqa: PLR0913
    *,
    status_code: int,
    detail: str,
    problem_type: str | None = None,
    title: str | None = None,
    errors: list[FieldError] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build a problem+json response carrying the current request id."""
    slug = problem_type or _slug_for(status_code)
    problem = Problem(
        type=f"{PROBLEM_BASE_URI}/{slug}",
        title=title or _STATUS_TITLES.get(status_code, "Error"),
        status=status_code,
        detail=detail,
        request_id=get_request_id(),
        errors=errors,
    )
    return JSONResponse(
        status_code=status_code,
        content=problem.model_dump(exclude_none=True),
        media_type=PROBLEM_CONTENT_TYPE,
        headers=headers,
    )


def _slug_for(status_code: int) -> str:
    return _STATUS_TITLES.get(status_code, "error").lower().replace(" ", "-")


def register_exception_handlers(app: FastAPI) -> None:
    """Install every handler the app needs. Called once, by the app factory."""

    @app.exception_handler(RequestValidationError)
    async def _validation(_request: Request, exc: RequestValidationError) -> JSONResponse:
        """Reshape FastAPI's validation errors into the one error format this API uses.

        Only the location and the message are copied. FastAPI's raw errors include the
        offending *input*, which on this service's endpoints is routinely a password or
        a token.
        """
        return problem_response(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="the request failed validation",
            problem_type="validation-failed",
            errors=[
                FieldError(
                    location=".".join(str(part) for part in error["loc"]),
                    message=error["msg"],
                )
                for error in exc.errors()
            ],
        )

    @app.exception_handler(RateLimitedError)
    async def _rate_limited(_request: Request, exc: Exception) -> JSONResponse:
        """Refuse, and say how long to wait.

        The header matters: a client left to guess either gives up on a working service
        or hammers it until the window resets.
        """
        retry_after = getattr(exc, "retry_after_seconds", 60.0)
        return problem_response(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(exc),
            headers={RETRY_AFTER_HEADER: str(int(retry_after) + 1)},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return problem_response(status_code=exc.status_code, detail=str(exc.detail))

    for error_type, status_code in _DOMAIN_STATUS.items():
        app.add_exception_handler(error_type, _domain_handler(status_code))


def unhandled_problem_response(exc: BaseException) -> JSONResponse:
    """Render an unexpected exception as a 500.

    The exception's own message is withheld: it can carry filesystem paths, internal
    hostnames, or a fragment of a credential. The request id ties the response to the
    log record that does have the detail -- which is why this is invoked from inside
    :class:`~keyring_api.api.middleware.RequestContextMiddleware`, while the id is still
    bound, rather than from Starlette's outermost error middleware, where the binding
    has already unwound and the response would carry no id at all.
    """
    logger.exception("unhandled_exception", error_type=type(exc).__name__)
    return problem_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="an unexpected error occurred; quote the request id when reporting it",
    )


def _domain_handler(
    status_code: int,
) -> Callable[[Request, Exception], Coroutine[Any, Any, JSONResponse]]:
    """Build a handler that renders a domain error at ``status_code``."""

    async def handler(_request: Request, exc: Exception) -> JSONResponse:
        return problem_response(status_code=status_code, detail=str(exc))

    return handler
