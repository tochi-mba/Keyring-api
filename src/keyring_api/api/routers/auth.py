"""Logging in, logging out, invites and passwords.

Every route here is either unauthenticated by necessity (you cannot present a session to
get a session) or administrative. That makes it the part of the API a stranger can
reach, so three things hold throughout:

* Rate limiting is applied by the service, keyed by the caller's address.
* Failures are undifferentiated. ``login`` cannot tell you whether the account exists;
  ``request_password_reset`` answers identically either way, and says so in its
  description so nobody "fixes" it later.
* Nothing echoes back what was sent. A validation error names the field, never the value.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status

from keyring_api.accounts.signing import TOKEN_TYPE
from keyring_api.api.dependencies import ContainerDep, CurrentAccountDep, CurrentSessionDep
from keyring_api.api.schemas.auth import (
    AccountResponse,
    AcknowledgedResponse,
    ChangePasswordRequest,
    LoginRequest,
    RedeemInviteRequest,
    RedeemPasswordResetRequest,
    RequestPasswordResetRequest,
    RevokedResponse,
    ServiceTokenRequest,
    SessionResponse,
)
from keyring_api.api.schemas.common import Problem
from keyring_api.api.schemas.profiles import ServiceTokenResponse

router = APIRouter(prefix="/v1", tags=["auth"])

NO_SUCH_ACCOUNT = "no account with that id"

RESET_ACKNOWLEDGEMENT = "if that address has an account, a reset link has been sent"
"""The single response every reset request gets. Never varied."""

UNKNOWN_CALLER = "unknown"
"""Used when no client address is available -- a test transport, or a misconfigured proxy."""

_PROBLEM = {"model": Problem}


def caller_of(request: Request) -> str:
    """The address rate limits are counted against.

    Taken from the connection, not from ``X-Forwarded-For``: that header is caller-
    supplied, and trusting it unconditionally would let anyone reset their own rate
    limit by changing a string. A deployment behind a reverse proxy configures the proxy
    to rewrite the connection address (uvicorn's ``--proxy-headers``), so the value
    arriving here has already been vouched for by something we run.
    """
    return request.client.host if request.client else UNKNOWN_CALLER


@router.post(
    "/auth/login",
    operation_id="login",
    summary="Exchange an email and password for a session token",
    description=(
        "Returns a session token to send as `Authorization: Bearer <token>` on every "
        "other endpoint. The token is shown once and stored only as a hash, so it "
        "cannot be recovered -- losing it means logging in again. Responds 401 for any "
        "failure, without distinguishing an unknown address from a wrong password, 429 "
        "when too many attempts come from one caller, and 503 when this service's "
        "settings-api grant is refused."
    ),
    response_model=SessionResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: _PROBLEM,
        status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM,
        status.HTTP_503_SERVICE_UNAVAILABLE: _PROBLEM,
    },
)
async def login(body: LoginRequest, container: ContainerDep, request: Request) -> SessionResponse:
    """Authenticate and open a session."""
    result = await container.account_service.login(
        email=body.email, password=body.password, caller=caller_of(request)
    )
    return SessionResponse(
        session_id=result.session_id, token=result.token, expires_at=result.expires_at
    )


@router.post(
    "/auth/logout",
    operation_id="logout",
    summary="End the current session",
    description=(
        "Revokes the session the request was made with, leaving other devices signed "
        "in. Idempotent: a session that is already gone still responds 204."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={status.HTTP_401_UNAUTHORIZED: _PROBLEM},
)
async def logout(container: ContainerDep, session: CurrentSessionDep) -> Response:
    """End the session this request was made with."""
    await container.account_service.logout(session.session_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/auth/logout-everywhere",
    operation_id="logout_everywhere",
    summary="End every session for this account",
    description=(
        "Revokes every session this account has, on every device, including the one "
        "making the request. Use it when a device is lost or a token may have leaked. "
        "Returns how many sessions were ended."
    ),
    response_model=RevokedResponse,
    responses={status.HTTP_401_UNAUTHORIZED: _PROBLEM},
)
async def logout_everywhere(container: ContainerDep, account: CurrentAccountDep) -> RevokedResponse:
    """End every session for the calling account."""
    revoked = await container.account_service.logout_everywhere(account.account_id)
    return RevokedResponse(revoked=revoked)


@router.get(
    "/auth/me",
    operation_id="get_current_account",
    summary="Describe the account this session belongs to",
    description=(
        "Returns the calling account's identifier, address and creation time. Useful to "
        "confirm which identity a stored token actually belongs to before acting as it."
    ),
    response_model=AccountResponse,
    responses={status.HTTP_401_UNAUTHORIZED: _PROBLEM},
)
async def get_current_account(account: CurrentAccountDep) -> AccountResponse:
    """Describe the calling account."""
    return AccountResponse(
        account_id=account.account_id, email=account.email, created_at=account.created_at
    )


@router.post(
    "/auth/invites/redeem",
    operation_id="redeem_invite",
    summary="Turn an invite into an account",
    description=(
        "Creates the account the invite was issued for and sets its password. The "
        "address comes from the invite, not from this request. An invite works once and "
        "expires; a rejected password does not consume it, so you can try again with a "
        "longer one. Responds 400 for a token that is unknown, expired or already used "
        "-- without distinguishing which."
    ),
    status_code=status.HTTP_201_CREATED,
    response_model=AccountResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: _PROBLEM,
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
        status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM,
    },
)
async def redeem_invite(
    body: RedeemInviteRequest, container: ContainerDep, request: Request
) -> AccountResponse:
    """Create an account from an invite."""
    account = await container.account_service.redeem_invite(
        token=body.token, password=body.password, caller=caller_of(request)
    )
    return AccountResponse(
        account_id=account.account_id, email=account.email, created_at=account.created_at
    )


@router.post(
    "/auth/password",
    operation_id="change_password",
    summary="Change this account's password",
    description=(
        "Requires the current password, so a stolen session cannot be turned into an "
        "account takeover. Every other session is revoked -- the one making the request "
        "survives -- and any outstanding reset link stops working."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_401_UNAUTHORIZED: _PROBLEM,
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
    },
)
async def change_password(
    body: ChangePasswordRequest, container: ContainerDep, session: CurrentSessionDep
) -> Response:
    """Replace the calling account's password."""
    await container.account_service.change_password(
        session.account_id,
        current_password=body.current_password,
        new_password=body.new_password,
        keep_session_id=session.session_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/auth/password/reset-request",
    operation_id="request_password_reset",
    summary="Ask for a password reset link",
    description=(
        "Always responds 200 with the same message, whether or not the address has an "
        "account. That is deliberate and must not be 'fixed': a different response for "
        "an unknown address would let anyone test which people have accounts here. When "
        "mail is configured the link is emailed; otherwise the operator delivers it. "
        "Rate limited per caller and per recipient address."
    ),
    response_model=AcknowledgedResponse,
    responses={status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM},
)
async def request_password_reset(
    body: RequestPasswordResetRequest, container: ContainerDep, request: Request
) -> AcknowledgedResponse:
    """Mint a reset token if the address has an account, and say nothing either way."""
    await container.account_service.request_password_reset(
        email=body.email, caller=caller_of(request)
    )
    # The result is deliberately discarded. Returning anything derived from it -- a
    # flag, a different status, even a different message length -- would restore exactly
    # the oracle this endpoint exists to avoid.
    return AcknowledgedResponse(detail=RESET_ACKNOWLEDGEMENT)


@router.post(
    "/auth/password/reset",
    operation_id="redeem_password_reset",
    summary="Set a new password using a reset token",
    description=(
        "Sets the password and revokes every session for the account, including any an "
        "attacker holds -- which is the point of resetting. The token works once and "
        "expires. Responds 400 for a token that is unknown, expired or already used."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        status.HTTP_400_BAD_REQUEST: _PROBLEM,
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
        status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM,
    },
)
async def redeem_password_reset(
    body: RedeemPasswordResetRequest, container: ContainerDep, request: Request
) -> Response:
    """Set a new password from a reset token."""
    await container.account_service.redeem_password_reset(
        token=body.token, new_password=body.password, caller=caller_of(request)
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/auth/service-token",
    operation_id="issue_service_token",
    summary="Mint a short-lived token for calling another service as yourself",
    description=(
        "Exchanges your session for a signed token scoped to one other service, which "
        "that service verifies locally against keyring's public keys -- no call back "
        "here per request. It expires in minutes: a signed token cannot be revoked, so "
        "the expiry is the only thing bounding how long a logged-out session keeps "
        "working elsewhere. Get a new one when it expires rather than caching it."
    ),
    response_model=ServiceTokenResponse,
    responses={status.HTTP_401_UNAUTHORIZED: _PROBLEM},
)
async def issue_service_token(
    body: ServiceTokenRequest, container: ContainerDep, account: CurrentAccountDep
) -> ServiceTokenResponse:
    """Mint a short-lived signed token for one audience."""
    ttl = container.settings.access_token_ttl_seconds
    token = container.signer.issue(
        account_id=account.account_id, audience=body.audience, ttl_seconds=ttl
    )
    return ServiceTokenResponse(token=token, token_type=TOKEN_TYPE, expires_in=ttl)
