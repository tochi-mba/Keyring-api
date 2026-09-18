"""The endpoints other services call.

This is the boundary that matters most in the whole service, and it is worth being
explicit about why it looks the way it does.

A consuming service -- example-tool, say -- needs a credential for a *particular person*.
If it could authenticate as itself and then name whoever it liked, then anything able to
reach keyring could request anybody's Spotify token: the confused deputy, moved from
inside one process to the gap between two. So a caller here must present **both**
credentials, and gets one thing only:

* its own service token, proving it is a service keyring is willing to talk to, and
* the end user's short-lived signed token, proving that person authorised this.

The account comes from the *user's* token. There is no parameter by which a service can
name an account, which means there is no request a compromised service can make to
obtain a credential it was not given a user token for.

What comes back is what to attach -- headers, query parameters -- not what is stored. A
refresh token never leaves this process. The single exception is
``resolve_form_secrets``, which necessarily returns a username and password because a
login form needs them; that is precisely why it is here, behind two credentials, rather
than on the person-facing surface.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, status
from fastapi.security import HTTPAuthorizationCredentials

from keyring_api.api.dependencies import ContainerDep, bearer_scheme
from keyring_api.api.schemas.common import Problem
from keyring_api.api.schemas.profiles import (
    ResolvedCredentialResponse,
    ResolvedFormSecretsResponse,
)
from keyring_api.credentials.kinds import OAuth2Credential
from keyring_api.domain.errors import AuthenticationError
from keyring_client import BAD_SERVICE
from keyring_client import AuthenticationError as ServiceRefusedError

router = APIRouter(prefix="/v1/internal", tags=["internal"])

USER_TOKEN_HEADER = "X-Keyring-User-Token"  # noqa: S105 -- a header name
"""Where the end user's signed token travels.

A separate header from Authorization, because the two credentials are genuinely
different things: one says which service is calling, the other says who it is calling
for. Overloading a single header would make it possible to send only one and have it
mean either.
"""

BAD_USER_TOKEN = "the user token was not accepted"  # noqa: S105 -- a message, not a token

_PROBLEM: dict[str, Any] = {"model": Problem}


async def calling_service(
    container: ContainerDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> str:
    """Identify the calling service by its configured token.

    The comparison is :class:`keyring_client.ServiceAuthenticator`'s, the one every consuming
    service uses on its own internal surface: constant time, over bytes, against every
    configured service, with a loop that does not stop early on a match. A comparison that
    returned as soon as it found one would leak, in its timing, roughly where in the list the
    caller sits.

    Raises:
        AuthenticationError: no token, or one that matches no configured service.
    """
    if credentials is None:
        raise AuthenticationError(BAD_SERVICE)
    try:
        return container.service_authenticator.identify(credentials.credentials)
    except ServiceRefusedError as exc:
        raise AuthenticationError(BAD_SERVICE) from exc


ServiceDep = Annotated[str, Depends(calling_service)]


async def acting_for(
    container: ContainerDep,
    service: ServiceDep,
    user_token: Annotated[str | None, Header(alias=USER_TOKEN_HEADER)] = None,
) -> str:
    """Resolve the end user this call is being made for.

    The account id comes out of the user's signed token and from nowhere else. There is
    deliberately no request parameter that names an account: a service that could name
    one could name anybody's.

    The token's audience must be the calling service, so a token minted for one service
    cannot be replayed at another -- which matters because a service holds these tokens
    for the length of a job.

    Raises:
        AuthenticationError: the token is missing, expired, forged, or was issued for a
            different service.
    """
    if user_token is None:
        raise AuthenticationError(BAD_USER_TOKEN)

    return container.signer.verify(user_token, audience=service)


ActingForDep = Annotated[str, Depends(acting_for)]


@router.get(
    "/credentials/{profile}/{service}",
    operation_id="resolve_credential",
    summary="Get what to attach to an outgoing request for a user",
    description=(
        "Called by another service, never by a person. Requires both the calling "
        "service's own token and the end user's short-lived token; the account is taken "
        "from the user's token, so a service cannot ask for a credential it was not "
        "given a token for. Returns headers and query parameters to attach -- refreshing "
        "the underlying token first if it is close to expiry -- and never the stored "
        "credential itself."
    ),
    response_model=ResolvedCredentialResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: _PROBLEM,
        status.HTTP_404_NOT_FOUND: _PROBLEM,
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": Problem,
            "description": (
                "The credential could not be made usable -- the vault is sealed, the "
                "grant was revoked at the provider, or a refresh failed. The detail "
                "names the fix."
            ),
        },
    },
)
async def resolve_credential(
    profile: str, service: str, container: ContainerDep, account_id: ActingForDep
) -> ResolvedCredentialResponse:
    """Produce a usable HTTP credential for one user, profile and service."""
    credential = await container.credential_service.resolve_http_auth(account_id, profile, service)
    headers = await credential.headers()
    params = await credential.query_params()

    # Read after resolving, not before: resolving may have refreshed the token, and
    # reporting the pre-refresh expiry would tell the caller to come back immediately.
    expires_at = None
    if isinstance(credential, OAuth2Credential):
        profile_record = await container.credential_service.get_profile(account_id, profile)
        connection = profile_record.connection(service)
        expires_at = connection.expires_at if connection else None

    return ResolvedCredentialResponse(
        service=service, headers=headers, query_params=params, expires_at=expires_at
    )


@router.get(
    "/form-secrets/{profile}/{service}",
    operation_id="resolve_form_secrets",
    summary="Get the values to type into a site's login form",
    description=(
        "For sites with no API, where a browser must complete a login form. This is the "
        "one endpoint in this service that returns credential material, which is why it "
        "requires both a service token and the end user's token. Includes a TOTP code "
        "generated at the moment of the call when a seed is stored. Never expose this "
        "as an assistant tool."
    ),
    response_model=ResolvedFormSecretsResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: _PROBLEM,
        status.HTTP_404_NOT_FOUND: _PROBLEM,
        status.HTTP_503_SERVICE_UNAVAILABLE: _PROBLEM,
    },
)
async def resolve_form_secrets(
    profile: str, service: str, container: ContainerDep, account_id: ActingForDep
) -> ResolvedFormSecretsResponse:
    """Produce the fields a login form needs."""
    credential = await container.credential_service.resolve_form_secrets(
        account_id, profile, service
    )
    return ResolvedFormSecretsResponse(service=service, fields=await credential.fields())
