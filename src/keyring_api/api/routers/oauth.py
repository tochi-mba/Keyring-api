"""The OAuth callback, and the keys other services verify keyring's tokens with.

Two unauthenticated routes, for two different reasons.

The **callback** cannot require a session: it is a redirect arriving from a third-party
provider, in a browser that may not be the one that started the flow. It is safe anyway
because the state parameter carries the authority -- single-use, short-lived, and bound
to the account, profile and service that began it. Everything about where the credential
lands comes from that stored binding, never from the callback's parameters.

The **JWKS document** cannot require a session either: it exists to be fetched by
anything that needs to verify a token this service issued. It contains only public key
material, and there is a test asserting nothing private can appear in it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, status

from keyring_api.api.dependencies import ContainerDep
from keyring_api.api.routers.profiles import render_connection
from keyring_api.api.schemas.common import Problem
from keyring_api.api.schemas.profiles import ConnectionResponse

router = APIRouter(prefix="/v1/oauth", tags=["oauth"])
well_known = APIRouter(tags=["oauth"])

_PROBLEM: dict[str, Any] = {"model": Problem}


@router.get(
    "/callback",
    operation_id="complete_authorization",
    summary="Finish an OAuth authorization",
    description=(
        "Where a provider sends the person back after they consent. Not called "
        "directly: the URL is handed to you by `authorize_connection` and opened in a "
        "browser. The account, profile and service all come from the stored state, so a "
        "callback cannot attach a credential anywhere its flow did not begin. Responds "
        "400 for state that is unknown, expired or already used."
    ),
    response_model=ConnectionResponse,
    responses={
        status.HTTP_400_BAD_REQUEST: _PROBLEM,
        status.HTTP_503_SERVICE_UNAVAILABLE: _PROBLEM,
    },
)
async def complete_authorization(
    state: str, code: str, container: ContainerDep
) -> ConnectionResponse:
    """Exchange the authorization code and store the resulting credential."""
    connection = await container.credential_service.complete_authorization(state=state, code=code)
    return render_connection(connection)


@well_known.get(
    "/.well-known/jwks.json",
    operation_id="get_jwks",
    summary="Public keys for verifying tokens keyring issued",
    description=(
        "The JSON Web Key Set another service uses to verify a keyring-issued token "
        "locally, without calling back here on every request. Contains public key "
        "material only. Unauthenticated by design -- a verifier has nothing to "
        "authenticate with yet, which is the problem this document solves."
    ),
    response_model=dict,
)
async def get_jwks(container: ContainerDep) -> dict[str, Any]:
    """The public half of the signing key."""
    return container.signer.jwks()
