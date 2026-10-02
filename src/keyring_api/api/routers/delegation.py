"""Session-authorized consent and two-credential, audience-restricted exchange."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Header, Response, status

from keyring_api.api.dependencies import ContainerDep, CurrentAccountDep
from keyring_api.api.routers.internal import USER_TOKEN_HEADER, ActingForDep, ServiceDep
from keyring_api.api.routers.profiles import NO_SUCH_CONNECTION, render
from keyring_api.api.schemas.common import Problem
from keyring_api.api.schemas.delegation import (
    CreateDelegatedGrantRequest,
    CreateGrantRequest,
    ExchangeRequest,
    ExchangeResponse,
    GrantListResponse,
    GrantResponse,
)
from keyring_api.api.schemas.profiles import AuthorizationResponse, ProfileResponse
from keyring_api.credentials.changes import Requester
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.errors import AuthenticationError, ConnectionNotFoundError

router = APIRouter(prefix="/v1", tags=["delegation"])
_PROBLEM = {"model": Problem}

SERVICE_REAUTH_NOTE = (
    " Responds 403 if the person's account asks for its password before a stored "
    "credential changes: a service cannot give it, so the person must do this with their "
    "own session. 503 if their settings cannot be read."
)


@router.post(
    "/internal/token-exchange",
    operation_id="exchange_user_token",
    summary="Exchange delegated authority for one downstream audience",
    description=(
        "Requires the calling service's credential and either a user JWT whose audience "
        "exactly names that service, or an offline grant bound to it. Mints for the same "
        "account and an allowlisted audience only. Never forwards the caller token. "
        "The result expires no later than the delegation or server token limit."
    ),
    response_model=ExchangeResponse,
    responses={401: _PROBLEM, 403: _PROBLEM},
)
async def exchange_user_token(
    body: ExchangeRequest,
    container: ContainerDep,
    service: ServiceDep,
    user_token: Annotated[str | None, Header(alias=USER_TOKEN_HEADER)] = None,
) -> ExchangeResponse:
    result = await container.delegation_service.exchange(
        service,
        audience=body.audience,
        ttl_seconds=body.ttl_seconds,
        user_token=user_token,
        grant_id=body.grant_id,
    )
    return ExchangeResponse(
        token=result.token, expires_in=result.expires_in, expires_at=result.expires_at
    )


@router.post(
    "/profiles/{name}/grants",
    operation_id="create_offline_grant",
    summary="Allow a service to act for this profile while you are away",
    description=(
        "Requires your human login session. Records expiring consent for one service and "
        "a set of exact downstream audiences within that service's configured allowlist. "
        "The returned handle alone is not a credential. Revoke it to stop future exchanges."
    ),
    status_code=status.HTTP_201_CREATED,
    response_model=GrantResponse,
    responses={401: _PROBLEM, 403: _PROBLEM, 404: _PROBLEM, 429: _PROBLEM},
)
async def create_offline_grant(
    name: str,
    body: CreateGrantRequest,
    container: ContainerDep,
    account: CurrentAccountDep,
) -> GrantResponse:
    grant = await container.delegation_service.create(
        account.account_id,
        name,
        service=body.service,
        audiences=tuple(body.audiences),
        ttl_seconds=body.ttl_seconds,
    )
    return GrantResponse.model_validate(grant)


@router.get(
    "/profiles/{name}/grants",
    operation_id="list_offline_grants",
    summary="Inspect every background delegation for this profile",
    description=(
        "Requires your login session. Returns the audiences, service and lifetime of each "
        "grant, including expired and revoked records. Never returns a stored credential."
    ),
    response_model=GrantListResponse,
    responses={401: _PROBLEM, 404: _PROBLEM},
)
async def list_offline_grants(
    name: str,
    container: ContainerDep,
    account: CurrentAccountDep,
) -> GrantListResponse:
    grants = await container.delegation_service.list(account.account_id, name)
    return GrantListResponse(grants=[GrantResponse.model_validate(grant) for grant in grants])


@router.delete(
    "/profiles/{name}/grants/{grant_id}",
    operation_id="revoke_offline_grant",
    summary="Stop future background exchanges under this grant",
    description=(
        "Requires the owning account's login session. Revocation is idempotent; already "
        "minted JWTs remain valid until their short expiry. Unknown and foreign handles "
        "both return 404. The revocation remains visible in the consent history."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={401: _PROBLEM, 404: _PROBLEM},
)
async def revoke_offline_grant(
    name: str,
    grant_id: str,
    container: ContainerDep,
    account: CurrentAccountDep,
) -> Response:
    await container.delegation_service.revoke(account.account_id, name, grant_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/internal/profiles/{name}",
    operation_id="describe_delegated_profile",
    summary="Read connection status for the person a service is acting for",
    description=(
        "Requires both the calling service's own credential and a user token whose "
        "audience exactly identifies it. Reads status, expiry and granted scopes only; "
        "no vault secret is resolved. Foreign and missing profiles both return 404."
    ),
    response_model=ProfileResponse,
    responses={401: _PROBLEM, 404: _PROBLEM},
)
async def describe_delegated_profile(
    name: str,
    container: ContainerDep,
    account_id: ActingForDep,
) -> ProfileResponse:
    account = await container.accounts.get(account_id)
    if account is None or account.status is not AccountStatus.ACTIVE:
        msg = "the user token was not accepted"
        raise AuthenticationError(msg)
    return render(await container.credential_service.get_profile(account_id, name))


@router.post(
    "/internal/profiles/{name}/connections/{connection}/authorize",
    operation_id="authorize_delegated_connection",
    summary="Begin provider consent for the person a service is acting for",
    description=(
        "Requires the calling service credential and a user token bound to that service. "
        "The account comes only from the signed user token. Returns a short-lived provider "
        "URL and never returns or accepts credential material." + SERVICE_REAUTH_NOTE
    ),
    response_model=AuthorizationResponse,
    responses={401: _PROBLEM, 403: _PROBLEM, 404: _PROBLEM, 429: _PROBLEM, 503: _PROBLEM},
)
async def authorize_delegated_connection(
    name: str,
    connection: str,
    container: ContainerDep,
    account_id: ActingForDep,
) -> AuthorizationResponse:
    authorization = await container.credential_changes.begin_authorization(
        account_id,
        name,
        connection,
        redirect_uri=container.settings.oauth_redirect_uri,
        requester=Requester.service(),
    )
    return AuthorizationResponse(
        authorization_url=authorization.authorization_url,
        expires_at=authorization.expires_at,
    )


@router.delete(
    "/internal/profiles/{name}/connections/{connection}",
    operation_id="delete_delegated_connection",
    summary="Remove a connection for the person a service is acting for",
    description=(
        "Requires the calling service credential and a user token bound to that service. "
        "Deletes only the named profile connection belonging to the token subject."
        + SERVICE_REAUTH_NOTE
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={401: _PROBLEM, 403: _PROBLEM, 404: _PROBLEM, 503: _PROBLEM},
)
async def delete_delegated_connection(
    name: str,
    connection: str,
    container: ContainerDep,
    account_id: ActingForDep,
) -> Response:
    removed = await container.credential_changes.remove_connection(
        account_id, name, connection, requester=Requester.service()
    )
    if not removed:
        raise ConnectionNotFoundError(NO_SUCH_CONNECTION)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/internal/profiles/{name}/grants",
    operation_id="create_delegated_grant",
    summary="Record standing consent for the calling service, while the person is present",
    description=(
        "Requires the calling service credential and a user token bound to that service, so "
        "the person is present: the account comes only from that token, and the grant is for "
        "the calling service only. Audiences must be within the service's allowlist and the "
        "lifetime is capped by the offline grant limit. The person sees and can revoke it "
        "with their own session like any other grant; the audit line names the service."
    ),
    status_code=status.HTTP_201_CREATED,
    response_model=GrantResponse,
    responses={401: _PROBLEM, 403: _PROBLEM, 404: _PROBLEM, 429: _PROBLEM},
)
async def create_delegated_grant(
    name: str,
    body: CreateDelegatedGrantRequest,
    container: ContainerDep,
    service: ServiceDep,
    account_id: ActingForDep,
) -> GrantResponse:
    grant = await container.delegation_service.create(
        account_id,
        name,
        service=service,
        audiences=tuple(body.audiences),
        ttl_seconds=body.ttl_seconds,
        created_by=service,
    )
    return GrantResponse.model_validate(grant)


@router.delete(
    "/internal/profiles/{name}/grants/{grant_id}",
    operation_id="revoke_delegated_grant",
    summary="Withdraw standing consent the calling service holds",
    description=(
        "Requires the calling service credential and a user token bound to that service. "
        "Revokes only a grant made to the calling service for the token's subject; a grant "
        "held by another service, a foreign one and a missing one are all 404."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={401: _PROBLEM, 404: _PROBLEM},
)
async def revoke_delegated_grant(
    name: str,
    grant_id: str,
    container: ContainerDep,
    service: ServiceDep,
    account_id: ActingForDep,
) -> Response:
    await container.delegation_service.revoke_for_service(
        account_id, name, grant_id, service=service
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
