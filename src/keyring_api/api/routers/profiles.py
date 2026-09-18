"""Profiles, connections and credential entry.

Every route requires a session, and every one addresses data through the calling
account -- so there is no request a person can make that reaches another person's
profile. A name somebody else owns answers 404, identically to a name nobody owns.

One rule governs the whole module: **values go in, status comes out.** Reads report
which connections exist and whether each is usable; no endpoint here returns a stored
secret, and a contract test walks every response schema to keep it that way.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response, status

from keyring_api.api.dependencies import ContainerDep, CurrentAccountDep
from keyring_api.api.schemas.common import Problem
from keyring_api.api.schemas.delegation import GrantResponse
from keyring_api.api.schemas.profiles import (
    AuthorizationResponse,
    ConnectionResponse,
    CreateProfileRequest,
    ProfileListResponse,
    ProfileResponse,
    PutApiKeyRequest,
    PutPasswordRequest,
)
from keyring_api.domain.errors import ConnectionNotFoundError
from keyring_api.domain.profiles import Connection, CredentialKind, Profile

router = APIRouter(prefix="/v1/profiles", tags=["profiles"])

NO_SUCH_CONNECTION = "this profile is not connected to that service"

# Two shapes, and they are not interchangeable: _PROBLEM is one response spec, used as
# a value; the others are whole {status: spec} mappings, splatted in.
_PROBLEM: dict[str, Any] = {"model": Problem}
_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    status.HTTP_404_NOT_FOUND: {
        "model": Problem,
        "description": (
            "No profile of that name. Returned identically for a profile owned by "
            "another account, so the API never confirms one exists."
        ),
    }
}
_SEALED: dict[int | str, dict[str, Any]] = {
    status.HTTP_503_SERVICE_UNAVAILABLE: {
        "model": Problem,
        "description": "The vault is sealed -- no master key is configured.",
    }
}


def render(profile: Profile) -> ProfileResponse:
    """Turn a profile into its wire form. Carries no credential material."""
    return ProfileResponse(
        name=profile.name,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
        connections=[
            render_connection(item)
            for item in sorted(profile.connections, key=lambda item: item.service)
        ],
    )


def render_connection(connection: Connection) -> ConnectionResponse:
    """Turn a connection into its wire form."""
    return ConnectionResponse(
        service=connection.service,
        kind=connection.kind,
        status=connection.status,
        created_at=connection.created_at,
        updated_at=connection.updated_at,
        expires_at=connection.expires_at,
        scopes=list(connection.scopes),
        stores_totp_seed=connection.stores_totp_seed,
        last_error=connection.last_error,
    )


@router.get(
    "",
    operation_id="list_profiles",
    summary="List your credential profiles",
    description=(
        "Returns every profile you own and, for each, which services it is connected to "
        "and whether each connection is currently usable. Status only -- no stored "
        "credential is ever returned. Safe to expose as a tool: it tells an assistant "
        "which identities are available without giving it any of them."
    ),
    response_model=ProfileListResponse,
    responses={status.HTTP_401_UNAUTHORIZED: _PROBLEM},
)
async def list_profiles(container: ContainerDep, account: CurrentAccountDep) -> ProfileListResponse:
    """Every profile the calling account owns."""
    profiles = await container.credential_service.list_profiles(account.account_id)
    return ProfileListResponse(profiles=[render(profile) for profile in profiles])


@router.post(
    "",
    operation_id="create_profile",
    summary="Create a credential profile",
    description=(
        "Creates an empty named credential set -- 'personal', 'work'. Names are scoped "
        "to your account, so one being taken by somebody else does not affect you. "
        "Responds 409 if you already have one by that name and 429 at your profile cap."
    ),
    status_code=status.HTTP_201_CREATED,
    response_model=ProfileResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: _PROBLEM,
        status.HTTP_409_CONFLICT: _PROBLEM,
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
        status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM,
    },
)
async def create_profile(
    body: CreateProfileRequest, container: ContainerDep, account: CurrentAccountDep
) -> ProfileResponse:
    """Create a named credential set."""
    profile = await container.credential_service.create_profile(account.account_id, body.name)
    return render(profile)


@router.get(
    "/{name}",
    operation_id="get_profile",
    summary="Describe one profile and its connections",
    description=(
        "Returns one profile with the state of each connection: which service, what "
        "kind of credential, whether it is active, when it expires, and why the last "
        "refresh failed if it did. Use it to find out whether a connection needs "
        "re-authorising before relying on it. Never returns a credential."
    ),
    response_model=ProfileResponse,
    responses={status.HTTP_401_UNAUTHORIZED: _PROBLEM, **_NOT_FOUND},
)
async def get_profile(
    name: str, container: ContainerDep, account: CurrentAccountDep
) -> ProfileResponse:
    """One of the calling account's profiles."""
    response = render(await container.credential_service.get_profile(account.account_id, name))
    response.grants = [
        GrantResponse.model_validate(grant)
        for grant in await container.delegation_service.list(account.account_id, response.name)
    ]
    return response


@router.delete(
    "/{name}",
    operation_id="delete_profile",
    summary="Delete a profile and every credential in it",
    description=(
        "Removes the profile and every stored credential it holds. Irreversible: the "
        "credentials are deleted from the vault, not merely unlinked, so each service "
        "must be authorised again afterwards. Third-party grants are not revoked at the "
        "provider -- do that at the provider if you want them gone there too."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={status.HTTP_401_UNAUTHORIZED: _PROBLEM, **_NOT_FOUND},
)
async def delete_profile(
    name: str, container: ContainerDep, account: CurrentAccountDep
) -> Response:
    """Delete a profile and its credentials."""
    # get_profile first, so a name that does not exist is a 404 rather than a silent
    # 204 that leaves the caller believing something was deleted.
    await container.credential_service.get_profile(account.account_id, name)
    await container.credential_service.delete_profile(account.account_id, name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put(
    "/{name}/connections/{service}/api-key",
    operation_id="put_api_key",
    summary="Store an API key for a service",
    description=(
        "Writes the key straight into the encrypted vault. It does not appear in this "
        "response, in any later read, or in the logs, and there is no endpoint that "
        "returns it -- it leaves only as a header attached by a service that asked for "
        "it. Replaces any key already stored for that service."
    ),
    response_model=ConnectionResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: _PROBLEM,
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
        status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM,
        **_SEALED,
        **_NOT_FOUND,
    },
)
async def put_api_key(
    name: str,
    service: str,
    body: PutApiKeyRequest,
    container: ContainerDep,
    account: CurrentAccountDep,
) -> ConnectionResponse:
    """Store an API key."""
    connection = await container.credential_service.put_direct_credential(
        account.account_id,
        name,
        service,
        kind=CredentialKind.API_KEY,
        secret={
            "api_key": body.api_key,
            "header": body.header,
            "template": body.template,
            "in_query": body.in_query,
            "query_name": body.query_name,
        },
    )
    return render_connection(connection)


@router.put(
    "/{name}/connections/{service}/password",
    operation_id="put_password",
    summary="Store a form login for a site with no API",
    description=(
        "For sites that offer no OAuth and no API key. Prefer OAuth wherever it exists: "
        "an OAuth grant is scoped and you can revoke it at the provider, whereas a "
        "stored password can only be revoked by changing it at the site. Sending a "
        "`totp_seed` puts your second factor in the same place as your first, and the "
        "connection is flagged as such so it is visible afterwards."
    ),
    response_model=ConnectionResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: _PROBLEM,
        status.HTTP_422_UNPROCESSABLE_CONTENT: _PROBLEM,
        status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM,
        **_SEALED,
        **_NOT_FOUND,
    },
)
async def put_password(
    name: str,
    service: str,
    body: PutPasswordRequest,
    container: ContainerDep,
    account: CurrentAccountDep,
) -> ConnectionResponse:
    """Store a form login."""
    secret: dict[str, object] = {"username": body.username, "password": body.password}
    if body.totp_seed:
        secret["totp_seed"] = body.totp_seed

    connection = await container.credential_service.put_direct_credential(
        account.account_id,
        name,
        service,
        kind=CredentialKind.PASSWORD,
        secret=secret,
        # Flagged from the caller's explicit act of sending a seed, and reported back so
        # the consequence is visible rather than buried.
        stores_totp_seed=bool(body.totp_seed),
    )
    return render_connection(connection)


@router.post(
    "/{name}/connections/{service}/authorize",
    operation_id="authorize_connection",
    summary="Begin an OAuth authorization for a service",
    description=(
        "Returns a provider URL to open in a browser. You consent at the provider, and "
        "the token arrives here server-to-server -- no credential ever passes through "
        "this API. The link is single-use and short-lived; if it expires, ask for "
        "another. Responds 503 if no OAuth provider is configured for that service."
    ),
    response_model=AuthorizationResponse,
    responses={
        status.HTTP_401_UNAUTHORIZED: _PROBLEM,
        status.HTTP_429_TOO_MANY_REQUESTS: _PROBLEM,
        **_SEALED,
        **_NOT_FOUND,
    },
)
async def authorize_connection(
    name: str, service: str, container: ContainerDep, account: CurrentAccountDep
) -> AuthorizationResponse:
    """Start an OAuth flow."""
    authorization = await container.credential_service.begin_authorization(
        account.account_id,
        name,
        service,
        redirect_uri=container.settings.oauth_redirect_uri,
    )
    return AuthorizationResponse(
        authorization_url=authorization.authorization_url,
        expires_at=authorization.expires_at,
    )


@router.delete(
    "/{name}/connections/{service}",
    operation_id="delete_connection",
    summary="Remove one connection and its credential",
    description=(
        "Deletes the stored credential for one service and removes the connection. The "
        "grant is not revoked at the provider -- do that at the provider as well if you "
        "want it gone there too."
    ),
    status_code=status.HTTP_204_NO_CONTENT,
    responses={status.HTTP_401_UNAUTHORIZED: _PROBLEM, **_NOT_FOUND},
)
async def delete_connection(
    name: str, service: str, container: ContainerDep, account: CurrentAccountDep
) -> Response:
    """Remove a connection."""
    if not await container.credential_service.revoke_connection(account.account_id, name, service):
        raise ConnectionNotFoundError(NO_SUCH_CONNECTION)

    return Response(status_code=status.HTTP_204_NO_CONTENT)
