"""Talking to a provider's token endpoint.

A port and one HTTP adapter. The port exists so every expiry rule, every error path and
every write-back in the credential service is testable against a fake endpoint, with no
network and no provider account -- which is the only way those paths get tested at all.

Nothing here stores anything. It exchanges what it is given and hands back the
provider's answer, normalized into the shape the secret store keeps.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx

from keyring_api.core.logging import get_logger
from keyring_api.domain.errors import CredentialUnavailableError

if TYPE_CHECKING:
    from keyring_api.credentials.providers import OAuthProvider
    from keyring_api.secrets.base import Secret

logger = get_logger(__name__)

DEFAULT_EXPIRES_IN_SECONDS = 3600
"""Assumed when a provider omits ``expires_in``, which some do.

Assuming an hour means the token is refreshed too eagerly at worst. Assuming it never
expires would mean discovering otherwise as a failed request at the provider.
"""


@runtime_checkable
class TokenEndpoint(Protocol):
    """Exchanges authorization codes and refresh tokens for access tokens."""

    async def exchange_code(
        self, provider: OAuthProvider, *, code: str, redirect_uri: str
    ) -> Secret:
        """Trade an authorization code for a token pair.

        Raises:
            CredentialUnavailableError: the provider refused or could not be reached.
        """
        ...

    async def refresh(self, provider: OAuthProvider, *, refresh_token: str) -> Secret:
        """Trade a refresh token for a fresh access token.

        Raises:
            CredentialUnavailableError: the provider refused or could not be reached.
        """
        ...

    async def aclose(self) -> None:
        """Release any connections held open."""
        ...


class HttpTokenEndpoint:
    """The real client, over HTTPS, with the client secret sent server to server."""

    def __init__(self, *, timeout_seconds: float) -> None:
        self._client = httpx.AsyncClient(timeout=timeout_seconds)

    async def exchange_code(
        self, provider: OAuthProvider, *, code: str, redirect_uri: str
    ) -> Secret:
        return await self._post(
            provider,
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )

    async def refresh(self, provider: OAuthProvider, *, refresh_token: str) -> Secret:
        renewed = await self._post(
            provider, {"grant_type": "refresh_token", "refresh_token": refresh_token}
        )

        # Most providers return a new access token and *no* refresh token, meaning
        # "keep using the one you have". Taking the response at face value would
        # discard the refresh token and break every future renewal -- an error that
        # only shows up when the next refresh is due, hours later.
        renewed.setdefault("refresh_token", refresh_token)
        return renewed

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _post(self, provider: OAuthProvider, form: dict[str, str]) -> Secret:
        """Post to the token endpoint and normalize the answer."""
        try:
            response = await self._client.post(
                str(provider.token_url),
                data={
                    **form,
                    "client_id": provider.client_id,
                    "client_secret": provider.client_secret,
                },
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            # The exception text can carry the full request, client secret included.
            logger.warning("token_endpoint_unreachable", service=provider.service)
            msg = f"could not reach the {provider.service} token endpoint"
            raise CredentialUnavailableError(msg) from exc

        if response.status_code >= httpx.codes.BAD_REQUEST:
            # The provider's error *code* is safe and useful ("invalid_grant" means the
            # person must re-authorise); its body is not guaranteed to be, so only the
            # code is carried out.
            logger.warning(
                "token_endpoint_refused",
                service=provider.service,
                status_code=response.status_code,
            )
            msg = (
                f"{provider.service} refused the request "
                f"({_error_code(response)}); the connection must be re-authorised"
            )
            raise CredentialUnavailableError(msg)

        return _normalize(response, service=provider.service)


def _error_code(response: httpx.Response) -> str:
    """Pull the RFC 6749 error code out of a refusal, if there is one."""
    try:
        body = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"

    code = body.get("error") if isinstance(body, dict) else None
    return str(code) if isinstance(code, str) else f"HTTP {response.status_code}"


def _normalize(response: httpx.Response, *, service: str) -> Secret:
    """Turn a token response into the shape the secret store keeps."""
    try:
        body = response.json()
    except ValueError as exc:
        msg = f"{service} returned a token response that is not JSON"
        raise CredentialUnavailableError(msg) from exc

    if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
        msg = f"{service} returned no access token"
        raise CredentialUnavailableError(msg)

    secret: Secret = {
        "access_token": body["access_token"],
        "token_type": body.get("token_type", "Bearer"),
        "expires_in": _expires_in(body),
    }
    if isinstance(body.get("refresh_token"), str):
        secret["refresh_token"] = body["refresh_token"]
    if isinstance(body.get("scope"), str):
        secret["scope"] = body["scope"]
    return secret


def _expires_in(body: dict[str, object]) -> int:
    """Seconds until expiry, defaulting when the provider does not say."""
    raw = body.get("expires_in")
    if isinstance(raw, int) and raw > 0:
        return raw
    if isinstance(raw, str) and raw.isdigit() and int(raw) > 0:
        # Some providers send it as a string. Accepting both is one line here and an
        # incident report otherwise.
        return int(raw)
    return DEFAULT_EXPIRES_IN_SECONDS
