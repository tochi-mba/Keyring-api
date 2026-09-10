"""The HTTP token endpoint client.

Driven against an httpx MockTransport rather than a live provider: every branch --
refusal, unreachable, malformed response, missing refresh token -- is exercised with no
network and no provider account, which is the only way those paths get tested at all.
"""

from __future__ import annotations

import httpx
import pytest

from keyring_api.credentials.oauth_client import (
    DEFAULT_EXPIRES_IN_SECONDS,
    HttpTokenEndpoint,
    TokenEndpoint,
)
from keyring_api.credentials.providers import OAuthProvider
from keyring_api.domain.errors import CredentialUnavailableError

PROVIDER = OAuthProvider.model_validate(
    {
        "service": "spotify",
        "authorize_url": "https://accounts.example.com/authorize",
        "token_url": "https://accounts.example.com/api/token",
        "client_id": "client-abc",
        "client_secret": "secret-abc",
    }
)


def endpoint_answering(handler: object) -> HttpTokenEndpoint:
    """An endpoint whose transport is a scripted handler."""
    client = HttpTokenEndpoint(timeout_seconds=1.0)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    return client


def answering(status_code: int, body: object) -> HttpTokenEndpoint:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=body)

    return endpoint_answering(handler)


def test_it_satisfies_the_port() -> None:
    checked: TokenEndpoint = HttpTokenEndpoint(timeout_seconds=1.0)

    assert isinstance(checked, TokenEndpoint)


class TestExchange:
    async def test_a_code_becomes_a_token_pair(self) -> None:
        client = answering(
            200,
            {
                "access_token": "access-1",
                "refresh_token": "refresh-1",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
        )

        secret = await client.exchange_code(PROVIDER, code="the-code", redirect_uri="https://k/cb")

        assert secret["access_token"] == "access-1"
        assert secret["expires_in"] == 3600

    async def test_the_client_secret_goes_in_the_body_not_the_url(self) -> None:
        # A secret in a query string ends up in the provider's access logs and in every
        # proxy between here and there.
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["body"] = request.content.decode()
            return httpx.Response(200, json={"access_token": "a"})

        await endpoint_answering(handler).exchange_code(
            PROVIDER, code="c", redirect_uri="https://k/cb"
        )

        assert "secret-abc" not in seen["url"]
        assert "client_secret=secret-abc" in seen["body"]

    async def test_a_refusal_carries_the_provider_s_error_code(self) -> None:
        # "invalid_grant" tells a person they must re-authorise. The rest of the body is
        # not guaranteed to be safe to repeat, so only the code comes out.
        client = answering(400, {"error": "invalid_grant", "error_description": "nope"})

        with pytest.raises(CredentialUnavailableError, match="invalid_grant"):
            await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

    async def test_a_refusal_with_no_error_code_still_says_something_useful(self) -> None:
        client = answering(503, {"unexpected": "shape"})

        with pytest.raises(CredentialUnavailableError, match="HTTP 503"):
            await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

    async def test_a_refusal_that_is_not_json_still_says_something_useful(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(502, text="<html>gateway error</html>")

        client = endpoint_answering(handler)

        with pytest.raises(CredentialUnavailableError, match="HTTP 502"):
            await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

    async def test_an_unreachable_provider_does_not_leak_the_request(self) -> None:
        # httpx's exception text can carry the full request, client secret included.
        leaky_message = "connection refused to secret-abc@host"

        def handler(_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(leaky_message)

        client = endpoint_answering(handler)

        with pytest.raises(CredentialUnavailableError) as caught:
            await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

        assert "secret-abc" not in str(caught.value)

    async def test_a_response_with_no_access_token_is_refused(self) -> None:
        client = answering(200, {"token_type": "Bearer"})

        with pytest.raises(CredentialUnavailableError, match="no access token"):
            await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

    async def test_a_response_that_is_not_json_is_refused(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not json")

        client = endpoint_answering(handler)

        with pytest.raises(CredentialUnavailableError, match="not JSON"):
            await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

    async def test_a_json_response_that_is_not_an_object_is_refused(self) -> None:
        client = answering(200, ["not", "an", "object"])

        with pytest.raises(CredentialUnavailableError, match="no access token"):
            await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")


class TestExpiry:
    async def test_a_missing_expiry_is_assumed_rather_than_treated_as_forever(self) -> None:
        # Assuming an hour refreshes too eagerly at worst. Assuming it never expires
        # means discovering otherwise as a failed request at the provider.
        client = answering(200, {"access_token": "a"})

        secret = await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

        assert secret["expires_in"] == DEFAULT_EXPIRES_IN_SECONDS

    async def test_an_expiry_sent_as_a_string_is_accepted(self) -> None:
        # Some providers do this. Accepting both is one line here and an incident
        # report otherwise.
        client = answering(200, {"access_token": "a", "expires_in": "1800"})

        secret = await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

        assert secret["expires_in"] == 1800

    @pytest.mark.parametrize("nonsense", [0, -5, "soon", None, 3.5])
    async def test_a_nonsensical_expiry_falls_back_to_the_default(self, nonsense: object) -> None:
        client = answering(200, {"access_token": "a", "expires_in": nonsense})

        secret = await client.exchange_code(PROVIDER, code="c", redirect_uri="https://k/cb")

        assert secret["expires_in"] == DEFAULT_EXPIRES_IN_SECONDS


class TestRefresh:
    async def test_a_refresh_token_becomes_a_new_access_token(self) -> None:
        client = answering(200, {"access_token": "access-2", "expires_in": 3600})

        secret = await client.refresh(PROVIDER, refresh_token="refresh-1")

        assert secret["access_token"] == "access-2"

    async def test_a_response_with_no_refresh_token_keeps_the_one_we_had(self) -> None:
        # Most providers say nothing about the refresh token on renewal, meaning "keep
        # using yours". Taking the response at face value would discard it and break
        # every future renewal -- an error that surfaces hours later, when the next one
        # is due, and nobody is watching.
        client = answering(200, {"access_token": "access-2"})

        secret = await client.refresh(PROVIDER, refresh_token="refresh-1")

        assert secret["refresh_token"] == "refresh-1"

    async def test_a_rotated_refresh_token_replaces_the_old_one(self) -> None:
        # And the providers that *do* rotate must be honoured, or the next refresh uses
        # a token they have already invalidated.
        client = answering(200, {"access_token": "a", "refresh_token": "refresh-2"})

        secret = await client.refresh(PROVIDER, refresh_token="refresh-1")

        assert secret["refresh_token"] == "refresh-2"

    async def test_a_granted_scope_is_carried_through(self) -> None:
        client = answering(200, {"access_token": "a", "scope": "only-this"})

        secret = await client.refresh(PROVIDER, refresh_token="r")

        assert secret["scope"] == "only-this"

    async def test_a_revoked_grant_surfaces_as_needing_reauthorisation(self) -> None:
        client = answering(400, {"error": "invalid_grant"})

        with pytest.raises(CredentialUnavailableError, match="re-authorised"):
            await client.refresh(PROVIDER, refresh_token="r")


async def test_closing_releases_the_connection_pool() -> None:
    client = HttpTokenEndpoint(timeout_seconds=1.0)

    await client.aclose()

    assert client._client.is_closed
