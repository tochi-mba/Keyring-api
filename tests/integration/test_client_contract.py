"""The client library against the real keyring, and the fake against both.

The client and keyring live in one repository so that this file can exist. Minting and
verifying are two halves of one rule, and the only way to keep them agreeing is to run the
real minting half into the real verifying half on every change to either:

* a token keyring's ``issue_service_token`` minted verifies through :class:`TokenVerifier`,
  using the keys keyring's own JWKS endpoint published;
* a credential stored through keyring's API resolves through :class:`CredentialClient`, with
  keyring's own two-credential check doing the refusing;
* :class:`~keyring_client.testing.FakeKeyring` answers in the same shape keyring does, so the
  services that test against the fake are testing against keyring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keyring_client import (
    AuthenticationError,
    CredentialClient,
    CredentialNotFoundError,
    ExactAudience,
    JwksClient,
    KeyringRejectedError,
    SystemClock,
    TokenVerifier,
    jwks_url,
)
from keyring_client.testing import DEFAULT_SERVICE, DEFAULT_SERVICE_TOKEN, FakeKeyring
from tests.conftest import (
    SERVICE_NAME,
    SERVICE_TOKEN,
    account_id_of,
    make_profile,
    onboard,
    put_api_key,
    service_token,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from fastapi import FastAPI

    from keyring_api.core.config import Settings

BASE = "http://keyring.test"


@pytest.fixture
async def served(app: FastAPI) -> AsyncIterator[tuple[ASGITransport, AsyncClient]]:
    """Keyring with its lifespan run for real, and a transport the client library can use."""
    async with LifespanManager(app) as managed:
        transport = ASGITransport(app=managed.app)
        async with AsyncClient(transport=transport, base_url=BASE) as http:
            yield transport, http


async def connected(http: AsyncClient) -> tuple[str, str]:
    """An account with a stored API key. Returns (account id, user token for the service)."""
    session = await onboard(http)
    await make_profile(http, session)
    await put_api_key(http, session, profile="personal", service="tmdb", key="the-api-key")
    return await account_id_of(http, session), await service_token(http, session)


class TestTokensKeyringMints:
    async def test_verify_through_the_library_against_keyrings_published_keys(
        self, served: tuple[ASGITransport, AsyncClient], settings: Settings
    ) -> None:
        transport, http = served
        account_id, token = await connected(http)
        clock = SystemClock()
        jwks = JwksClient(url=jwks_url(BASE), clock=clock, transport=transport)
        verifier = TokenVerifier(jwks=jwks, issuer=settings.issuer, clock=clock)

        try:
            verified = await verifier.verify(token, audience=ExactAudience(SERVICE_NAME))
        finally:
            await jwks.aclose()

        assert verified.account_id == account_id
        assert verified.audience == SERVICE_NAME

    async def test_are_refused_by_the_library_for_any_other_audience(
        self, served: tuple[ASGITransport, AsyncClient], settings: Settings
    ) -> None:
        transport, http = served
        _, token = await connected(http)
        clock = SystemClock()
        jwks = JwksClient(url=jwks_url(BASE), clock=clock, transport=transport)
        verifier = TokenVerifier(jwks=jwks, issuer=settings.issuer, clock=clock)

        try:
            with pytest.raises(AuthenticationError):
                await verifier.verify(token, audience=ExactAudience("spotify"))
        finally:
            await jwks.aclose()


class TestCredentialsKeyringStores:
    async def test_resolve_through_the_library(
        self, served: tuple[ASGITransport, AsyncClient]
    ) -> None:
        transport, http = served
        _, token = await connected(http)
        client = CredentialClient(base_url=BASE, service_token=SERVICE_TOKEN, transport=transport)

        try:
            resolved = await client.resolve_credential(
                user_token=token, profile="personal", service="tmdb"
            )
        finally:
            await client.aclose()

        assert resolved.headers == {"Authorization": "Bearer the-api-key"}
        assert resolved.query_params == {}

    async def test_keyrings_refusals_map_to_the_errors_the_library_documents(
        self, served: tuple[ASGITransport, AsyncClient]
    ) -> None:
        transport, http = served
        _, token = await connected(http)
        good = CredentialClient(base_url=BASE, service_token=SERVICE_TOKEN, transport=transport)
        wrong = CredentialClient(
            base_url=BASE, service_token="not-a-configured-token", transport=transport
        )

        try:
            with pytest.raises(CredentialNotFoundError):
                await good.resolve_credential(user_token=token, profile="personal", service="nope")
            with pytest.raises(KeyringRejectedError):
                await wrong.resolve_credential(user_token=token, profile="personal", service="tmdb")
        finally:
            await good.aclose()
            await wrong.aclose()


class TestTheFakeAnswersLikeKeyring:
    async def test_a_resolved_credential_has_the_same_members(
        self, served: tuple[ASGITransport, AsyncClient]
    ) -> None:
        _, http = served
        _, token = await connected(http)
        real = await http.get(
            "/v1/internal/credentials/personal/tmdb",
            headers={"Authorization": f"Bearer {SERVICE_TOKEN}", "X-Keyring-User-Token": token},
        )

        fake = FakeKeyring()
        fake.connect(account_id="account-a", profile="personal", service="tmdb", headers={"X": "y"})
        async with AsyncClient(transport=fake.transport(), base_url=BASE) as fake_http:
            imitation = await fake_http.get(
                "/v1/internal/credentials/personal/tmdb",
                headers={
                    "Authorization": f"Bearer {DEFAULT_SERVICE_TOKEN}",
                    "X-Keyring-User-Token": fake.mint(audience=DEFAULT_SERVICE),
                },
            )

        real_body: dict[str, Any] = real.json()
        fake_body: dict[str, Any] = imitation.json()
        assert real.status_code == imitation.status_code == 200
        assert set(real_body) == set(fake_body)

    async def test_the_published_key_documents_have_the_same_members(
        self, served: tuple[ASGITransport, AsyncClient]
    ) -> None:
        _, http = served
        real_key = (await http.get("/.well-known/jwks.json")).json()["keys"][0]

        async with AsyncClient(transport=FakeKeyring().transport(), base_url=BASE) as fake_http:
            fake_key = (await fake_http.get("/.well-known/jwks.json")).json()["keys"][0]

        assert set(real_key) == set(fake_key)
        assert (real_key["kty"], real_key["alg"], real_key["use"]) == (
            fake_key["kty"],
            fake_key["alg"],
            fake_key["use"],
        )
