"""The OAuth flow and the JWKS document, over HTTP.

The unit tests establish the rules of the flow against the service. These cover what a
caller can actually observe across the wire: which status codes come back, what the
connection looks like between the consent URL and the callback, and -- the two that
matter most -- that a captured callback URL is worth nothing on its second use, and that
nothing served here can sign a token or authenticate keyring to a provider.

No network is touched. The provider's token endpoint is substituted with a fake once the
container exists, so the "server-to-server" half of the flow runs entirely in process.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient, Response

from keyring_api.accounts.signing import ALGORITHM
from keyring_api.api.app import create_app
from keyring_api.api.schemas.common import PROBLEM_CONTENT_TYPE
from tests.conftest import (
    SERVICE_NAME,
    SERVICE_TOKEN,
    auth,
    build_settings,
    container_of,
    make_profile,
    onboard,
    service_call,
    service_token,
)
from tests.fakes.clock import FakeClock
from tests.fakes.oauth import FakeTokenEndpoint

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from fastapi import FastAPI

    from keyring_api.core.config import Settings

SERVICE = "spotify"
AUTHORIZE_URL = "https://accounts.example.com/authorize"
CLIENT_SECRET = "the-client-secret"
SCOPE = "user-read-private"

PROVIDER = {
    "service": SERVICE,
    "authorize_url": AUTHORIZE_URL,
    "token_url": "https://accounts.example.com/api/token",
    "client_id": "client-abc",
    "client_secret": CLIENT_SECRET,
    "scopes": [SCOPE],
}


def provider_settings(tmp_path: Path) -> Settings:
    """Settings with one OAuth provider configured, from a file on disk.

    The file holds a client secret, so the loader refuses to start unless it is
    owner-only: writing it is not enough, it has to be chmodded too.
    """
    path = tmp_path / "providers.json"
    path.write_text(json.dumps([PROVIDER]))
    path.chmod(0o600)
    return build_settings(tmp_path, oauth_providers_path=path)


@pytest.fixture
def token_endpoint() -> FakeTokenEndpoint:
    """Stands in for the provider's token endpoint, so no test reaches the network."""
    return FakeTokenEndpoint()


@pytest.fixture
def oauth_app(tmp_path: Path) -> FastAPI:
    return create_app(provider_settings(tmp_path))


@pytest.fixture
async def oauth_client(
    oauth_app: FastAPI, token_endpoint: FakeTokenEndpoint
) -> AsyncIterator[AsyncClient]:
    """An app with a provider configured and its token endpoint faked."""
    async with (
        LifespanManager(oauth_app) as managed,
        AsyncClient(
            transport=ASGITransport(app=managed.app), base_url="http://keyring.test"
        ) as http,
    ):
        # Substituted after startup rather than before: the container, and the real HTTP
        # token endpoint inside it, only exist once the lifespan has run.
        container_of(oauth_app).credential_service._tokens = token_endpoint
        yield http


async def a_person_with_a_profile(client: AsyncClient, email: str = "person@example.com") -> str:
    """Onboard an account with an empty 'personal' profile. Returns the session token."""
    token = await onboard(client, email)
    await make_profile(client, token)
    return token


async def begin(client: AsyncClient, token: str, service: str = SERVICE) -> Response:
    """Ask for a consent URL for one service."""
    return await client.post(
        f"/v1/profiles/personal/connections/{service}/authorize", headers=auth(token)
    )


async def delegated_headers(client: AsyncClient, session: str) -> dict[str, str]:
    """Two-credential proof for the service acting for this signed-in person."""
    user = await service_token(client, session)
    return service_call(service_token_value=SERVICE_TOKEN, user_token=user)


def state_from(response: Response) -> str:
    """Read the state out of the consent URL, exactly as the provider will.

    Recovered the way the provider recovers it rather than from the state store, so a
    change that stopped putting it in the URL fails these tests instead of passing them.
    """
    url: str = response.json()["authorization_url"]
    return parse_qs(urlparse(url).query)["state"][0]


async def callback(client: AsyncClient, state: str, code: str = "the-code") -> Response:
    """Arrive back from the provider.

    No session token: this is a redirect landing in a browser that may not be the one
    the flow started in. The state carries the whole of the authority.
    """
    return await client.get("/v1/oauth/callback", params={"state": state, "code": code})


async def connection_of(client: AsyncClient, token: str, service: str = SERVICE) -> Any:
    """The connection record for one service, as the profile endpoint reports it."""
    response = await client.get("/v1/profiles/personal", headers=auth(token))
    assert response.status_code == 200, response.text
    return next(
        (item for item in response.json()["connections"] if item["service"] == service), None
    )


def problem_without_request_id(response: Response) -> dict[str, Any]:
    """A problem body minus the one field that is meant to differ between requests."""
    body: dict[str, Any] = response.json()
    return {key: value for key, value in body.items() if key != "request_id"}


async def test_a_delegated_service_can_start_and_remove_a_connection_without_bearer_forwarding(
    oauth_client: AsyncClient,
) -> None:
    session = await a_person_with_a_profile(oauth_client)
    headers = await delegated_headers(oauth_client, session)

    started = await oauth_client.post(
        "/v1/internal/profiles/personal/connections/spotify/authorize", headers=headers
    )
    assert started.status_code == 200, started.text
    assert started.json()["authorization_url"].startswith(AUTHORIZE_URL)

    profile = await oauth_client.get("/v1/internal/profiles/personal", headers=headers)
    assert profile.json()["connections"][0]["status"] == "pending"

    removed = await oauth_client.delete(
        "/v1/internal/profiles/personal/connections/spotify", headers=headers
    )
    assert removed.status_code == 204
    after = await oauth_client.get("/v1/internal/profiles/personal", headers=headers)
    assert after.json()["connections"] == []


async def test_delegated_connection_mutations_are_bound_to_the_user_token_subject(
    oauth_client: AsyncClient,
) -> None:
    alice = await a_person_with_a_profile(oauth_client)
    bob = await a_person_with_a_profile(oauth_client, "other@example.com")
    alice_headers = await delegated_headers(oauth_client, alice)
    bob_headers = await delegated_headers(oauth_client, bob)
    started = await oauth_client.post(
        "/v1/internal/profiles/personal/connections/spotify/authorize",
        headers=alice_headers,
    )
    assert started.status_code == 200

    bob_profile = await oauth_client.get("/v1/internal/profiles/personal", headers=bob_headers)
    assert bob_profile.json()["connections"] == []
    removed = await oauth_client.delete(
        "/v1/internal/profiles/personal/connections/spotify", headers=bob_headers
    )
    assert removed.status_code == 404


class TestBeginningAuthorization:
    async def test_it_returns_a_provider_url_carrying_the_state(
        self, oauth_client: AsyncClient
    ) -> None:
        token = await a_person_with_a_profile(oauth_client)

        response = await begin(oauth_client, token)

        assert response.status_code == 200
        assert response.json()["authorization_url"].startswith(AUTHORIZE_URL)
        assert len(state_from(response)) > 0

    async def test_the_connection_is_pending_until_the_callback_lands(
        self, oauth_client: AsyncClient
    ) -> None:
        token = await a_person_with_a_profile(oauth_client)

        await begin(oauth_client, token)

        connection = await connection_of(oauth_client, token)
        assert connection["status"] == "pending"
        assert connection["kind"] == "oauth2_authorization_code"

    async def test_a_pending_connection_reports_no_granted_scopes(
        self, oauth_client: AsyncClient
    ) -> None:
        """Nobody has consented yet, so nothing is reported as granted.

        The bug, named: the pending placeholder was stored with the provider's configured
        scopes, so between the consent URL and the callback this route listed every
        requested scope under ``scopes`` -- a field documented as "what the provider
        actually granted" (``api/schemas/profiles.py``). The assistant hub reads exactly
        this route (LUCY-assistant ``src/lucy_api/clients/keyring.py``, ``connections``)
        and showed the person a grant they had not given.
        """
        session = await a_person_with_a_profile(oauth_client)
        headers = await delegated_headers(oauth_client, session)
        await begin(oauth_client, session)

        profile = await oauth_client.get("/v1/internal/profiles/personal", headers=headers)

        [connection] = profile.json()["connections"]
        assert connection["status"] == "pending"
        assert connection["scopes"] == []

    async def test_a_pending_connection_cannot_yet_produce_a_credential(
        self, oauth_client: AsyncClient
    ) -> None:
        # An unfinished flow leaves a connection record but no stored token. Handing a
        # consuming service anything at all here would be handing it nothing usable,
        # reported as a success.
        token = await a_person_with_a_profile(oauth_client)
        await begin(oauth_client, token)
        minted = await service_token(oauth_client, token)

        response = await oauth_client.get(
            f"/v1/internal/credentials/personal/{SERVICE}",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=minted),
        )

        assert response.status_code == 503
        assert "never completed" in response.json()["detail"]

    async def test_a_service_with_no_configured_provider_is_refused(
        self, oauth_client: AsyncClient
    ) -> None:
        # A provider is configuration, not code, so "we have no provider for that" is an
        # operator's missing entry rather than a caller's bad request.
        token = await a_person_with_a_profile(oauth_client)

        response = await begin(oauth_client, token, "tmdb")

        assert response.status_code == 503
        assert response.headers["content-type"].startswith(PROBLEM_CONTENT_TYPE)
        assert "no OAuth provider" in response.json()["detail"]


class TestCompletingAuthorization:
    async def test_the_callback_activates_the_connection(self, oauth_client: AsyncClient) -> None:
        token = await a_person_with_a_profile(oauth_client)
        state = state_from(await begin(oauth_client, token))

        response = await callback(oauth_client, state)

        assert response.status_code == 200
        assert response.json()["status"] == "active"
        assert (await connection_of(oauth_client, token))["status"] == "active"

    async def test_the_completed_connection_produces_a_credential(
        self, oauth_client: AsyncClient
    ) -> None:
        # The end of the whole errand: a consuming service asks for a header and gets
        # one, without the token having passed through any browser on the way.
        token = await a_person_with_a_profile(oauth_client)
        await callback(oauth_client, state_from(await begin(oauth_client, token)))
        minted = await service_token(oauth_client, token)

        response = await oauth_client.get(
            f"/v1/internal/credentials/personal/{SERVICE}",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=minted),
        )

        assert response.status_code == 200
        assert response.json()["headers"] == {"Authorization": "Bearer access-1"}

    async def test_a_state_cannot_be_replayed(self, oauth_client: AsyncClient) -> None:
        # Single use is what makes a captured callback URL worthless -- out of a browser
        # history, a referer header, or a proxy log.
        token = await a_person_with_a_profile(oauth_client)
        state = state_from(await begin(oauth_client, token))
        await callback(oauth_client, state)

        response = await callback(oauth_client, state, code="a-second-code")

        assert response.status_code == 400

    async def test_a_replay_reaches_no_provider_at_all(
        self, oauth_client: AsyncClient, token_endpoint: FakeTokenEndpoint
    ) -> None:
        # The state is spent before the code is exchanged, so a replayed callback cannot
        # be used to drive traffic at the provider on keyring's credentials either.
        token = await a_person_with_a_profile(oauth_client)
        state = state_from(await begin(oauth_client, token))
        await callback(oauth_client, state)

        await callback(oauth_client, state, code="a-second-code")

        assert token_endpoint.exchanges == ["the-code"]

    async def test_an_expired_state_is_refused(
        self, oauth_app: FastAPI, oauth_client: AsyncClient
    ) -> None:
        # An unfinished flow is a loose end: the window in which a leaked callback URL is
        # worth anything to somebody else is exactly this TTL.
        container = container_of(oauth_app)
        clock = FakeClock()
        # The store's own clock decides expiry, and it stamps the flow at issue time --
        # so it has to be substituted before the flow begins, not after.
        container.credential_service._states._clock = clock
        token = await a_person_with_a_profile(oauth_client)
        state = state_from(await begin(oauth_client, token))

        clock.advance(container.settings.oauth_state_ttl_seconds)

        response = await callback(oauth_client, state)
        assert response.status_code == 400

    async def test_an_invented_state_is_refused_exactly_like_a_replayed_one(
        self, oauth_client: AsyncClient
    ) -> None:
        # Unknown, expired and already-used answer identically. Anything that told them
        # apart would let someone forging callbacks learn which states had ever existed.
        token = await a_person_with_a_profile(oauth_client)
        state = state_from(await begin(oauth_client, token))
        await callback(oauth_client, state)

        replayed = await callback(oauth_client, state, code="a-second-code")
        invented = await callback(oauth_client, "never-issued", code="a-third-code")

        assert replayed.status_code == 400
        assert invented.status_code == 400
        assert problem_without_request_id(replayed) == problem_without_request_id(invented)

    async def test_a_callback_missing_its_code_leaves_the_state_unspent(
        self, oauth_client: AsyncClient
    ) -> None:
        # A truncated redirect must not burn the flow: the person would have no way back
        # except starting again, and single use would be doing the attacker's work.
        token = await a_person_with_a_profile(oauth_client)
        state = state_from(await begin(oauth_client, token))

        truncated = await oauth_client.get("/v1/oauth/callback", params={"state": state})

        assert truncated.status_code == 422
        assert (await callback(oauth_client, state)).json()["status"] == "active"

    async def test_the_credential_lands_only_on_the_profile_that_began_the_flow(
        self, oauth_client: AsyncClient
    ) -> None:
        # The callback is unauthenticated, so the account, profile and service come from
        # the stored state and never from its parameters. Otherwise a crafted callback
        # could attach a credential to a profile somebody else owns.
        mine = await a_person_with_a_profile(oauth_client)
        theirs = await a_person_with_a_profile(oauth_client, "other@example.com")

        await callback(oauth_client, state_from(await begin(oauth_client, mine)))

        assert await connection_of(oauth_client, theirs) is None

    async def test_the_client_secret_appears_in_no_response(
        self, oauth_client: AsyncClient
    ) -> None:
        # The client secret authenticates keyring itself to the provider. It belongs in
        # the server-to-server exchange and nowhere a browser or a caller can read it.
        token = await a_person_with_a_profile(oauth_client)
        started = await begin(oauth_client, token)
        completed = await callback(oauth_client, state_from(started))
        profile = await oauth_client.get("/v1/profiles/personal", headers=auth(token))

        for response in (started, completed, profile):
            assert CLIENT_SECRET not in response.text


class TestJwks:
    async def test_it_is_served_without_authentication(self, client: AsyncClient) -> None:
        # A verifier has nothing to authenticate with yet -- that is the problem this
        # document exists to solve.
        response = await client.get("/.well-known/jwks.json")

        assert response.status_code == 200

    async def test_it_carries_public_key_material_only(self, client: AsyncClient) -> None:
        # This is fetched by anything that wants to verify, so it must contain nothing
        # that could sign: the private exponent, or either prime factor, would let its
        # holder mint tokens every consuming service trusts.
        key = (await client.get("/.well-known/jwks.json")).json()["keys"][0]

        assert set(key) == {"kty", "use", "alg", "kid", "n", "e"}
        assert "d" not in key
        assert "p" not in key
        assert "q" not in key

    async def test_the_key_id_matches_the_tokens_it_verifies(self, client: AsyncClient) -> None:
        # A consumer caches this document by kid; a token whose header named a different
        # one would send it back here on every request, or fail to verify at all.
        minted = await service_token(client, await onboard(client))

        document = (await client.get("/.well-known/jwks.json")).json()

        assert jwt.get_unverified_header(minted)["kid"] == document["keys"][0]["kid"]

    async def test_a_consumer_can_verify_a_keyring_token_with_it_alone(
        self, app: FastAPI, client: AsyncClient
    ) -> None:
        # The whole point of publishing it: another service verifies locally, with no
        # call back here on every request it serves. Verified the way that service will,
        # from the fetched document, with a real JWT library.
        token = await onboard(client)
        account_id = (await client.get("/v1/auth/me", headers=auth(token))).json()["account_id"]
        minted = await service_token(client, token)
        document = (await client.get("/.well-known/jwks.json")).json()

        claims = jwt.decode(
            minted,
            jwt.PyJWK(document["keys"][0]),
            algorithms=[ALGORITHM],
            audience=SERVICE_NAME,
            issuer=container_of(app).settings.issuer,
        )

        assert claims["sub"] == account_id
