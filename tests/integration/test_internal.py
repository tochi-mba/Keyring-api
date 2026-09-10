"""The service-to-service surface.

The most security-critical file in the suite. Every test here is about one boundary: a
service asking keyring for a credential must be able to obtain exactly one thing -- the
credential belonging to the person whose token it was given -- and nothing else.

Without that pairing, anything able to reach keyring could request anybody's token. That
is the confused deputy, moved out of one process and into the gap between two.
"""

from __future__ import annotations

from httpx import AsyncClient

from keyring_api.api.routers.internal import USER_TOKEN_HEADER
from tests.conftest import (
    SERVICE_NAME,
    SERVICE_TOKEN,
    auth,
    make_profile,
    onboard,
    put_api_key,
    service_call,
    service_token,
)

OTHER_EMAIL = "other@example.com"


async def a_connected_account(
    client: AsyncClient, email: str = "person@example.com", *, key: str = "the-api-key"
) -> tuple[str, str]:
    """Onboard, create a profile, store a key. Returns (session token, user token)."""
    session = await onboard(client, email)
    await make_profile(client, session)
    await put_api_key(client, session, profile="personal", service="tmdb", key=key)
    return session, await service_token(client, session)


class TestHappyPath:
    async def test_a_service_gets_headers_to_attach(self, client: AsyncClient) -> None:
        _, user_token = await a_connected_account(client)

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
        )

        assert response.status_code == 200
        assert response.json()["headers"] == {"Authorization": "Bearer the-api-key"}

    async def test_the_response_carries_no_refresh_token_or_stored_field(
        self, client: AsyncClient
    ) -> None:
        # What comes back is what to attach, not what is stored.
        _, user_token = await a_connected_account(client)

        body = (
            await client.get(
                "/v1/internal/credentials/personal/tmdb",
                headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
            )
        ).json()

        assert set(body) == {"service", "headers", "query_params", "expires_at"}


class TestBothCredentialsRequired:
    async def test_the_service_token_alone_is_not_enough(self, client: AsyncClient) -> None:
        # Otherwise a service could name whoever it liked, and one compromised service
        # would mean every account's credentials.
        await a_connected_account(client)

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb", headers=auth(SERVICE_TOKEN)
        )

        assert response.status_code == 401

    async def test_the_user_token_alone_is_not_enough(self, client: AsyncClient) -> None:
        # A user token is handed to a service and lives in its memory for the length of a
        # job. On its own it must not open this door.
        _, user_token = await a_connected_account(client)

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers={USER_TOKEN_HEADER: user_token},
        )

        assert response.status_code == 401

    async def test_a_wrong_service_token_is_refused(self, client: AsyncClient) -> None:
        _, user_token = await a_connected_account(client)

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(
                service_token_value="not-a-real-service-token", user_token=user_token
            ),
        )

        assert response.status_code == 401

    async def test_a_session_token_is_not_a_service_token(self, client: AsyncClient) -> None:
        # A person's session must not be usable to impersonate a service.
        session, user_token = await a_connected_account(client)

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(service_token_value=session, user_token=user_token),
        )

        assert response.status_code == 401


class TestTheAccountComesFromTheUserToken:
    async def test_one_account_s_token_cannot_reach_another_s_profile(
        self, client: AsyncClient
    ) -> None:
        # THE test. Account A has the credential; account B holds a perfectly valid user
        # token and the service holds a perfectly valid service token. There is no
        # parameter naming an account, so the only profile reachable is B's own -- and B
        # has no profile called "personal".
        await a_connected_account(client)
        other_session = await onboard(client, OTHER_EMAIL)
        other_user_token = await service_token(client, other_session)

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=other_user_token),
        )

        assert response.status_code == 404

    async def test_a_same_named_profile_resolves_to_the_token_holder_s_own(
        self, client: AsyncClient
    ) -> None:
        # Both accounts have a profile called "personal" with a connection to the same
        # service. The credential returned must be the token holder's, not the other's.
        await a_connected_account(client, key="account-a-key")
        other_session = await onboard(client, OTHER_EMAIL)
        await make_profile(client, other_session)
        await put_api_key(
            client, other_session, profile="personal", service="tmdb", key="account-b-key"
        )
        other_user_token = await service_token(client, other_session)

        body = (
            await client.get(
                "/v1/internal/credentials/personal/tmdb",
                headers=service_call(
                    service_token_value=SERVICE_TOKEN, user_token=other_user_token
                ),
            )
        ).json()

        assert body["headers"]["Authorization"] == "Bearer account-b-key"


class TestUserTokenValidity:
    async def test_a_token_minted_for_another_service_is_refused(self, client: AsyncClient) -> None:
        # A service holds one of these for the length of a job. If audience were not
        # checked, a token given to one service would work at every other service that
        # trusts this issuer -- so a single careless service would leak into all of them.
        session, _ = await a_connected_account(client)
        for_someone_else = await service_token(client, session, audience="some-other-service")

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=for_someone_else),
        )

        assert response.status_code == 401

    async def test_a_forged_token_is_refused(self, client: AsyncClient) -> None:
        await a_connected_account(client)

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token="not.a.jwt"),
        )

        assert response.status_code == 401

    async def test_a_token_survives_its_session_being_logged_out(self, client: AsyncClient) -> None:
        # Asserting the CURRENT behaviour, not a wish. A signed token cannot be revoked --
        # that is exactly what makes it verifiable without calling back here -- so the
        # short expiry is the only revocation there is. See ADR-0008.
        session, user_token = await a_connected_account(client)
        await client.post("/v1/auth/logout-everywhere", headers=auth(session))

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
        )

        assert response.status_code == 200

    async def test_the_audience_is_the_service_the_token_is_presented_to(
        self, client: AsyncClient
    ) -> None:
        session, _ = await a_connected_account(client)
        correct = await service_token(client, session, audience=SERVICE_NAME)

        response = await client.get(
            "/v1/internal/credentials/personal/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=correct),
        )

        assert response.status_code == 200


class TestFormSecrets:
    async def test_it_returns_what_to_type_into_a_login_form(self, client: AsyncClient) -> None:
        session = await onboard(client)
        await make_profile(client, session)
        await client.put(
            "/v1/profiles/personal/connections/somesite/password",
            json={"username": "person", "password": "hunter2"},
            headers=auth(session),
        )
        user_token = await service_token(client, session)

        response = await client.get(
            "/v1/internal/form-secrets/personal/somesite",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
        )

        assert response.status_code == 200
        assert response.json()["fields"]["username"] == "person"

    async def test_a_current_totp_code_is_generated_when_a_seed_is_stored(
        self, client: AsyncClient
    ) -> None:
        # Generated at the moment of the call: by the time a browser has navigated to the
        # login page, a code from thirty seconds ago is already wrong.
        session = await onboard(client)
        await make_profile(client, session)
        await client.put(
            "/v1/profiles/personal/connections/somesite/password",
            json={
                "username": "person",
                "password": "hunter2",
                "totp_seed": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            },
            headers=auth(session),
        )
        user_token = await service_token(client, session)

        fields = (
            await client.get(
                "/v1/internal/form-secrets/personal/somesite",
                headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
            )
        ).json()["fields"]

        assert len(fields["totp"]) == 6
        assert fields["totp"].isdigit()

    async def test_it_needs_both_credentials_like_everything_else_here(
        self, client: AsyncClient
    ) -> None:
        # This is the one endpoint that returns credential material, which is exactly why.
        response = await client.get("/v1/internal/form-secrets/personal/somesite")

        assert response.status_code == 401

    async def test_an_api_key_is_not_available_as_a_form_login(self, client: AsyncClient) -> None:
        # The two consumption ports are not interchangeable. Producing an Authorization
        # header full of somebody's password, or typing an API key into a password field,
        # are both worse than failing.
        _, user_token = await a_connected_account(client)

        response = await client.get(
            "/v1/internal/form-secrets/personal/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
        )

        assert response.status_code == 503

    async def test_a_form_login_is_not_available_as_an_http_credential(
        self, client: AsyncClient
    ) -> None:
        session = await onboard(client)
        await make_profile(client, session)
        await client.put(
            "/v1/profiles/personal/connections/somesite/password",
            json={"username": "a", "password": "b"},
            headers=auth(session),
        )
        user_token = await service_token(client, session)

        response = await client.get(
            "/v1/internal/credentials/personal/somesite",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
        )

        assert response.status_code == 503


class TestMisses:
    async def test_an_unknown_profile_is_not_found(self, client: AsyncClient) -> None:
        _, user_token = await a_connected_account(client)

        response = await client.get(
            "/v1/internal/credentials/no-such-profile/tmdb",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
        )

        assert response.status_code == 404

    async def test_an_unconnected_service_is_not_found(self, client: AsyncClient) -> None:
        _, user_token = await a_connected_account(client)

        response = await client.get(
            "/v1/internal/credentials/personal/never-connected",
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user_token),
        )

        assert response.status_code == 404
