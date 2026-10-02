"""A person's re-authentication and notice settings, on every route that changes a credential.

settings-api is its shared fake, wired in through the composition root the way the real
client is; mail goes to a recording sender swapped in after onboarding, so the invite
token still comes back in the response the way it does with mail disabled.

The routes under test are every one that adds, replaces or removes a stored credential:
an API key, a form login, the OAuth consent that will store a token, one connection, and a
profile with its connections -- through a person's session, and the two of them a service
can reach through the delegated surface.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keyring_api.admin.service import OWN_PROFILE_NEEDS_PASSWORD
from keyring_api.api.app import create_app
from keyring_api.core.preferences import (
    EMAIL_NOTIFICATIONS,
    NAMESPACE,
    NOT_GUESSED,
    NOTIFY_ON_CREDENTIAL_CHANGE,
    NOTIFY_ON_NEW_SESSION,
    REFUSED,
    REQUIRE_REAUTH,
)
from keyring_api.credentials.changes import SEND_YOUR_PASSWORD, SERVICES_CANNOT
from keyring_api.domain.rbac import OWNER
from keyring_api.notifications.templates import CREDENTIAL_CHANGE_SUBJECT, NEW_SESSION_SUBJECT
from settings_client.testing import FakeSettingsClient
from tests.conftest import (
    ADMIN_TOKEN,
    EMAIL,
    PASSWORD,
    SERVICE_TOKEN,
    account_id_of,
    auth,
    container_of,
    grant_roles,
    log_in,
    make_profile,
    onboard,
    put_api_key,
    service_call,
    service_token,
)
from tests.fakes.email import RecordingSender
from tests.fakes.oauth import FakeTokenEndpoint
from tests.integration.test_oauth import callback, provider_settings, state_from

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from fastapi import FastAPI
    from httpx import Response

API_KEY = "the-api-key"
NEW_KEY = "a-replacement-key"
SITE_PASSWORD = "the-site-password"

# Every person-facing route that adds, replaces or removes a credential, against a profile
# 'personal' that already holds a 'tmdb' API key. The body is what the route needs apart
# from the password; None for a route that had no body before.
SESSION_ROUTES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("PUT", "/v1/profiles/personal/connections/tmdb/api-key", {"api_key": NEW_KEY}),
    ("PUT", "/v1/profiles/personal/connections/omdb/api-key", {"api_key": NEW_KEY}),
    (
        "PUT",
        "/v1/profiles/personal/connections/site/password",
        {"username": "me", "password": SITE_PASSWORD},
    ),
    ("POST", "/v1/profiles/personal/connections/spotify/authorize", None),
    ("DELETE", "/v1/profiles/personal/connections/tmdb", None),
    ("DELETE", "/v1/profiles/personal", None),
]
SESSION_IDS = [
    "replace-api-key",
    "add-api-key",
    "add-password",
    "begin-oauth",
    "remove-one",
    "remove-profile",
]

# The same, through the surface a service reaches with its own token and a user token.
SERVICE_ROUTES: list[tuple[str, str]] = [
    ("POST", "/v1/internal/profiles/personal/connections/spotify/authorize"),
    ("DELETE", "/v1/internal/profiles/personal/connections/tmdb"),
]
SERVICE_IDS = ["begin-oauth", "remove-one"]


@pytest.fixture
def chosen() -> FakeSettingsClient:
    return FakeSettingsClient()


@pytest.fixture
def token_endpoint() -> FakeTokenEndpoint:
    return FakeTokenEndpoint()


@pytest.fixture
def recorder() -> RecordingSender:
    return RecordingSender()


@pytest.fixture
def vault_app(tmp_path: Path, chosen: FakeSettingsClient) -> FastAPI:
    return create_app(provider_settings(tmp_path), settings_client=chosen)


@pytest.fixture
async def vault(
    vault_app: FastAPI, token_endpoint: FakeTokenEndpoint
) -> AsyncIterator[AsyncClient]:
    async with (
        LifespanManager(vault_app) as managed,
        AsyncClient(
            transport=ASGITransport(app=managed.app), base_url="http://keyring.test"
        ) as http,
    ):
        container_of(vault_app).credential_service._tokens = token_endpoint
        yield http


async def a_person_with_a_key(client: AsyncClient) -> str:
    """Onboard, make 'personal', store a 'tmdb' key. Returns the session token.

    Done before any setting is seeded, so it is the setup and not the subject.
    """
    session = await onboard(client)
    await make_profile(client, session)
    await put_api_key(client, session, key=API_KEY)
    return session


def start_mail(app: FastAPI, recorder: RecordingSender) -> None:
    """Deliver to the recorder from now on. After onboarding, so invites still come back."""
    container_of(app).outbox._sender = recorder


async def delivered(app: FastAPI, recorder: RecordingSender) -> list[Any]:
    await container_of(app).outbox.drain()
    return recorder.sent


async def send(
    client: AsyncClient,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    *,
    session: str,
    password: str | None = None,
) -> Response:
    """Call one credential route as the person, with or without the password re-entered."""
    payload = dict(body or {})
    if password is not None:
        payload["current_password"] = password
    return await client.request(
        method, path, json=payload if payload else None, headers=auth(session)
    )


async def services_of(client: AsyncClient, session: str) -> dict[str, str]:
    """What 'personal' is connected to now, by service, with each status. {} if it is gone."""
    response = await client.get("/v1/profiles/personal", headers=auth(session))
    if response.status_code == 404:
        return {}
    return {item["service"]: item["status"] for item in response.json()["connections"]}


async def as_service(client: AsyncClient, session: str) -> dict[str, str]:
    return service_call(
        service_token_value=SERVICE_TOKEN, user_token=await service_token(client, session)
    )


class TestNobodyChose:
    async def test_every_credential_route_works_as_before_and_nothing_is_mailed(
        self, vault: AsyncClient, vault_app: FastAPI, recorder: RecordingSender
    ) -> None:
        """The bug, named: wiring these settings up changing things for people who chose nothing.

        Before keyring read them it asked for no second password and sent no notices, and a
        person with no stored choice must see exactly that -- no 403, no mail.
        """
        session = await a_person_with_a_key(vault)
        start_mail(vault_app, recorder)

        for method, path, body in SESSION_ROUTES:
            response = await send(vault, method, path, body, session=session)
            assert response.status_code < 300, (path, response.text)
        await log_in(vault)

        assert await delivered(vault_app, recorder) == []

    async def test_without_settings_api_nothing_is_asked_or_mailed(
        self, client: AsyncClient, app: FastAPI, recorder: RecordingSender
    ) -> None:
        session = await onboard(client)
        await make_profile(client, session)
        start_mail(app, recorder)

        await put_api_key(client, session)
        await log_in(client)
        removed = await client.delete(
            "/v1/profiles/personal/connections/tmdb", headers=auth(session)
        )

        assert removed.status_code == 204
        assert await delivered(app, recorder) == []


class TestReauthenticationOn:
    @pytest.mark.parametrize(("method", "path", "body"), SESSION_ROUTES, ids=SESSION_IDS)
    async def test_a_session_alone_cannot_change_a_credential(
        self,
        vault: AsyncClient,
        chosen: FakeSettingsClient,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> None:
        """The bug, named: a stolen session token was every credential the account holds.

        With re-authentication on, the session is not enough to add, replace or remove one;
        and refusing changes nothing -- the key that was there is still there.
        """
        session = await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True})

        response = await send(vault, method, path, body, session=session)

        assert response.status_code == 403, response.text
        assert response.json()["detail"] == SEND_YOUR_PASSWORD
        assert await services_of(vault, session) == {"tmdb": "active"}

    @pytest.mark.parametrize(("method", "path", "body"), SESSION_ROUTES, ids=SESSION_IDS)
    async def test_the_password_entered_again_lets_it_through(
        self,
        vault: AsyncClient,
        chosen: FakeSettingsClient,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> None:
        session = await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True})

        response = await send(vault, method, path, body, session=session, password=PASSWORD)

        assert response.status_code < 300, response.text

    @pytest.mark.parametrize(("method", "path", "body"), SESSION_ROUTES, ids=SESSION_IDS)
    async def test_a_wrong_password_is_refused_whatever_the_setting(
        self,
        vault: AsyncClient,
        chosen: FakeSettingsClient,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> None:
        """The bug, named: a password somebody sent and got wrong, waved through.

        Checked even with re-authentication off: a wrong one is a reason to stop, and being
        checked always is what lets a right one stand in for the setting during an outage.
        """
        session = await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: False})

        response = await send(
            vault, method, path, body, session=session, password="not the password"
        )

        assert response.status_code == 401, response.text
        assert await services_of(vault, session) == {"tmdb": "active"}

    async def test_an_empty_profile_holds_no_credential_and_is_not_asked_about(
        self, vault: AsyncClient, chosen: FakeSettingsClient
    ) -> None:
        session = await onboard(vault)
        await make_profile(vault, session)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True})

        response = await vault.delete("/v1/profiles/personal", headers=auth(session))

        assert response.status_code == 204

    async def test_an_unknown_profile_is_still_a_404(
        self, vault: AsyncClient, chosen: FakeSettingsClient
    ) -> None:
        session = await onboard(vault)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True})

        response = await vault.delete("/v1/profiles/never", headers=auth(session))

        assert response.status_code == 404

    async def test_repeated_wrong_passwords_lock_the_account(
        self, tmp_path: Path, chosen: FakeSettingsClient
    ) -> None:
        """The bug, named: a credential route as a password oracle that never locks."""
        settings = provider_settings(tmp_path).model_copy(update={"lockout_threshold": 3})
        app = create_app(settings, settings_client=chosen)
        async with (
            LifespanManager(app) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            session = await a_person_with_a_key(http)
            for _ in range(3):
                guessed = await send(
                    http,
                    "PUT",
                    "/v1/profiles/personal/connections/tmdb/api-key",
                    {"api_key": NEW_KEY},
                    session=session,
                    password="a guess",
                )
                assert guessed.status_code == 401

            login = await http.post("/v1/auth/login", json={"email": EMAIL, "password": PASSWORD})

        assert login.status_code == 401


class TestAnAdministratorsOwnProfile:
    async def owner_with_a_key(self, client: AsyncClient) -> tuple[str, str]:
        """A person holding the owner role, with 'personal' and its key. (session, id)."""
        session = await a_person_with_a_key(client)
        account_id = await account_id_of(client, session)
        await grant_roles(client, account_id, [OWNER])
        return session, account_id

    async def test_their_own_setting_holds_on_the_administrative_route(
        self, vault: AsyncClient, chosen: FakeSettingsClient
    ) -> None:
        """The bug, named: a stolen owner's session removing credentials through the admin route.

        An administrator deleting somebody else's profile is not asked for a password they
        do not have. Deleting their own is a change to their own credentials, and their own
        re-authentication setting holds wherever the request comes in.
        """
        session, account_id = await self.owner_with_a_key(vault)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True})

        response = await vault.delete(
            f"/v1/admin/accounts/{account_id}/profiles/personal", headers=auth(session)
        )

        assert response.status_code == 403, response.text
        assert response.json()["detail"] == OWN_PROFILE_NEEDS_PASSWORD
        assert await services_of(vault, session) == {"tmdb": "active"}

    async def test_an_outage_refuses_it_too(
        self, vault: AsyncClient, chosen: FakeSettingsClient
    ) -> None:
        session, account_id = await self.owner_with_a_key(vault)
        chosen.unavailable = True

        response = await vault.delete(
            f"/v1/admin/accounts/{account_id}/profiles/personal", headers=auth(session)
        )

        assert response.status_code == 503, response.text
        assert await services_of(vault, session) == {"tmdb": "active"}

    async def test_with_it_off_the_deletion_goes_ahead_as_their_own(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
    ) -> None:
        session, account_id = await self.owner_with_a_key(vault)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: False, NOTIFY_ON_CREDENTIAL_CHANGE: True})
        start_mail(vault_app, recorder)

        response = await vault.delete(
            f"/v1/admin/accounts/{account_id}/profiles/personal", headers=auth(session)
        )

        assert response.status_code == 204, response.text
        assert await services_of(vault, session) == {}
        (message,) = await delivered(vault_app, recorder)
        assert "signed-in session" in message.body


class TestAServiceCannotReauthenticate:
    @pytest.mark.parametrize(("method", "path"), SERVICE_ROUTES, ids=SERVICE_IDS)
    async def test_a_service_is_refused_when_the_person_wants_their_password(
        self, vault: AsyncClient, chosen: FakeSettingsClient, method: str, path: str
    ) -> None:
        """The bug, named: the service most likely to want the check off walking around it.

        A service holds the person's user token and never their password, so on the
        delegated routes there is nothing it can send -- not even a password in a body,
        which these routes do not read.
        """
        session = await a_person_with_a_key(vault)
        headers = await as_service(vault, session)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True})

        response = await vault.request(
            method, path, json={"current_password": PASSWORD}, headers=headers
        )

        assert response.status_code == 403, response.text
        assert response.json()["detail"] == SERVICES_CANNOT
        assert await services_of(vault, session) == {"tmdb": "active"}

    @pytest.mark.parametrize(("method", "path"), SERVICE_ROUTES, ids=SERVICE_IDS)
    async def test_a_service_goes_ahead_when_the_person_did_not_ask(
        self, vault: AsyncClient, chosen: FakeSettingsClient, method: str, path: str
    ) -> None:
        session = await a_person_with_a_key(vault)
        headers = await as_service(vault, session)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: False})

        response = await vault.request(method, path, headers=headers)

        assert response.status_code < 300, response.text

    @pytest.mark.parametrize(("method", "path", "body"), SESSION_ROUTES, ids=SESSION_IDS)
    async def test_a_service_token_is_not_a_session(
        self,
        vault: AsyncClient,
        chosen: FakeSettingsClient,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> None:
        """The bug, named: a service presenting its tokens, and a password, on a person's route.

        The person-facing routes take a session and nothing else, so a service that had
        somehow learned the password still cannot use it there.
        """
        session = await a_person_with_a_key(vault)
        headers = await as_service(vault, session)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True})

        response = await vault.request(
            method, path, json={**(body or {}), "current_password": PASSWORD}, headers=headers
        )

        assert response.status_code == 401, response.text
        assert await services_of(vault, session) == {"tmdb": "active"}


class TestWhenSettingsApiCannotSay:
    @pytest.mark.parametrize(("method", "path", "body"), SESSION_ROUTES, ids=SESSION_IDS)
    async def test_an_outage_refuses_a_change_without_the_password(
        self,
        vault: AsyncClient,
        chosen: FakeSettingsClient,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> None:
        """The bug, named: an outage silently disarming re-authentication for whoever turned it on.

        The entry refuses rather than falling back, so with settings-api down nobody here
        knows the answer, and a change that needs it does not happen.
        """
        session = await a_person_with_a_key(vault)
        chosen.unavailable = True

        response = await send(vault, method, path, body, session=session)

        assert response.status_code == 503, response.text
        assert response.json()["detail"] == NOT_GUESSED
        assert await services_of(vault, session) == {"tmdb": "active"}

    @pytest.mark.parametrize(("method", "path", "body"), SESSION_ROUTES, ids=SESSION_IDS)
    async def test_an_outage_lets_the_password_through(
        self,
        vault: AsyncClient,
        chosen: FakeSettingsClient,
        method: str,
        path: str,
        body: dict[str, Any] | None,
    ) -> None:
        """Not a guess: the right password satisfies the setting whichever way it is set."""
        session = await a_person_with_a_key(vault)
        chosen.unavailable = True

        response = await send(vault, method, path, body, session=session, password=PASSWORD)

        assert response.status_code < 300, response.text

    @pytest.mark.parametrize(("method", "path"), SERVICE_ROUTES, ids=SERVICE_IDS)
    async def test_an_outage_refuses_a_service(
        self, vault: AsyncClient, chosen: FakeSettingsClient, method: str, path: str
    ) -> None:
        session = await a_person_with_a_key(vault)
        headers = await as_service(vault, session)
        chosen.unavailable = True

        response = await vault.request(method, path, headers=headers)

        assert response.status_code == 503, response.text

    async def test_an_outage_does_not_fail_a_login(
        self, vault: AsyncClient, chosen: FakeSettingsClient
    ) -> None:
        await a_person_with_a_key(vault)
        chosen.unavailable = True

        await log_in(vault)

    async def test_a_refused_grant_stores_nothing_even_with_the_password(
        self, vault: AsyncClient, chosen: FakeSettingsClient
    ) -> None:
        session = await a_person_with_a_key(vault)
        chosen.rejects[NAMESPACE] = (403, "keyring-api was not granted keyring")

        response = await send(
            vault,
            "PUT",
            "/v1/profiles/personal/connections/site/password",
            {"username": "me", "password": SITE_PASSWORD},
            session=session,
            password=PASSWORD,
        )

        assert response.status_code == 503
        assert response.json()["detail"] == REFUSED
        chosen.rejects.clear()
        assert await services_of(vault, session) == {"tmdb": "active"}

    async def test_a_refused_grant_at_the_callback_stores_nothing(
        self, vault: AsyncClient, chosen: FakeSettingsClient, token_endpoint: FakeTokenEndpoint
    ) -> None:
        """The bug, named: a token exchanged and stored, and the callback then failing anyway."""
        session = await a_person_with_a_key(vault)
        started = await send(
            vault,
            "POST",
            "/v1/profiles/personal/connections/spotify/authorize",
            None,
            session=session,
        )
        chosen.rejects[NAMESPACE] = (403, "keyring-api was not granted keyring")

        response = await callback(vault, state_from(started))

        assert response.status_code == 503
        assert token_endpoint.exchanges == []
        chosen.rejects.clear()
        assert (await services_of(vault, session))["spotify"] == "pending"


class TestCredentialChangeNotices:
    async def test_storing_a_key_is_announced_without_naming_it(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
    ) -> None:
        """The bug, named: a notice carrying the secret, or naming what the account holds."""
        session = await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {NOTIFY_ON_CREDENTIAL_CHANGE: True})
        start_mail(vault_app, recorder)

        await put_api_key(vault, session, key=NEW_KEY)

        sent = await delivered(vault_app, recorder)
        assert [message.subject for message in sent] == [CREDENTIAL_CHANGE_SUBJECT]
        assert sent[0].to_address == EMAIL
        body = sent[0].body
        assert "added or replaced" in body
        assert "signed-in session" in body
        for leaked in (NEW_KEY, API_KEY, "tmdb", "personal", session, PASSWORD):
            assert leaked not in body

    async def test_a_service_removing_one_is_announced_as_a_service(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
    ) -> None:
        session = await a_person_with_a_key(vault)
        headers = await as_service(vault, session)
        chosen.seed(NAMESPACE, {NOTIFY_ON_CREDENTIAL_CHANGE: True})
        start_mail(vault_app, recorder)

        removed = await vault.delete(
            "/v1/internal/profiles/personal/connections/tmdb", headers=headers
        )

        assert removed.status_code == 204
        (message,) = await delivered(vault_app, recorder)
        assert "removed" in message.body
        assert "a service acting for you" in message.body
        assert "downstream-tool" not in message.body

    async def test_an_oauth_token_is_announced_when_it_lands_not_when_consent_starts(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
        token_endpoint: FakeTokenEndpoint,
    ) -> None:
        session = await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {NOTIFY_ON_CREDENTIAL_CHANGE: True})
        start_mail(vault_app, recorder)

        started = await send(
            vault,
            "POST",
            "/v1/profiles/personal/connections/spotify/authorize",
            None,
            session=session,
        )
        assert await delivered(vault_app, recorder) == []
        finished = await callback(vault, state_from(started))

        assert finished.status_code == 200, finished.text
        (message,) = await delivered(vault_app, recorder)
        assert "added or replaced" in message.body
        assert "sign-in page" in message.body
        assert token_endpoint.access_token not in message.body
        assert token_endpoint.refresh_token not in message.body
        assert "spotify" not in message.body.lower()

    async def test_deleting_a_profile_is_announced_once(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
    ) -> None:
        session = await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {NOTIFY_ON_CREDENTIAL_CHANGE: True})
        start_mail(vault_app, recorder)

        response = await vault.delete("/v1/profiles/personal", headers=auth(session))

        assert response.status_code == 204
        assert len(await delivered(vault_app, recorder)) == 1

    async def test_an_administrator_is_not_asked_for_the_password_and_is_announced(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
    ) -> None:
        """The administrator never has the person's password; the audit log holds them.

        The person still hears that somebody removed their credentials.
        """
        session = await a_person_with_a_key(vault)
        account_id = await account_id_of(vault, session)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True, NOTIFY_ON_CREDENTIAL_CHANGE: True})
        start_mail(vault_app, recorder)

        response = await vault.delete(
            f"/v1/admin/accounts/{account_id}/profiles/personal", headers=auth(ADMIN_TOKEN)
        )

        assert response.status_code == 204, response.text
        (message,) = await delivered(vault_app, recorder)
        assert "by an administrator" in message.body

    async def test_the_master_switch_silences_it(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
    ) -> None:
        session = await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {EMAIL_NOTIFICATIONS: False, NOTIFY_ON_CREDENTIAL_CHANGE: True})
        start_mail(vault_app, recorder)

        await put_api_key(vault, session, key=NEW_KEY)

        assert await delivered(vault_app, recorder) == []

    async def test_a_refused_change_is_not_announced(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
    ) -> None:
        session = await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {REQUIRE_REAUTH: True, NOTIFY_ON_CREDENTIAL_CHANGE: True})
        start_mail(vault_app, recorder)

        refused = await vault.delete(
            "/v1/profiles/personal/connections/tmdb", headers=auth(session)
        )

        assert refused.status_code == 403
        assert await delivered(vault_app, recorder) == []


class TestNewSessionNotices:
    async def test_a_login_is_announced_to_somebody_who_asked(
        self,
        vault: AsyncClient,
        vault_app: FastAPI,
        chosen: FakeSettingsClient,
        recorder: RecordingSender,
    ) -> None:
        await a_person_with_a_key(vault)
        chosen.seed(NAMESPACE, {NOTIFY_ON_NEW_SESSION: True})
        start_mail(vault_app, recorder)

        token = await log_in(vault)

        (message,) = await delivered(vault_app, recorder)
        assert message.subject == NEW_SESSION_SUBJECT
        assert message.to_address == EMAIL
        assert token not in message.body
