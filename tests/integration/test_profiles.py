"""The profile endpoints over HTTP.

The unit tests cover the credential service's rules. These cover what a caller can
actually observe across the whole route group: status codes, body shapes, and the two
properties this surface exists to keep -- that no stored secret comes back out, and that
one account cannot learn anything at all about another account's profiles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from keyring_api.api.app import create_app
from tests.conftest import (
    EMAIL,
    PASSWORD,
    auth,
    build_settings,
    container_of,
    make_profile,
    onboard,
    put_api_key,
)

if TYPE_CHECKING:
    from pathlib import Path

OTHER_EMAIL = "other@example.com"
API_KEY = "sk-live-must-never-come-back-out"
FORM_PASSWORD = "hunter2-must-never-come-back-out"
TOTP_SEED = "JBSWY3DPEHPK3PXP"


def apart_from_request_id(body: dict[str, Any]) -> dict[str, Any]:
    """A problem body minus the one field that legitimately differs per request."""
    return {key: value for key, value in body.items() if key != "request_id"}


async def account_id_of(client: AsyncClient, token: str) -> str:
    """The opaque account id behind a session token."""
    response = await client.get("/v1/auth/me", headers=auth(token))
    assert response.status_code == 200, response.text
    identifier: str = response.json()["account_id"]
    return identifier


class TestCreatingAProfile:
    async def test_creating_a_profile_returns_it_with_no_connections(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)

        response = await client.post("/v1/profiles", json={"name": "personal"}, headers=auth(token))

        assert response.status_code == 201
        body = response.json()
        assert set(body) == {"name", "created_at", "updated_at", "connections"}
        assert body["name"] == "personal"
        assert body["connections"] == []

    async def test_a_second_profile_of_the_same_name_conflicts(self, client: AsyncClient) -> None:
        token = await onboard(client)
        await make_profile(client, token)

        response = await client.post("/v1/profiles", json={"name": "personal"}, headers=auth(token))

        assert response.status_code == 409

    async def test_two_accounts_can_each_have_a_profile_called_personal(
        self, client: AsyncClient
    ) -> None:
        # Names are account-scoped. If they were global, one person's choice of name
        # would tell them a name was taken -- which is to say, that somebody else exists.
        mine = await onboard(client)
        theirs = await onboard(client, OTHER_EMAIL)

        await make_profile(client, mine)
        response = await client.post(
            "/v1/profiles", json={"name": "personal"}, headers=auth(theirs)
        )

        assert response.status_code == 201
        assert response.json()["name"] == "personal"

    @pytest.mark.parametrize(
        "name",
        [
            "../etc",
            "with space",
            "",
            "   ",
            ".",
            "-leading",
            "trailing-",
            "slash/inside",
            "a" * 65,
        ],
    )
    async def test_a_name_that_cannot_be_addressed_is_rejected(
        self, client: AsyncClient, name: str
    ) -> None:
        # These names become path segments in the secret store, so anything that could
        # traverse or fail to round-trip is refused at the door rather than sanitised.
        token = await onboard(client)

        response = await client.post("/v1/profiles", json={"name": name}, headers=auth(token))

        assert response.status_code == 422

    async def test_a_name_is_stored_trimmed_and_lowercased(self, client: AsyncClient) -> None:
        # Otherwise "Personal" and "personal" become two profiles a person then has to
        # tell apart in a list.
        token = await onboard(client)

        response = await client.post(
            "/v1/profiles", json={"name": "  Personal  "}, headers=auth(token)
        )

        assert response.status_code == 201
        assert response.json()["name"] == "personal"

    async def test_a_field_the_request_does_not_have_is_refused_not_ignored(
        self, client: AsyncClient
    ) -> None:
        # There is no way to choose whose profile this is. Ignoring the field silently
        # would let a caller believe they had.
        token = await onboard(client)

        response = await client.post(
            "/v1/profiles",
            json={"name": "personal", "account_id": "acct_somebody_else"},
            headers=auth(token),
        )

        assert response.status_code == 422


class TestListingProfiles:
    async def test_an_account_with_no_profiles_gets_an_empty_list(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)

        response = await client.get("/v1/profiles", headers=auth(token))

        assert response.status_code == 200
        assert response.json() == {"profiles": []}

    async def test_listing_returns_every_profile_the_account_owns_oldest_first(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token, "personal")
        await make_profile(client, token, "work")

        response = await client.get("/v1/profiles", headers=auth(token))

        assert response.status_code == 200
        assert [profile["name"] for profile in response.json()["profiles"]] == ["personal", "work"]

    async def test_an_account_never_sees_another_accounts_profiles(
        self, client: AsyncClient
    ) -> None:
        mine = await onboard(client)
        await make_profile(client, mine, "work")
        theirs = await onboard(client, OTHER_EMAIL)

        response = await client.get("/v1/profiles", headers=auth(theirs))

        assert response.json() == {"profiles": []}


class TestReadingAProfile:
    async def test_a_profile_is_addressable_however_its_name_is_cased(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token, "  Personal  ")

        lowercase = await client.get("/v1/profiles/personal", headers=auth(token))
        titlecase = await client.get("/v1/profiles/Personal", headers=auth(token))

        assert lowercase.status_code == 200
        assert titlecase.status_code == 200
        assert lowercase.json()["name"] == titlecase.json()["name"] == "personal"

    async def test_a_name_nobody_owns_is_not_found(self, client: AsyncClient) -> None:
        token = await onboard(client)

        response = await client.get("/v1/profiles/nobody-owns-this", headers=auth(token))

        assert response.status_code == 404

    async def test_a_name_that_cannot_be_addressed_is_rejected(self, client: AsyncClient) -> None:
        token = await onboard(client)

        response = await client.get("/v1/profiles/not a name", headers=auth(token))

        assert response.status_code == 422


class TestDeletingAProfile:
    async def test_deleting_a_profile_removes_it(self, client: AsyncClient) -> None:
        token = await onboard(client)
        await make_profile(client, token)

        response = await client.delete("/v1/profiles/personal", headers=auth(token))

        assert response.status_code == 204
        assert (await client.get("/v1/profiles/personal", headers=auth(token))).status_code == 404

    async def test_deleting_a_profile_that_does_not_exist_is_not_found(
        self, client: AsyncClient
    ) -> None:
        # Not a silent 204: that would leave the caller believing something was deleted.
        token = await onboard(client)

        response = await client.delete("/v1/profiles/never-existed", headers=auth(token))

        assert response.status_code == 404

    async def test_deleting_a_profile_takes_its_connections_with_it(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)
        await put_api_key(client, token, key=API_KEY)

        await client.delete("/v1/profiles/personal", headers=auth(token))
        await make_profile(client, token)

        response = await client.get("/v1/profiles/personal", headers=auth(token))
        assert response.json()["connections"] == []

    async def test_deleting_a_profile_deletes_its_credentials_from_the_vault(
        self, client: AsyncClient, app: FastAPI
    ) -> None:
        # Unlinked-but-still-stored would be credential material that nothing knows
        # about and nothing will ever clean up. Read through the store directly,
        # because no endpoint will show it either way.
        token = await onboard(client)
        account_id = await account_id_of(client, token)
        await make_profile(client, token)
        await put_api_key(client, token, key=API_KEY)

        secrets = container_of(app).secrets
        assert await secrets.get(account_id, "personal", "tmdb") is not None

        await client.delete("/v1/profiles/personal", headers=auth(token))

        assert await secrets.get(account_id, "personal", "tmdb") is None


class TestTheProfileCap:
    async def test_creating_a_profile_past_the_cap_is_refused(self, tmp_path: Path) -> None:
        # A cap that is not enforced is an unbounded write for anyone with an account.
        settings = build_settings(tmp_path, max_profiles_per_account=2)

        async with (
            LifespanManager(create_app(settings)) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            token = await onboard(http)
            await make_profile(http, token, "personal")
            await make_profile(http, token, "work")

            response = await http.post("/v1/profiles", json={"name": "spare"}, headers=auth(token))

        assert response.status_code == 429


class TestStoringAnApiKey:
    async def test_storing_a_key_returns_an_active_api_key_connection(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)

        response = await client.put(
            "/v1/profiles/personal/connections/tmdb/api-key",
            json={"api_key": API_KEY},
            headers=auth(token),
        )

        assert response.status_code == 200
        body = response.json()
        assert body["service"] == "tmdb"
        assert body["kind"] == "api_key"
        assert body["status"] == "active"
        assert body["stores_totp_seed"] is False

    async def test_the_connection_then_appears_on_the_profile(self, client: AsyncClient) -> None:
        token = await onboard(client)
        await make_profile(client, token)
        await put_api_key(client, token, key=API_KEY)

        connections = (await client.get("/v1/profiles/personal", headers=auth(token))).json()[
            "connections"
        ]

        assert [connection["service"] for connection in connections] == ["tmdb"]
        assert connections[0]["kind"] == "api_key"
        assert connections[0]["status"] == "active"

    async def test_the_stored_key_never_appears_in_any_response(self, client: AsyncClient) -> None:
        # The one property this whole surface exists to keep: values go in, status comes
        # out. Checked against the raw text, so a key nested anywhere is still caught.
        token = await onboard(client)
        await make_profile(client, token)

        stored = await client.put(
            "/v1/profiles/personal/connections/tmdb/api-key",
            json={"api_key": API_KEY},
            headers=auth(token),
        )
        fetched = await client.get("/v1/profiles/personal", headers=auth(token))
        listed = await client.get("/v1/profiles", headers=auth(token))

        assert API_KEY not in stored.text
        assert API_KEY not in fetched.text
        assert API_KEY not in listed.text

    async def test_storing_a_second_key_for_one_service_replaces_the_connection(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)
        await put_api_key(client, token, key=API_KEY)

        await put_api_key(client, token, key="a-rotated-key")

        connections = (await client.get("/v1/profiles/personal", headers=auth(token))).json()[
            "connections"
        ]
        assert len(connections) == 1

    async def test_an_empty_key_is_rejected(self, client: AsyncClient) -> None:
        token = await onboard(client)
        await make_profile(client, token)

        response = await client.put(
            "/v1/profiles/personal/connections/tmdb/api-key",
            json={"api_key": ""},
            headers=auth(token),
        )

        assert response.status_code == 422

    async def test_storing_into_a_profile_that_does_not_exist_is_not_found(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)

        response = await client.put(
            "/v1/profiles/never-existed/connections/tmdb/api-key",
            json={"api_key": API_KEY},
            headers=auth(token),
        )

        assert response.status_code == 404

    async def test_a_sealed_vault_refuses_to_store_rather_than_storing_in_the_clear(
        self, tmp_path: Path
    ) -> None:
        settings = build_settings(tmp_path, master_key=None)

        async with (
            LifespanManager(create_app(settings)) as managed,
            AsyncClient(transport=ASGITransport(app=managed.app), base_url="http://k.test") as http,
        ):
            token = await onboard(http)
            await make_profile(http, token)

            response = await http.put(
                "/v1/profiles/personal/connections/tmdb/api-key",
                json={"api_key": API_KEY},
                headers=auth(token),
            )
            profile = await http.get("/v1/profiles/personal", headers=auth(token))

        assert response.status_code == 503
        # And no connection was recorded, so the profile does not claim a credential
        # that was never written.
        assert profile.json()["connections"] == []


class TestStoringAFormLogin:
    async def test_storing_a_login_returns_an_active_password_connection(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)

        response = await client.put(
            "/v1/profiles/personal/connections/somesite/password",
            json={"username": EMAIL, "password": FORM_PASSWORD},
            headers=auth(token),
        )

        assert response.status_code == 200
        assert response.json()["kind"] == "password"
        assert response.json()["status"] == "active"

    async def test_a_login_sent_without_a_seed_is_not_flagged_as_storing_one(
        self, client: AsyncClient
    ) -> None:
        # The flag is opt-in and never inferred: it means somebody decided to put their
        # second factor in the same place as their first.
        token = await onboard(client)
        await make_profile(client, token)

        response = await client.put(
            "/v1/profiles/personal/connections/somesite/password",
            json={"username": EMAIL, "password": FORM_PASSWORD},
            headers=auth(token),
        )

        assert response.json()["stores_totp_seed"] is False

    async def test_a_login_sent_with_a_seed_is_flagged_as_storing_one(
        self, client: AsyncClient
    ) -> None:
        # Flagged so the consequence stays visible in every later read, rather than
        # being a thing that happened once and was never mentioned again.
        token = await onboard(client)
        await make_profile(client, token)

        await client.put(
            "/v1/profiles/personal/connections/somesite/password",
            json={"username": EMAIL, "password": FORM_PASSWORD, "totp_seed": TOTP_SEED},
            headers=auth(token),
        )

        connections = (await client.get("/v1/profiles/personal", headers=auth(token))).json()[
            "connections"
        ]
        assert connections[0]["stores_totp_seed"] is True

    async def test_the_stored_password_and_seed_never_appear_in_any_response(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)

        stored = await client.put(
            "/v1/profiles/personal/connections/somesite/password",
            json={"username": EMAIL, "password": FORM_PASSWORD, "totp_seed": TOTP_SEED},
            headers=auth(token),
        )
        fetched = await client.get("/v1/profiles/personal", headers=auth(token))

        assert FORM_PASSWORD not in stored.text
        assert FORM_PASSWORD not in fetched.text
        assert TOTP_SEED not in stored.text
        assert TOTP_SEED not in fetched.text


class TestRemovingAConnection:
    async def test_deleting_a_connection_removes_it_from_the_profile(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)
        await put_api_key(client, token, key=API_KEY)

        response = await client.delete(
            "/v1/profiles/personal/connections/tmdb", headers=auth(token)
        )

        assert response.status_code == 204
        profile = await client.get("/v1/profiles/personal", headers=auth(token))
        assert profile.json()["connections"] == []

    async def test_deleting_a_connection_leaves_the_others_alone(self, client: AsyncClient) -> None:
        token = await onboard(client)
        await make_profile(client, token)
        await put_api_key(client, token, service="tmdb", key=API_KEY)
        await put_api_key(client, token, service="spotify", key="another-key")

        await client.delete("/v1/profiles/personal/connections/tmdb", headers=auth(token))

        profile = await client.get("/v1/profiles/personal", headers=auth(token))
        assert [item["service"] for item in profile.json()["connections"]] == ["spotify"]

    async def test_deleting_a_connection_that_is_not_there_is_not_found(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)

        response = await client.delete(
            "/v1/profiles/personal/connections/tmdb", headers=auth(token)
        )

        assert response.status_code == 404

    async def test_deleting_a_connection_twice_is_not_found_the_second_time(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)
        await put_api_key(client, token, key=API_KEY)

        await client.delete("/v1/profiles/personal/connections/tmdb", headers=auth(token))
        response = await client.delete(
            "/v1/profiles/personal/connections/tmdb", headers=auth(token)
        )

        assert response.status_code == 404


class TestStartingAnAuthorization:
    async def test_a_service_with_no_configured_provider_is_unavailable(
        self, client: AsyncClient
    ) -> None:
        token = await onboard(client)
        await make_profile(client, token)

        response = await client.post(
            "/v1/profiles/personal/connections/spotify/authorize", headers=auth(token)
        )

        assert response.status_code == 503

    async def test_an_unknown_profile_is_not_found_even_when_no_provider_exists(
        self, client: AsyncClient
    ) -> None:
        # The profile is checked first. Answering 503 here would say "that profile is
        # fine, the provider is not" about a profile the caller does not own.
        token = await onboard(client)

        response = await client.post(
            "/v1/profiles/never-existed/connections/spotify/authorize", headers=auth(token)
        )

        assert response.status_code == 404


class TestAccountIsolation:
    """Every verb, against a profile somebody else owns.

    404 rather than 403 throughout: a 403 confirms the resource exists, which tells one
    person that another person has a profile by that name. Each test compares its answer
    against the answer for a name nobody owns, because the two being *identical* is the
    property -- a same-status-but-different-detail response is still an oracle.
    """

    async def test_another_account_reading_this_profile_is_told_it_does_not_exist(
        self, client: AsyncClient
    ) -> None:
        mine = await onboard(client)
        await make_profile(client, mine)
        theirs = await onboard(client, OTHER_EMAIL)

        cross = await client.get("/v1/profiles/personal", headers=auth(theirs))
        unknown = await client.get("/v1/profiles/nobody-owns-this", headers=auth(theirs))

        assert cross.status_code == unknown.status_code == 404
        assert apart_from_request_id(cross.json()) == apart_from_request_id(unknown.json())
        assert cross.headers["content-type"] == unknown.headers["content-type"]

    async def test_another_account_deleting_this_profile_is_told_it_does_not_exist(
        self, client: AsyncClient
    ) -> None:
        mine = await onboard(client)
        await make_profile(client, mine)
        theirs = await onboard(client, OTHER_EMAIL)

        cross = await client.delete("/v1/profiles/personal", headers=auth(theirs))
        unknown = await client.delete("/v1/profiles/nobody-owns-this", headers=auth(theirs))

        assert cross.status_code == unknown.status_code == 404
        assert apart_from_request_id(cross.json()) == apart_from_request_id(unknown.json())
        # And the profile is still there for the account that owns it.
        assert (await client.get("/v1/profiles/personal", headers=auth(mine))).status_code == 200

    async def test_another_account_storing_a_credential_here_is_told_it_does_not_exist(
        self, client: AsyncClient
    ) -> None:
        mine = await onboard(client)
        await make_profile(client, mine)
        theirs = await onboard(client, OTHER_EMAIL)

        cross = await client.put(
            "/v1/profiles/personal/connections/tmdb/api-key",
            json={"api_key": API_KEY},
            headers=auth(theirs),
        )
        unknown = await client.put(
            "/v1/profiles/nobody-owns-this/connections/tmdb/api-key",
            json={"api_key": API_KEY},
            headers=auth(theirs),
        )

        assert cross.status_code == unknown.status_code == 404
        assert apart_from_request_id(cross.json()) == apart_from_request_id(unknown.json())
        # And nothing was written into the owner's profile.
        owner_view = await client.get("/v1/profiles/personal", headers=auth(mine))
        assert owner_view.json()["connections"] == []

    async def test_another_account_removing_this_profiles_connection_is_told_it_does_not_exist(
        self, client: AsyncClient
    ) -> None:
        mine = await onboard(client)
        await make_profile(client, mine)
        await put_api_key(client, mine, key=API_KEY)
        theirs = await onboard(client, OTHER_EMAIL)

        cross = await client.delete("/v1/profiles/personal/connections/tmdb", headers=auth(theirs))
        unknown = await client.delete(
            "/v1/profiles/nobody-owns-this/connections/tmdb", headers=auth(theirs)
        )

        assert cross.status_code == unknown.status_code == 404
        assert apart_from_request_id(cross.json()) == apart_from_request_id(unknown.json())
        owner_view = await client.get("/v1/profiles/personal", headers=auth(mine))
        assert len(owner_view.json()["connections"]) == 1


class TestAuthenticationRequired:
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "/v1/profiles"),
            ("POST", "/v1/profiles"),
            ("GET", "/v1/profiles/personal"),
            ("DELETE", "/v1/profiles/personal"),
            ("PUT", "/v1/profiles/personal/connections/tmdb/api-key"),
            ("PUT", "/v1/profiles/personal/connections/somesite/password"),
            ("POST", "/v1/profiles/personal/connections/spotify/authorize"),
            ("DELETE", "/v1/profiles/personal/connections/tmdb"),
        ],
    )
    async def test_an_unauthenticated_request_is_refused(
        self, client: AsyncClient, method: str, path: str
    ) -> None:
        # Refused before the body is validated and before the name is looked up, so an
        # anonymous caller cannot use validation differences to probe what exists.
        await onboard(client)

        response = await client.request(
            method,
            path,
            json={"name": "personal", "api_key": API_KEY, "username": EMAIL, "password": PASSWORD},
        )

        assert response.status_code == 401

    async def test_an_invented_session_token_reaches_nothing(self, client: AsyncClient) -> None:
        owner = await onboard(client)
        await make_profile(client, owner)

        response = await client.get("/v1/profiles/personal", headers=auth("not-a-real-token"))

        assert response.status_code == 401
