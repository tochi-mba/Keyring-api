"""The credential service.

The refresh path gets the most attention, because it is the one that runs unattended:
nobody is watching when a token is renewed at three in the morning, so every branch of
it has to be established here rather than in production.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import pytest

from keyring_api.accounts.sql_store import SqlAccountStore
from keyring_api.credentials.kinds import ApiKeyCredential
from keyring_api.credentials.providers import OAuthProvider
from keyring_api.credentials.service import Authorization, CredentialService
from keyring_api.credentials.state import InMemoryOAuthStateStore
from keyring_api.domain.accounts import Account
from keyring_api.domain.errors import (
    ConnectionNotFoundError,
    CredentialUnavailableError,
    InvalidOAuthStateError,
    LimitExceededError,
    ProfileExistsError,
    ProfileNotFoundError,
)
from keyring_api.domain.profiles import ConnectionStatus, CredentialKind
from keyring_api.profiles.sql_store import SqlProfileStore
from keyring_api.secrets.sql import SqlSecretStore
from tests.fakes.clock import FakeClock
from tests.fakes.oauth import FakeTokenEndpoint

if TYPE_CHECKING:
    from keyring_api.core.config import Settings
    from keyring_api.storage.database import Database

ACCOUNT = "acct_1"
OTHER = "acct_2"
REDIRECT = "https://keyring.local/v1/oauth/callback"

SPOTIFY = OAuthProvider.model_validate(
    {
        "service": "spotify",
        "authorize_url": "https://accounts.example.com/authorize",
        "token_url": "https://accounts.example.com/api/token",
        "client_id": "client-abc",
        "client_secret": "secret-abc",
        "scopes": ["user-read-private"],
    }
)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def endpoint() -> FakeTokenEndpoint:
    return FakeTokenEndpoint()


@pytest.fixture
async def service(
    clock: FakeClock, endpoint: FakeTokenEndpoint, settings: Settings, database: Database
) -> CredentialService:
    # Profiles are foreign-keyed to an account, so the two accounts these tests use have
    # to exist. That is the point of the key: a profile whose owner is gone is credential
    # metadata nothing can reach and nothing will collect.
    accounts = SqlAccountStore(database=database)
    for account_id in (ACCOUNT, OTHER):
        await accounts.add(
            Account(
                account_id=account_id,
                email=f"{account_id}@example.com",
                password_hash="$argon2id$fake",
                created_at=clock.now(),
                updated_at=clock.now(),
            )
        )

    return CredentialService(
        profiles=SqlProfileStore(database=database),
        secrets=SqlSecretStore(
            database=database, master_key=settings.master_key_bytes(), clock=clock
        ),
        states=InMemoryOAuthStateStore(clock=clock),
        tokens=endpoint,
        providers={"spotify": SPOTIFY},
        clock=clock,
        settings=settings,
    )


def state_from(authorization: Authorization) -> str:
    """Read the state out of the consent URL, exactly as the provider will.

    Recovered the way a real caller recovers it rather than by reaching into the store,
    so a change that stopped putting the state in the URL would fail these tests instead
    of passing them.
    """
    query = parse_qs(urlparse(authorization.authorization_url).query)
    return query["state"][0]


async def begin(
    service: CredentialService, account: str = ACCOUNT, profile: str = "personal"
) -> str:
    """Start a flow and return its state."""
    return state_from(
        await service.begin_authorization(account, profile, "spotify", redirect_uri=REDIRECT)
    )


async def connect_oauth(service: CredentialService, profile: str = "personal") -> None:
    """Run a whole authorization flow, from consent URL to stored token."""
    state = await begin(service, profile=profile)
    await service.complete_authorization(state=state, code="the-code")


class TestProfiles:
    async def test_a_profile_can_be_created_and_read_back(self, service: CredentialService) -> None:
        await service.create_profile(ACCOUNT, "personal")

        assert (await service.get_profile(ACCOUNT, "personal")).name == "personal"

    async def test_a_profile_name_is_normalized_on_the_way_in_and_out(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "  Personal ")

        assert (await service.get_profile(ACCOUNT, "PERSONAL")).name == "personal"

    async def test_a_duplicate_name_is_refused(self, service: CredentialService) -> None:
        await service.create_profile(ACCOUNT, "personal")

        with pytest.raises(ProfileExistsError):
            await service.create_profile(ACCOUNT, "personal")

    async def test_another_account_s_profile_is_not_found(self, service: CredentialService) -> None:
        # Not found, never forbidden: a distinguishable "not yours" tells one person
        # that another person has a profile by that name.
        await service.create_profile(OTHER, "personal")

        with pytest.raises(ProfileNotFoundError):
            await service.get_profile(ACCOUNT, "personal")

    async def test_the_error_for_someone_else_s_profile_matches_the_error_for_none(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(OTHER, "personal")

        with pytest.raises(ProfileNotFoundError) as theirs:
            await service.get_profile(ACCOUNT, "personal")
        with pytest.raises(ProfileNotFoundError) as absent:
            await service.get_profile(ACCOUNT, "never-existed")

        assert str(theirs.value) == str(absent.value)

    async def test_listing_shows_only_this_account_s_profiles(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "mine")
        await service.create_profile(OTHER, "theirs")

        assert [profile.name for profile in await service.list_profiles(ACCOUNT)] == ["mine"]

    async def test_the_profile_cap_is_enforced(
        self, service: CredentialService, settings: Settings
    ) -> None:
        for index in range(settings.max_profiles_per_account):
            await service.create_profile(ACCOUNT, f"profile-{index}")

        with pytest.raises(LimitExceededError, match="profiles per account"):
            await service.create_profile(ACCOUNT, "one-too-many")

    async def test_the_cap_is_per_account(
        self, service: CredentialService, settings: Settings
    ) -> None:
        for index in range(settings.max_profiles_per_account):
            await service.create_profile(ACCOUNT, f"profile-{index}")

        assert (await service.create_profile(OTHER, "personal")).name == "personal"

    async def test_deleting_a_profile_takes_its_credentials_with_it(
        self, service: CredentialService
    ) -> None:
        # A profile record without its secrets would be tidy. Secrets without their
        # profile record are credential material nothing knows about and nothing will
        # ever clean up.
        await service.create_profile(ACCOUNT, "personal")
        await service.put_direct_credential(
            ACCOUNT, "personal", "tmdb", kind=CredentialKind.API_KEY, secret={"api_key": "abc"}
        )

        assert await service.delete_profile(ACCOUNT, "personal")

        assert await service._secrets.get(ACCOUNT, "personal", "tmdb") is None

    async def test_deleting_an_unknown_profile_reports_that_nothing_went(
        self, service: CredentialService
    ) -> None:
        assert not await service.delete_profile(ACCOUNT, "personal")

    async def test_deleting_an_account_removes_its_profiles_and_secrets(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await service.put_direct_credential(
            ACCOUNT, "personal", "tmdb", kind=CredentialKind.API_KEY, secret={"api_key": "abc"}
        )

        await service.delete_account_data(ACCOUNT)

        assert await service.list_profiles(ACCOUNT) == []
        assert await service._secrets.get(ACCOUNT, "personal", "tmdb") is None


class TestDirectCredentials:
    async def test_an_api_key_can_be_stored_and_used(self, service: CredentialService) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await service.put_direct_credential(
            ACCOUNT, "personal", "tmdb", kind=CredentialKind.API_KEY, secret={"api_key": "abc"}
        )

        credential = await service.resolve_http_auth(ACCOUNT, "personal", "tmdb")

        assert isinstance(credential, ApiKeyCredential)
        assert await credential.headers() == {"Authorization": "Bearer abc"}

    async def test_a_form_login_is_resolved_through_the_other_port(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await service.put_direct_credential(
            ACCOUNT,
            "personal",
            "somesite",
            kind=CredentialKind.PASSWORD,
            secret={"username": "person", "password": "hunter2"},
        )

        credential = await service.resolve_form_secrets(ACCOUNT, "personal", "somesite")

        assert (await credential.fields())["username"] == "person"

    async def test_a_form_login_is_not_available_as_an_http_credential(
        self, service: CredentialService
    ) -> None:
        # The two ports are not interchangeable, and the error says why rather than
        # producing an Authorization header full of somebody's password.
        await service.create_profile(ACCOUNT, "personal")
        await service.put_direct_credential(
            ACCOUNT,
            "personal",
            "somesite",
            kind=CredentialKind.PASSWORD,
            secret={"username": "a", "password": "b"},
        )

        with pytest.raises(CredentialUnavailableError, match="form login"):
            await service.resolve_http_auth(ACCOUNT, "personal", "somesite")

    async def test_an_api_key_is_not_available_as_a_form_login(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await service.put_direct_credential(
            ACCOUNT, "personal", "tmdb", kind=CredentialKind.API_KEY, secret={"api_key": "a"}
        )

        with pytest.raises(CredentialUnavailableError, match="not a form login"):
            await service.resolve_form_secrets(ACCOUNT, "personal", "tmdb")

    async def test_a_totp_seed_is_only_flagged_when_the_caller_says_so(
        self, service: CredentialService
    ) -> None:
        # Never inferred from the seed being present in the request: storing one beside
        # the password collapses that person's second factor into the same place as
        # their first, so it has to be a decision somebody made.
        await service.create_profile(ACCOUNT, "personal")

        connection = await service.put_direct_credential(
            ACCOUNT,
            "personal",
            "somesite",
            kind=CredentialKind.PASSWORD,
            secret={"username": "a", "password": "b", "totp_seed": "GEZDGNBV"},
            stores_totp_seed=True,
        )

        assert connection.stores_totp_seed

    async def test_storing_into_another_account_s_profile_is_refused(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(OTHER, "personal")

        with pytest.raises(ProfileNotFoundError):
            await service.put_direct_credential(
                ACCOUNT,
                "personal",
                "tmdb",
                kind=CredentialKind.API_KEY,
                secret={"api_key": "abc"},
            )

    async def test_the_connection_cap_is_enforced(
        self, service: CredentialService, settings: Settings
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        for index in range(settings.max_connections_per_profile):
            await service.put_direct_credential(
                ACCOUNT,
                "personal",
                f"service-{index}",
                kind=CredentialKind.API_KEY,
                secret={"api_key": "abc"},
            )

        with pytest.raises(LimitExceededError, match="connections per profile"):
            await service.put_direct_credential(
                ACCOUNT,
                "personal",
                "one-too-many",
                kind=CredentialKind.API_KEY,
                secret={"api_key": "abc"},
            )

    async def test_replacing_an_existing_connection_is_never_capped(
        self, service: CredentialService, settings: Settings
    ) -> None:
        # Otherwise a profile at its cap can never rotate a key it already has.
        await service.create_profile(ACCOUNT, "personal")
        for index in range(settings.max_connections_per_profile):
            await service.put_direct_credential(
                ACCOUNT,
                "personal",
                f"service-{index}",
                kind=CredentialKind.API_KEY,
                secret={"api_key": "abc"},
            )

        rotated = await service.put_direct_credential(
            ACCOUNT,
            "personal",
            "service-0",
            kind=CredentialKind.API_KEY,
            secret={"api_key": "rotated"},
        )

        assert rotated.service == "service-0"


class TestAuthorizationFlow:
    async def test_it_returns_a_provider_url_carrying_the_state(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")

        authorization = await service.begin_authorization(
            ACCOUNT, "personal", "spotify", redirect_uri=REDIRECT
        )

        assert authorization.authorization_url.startswith(str(SPOTIFY.authorize_url))
        assert "state=" in authorization.authorization_url

    async def test_the_connection_is_pending_until_the_callback_arrives(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await service.begin_authorization(ACCOUNT, "personal", "spotify", redirect_uri=REDIRECT)

        profile = await service.get_profile(ACCOUNT, "personal")
        connection = profile.connection("spotify")
        assert connection is not None
        assert connection.status is ConnectionStatus.PENDING

    async def test_a_pending_connection_cannot_produce_a_credential(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await service.begin_authorization(ACCOUNT, "personal", "spotify", redirect_uri=REDIRECT)

        with pytest.raises(CredentialUnavailableError, match="never completed"):
            await service.resolve_http_auth(ACCOUNT, "personal", "spotify")

    async def test_completing_the_flow_stores_a_usable_credential(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")

        await connect_oauth(service)

        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        assert await credential.headers() == {"Authorization": "Bearer access-1"}

    async def test_no_secret_ever_crosses_the_api_during_the_flow(
        self, service: CredentialService
    ) -> None:
        # The person consents at the provider; the token comes back to us server to
        # server. Nothing in what we hand the browser is a credential.
        await service.create_profile(ACCOUNT, "personal")

        authorization = await service.begin_authorization(
            ACCOUNT, "personal", "spotify", redirect_uri=REDIRECT
        )

        assert SPOTIFY.client_secret not in authorization.authorization_url

    async def test_a_state_cannot_be_replayed(self, service: CredentialService) -> None:
        # Single use is what stops a captured callback URL being used again -- from a
        # browser history, a referer header, or a shoulder.
        await service.create_profile(ACCOUNT, "personal")
        state = await begin(service)
        await service.complete_authorization(state=state, code="code-1")

        with pytest.raises(InvalidOAuthStateError):
            await service.complete_authorization(state=state, code="code-2")

    async def test_an_expired_state_is_refused(
        self, service: CredentialService, clock: FakeClock, settings: Settings
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        state = await begin(service)

        clock.advance(timedelta(seconds=settings.oauth_state_ttl_seconds))

        with pytest.raises(InvalidOAuthStateError):
            await service.complete_authorization(state=state, code="the-code")

    async def test_an_invented_state_is_refused_identically(
        self, service: CredentialService
    ) -> None:
        with pytest.raises(InvalidOAuthStateError) as invented:
            await service.complete_authorization(state="never-issued", code="c")

        assert "invalid or has expired" in str(invented.value)

    async def test_the_credential_lands_on_the_profile_the_state_names(
        self, service: CredentialService
    ) -> None:
        # The account, profile and service come from the stored state, never from the
        # callback. Without that binding a crafted callback could attach a credential to
        # somebody else's profile.
        await service.create_profile(ACCOUNT, "personal")
        await service.create_profile(OTHER, "personal")
        await connect_oauth(service)

        theirs = await service.get_profile(OTHER, "personal")
        assert theirs.connection("spotify") is None

    async def test_a_profile_deleted_mid_flow_fails_cleanly(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        state = await begin(service)
        await service.delete_profile(ACCOUNT, "personal")

        with pytest.raises(InvalidOAuthStateError, match="no longer exists"):
            await service.complete_authorization(state=state, code="the-code")

    async def test_an_unconfigured_service_is_refused_with_a_usable_message(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")

        with pytest.raises(CredentialUnavailableError, match="no OAuth provider"):
            await service.begin_authorization(
                ACCOUNT, "personal", "unconfigured", redirect_uri=REDIRECT
            )

    async def test_a_provider_that_refuses_the_exchange_surfaces_the_reason(
        self, service: CredentialService, endpoint: FakeTokenEndpoint
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        state = await begin(service)
        endpoint.fail_with = "invalid_grant"

        with pytest.raises(CredentialUnavailableError, match="invalid_grant"):
            await service.complete_authorization(state=state, code="the-code")

    async def test_the_granted_scopes_are_recorded_rather_than_the_requested_ones(
        self, service: CredentialService, endpoint: FakeTokenEndpoint
    ) -> None:
        # Providers grant less than you ask for. Recording the request would show a
        # connection as having a scope it does not have.
        await service.create_profile(ACCOUNT, "personal")
        state = await begin(service)
        endpoint.granted_scope = "only-this"

        connection = await service.complete_authorization(state=state, code="the-code")

        assert connection.scopes == ("only-this",)

    async def test_abandoned_flows_are_swept(
        self, service: CredentialService, clock: FakeClock, settings: Settings
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await service.begin_authorization(ACCOUNT, "personal", "spotify", redirect_uri=REDIRECT)

        clock.advance(timedelta(seconds=settings.oauth_state_ttl_seconds * 2))

        assert await service.sweep_once() == 1


class TestRefresh:
    async def test_a_live_token_is_not_refreshed(
        self, service: CredentialService, endpoint: FakeTokenEndpoint
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)

        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        await credential.headers()

        assert endpoint.refreshes == []

    async def test_a_token_inside_its_margin_is_refreshed_before_it_expires(
        self, service: CredentialService, endpoint: FakeTokenEndpoint, clock: FakeClock
    ) -> None:
        # Before, not after a 401: refreshing on failure means one request has already
        # failed and every caller has to know to retry.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        endpoint.access_token = "access-2"

        clock.advance(timedelta(seconds=3600 - 60))
        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")

        assert await credential.headers() == {"Authorization": "Bearer access-2"}
        assert endpoint.refreshes == ["refresh-1"]

    async def test_the_renewed_token_is_written_back(
        self, service: CredentialService, endpoint: FakeTokenEndpoint, clock: FakeClock
    ) -> None:
        # Otherwise every single request refreshes, and the provider rate-limits us.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        clock.advance(timedelta(seconds=3600 - 60))
        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        await credential.headers()

        again = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        await again.headers()

        assert len(endpoint.refreshes) == 1

    async def test_a_refresh_that_returns_no_new_refresh_token_keeps_the_old_one(
        self, service: CredentialService, endpoint: FakeTokenEndpoint, clock: FakeClock
    ) -> None:
        # Most providers say nothing about the refresh token on renewal, meaning "keep
        # using yours". Taking the response at face value would break every future
        # renewal -- and only show up hours later, when the next one was due.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        endpoint.omit_refresh_token = True

        clock.advance(timedelta(seconds=3600 - 60))
        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        await credential.headers()

        stored = await service._secrets.get(ACCOUNT, "personal", "spotify")
        assert stored is not None
        assert stored["refresh_token"] == "refresh-1"

    async def test_a_failed_refresh_marks_the_connection_without_deleting_it(
        self, service: CredentialService, endpoint: FakeTokenEndpoint, clock: FakeClock
    ) -> None:
        # A provider being down for five minutes must not destroy a refresh token that
        # will work again afterwards.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        endpoint.fail_with = "temporarily_unavailable"

        clock.advance(timedelta(seconds=3600 - 60))
        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        with pytest.raises(CredentialUnavailableError):
            await credential.headers()

        assert await service._secrets.get(ACCOUNT, "personal", "spotify") is not None

    async def test_a_failed_refresh_records_why_on_the_connection(
        self, service: CredentialService, endpoint: FakeTokenEndpoint, clock: FakeClock
    ) -> None:
        # So /healthy and the profile endpoint can say what is wrong and what to do,
        # instead of a job failing mysteriously somewhere downstream.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        endpoint.fail_with = "invalid_grant"

        clock.advance(timedelta(seconds=3600 - 60))
        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        with pytest.raises(CredentialUnavailableError):
            await credential.headers()

        profile = await service.get_profile(ACCOUNT, "personal")
        connection = profile.connection("spotify")
        assert connection is not None
        assert connection.status is ConnectionStatus.EXPIRED
        assert connection.last_error is not None

    async def test_a_successful_refresh_clears_a_previous_error(
        self, service: CredentialService, endpoint: FakeTokenEndpoint, clock: FakeClock
    ) -> None:
        # A stale error on a working connection sends people to fix nothing.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        endpoint.fail_with = "temporarily_unavailable"
        clock.advance(timedelta(seconds=3600 - 60))
        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        with pytest.raises(CredentialUnavailableError):
            await credential.headers()

        endpoint.fail_with = None
        retried = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        await retried.headers()

        profile = await service.get_profile(ACCOUNT, "personal")
        connection = profile.connection("spotify")
        assert connection is not None
        assert connection.last_error is None

    async def test_a_connection_with_no_refresh_token_says_it_must_be_reauthorised(
        self, service: CredentialService, clock: FakeClock
    ) -> None:
        # Some providers issue no refresh token at all unless asked correctly. The
        # message has to name the remedy, because the remedy needs a person.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        await service._secrets.put(
            ACCOUNT, "personal", "spotify", {"access_token": "a", "expires_in": 3600}
        )

        clock.advance(timedelta(seconds=3600 - 60))
        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")

        with pytest.raises(CredentialUnavailableError, match="authorised again"):
            await credential.headers()


class TestResolutionFailures:
    async def test_an_unknown_profile_is_not_found(self, service: CredentialService) -> None:
        with pytest.raises(ProfileNotFoundError):
            await service.resolve_http_auth(ACCOUNT, "personal", "spotify")

    async def test_an_unconnected_service_is_not_found(self, service: CredentialService) -> None:
        await service.create_profile(ACCOUNT, "personal")

        with pytest.raises(ConnectionNotFoundError):
            await service.resolve_http_auth(ACCOUNT, "personal", "spotify")

    async def test_another_account_cannot_resolve_this_account_s_credential(
        self, service: CredentialService
    ) -> None:
        # The isolation test that matters most: not "can they see it listed" but "can
        # they get a working token out of it".
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)

        with pytest.raises(ProfileNotFoundError):
            await service.resolve_http_auth(OTHER, "personal", "spotify")

    async def test_a_connection_whose_secret_has_vanished_is_reported_not_hidden(
        self, service: CredentialService
    ) -> None:
        # The connection record and the vault disagreeing is a real inconsistency;
        # pretending there is simply no connection would hide it.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        await service._secrets.delete(ACCOUNT, "personal", "spotify")

        with pytest.raises(CredentialUnavailableError, match="missing from the vault"):
            await service.resolve_http_auth(ACCOUNT, "personal", "spotify")


class TestRevocation:
    async def test_revoking_removes_the_connection_and_the_credential(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)

        assert await service.revoke_connection(ACCOUNT, "personal", "spotify")

        profile = await service.get_profile(ACCOUNT, "personal")
        assert profile.connection("spotify") is None
        assert await service._secrets.get(ACCOUNT, "personal", "spotify") is None

    async def test_revoking_something_absent_reports_that_nothing_went(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")

        assert not await service.revoke_connection(ACCOUNT, "personal", "spotify")

    async def test_another_account_cannot_revoke_this_one_s_connection(
        self, service: CredentialService
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)

        with pytest.raises(ProfileNotFoundError):
            await service.revoke_connection(OTHER, "personal", "spotify")


class TestRevocationDuringARefresh:
    """A write-back must not resurrect something that was revoked while it was in flight.

    Both OAuth write-back paths read the profile *before* a network round trip. A
    write-back based on that stale object silently undoes anything that happened in
    between -- and the thing most likely to happen in between is the person revoking a
    credential they believe has leaked.
    """

    async def test_a_revoke_during_a_refresh_is_not_undone(
        self, service: CredentialService, clock: FakeClock
    ) -> None:
        # The scenario in full: somebody thinks their grant leaked and revokes it while a
        # service is mid-refresh. Without the re-read, the renewed token is written back
        # against the pre-revoke profile -- the connection reappears, the vault file is
        # recreated, and the credential they revoked is live again with nothing saying so.
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        clock.advance(timedelta(seconds=3600 - 60))

        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        await service.revoke_connection(ACCOUNT, "personal", "spotify")

        with pytest.raises(ConnectionNotFoundError):
            await credential.headers()

        assert await service._secrets.get(ACCOUNT, "personal", "spotify") is None
        profile = await service.get_profile(ACCOUNT, "personal")
        assert profile.connection("spotify") is None

    async def test_a_profile_deleted_during_a_refresh_is_not_recreated(
        self, service: CredentialService, clock: FakeClock
    ) -> None:
        await service.create_profile(ACCOUNT, "personal")
        await connect_oauth(service)
        clock.advance(timedelta(seconds=3600 - 60))

        credential = await service.resolve_http_auth(ACCOUNT, "personal", "spotify")
        await service.delete_profile(ACCOUNT, "personal")

        with pytest.raises(ConnectionNotFoundError):
            await credential.headers()

        with pytest.raises(ProfileNotFoundError):
            await service.get_profile(ACCOUNT, "personal")

    async def test_a_profile_deleted_during_the_code_exchange_is_not_recreated(
        self, service: CredentialService
    ) -> None:
        # The same window on the other path: begin_authorization reads the profile, the
        # person completes consent at the provider, and the profile is deleted before the
        # callback lands. Caught by the state check here.
        await service.create_profile(ACCOUNT, "personal")
        state = await begin(service)
        await service.delete_profile(ACCOUNT, "personal")

        with pytest.raises(InvalidOAuthStateError):
            await service.complete_authorization(state=state, code="the-code")

        with pytest.raises(ProfileNotFoundError):
            await service.get_profile(ACCOUNT, "personal")

    async def test_a_profile_deleted_during_the_token_call_is_not_recreated(
        self, service: CredentialService, endpoint: FakeTokenEndpoint
    ) -> None:
        # And the narrower window the state check cannot cover: the profile is still
        # there when the state is redeemed, and gone by the time the provider answers.
        # Without the re-read in _store_oauth_secret, the exchange would recreate both
        # the profile record and its vault file.
        await service.create_profile(ACCOUNT, "personal")
        state = await begin(service)

        async def delete_midway() -> None:
            await service.delete_profile(ACCOUNT, "personal")

        endpoint.during_call = delete_midway

        with pytest.raises(ConnectionNotFoundError):
            await service.complete_authorization(state=state, code="the-code")

        assert await service._secrets.get(ACCOUNT, "personal", "spotify") is None
