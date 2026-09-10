"""Profile and connection rules."""

from __future__ import annotations

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from keyring_api.domain.errors import InvalidProfileNameError
from keyring_api.domain.profiles import (
    Connection,
    ConnectionStatus,
    CredentialKind,
    Profile,
    new_profile_id,
    normalize_profile_name,
    normalize_service_name,
)
from tests.fakes.clock import EPOCH


def make_connection(service: str = "spotify", **overrides: object) -> Connection:
    defaults: dict[str, object] = {
        "service": service,
        "kind": CredentialKind.OAUTH2_AUTHORIZATION_CODE,
        "status": ConnectionStatus.ACTIVE,
        "created_at": EPOCH,
        "updated_at": EPOCH,
    }
    return Connection(**{**defaults, **overrides})  # type: ignore[arg-type]


def make_profile(**overrides: object) -> Profile:
    defaults: dict[str, object] = {
        "profile_id": new_profile_id(),
        "account_id": "acct_1",
        "name": "personal",
        "created_at": EPOCH,
        "updated_at": EPOCH,
    }
    return Profile(**{**defaults, **overrides})  # type: ignore[arg-type]


class TestNames:
    def test_a_name_is_lowercased(self) -> None:
        # Otherwise "Personal" and "personal" become two profiles a person then has to
        # tell apart in a list.
        assert normalize_profile_name("Personal") == "personal"

    def test_surrounding_whitespace_is_removed(self) -> None:
        assert normalize_profile_name("  personal  ") == "personal"

    @pytest.mark.parametrize("name", ["work-laptop", "family.shared", "a1", "x_y"])
    def test_ordinary_names_are_accepted(self, name: str) -> None:
        assert normalize_profile_name(name) == name

    @pytest.mark.parametrize(
        "name",
        ["", "   ", "..", ".", "../etc", "a/b", "a\\b", "-leading", "trailing-", "with space"],
    )
    def test_a_name_that_could_not_be_a_path_segment_is_refused(self, name: str) -> None:
        # These become directory names in the secret store. That store validates them
        # again -- two layers that would each have to fail for a traversal to happen.
        with pytest.raises(InvalidProfileNameError):
            normalize_profile_name(name)

    def test_an_over_long_name_is_refused(self) -> None:
        with pytest.raises(InvalidProfileNameError, match="at most"):
            normalize_profile_name("a" * 65)

    def test_service_names_follow_the_same_rules(self) -> None:
        assert normalize_service_name("Spotify") == "spotify"

        with pytest.raises(InvalidProfileNameError):
            normalize_service_name("../secrets")

    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=30))
    def test_normalization_is_idempotent(self, name: str) -> None:
        once = normalize_profile_name(name)

        assert normalize_profile_name(once) == once


class TestProfileIds:
    def test_ids_are_unique_and_recognisable(self) -> None:
        assert new_profile_id() != new_profile_id()
        assert new_profile_id().startswith("prof_")


class TestConnections:
    def test_a_connection_can_be_found_by_service(self) -> None:
        profile = make_profile().with_connection(make_connection(), now=EPOCH)

        connection = profile.connection("spotify")
        assert connection is not None
        assert connection.service == "spotify"

    def test_an_absent_service_returns_nothing(self) -> None:
        assert make_profile().connection("spotify") is None

    def test_adding_a_second_connection_keeps_the_first(self) -> None:
        profile = make_profile().with_connection(make_connection("spotify"), now=EPOCH)

        profile = profile.with_connection(make_connection("tmdb"), now=EPOCH)

        assert {item.service for item in profile.connections} == {"spotify", "tmdb"}

    def test_re_authorising_a_service_replaces_rather_than_duplicates(self) -> None:
        # Two connections to the same service would mean two stored credentials and no
        # rule for which one is used.
        profile = make_profile().with_connection(make_connection(), now=EPOCH)

        profile = profile.with_connection(
            make_connection(status=ConnectionStatus.EXPIRED), now=EPOCH
        )

        assert len(profile.connections) == 1
        connection = profile.connection("spotify")
        assert connection is not None
        assert connection.status is ConnectionStatus.EXPIRED

    def test_removing_a_connection_leaves_the_others(self) -> None:
        profile = make_profile()
        profile = profile.with_connection(make_connection("spotify"), now=EPOCH)
        profile = profile.with_connection(make_connection("tmdb"), now=EPOCH)

        profile = profile.without_connection("spotify", now=EPOCH)

        assert {item.service for item in profile.connections} == {"tmdb"}

    def test_removing_an_absent_connection_is_not_an_error(self) -> None:
        assert make_profile().without_connection("spotify", now=EPOCH).connections == ()


class TestRefreshTiming:
    def test_a_credential_with_no_expiry_never_needs_refreshing(self) -> None:
        connection = make_connection(kind=CredentialKind.API_KEY, expires_at=None)

        assert not connection.needs_refresh(now=EPOCH, margin_seconds=120)

    def test_a_credential_is_refreshed_before_it_expires_not_after_it_fails(self) -> None:
        # Refreshing on a 401 means one request has already failed and the caller has to
        # know to retry. The margin makes that the provider's problem, not ours.
        connection = make_connection(expires_at=EPOCH + timedelta(seconds=100))

        assert connection.needs_refresh(now=EPOCH, margin_seconds=120)

    def test_a_credential_outside_the_margin_is_left_alone(self) -> None:
        connection = make_connection(expires_at=EPOCH + timedelta(seconds=1000))

        assert not connection.needs_refresh(now=EPOCH, margin_seconds=120)


class TestUsability:
    def test_an_active_connection_with_no_expiry_is_usable(self) -> None:
        assert make_connection(kind=CredentialKind.API_KEY).is_usable(now=EPOCH)

    @pytest.mark.parametrize(
        "status", [ConnectionStatus.PENDING, ConnectionStatus.REVOKED, ConnectionStatus.EXPIRED]
    )
    def test_a_connection_that_is_not_active_is_not_usable(self, status: ConnectionStatus) -> None:
        assert not make_connection(status=status).is_usable(now=EPOCH)

    def test_an_expired_oauth_token_is_still_usable_because_it_can_be_refreshed(self) -> None:
        connection = make_connection(expires_at=EPOCH)

        assert connection.is_usable(now=EPOCH + timedelta(hours=1))

    def test_an_expired_password_is_not_usable_because_nothing_can_renew_it(self) -> None:
        # Only the person can change their password at the service. An expired one is
        # finished, whereas an expired OAuth token is merely due.
        connection = make_connection(kind=CredentialKind.PASSWORD, expires_at=EPOCH)

        assert not connection.is_usable(now=EPOCH + timedelta(hours=1))

    def test_only_the_oauth_kind_refreshes_itself(self) -> None:
        assert CredentialKind.OAUTH2_AUTHORIZATION_CODE.can_refresh
        assert not CredentialKind.API_KEY.can_refresh
        assert not CredentialKind.PASSWORD.can_refresh


class TestFailureRecording:
    def test_recording_an_error_marks_the_connection_expired(self) -> None:
        connection = make_connection().with_error("provider returned 400", now=EPOCH)

        assert connection.status is ConnectionStatus.EXPIRED
        assert connection.last_error == "provider returned 400"

    def test_recording_an_error_does_not_discard_the_stored_credential(self) -> None:
        # A transient provider outage must not delete a refresh token that will work
        # again in five minutes. This type does not touch the secret store at all --
        # which is the point.
        connection = make_connection()

        failed = connection.with_error("timeout", now=EPOCH)

        assert failed.service == connection.service
        assert failed.kind == connection.kind


class TestTotpFlagging:
    def test_a_connection_does_not_store_a_totp_seed_by_default(self) -> None:
        # Opt-in, never inferred. Storing a seed beside the password collapses that
        # person's second factor into the same place as their first, so it has to be a
        # decision somebody made rather than a side effect of sending a field.
        assert not make_connection().stores_totp_seed
