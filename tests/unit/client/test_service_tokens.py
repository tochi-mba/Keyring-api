"""Which service a static token belongs to, and the configurations refused before startup."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from keyring_client import (
    BAD_SERVICE,
    MIN_SERVICE_TOKEN_CHARS,
    AuthenticationError,
    ServiceAuthenticator,
    check_service_token,
)

if TYPE_CHECKING:
    from tests.unit.client.conftest import RecordingLogger

DOWNSTREAM = "downstream-tool-service-token-0123456789abcdef"
SPOTIFY = "spotify-api-service-token-0123456789abcdef"


@pytest.fixture
def services(recorder: RecordingLogger) -> ServiceAuthenticator:
    return ServiceAuthenticator(
        {"downstream-tool": DOWNSTREAM, "spotify-api": SPOTIFY}, logger=recorder
    )


class TestCheckingATokenAtStartup:
    def test_a_long_enough_token_is_accepted_as_it_is(self) -> None:
        assert check_service_token(DOWNSTREAM) == DOWNSTREAM

    def test_a_placeholder_is_refused(self) -> None:
        # A deployment that pasted "change-me" looks exactly like a working one until the
        # first internal call, unless it is refused here.
        with pytest.raises(ValueError, match=f"at least {MIN_SERVICE_TOKEN_CHARS}"):
            check_service_token("change-me")

    def test_surrounding_whitespace_is_refused(self) -> None:
        # A token copied with its newline matches nothing, and every call is a 401.
        with pytest.raises(ValueError, match="whitespace"):
            check_service_token(DOWNSTREAM + "\n")


class TestBuildingTheAuthenticator:
    def test_a_short_token_is_refused_when_the_authenticator_is_built(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            ServiceAuthenticator({"downstream-tool": "short"})

    def test_two_services_sharing_a_token_is_refused(self) -> None:
        # Whichever name matched first would decide the grant, so the weaker grant would be
        # reachable with the other's token.
        with pytest.raises(ValueError, match="share a service token"):
            ServiceAuthenticator({"downstream-tool": DOWNSTREAM, "spotify-api": DOWNSTREAM})

    def test_the_configured_names_are_listed_sorted_and_without_their_tokens(
        self, services: ServiceAuthenticator
    ) -> None:
        assert services.configured == ("downstream-tool", "spotify-api")

    def test_a_default_logger_is_used_when_none_is_given(self) -> None:
        plain = ServiceAuthenticator({"downstream-tool": DOWNSTREAM})

        with pytest.raises(AuthenticationError):
            plain.identify("nope")


class TestIdentifying:
    def test_each_token_identifies_its_own_service(self, services: ServiceAuthenticator) -> None:
        assert services.identify(DOWNSTREAM) == "downstream-tool"
        assert services.identify(SPOTIFY) == "spotify-api"

    @pytest.mark.parametrize("presented", [None, "", "not-a-configured-token", "ünïcödé"])
    def test_anything_else_is_refused_in_one_set_of_words(
        self, services: ServiceAuthenticator, presented: str | None
    ) -> None:
        # Non-ASCII included: compare_digest raises on a non-ASCII str, which would be a 500
        # from anybody who can send a header.
        with pytest.raises(AuthenticationError) as refusal:
            services.identify(presented)

        assert str(refusal.value) == BAD_SERVICE

    def test_the_refusal_logs_why_and_never_the_token(
        self, services: ServiceAuthenticator, recorder: RecordingLogger
    ) -> None:
        with pytest.raises(AuthenticationError):
            services.identify("a-token-somebody-guessed-0123456789")

        assert recorder.events() == ["service_token_rejected"]
        assert "a-token-somebody-guessed" not in recorder.rendered()


class TestTheAuthorizationHeader:
    def test_a_bearer_header_identifies_its_service(self, services: ServiceAuthenticator) -> None:
        assert services.identify_authorization(f"Bearer {DOWNSTREAM}") == "downstream-tool"

    @pytest.mark.parametrize(
        "header", [None, DOWNSTREAM, f"Basic {DOWNSTREAM}", f"bearer {DOWNSTREAM}"]
    )
    def test_a_missing_header_or_another_scheme_is_refused(
        self, services: ServiceAuthenticator, header: str | None
    ) -> None:
        with pytest.raises(AuthenticationError) as refusal:
            services.identify_authorization(header)

        assert str(refusal.value) == BAD_SERVICE
