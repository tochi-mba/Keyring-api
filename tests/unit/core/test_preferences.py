"""One person's choices, and what keyring does with them -- and without them.

Every test that reads settings-api here uses its shared fake, including with it switched
off, because the outage is the case most services forget and the one their users notice.
"""

from __future__ import annotations

from typing import Any

import pytest
from structlog.testing import capture_logs

from keyring_api.core.config import LogFormat, Settings
from keyring_api.core.logging import configure_logging
from keyring_api.core.preferences import (
    MAX_SESSIONS_MAX,
    NAMESPACE,
    NOT_GUESSED,
    REFUSED,
    SECONDS_PER_DAY,
    SESSION_ABSOLUTE_TTL_DAYS_MAX,
    SESSION_TTL_DAYS_MAX,
    SETTINGS_TOKEN_TTL_SECONDS,
    DeploymentPreferences,
    Preferences,
    SettingsApiPreferences,
    build_preference_source,
    deployment_preferences,
)
from keyring_api.domain.errors import PreferencesUnavailableError
from settings_client import Fallback, OnUnavailable
from settings_client.testing import FakeSettingsClient

ACCOUNT_ID = "acct_person"
SETTINGS_API_TOKEN = "settings-api-token-for-keyring-tests-01"
SETTINGS_API_URL = "http://127.0.0.1:8003"
MINTED_TOKEN = "minted-settings-round-trip-token"

FALLBACKS = {
    "session_ttl_days": Fallback(default=14, on_unavailable=OnUnavailable.USE_DEFAULT),
    "session_absolute_ttl_days": Fallback(default=90, on_unavailable=OnUnavailable.USE_DEFAULT),
    "max_sessions": Fallback(default=20, on_unavailable=OnUnavailable.USE_DEFAULT),
}


class RecordingIssuer:
    """Captures the short-lived token a settings-api round trip is minted with."""

    def __init__(self, token: str = MINTED_TOKEN) -> None:
        self.token = token
        self.calls: list[dict[str, object]] = []

    def issue(self, *, account_id: str, audience: str, ttl_seconds: float) -> str:
        self.calls.append(
            {"account_id": account_id, "audience": audience, "ttl_seconds": ttl_seconds}
        )
        return self.token


@pytest.fixture(autouse=True)
def _logs() -> None:
    configure_logging(level="INFO", log_format=LogFormat.CONSOLE)


def settings_with(**overrides: Any) -> Settings:
    return Settings(**{"_env_file": None, **overrides})


def reading(
    client: FakeSettingsClient, issuer: RecordingIssuer | None = None, **overrides: Any
) -> SettingsApiPreferences:
    return SettingsApiPreferences(
        client=client, settings=settings_with(**overrides), issuer=issuer or RecordingIssuer()
    )


class TestWithoutSettingsApi:
    def test_the_configuration_is_what_everybody_gets(self) -> None:
        settings = settings_with(
            session_ttl_seconds=600,
            session_absolute_ttl_seconds=3_600,
            max_sessions_per_account=2,
        )

        assert deployment_preferences(settings) == Preferences(
            session_ttl_seconds=600,
            session_absolute_ttl_seconds=3_600,
            max_sessions=2,
        )

    async def test_nobody_is_asked_when_settings_api_is_not_configured(self) -> None:
        settings = settings_with()
        source = build_preference_source(settings)

        assert isinstance(source, DeploymentPreferences)
        assert await source.for_account(ACCOUNT_ID) == deployment_preferences(settings)
        await source.aclose()

    async def test_a_configured_settings_api_is_asked_per_person(self) -> None:
        source = build_preference_source(
            settings_with(
                settings_api_base_url=SETTINGS_API_URL,
                settings_api_token=SETTINGS_API_TOKEN,
            ),
            issuer=RecordingIssuer(),
        )

        assert isinstance(source, SettingsApiPreferences)
        await source.aclose()

    async def test_a_substituted_client_is_the_one_asked(self) -> None:
        client = FakeSettingsClient()
        issuer = RecordingIssuer()

        await build_preference_source(settings_with(), client=client, issuer=issuer).for_account(
            ACCOUNT_ID
        )

        assert client.resolves == 1
        assert issuer.calls == [
            {
                "account_id": ACCOUNT_ID,
                "audience": NAMESPACE,
                "ttl_seconds": SETTINGS_TOKEN_TTL_SECONDS,
            }
        ]

    def test_settings_api_in_use_without_an_issuer_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError, match="issuer"):
            build_preference_source(settings_with(), client=FakeSettingsClient())

        with pytest.raises(ValueError, match="issuer"):
            build_preference_source(
                settings_with(
                    settings_api_base_url=SETTINGS_API_URL,
                    settings_api_token=SETTINGS_API_TOKEN,
                )
            )


class TestAPersonsChoices:
    async def test_days_become_the_seconds_a_login_is_stamped_with(self) -> None:
        client = FakeSettingsClient()
        client.seed(
            NAMESPACE,
            {"session_ttl_days": 3, "session_absolute_ttl_days": 30, "max_sessions": 4},
        )

        preferences = await reading(client).for_account(ACCOUNT_ID)

        assert preferences == Preferences(
            session_ttl_seconds=3 * SECONDS_PER_DAY,
            session_absolute_ttl_seconds=30 * SECONDS_PER_DAY,
            max_sessions=4,
        )

    async def test_a_ceiling_can_be_narrowed_and_never_raised(self) -> None:
        client = FakeSettingsClient()
        client.seed(
            NAMESPACE,
            {"session_ttl_days": 90, "session_absolute_ttl_days": 365, "max_sessions": 20},
        )

        preferences = await reading(
            client,
            session_ttl_seconds=2 * SECONDS_PER_DAY,
            session_absolute_ttl_seconds=10 * SECONDS_PER_DAY,
            max_sessions_per_account=5,
        ).for_account(ACCOUNT_ID)

        assert preferences.session_ttl_seconds == 2 * SECONDS_PER_DAY
        assert preferences.session_absolute_ttl_seconds == 10 * SECONDS_PER_DAY
        assert preferences.max_sessions == 5

    async def test_catalogue_bounds_cap_a_value_settings_api_should_not_have_stored(self) -> None:
        client = FakeSettingsClient()
        client.seed(
            NAMESPACE,
            {"session_ttl_days": 200, "session_absolute_ttl_days": 900, "max_sessions": 50},
        )

        preferences = await reading(
            client,
            session_ttl_seconds=400 * SECONDS_PER_DAY,
            session_absolute_ttl_seconds=900 * SECONDS_PER_DAY,
            max_sessions_per_account=20,
        ).for_account(ACCOUNT_ID)

        assert preferences.session_ttl_seconds == SESSION_TTL_DAYS_MAX * SECONDS_PER_DAY
        assert (
            preferences.session_absolute_ttl_seconds
            == SESSION_ABSOLUTE_TTL_DAYS_MAX * SECONDS_PER_DAY
        )
        assert preferences.max_sessions == MAX_SESSIONS_MAX

    async def test_an_absolute_ceiling_below_idle_becomes_idle(self) -> None:
        # keyring refuses this at startup for the deployment. A person can still set the
        # two independently; failing login over it would make settings-api a hard
        # dependency of authentication.
        client = FakeSettingsClient()
        client.seed(
            NAMESPACE,
            {"session_ttl_days": 14, "session_absolute_ttl_days": 1, "max_sessions": 20},
        )

        preferences = await reading(client).for_account(ACCOUNT_ID)

        assert preferences.session_ttl_seconds == 14 * SECONDS_PER_DAY
        assert preferences.session_absolute_ttl_seconds == preferences.session_ttl_seconds


class TestWhenSettingsApiCannotBeReached:
    async def test_never_having_answered_leaves_the_configuration(self) -> None:
        client = FakeSettingsClient()
        client.unavailable = True
        settings = settings_with()

        preferences = await SettingsApiPreferences(
            client=client, settings=settings, issuer=RecordingIssuer()
        ).for_account(ACCOUNT_ID)

        assert preferences == deployment_preferences(settings)

    async def test_a_person_who_chose_one_day_gets_fourteen_during_an_outage(self) -> None:
        client = FakeSettingsClient()
        client.seed(NAMESPACE, {"session_ttl_days": 1})
        client.unavailable = True
        settings = settings_with()

        preferences = await SettingsApiPreferences(
            client=client, settings=settings, issuer=RecordingIssuer()
        ).for_account(ACCOUNT_ID)

        assert preferences.session_ttl_seconds == 14 * SECONDS_PER_DAY
        assert preferences.session_absolute_ttl_seconds == 90 * SECONDS_PER_DAY
        assert preferences.max_sessions == 20

    async def test_known_fallbacks_are_used_inside_the_deployment_ceilings(self) -> None:
        client = FakeSettingsClient(fallbacks={NAMESPACE: FALLBACKS})
        client.unavailable = True

        preferences = await reading(
            client,
            session_ttl_seconds=7 * SECONDS_PER_DAY,
            session_absolute_ttl_seconds=30 * SECONDS_PER_DAY,
            max_sessions_per_account=5,
        ).for_account(ACCOUNT_ID)

        assert preferences.session_ttl_seconds == 7 * SECONDS_PER_DAY
        assert preferences.session_absolute_ttl_seconds == 30 * SECONDS_PER_DAY
        assert preferences.max_sessions == 5

    async def test_a_setting_that_refuses_fails_rather_than_being_guessed(self) -> None:
        refusing = {"session_ttl_days": Fallback(default=14, on_unavailable=OnUnavailable.REFUSE)}
        client = FakeSettingsClient(fallbacks={NAMESPACE: refusing})
        client.unavailable = True

        with pytest.raises(PreferencesUnavailableError, match=NOT_GUESSED):
            await reading(client).for_account(ACCOUNT_ID)

    async def test_an_outage_logs_one_line_and_never_a_url_or_token(self) -> None:
        client = FakeSettingsClient()
        client.unavailable = True

        with capture_logs() as logs:
            await reading(client).for_account(ACCOUNT_ID)

        assert [entry["event"] for entry in logs] == ["settings_unavailable"]
        assert all(SETTINGS_API_URL not in str(entry) for entry in logs)
        assert all(MINTED_TOKEN not in str(entry) for entry in logs)
        assert all(SETTINGS_API_TOKEN not in str(entry) for entry in logs)


class TestWhenSettingsApiRefusesThisService:
    @pytest.mark.parametrize("status_code", [401, 403])
    async def test_the_refusal_is_not_hidden_behind_defaults(self, status_code: int) -> None:
        client = FakeSettingsClient()
        client.rejects[NAMESPACE] = (status_code, "keyring-api was not granted keyring")

        with pytest.raises(PreferencesUnavailableError) as caught:
            await reading(client).for_account(ACCOUNT_ID)

        assert str(caught.value) == REFUSED
        assert "granted" not in str(caught.value)
        assert "keyring-api" not in str(caught.value)

    async def test_the_refusal_logs_the_status_and_never_the_detail(self) -> None:
        client = FakeSettingsClient()
        client.rejects[NAMESPACE] = (403, "keyring-api was not granted keyring")

        with capture_logs() as logs, pytest.raises(PreferencesUnavailableError):
            await reading(client).for_account(ACCOUNT_ID)

        assert any(entry.get("status_code") == 403 for entry in logs)
        assert all("granted" not in str(entry) for entry in logs)
        assert all(MINTED_TOKEN not in str(entry) for entry in logs)
        assert all(SETTINGS_API_URL not in str(entry) for entry in logs)


class TestValuesThatCannotBeUsed:
    @pytest.mark.parametrize("value", [True, "3", 0, -1, None, 3.0])
    async def test_an_unusable_idle_lifetime_leaves_the_configuration(self, value: Any) -> None:
        client = FakeSettingsClient()
        client.seed(NAMESPACE, {"session_ttl_days": value})

        preferences = await reading(client, session_ttl_seconds=600).for_account(ACCOUNT_ID)

        assert preferences.session_ttl_seconds == 600

    @pytest.mark.parametrize("value", [True, "3", 0, -1, None, 3.0])
    async def test_an_unusable_absolute_lifetime_leaves_the_configuration(self, value: Any) -> None:
        client = FakeSettingsClient()
        client.seed(NAMESPACE, {"session_absolute_ttl_days": value})

        preferences = await reading(
            client, session_ttl_seconds=600, session_absolute_ttl_seconds=3_600
        ).for_account(ACCOUNT_ID)

        assert preferences.session_absolute_ttl_seconds == 3_600

    @pytest.mark.parametrize("value", [True, "3", 0, -1, None, 3.0])
    async def test_an_unusable_session_cap_leaves_the_configuration(self, value: Any) -> None:
        client = FakeSettingsClient()
        client.seed(NAMESPACE, {"max_sessions": value})

        preferences = await reading(client, max_sessions_per_account=7).for_account(ACCOUNT_ID)

        assert preferences.max_sessions == 7

    async def test_a_missing_setting_leaves_the_configuration(self) -> None:
        client = FakeSettingsClient()
        client.seed(NAMESPACE, {})
        settings = settings_with()

        preferences = await SettingsApiPreferences(
            client=client, settings=settings, issuer=RecordingIssuer()
        ).for_account(ACCOUNT_ID)

        assert preferences == deployment_preferences(settings)

    async def test_the_key_is_logged_and_the_value_never_is(self) -> None:
        client = FakeSettingsClient()
        client.seed(NAMESPACE, {"session_ttl_days": "a-value-nobody-should-read"})

        with capture_logs() as logs:
            await reading(client).for_account(ACCOUNT_ID)

        assert any(entry.get("key") == "session_ttl_days" for entry in logs)
        assert all("a-value-nobody-should-read" not in str(entry) for entry in logs)
        assert all(MINTED_TOKEN not in str(entry) for entry in logs)


class TestSecretsStayOutOfRepr:
    async def test_the_round_trip_token_is_absent_from_repr(self) -> None:
        client = FakeSettingsClient()
        issuer = RecordingIssuer()
        source = SettingsApiPreferences(client=client, settings=settings_with(), issuer=issuer)

        rendered = repr(source)

        assert MINTED_TOKEN not in rendered
        assert SETTINGS_API_TOKEN not in rendered
        assert SETTINGS_API_URL not in rendered
        await source.aclose()
