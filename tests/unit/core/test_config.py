"""Configuration: env precedence, validation, and the settings that must not be guessed."""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from keyring_api.core.config import (
    ENV_PREFIX,
    MIN_SERVICE_TOKEN_CHARS,
    ConfigurationError,
    LogFormat,
    Settings,
    UnknownSettingError,
    check_for_unknown_env_vars,
    known_env_names,
    load_settings,
)

REPOSITORY = Path(__file__).resolve().parents[3]

DOWNSTREAM_TOKEN = "downstream-tool-service-token-0123456789abcdef"
SPOTIFY_TOKEN = "spotify-api-service-token-0123456789abcdef"


def build(**overrides: Any) -> Settings:
    """Settings built from arguments alone, with no ambient .env or environment."""
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


class TestDefaults:
    def test_it_binds_to_loopback_by_default(self) -> None:
        # This service must sit behind a reverse proxy, so the default must not be a
        # public bind. Someone deploying it should have to say so deliberately.
        assert build().host == "127.0.0.1"

    def test_logs_are_json_by_default(self) -> None:
        assert build().log_format is LogFormat.JSON

    def test_registration_is_invite_only_and_cannot_be_turned_off_by_accident(self) -> None:
        # There is no `allow_open_signup` knob. The absence is the feature: every
        # account is invited by an administrator, which removes open-signup abuse and
        # the account-enumeration surface that comes with a public registration form.
        assert not hasattr(build(), "allow_open_signup")

    def test_the_default_issuer_is_the_one_every_sibling_service_pins_locally(self) -> None:
        # A family started on a laptop must agree about who signed a token without anybody
        # setting anything. The siblings default to keyring's own loopback address.
        assert build().issuer == "http://127.0.0.1:8001"


class TestTheExampleFile:
    def test_every_line_in_env_example_is_a_setting_that_exists(self) -> None:
        # Copying .env.example to .env is the first thing a new engineer does. A line
        # naming a setting that no longer exists turned that into a startup error once,
        # and nothing in the build noticed.
        settings = Settings(_env_file=REPOSITORY / ".env.example")  # type: ignore[call-arg]

        assert settings.port == 8001
        assert settings.issuer == build().issuer


class TestEnvironment:
    def test_a_variable_overrides_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KEYRING_PORT", "9999")

        assert load_settings().port == 9999

    def test_nested_settings_use_a_double_underscore(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KEYRING_ARGON2__TIME_COST", "5")

        assert load_settings().argon2.time_cost == 5

    def test_a_misspelled_variable_is_rejected_rather_than_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # pydantic-settings ignores prefixed variables it does not recognise. Here that
        # is not acceptable: the same typo in KEYRING_MASTER_KEY would start the
        # service with no vault and nothing in the logs saying so.
        monkeypatch.setenv("KEYRING_SESION_TTL_SECONDS", "60")

        with pytest.raises(UnknownSettingError, match="KEYRING_SESION_TTL_SECONDS"):
            load_settings()

    def test_every_unknown_variable_is_named_at_once(self) -> None:
        # One restart per typo is a bad way to fix a deployment.
        with pytest.raises(UnknownSettingError) as caught:
            check_for_unknown_env_vars({"KEYRING_A": "1", "KEYRING_B": "2", "PATH": "/"})

        assert "KEYRING_A" in str(caught.value)
        assert "KEYRING_B" in str(caught.value)

    def test_variables_outside_the_prefix_are_none_of_our_business(self) -> None:
        check_for_unknown_env_vars({"PATH": "/usr/bin", "HOME": "/root"})

    def test_nested_names_are_recognised_as_known(self) -> None:
        known = known_env_names()

        assert "KEYRING_ARGON2__TIME_COST" in known
        assert "KEYRING_RATE_LIMIT__LOGIN_ATTEMPTS" in known
        assert "KEYRING_PORT" in known

    def test_a_rejected_setting_is_reported_without_its_value(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # pydantic renders the input beside each failure, and a startup crash is logged
        # verbatim -- which for the master key would put the vault key in the log.
        monkeypatch.setenv("KEYRING_MASTER_KEY", "not-base64-but-still-secret-material")

        with pytest.raises(ConfigurationError) as caught:
            load_settings()

        assert "master_key" in str(caught.value)
        assert "secret-material" not in str(caught.value)
        assert caught.value.__cause__ is None


class TestMasterKey:
    def test_a_valid_key_decodes_to_thirty_two_bytes(self) -> None:
        raw = bytes(range(32))

        settings = build(master_key=base64.b64encode(raw).decode())

        assert settings.master_key_bytes() == raw

    def test_a_key_of_the_wrong_length_is_rejected_at_startup(self) -> None:
        # AES-256-GCM needs exactly 32 bytes. Finding out at the first write would mean
        # a service that starts, accepts a credential, and then cannot store it.
        with pytest.raises(ValidationError, match="32 bytes"):
            build(master_key=base64.b64encode(b"too short").decode())

    def test_a_key_that_is_not_base64_is_rejected_with_a_usable_message(self) -> None:
        with pytest.raises(ValidationError, match="base64"):
            build(master_key="not base64 at all!!")

    def test_no_key_configured_is_allowed_so_the_service_can_start_degraded(self) -> None:
        # Starting without a key lets /healthy report exactly what is wrong. Refusing to
        # boot would leave an operator with a crash loop and no diagnosis.
        assert build().master_key is None
        assert build().master_key_bytes() is None

    def test_the_key_is_never_rendered_when_settings_are_printed(self) -> None:
        # Settings get logged at startup and dumped into crash reports.
        settings = build(master_key=base64.b64encode(bytes(32)).decode())

        assert "AAAA" not in repr(settings)


class TestServiceTokens:
    def test_long_distinct_tokens_are_accepted(self) -> None:
        settings = build(
            service_tokens={"downstream-tool": DOWNSTREAM_TOKEN, "spotify-api": SPOTIFY_TOKEN}
        )

        assert set(settings.service_tokens) == {"downstream-tool", "spotify-api"}

    @pytest.mark.parametrize(
        "token",
        ["change-me", DOWNSTREAM_TOKEN + "\n", " " + DOWNSTREAM_TOKEN],
        ids=["a-placeholder", "a-pasted-newline", "leading-space"],
    )
    def test_a_token_that_is_short_or_untrimmed_is_refused_at_startup(self, token: str) -> None:
        # A service token is the entire proof that a caller on /v1/internal is a service,
        # and a pasted placeholder looks exactly like a working configuration.
        with pytest.raises(ValidationError, match=f"at least {MIN_SERVICE_TOKEN_CHARS}"):
            build(service_tokens={"downstream-tool": token})

    def test_two_services_sharing_a_token_is_refused(self) -> None:
        # Whichever name matched would decide which audience a user token must carry, so
        # the weaker service could present the stronger one's tokens.
        with pytest.raises(ValidationError, match="share a service token"):
            build(
                service_tokens={
                    "downstream-tool": DOWNSTREAM_TOKEN,
                    "spotify-api": DOWNSTREAM_TOKEN,
                }
            )

    def test_the_minimum_is_the_one_consuming_services_check_against(self) -> None:
        # Keyring refusing a token its consumers would accept, or the reverse, is a
        # deployment that works on one side of the boundary only.
        from keyring_client import MIN_SERVICE_TOKEN_CHARS as CLIENT_MINIMUM

        assert MIN_SERVICE_TOKEN_CHARS == CLIENT_MINIMUM


class TestExchangeAudiences:
    """An audience a service is not configured to mint for is a startup error, not a 403 later."""

    def test_an_allowlist_for_a_configured_service_is_accepted(self) -> None:
        settings = build(
            service_tokens={"downstream-tool": DOWNSTREAM_TOKEN},
            exchange_audiences={"downstream-tool": ("user.home", "user.work")},
        )

        assert settings.exchange_audiences == {"downstream-tool": ("user.home", "user.work")}

    def test_an_allowlist_for_an_unconfigured_service_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="unconfigured service"):
            build(
                service_tokens={"downstream-tool": DOWNSTREAM_TOKEN},
                exchange_audiences={"other-tool": ("user.home",)},
            )

    @pytest.mark.parametrize(
        "audience",
        ["", " user.home", "user.home ", "x" * 129],
        ids=["empty", "leading-space", "trailing-space", "too-long"],
    )
    def test_an_audience_that_is_blank_padded_or_too_long_is_refused(self, audience: str) -> None:
        with pytest.raises(ValidationError, match="nonempty exact names"):
            build(
                service_tokens={"downstream-tool": DOWNSTREAM_TOKEN},
                exchange_audiences={"downstream-tool": (audience,)},
            )


class TestValidation:
    def test_a_session_cannot_outlive_its_own_absolute_ceiling(self) -> None:
        with pytest.raises(ValidationError, match="absolute"):
            build(session_ttl_seconds=100, session_absolute_ttl_seconds=50)

    def test_an_access_token_shorter_than_its_refresh_margin_is_rejected(self) -> None:
        # Otherwise every token issued is already inside the refresh window, and the
        # service refreshes on every single call.
        with pytest.raises(ValidationError, match="refresh margin"):
            build(oauth_refresh_margin_seconds=600, access_token_ttl_seconds=300)

    def test_the_database_path_is_resolved_eagerly(self) -> None:
        # A relative path must not mean two different places before and after a chdir --
        # which for this file would mean silently losing every stored credential.
        assert build(database_path="var/keyring.db").database_path.is_absolute()

    @pytest.mark.parametrize("bad", [0, -1])
    def test_a_non_positive_lifetime_is_rejected(self, bad: int) -> None:
        with pytest.raises(ValidationError):
            build(session_ttl_seconds=bad)

    def test_the_issuer_is_a_url_shaped_string_other_services_can_pin(self) -> None:
        # downstream-tool verifies keyring's tokens by issuer; a bare hostname would not be
        # comparable across the two.
        assert re.match(r"^https?://", build().issuer)


class TestArgon2Parameters:
    def test_memory_must_cover_every_lane(self) -> None:
        # Argon2 needs 8 KiB per lane. Raising parallelism without raising memory
        # otherwise fails at the first login with a message from inside the hashing
        # library rather than at startup with one naming the fix.
        with pytest.raises(ValidationError, match="per lane"):
            build(argon2={"memory_cost_kib": 16, "parallelism": 4})

    def test_the_defaults_satisfy_their_own_constraint(self) -> None:
        assert build().argon2.memory_cost_kib >= 8 * build().argon2.parallelism


SETTINGS_API_TOKEN = "settings-api-token-for-keyring-tests-01"
SETTINGS_API_URL = "http://127.0.0.1:8003"


class TestSettingsApi:
    """Per-person settings are off unless configured, and configured whole or not at all."""

    def test_it_is_off_unless_configured(self) -> None:
        assert build().settings_api is None

    def test_a_base_url_and_a_token_together_turn_it_on(self) -> None:
        settings = build(
            settings_api_base_url=SETTINGS_API_URL, settings_api_token=SETTINGS_API_TOKEN
        )

        assert settings.settings_api is not None
        base_url, token = settings.settings_api
        assert base_url == SETTINGS_API_URL
        assert token.get_secret_value() == SETTINGS_API_TOKEN

    @pytest.mark.parametrize(
        "half",
        [
            {"settings_api_base_url": SETTINGS_API_URL},
            {"settings_api_token": SETTINGS_API_TOKEN},
        ],
    )
    def test_half_a_configuration_refuses_to_start(self, half: dict[str, str]) -> None:
        with pytest.raises(ValidationError, match="set together"):
            build(**half)

    def test_a_blank_base_url_means_off(self) -> None:
        assert build(settings_api_base_url="").settings_api_base_url is None

    def test_a_blank_token_means_off(self) -> None:
        assert build(settings_api_token="").settings_api_token is None
        assert build(settings_api_token=SecretStr("")).settings_api_token is None

    def test_a_short_token_is_refused_without_being_echoed(self) -> None:
        with pytest.raises(ValidationError) as caught:
            build(settings_api_base_url=SETTINGS_API_URL, settings_api_token="short-token")

        messages = [error["msg"] for error in caught.value.errors()]
        assert messages
        assert all("short-token" not in message for message in messages)
        assert any("32" in message for message in messages)

    def test_a_token_with_surrounding_whitespace_is_refused_without_being_echoed(self) -> None:
        padded = f" {SETTINGS_API_TOKEN}"
        with pytest.raises(ValidationError) as caught:
            build(settings_api_base_url=SETTINGS_API_URL, settings_api_token=padded)

        messages = [error["msg"] for error in caught.value.errors()]
        assert messages
        assert all(SETTINGS_API_TOKEN not in message for message in messages)
        assert all(padded not in message for message in messages)

    def test_the_token_does_not_render_itself(self) -> None:
        settings = build(
            settings_api_base_url=SETTINGS_API_URL, settings_api_token=SETTINGS_API_TOKEN
        )

        assert SETTINGS_API_TOKEN not in repr(settings)
        assert SETTINGS_API_TOKEN not in str(settings)

    def test_the_prefixed_names_are_recognised(self) -> None:
        names = known_env_names()

        assert f"{ENV_PREFIX}SETTINGS_API_BASE_URL" in names
        assert f"{ENV_PREFIX}SETTINGS_API_TOKEN" in names
