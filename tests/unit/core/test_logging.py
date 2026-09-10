"""Structured logging, and the processor that keeps secrets out of it.

A credential vault that logs credentials has moved the secret rather than protected it:
log records are copied to aggregators, shipped off the box, and read by whoever is
debugging at the time. The redaction processor is the mechanism, and these are the
tests that prove it does something.
"""

from __future__ import annotations

import json

import pytest
import structlog

from keyring_api.core.config import LogFormat
from keyring_api.core.context import bind_account_id, bind_request_id
from keyring_api.core.logging import (
    REDACTED,
    add_account_id,
    add_request_id,
    configure_logging,
    get_logger,
    redact_secrets,
)


def render(event_dict: dict[str, object]) -> dict[str, object]:
    """Run one event dict through the redaction processor."""
    return dict(redact_secrets(None, "info", event_dict))


class TestRedaction:
    @pytest.mark.parametrize(
        "field",
        [
            "password",
            "new_password",
            "current_password",
            "token",
            "session_token",
            "refresh_token",
            "access_token",
            "api_key",
            "client_secret",
            "master_key",
            "totp_seed",
            "authorization",
            "cookie",
            "credential",
        ],
    )
    def test_a_sensitive_field_never_survives_to_the_record(self, field: str) -> None:
        assert render({field: "hunter2"})[field] == REDACTED

    def test_matching_is_case_insensitive(self) -> None:
        # Header names arrive capitalised; a case-sensitive rule would miss them.
        assert render({"Authorization": "Bearer abc"})["Authorization"] == REDACTED

    def test_ordinary_fields_are_left_alone(self) -> None:
        # Redacting everything would be safe and useless. A record has to stay readable.
        assert render({"account_id": "acct_1", "event": "login_failed"}) == {
            "account_id": "acct_1",
            "event": "login_failed",
        }

    def test_nesting_does_not_smuggle_a_secret_past_the_processor(self) -> None:
        # Credentials arrive as structures far more often than as top-level strings.
        redacted = render({"connection": {"service": "spotify", "refresh_token": "abc"}})

        assert redacted["connection"] == {"service": "spotify", "refresh_token": REDACTED}

    def test_secrets_inside_a_list_are_redacted_too(self) -> None:
        redacted = render({"connections": [{"api_key": "abc"}, {"service": "tmdb"}]})

        assert redacted["connections"] == [{"api_key": REDACTED}, {"service": "tmdb"}]

    def test_a_non_string_secret_is_replaced_rather_than_stringified(self) -> None:
        # Otherwise `password=None` reveals that the field was absent, and
        # `token=["a", "b"]` leaks both entries through repr.
        assert render({"password": ["a", "b"]})["password"] == REDACTED

    def test_recursion_stops_at_a_sane_depth(self) -> None:
        # A structure deep enough to blow the stack is not a reason to crash the logger;
        # anything past the limit is dropped wholesale, which fails closed.
        deep: dict[str, object] = {"password": "leak"}
        for _ in range(12):
            deep = {"nested": deep}

        assert REDACTED in json.dumps(render(deep))
        assert "leak" not in json.dumps(render(deep))


class TestContextProcessors:
    def test_the_request_id_is_attached_when_one_is_bound(self) -> None:
        with bind_request_id("req-1"):
            assert add_request_id(None, "info", {})["request_id"] == "req-1"

    def test_the_request_id_is_absent_rather_than_null_outside_a_request(self) -> None:
        # Absent rather than present-and-null, so a log query can filter on existence.
        assert "request_id" not in add_request_id(None, "info", {})

    def test_the_account_id_is_attached_when_one_is_bound(self) -> None:
        with bind_account_id("acct_1"):
            assert add_account_id(None, "info", {})["account_id"] == "acct_1"

    def test_the_account_id_is_absent_on_an_anonymous_request(self) -> None:
        assert "account_id" not in add_account_id(None, "info", {})


class TestConfiguration:
    @pytest.mark.parametrize("log_format", list(LogFormat))
    def test_every_format_configures_without_error(self, log_format: LogFormat) -> None:
        configure_logging(level="INFO", log_format=log_format)

        assert structlog.is_configured()

    def test_a_logger_carries_the_name_it_was_asked_for(self) -> None:
        configure_logging(level="INFO", log_format=LogFormat.JSON)

        bound = get_logger("keyring_api.test")._context

        assert bound["logger"] == "keyring_api.test"

    def test_the_configured_pipeline_redacts_end_to_end(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The unit tests above prove the processor works; this proves it is actually
        # installed in the pipeline the service logs through.
        configure_logging(level="INFO", log_format=LogFormat.JSON)

        get_logger("test").info("login_attempted", password="hunter2")

        record = json.loads(capsys.readouterr().out)
        assert record["password"] == REDACTED
