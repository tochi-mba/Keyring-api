"""The two small pieces every other module leans on: where diagnostics go, and what time it is."""

from __future__ import annotations

import logging
from datetime import UTC

import pytest

from keyring_client import Clock, Logger, StdlibLogger, SystemClock
from keyring_client._log import render


class TestTheFallbackLogger:
    def test_fields_are_rendered_into_the_message_in_a_stable_order(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        logger: Logger = StdlibLogger("keyring_client.test")

        with caplog.at_level(logging.INFO, logger="keyring_client.test"):
            logger.info("token_rejected", reason="decode", kid="abc")
            logger.warning("jwks_fetch_failed")

        assert [record.getMessage() for record in caplog.records] == [
            "token_rejected kid=abc reason=decode",
            "jwks_fetch_failed",
        ]
        assert [record.levelno for record in caplog.records] == [logging.INFO, logging.WARNING]

    def test_an_exception_is_logged_with_its_traceback(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        logger = StdlibLogger("keyring_client.test")

        with caplog.at_level(logging.ERROR, logger="keyring_client.test"):
            message = "boom"
            try:
                raise RuntimeError(message)  # noqa: TRY301 -- a traceback needs a raise
            except RuntimeError:
                logger.exception("jwks_health_check_failed", attempt=1)

        [record] = caplog.records
        assert record.getMessage() == "jwks_health_check_failed attempt=1"
        assert record.exc_info is not None

    def test_an_event_with_no_fields_renders_as_itself(self) -> None:
        assert render("jwks_fetched", {}) == "jwks_fetched"


class TestTheSystemClock:
    def test_it_is_timezone_aware_and_monotonic(self) -> None:
        clock = SystemClock()
        assert isinstance(clock, Clock)

        first = clock.monotonic()
        assert clock.now().tzinfo is UTC
        assert clock.monotonic() >= first
