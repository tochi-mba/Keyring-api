"""The real clock is thin, but it is the thing every expiry in this service trusts."""

from __future__ import annotations

from datetime import UTC, timedelta

from keyring_api.core.clock import Clock, SystemClock
from tests.fakes.clock import FakeClock


def test_the_system_clock_satisfies_the_port() -> None:
    checked: Clock = SystemClock()

    assert isinstance(checked, Clock)


def test_now_is_timezone_aware_utc() -> None:
    # A naive datetime compared against an aware one raises, and a session that cannot
    # be compared to its own expiry is a session that never expires.
    assert SystemClock().now().tzinfo is UTC


def test_monotonic_never_goes_backwards() -> None:
    clock = SystemClock()

    first = clock.monotonic()

    assert clock.monotonic() >= first


def test_the_fake_clock_also_satisfies_the_port() -> None:
    # If the fake drifts from the port, every expiry test in the suite is testing
    # something the real service does not do.
    checked: Clock = FakeClock()

    assert isinstance(checked, Clock)


def test_advancing_the_fake_moves_both_readings_together() -> None:
    clock = FakeClock()
    before = clock.now()

    clock.advance(timedelta(minutes=5))

    assert clock.now() - before == timedelta(minutes=5)
    assert clock.monotonic() == 300.0
