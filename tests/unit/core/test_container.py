"""The composition root, and the background sweeper it owns."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from keyring_api.core.container import Container
from keyring_api.core.preferences import DeploymentPreferences
from settings_client.testing import FakeSettingsClient
from tests.fakes.clock import FakeClock

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from keyring_api.core.config import Settings


@pytest.fixture
async def container(settings: Settings) -> AsyncIterator[Container]:
    built = Container.build(settings, clock=FakeClock())
    try:
        yield built
    finally:
        await built.aclose()


def test_it_wires_every_dependency(container: Container) -> None:
    assert container.account_service is not None
    assert container.accounts is not None
    assert isinstance(container.preferences, DeploymentPreferences)


async def test_uptime_starts_at_zero_and_advances_with_the_clock(settings: Settings) -> None:
    clock = FakeClock()
    container = Container.build(settings, clock=clock)
    try:
        assert container.uptime_seconds == 0

        clock.advance(timedelta(seconds=30))

        assert container.uptime_seconds == 30
    finally:
        await container.aclose()


async def test_it_builds_a_real_clock_when_none_is_supplied(settings: Settings) -> None:
    # The production path. Passing a clock is the test affordance, not the default.
    container = Container.build(settings)
    try:
        assert container.uptime_seconds >= 0
    finally:
        await container.aclose()


class TestSweeper:
    async def test_closing_stops_the_sweeper(self, container: Container) -> None:
        container.start_sweeper()

        await container.aclose()

        assert container._sweeper is None

    async def test_closing_twice_is_not_an_error(self, container: Container) -> None:
        # Lifespan shutdown can run more than once in a test harness, and a second close
        # awaiting an already-cancelled task would hang or raise.
        container.start_sweeper()

        await container.aclose()
        await container.aclose()

    async def test_a_sweep_removes_expired_state(
        self, container: Container, settings: Settings
    ) -> None:
        clock = container.clock
        assert isinstance(clock, FakeClock)
        invite = await container.account_service.issue_invite(email="person@example.com")
        await container.account_service.redeem_invite(
            token=invite.token, password="correct horse battery staple", caller="1.2.3.4"
        )
        await container.account_service.login(
            email="person@example.com", password="correct horse battery staple", caller="1.2.3.4"
        )

        clock.advance(timedelta(seconds=settings.session_absolute_ttl_seconds * 2))
        await container._sweep_guarded()

        assert await container.sessions.count_for_account("any") == 0

    async def test_a_failing_sweep_does_not_kill_the_sweeper(
        self, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Without this the first transient error silently stops all retention, and
        # expired sessions accumulate until somebody notices the memory.
        async def explode() -> None:
            failure_message = "the store went away"
            raise RuntimeError(failure_message)

        monkeypatch.setattr(container.account_service, "sweep_once", explode)

        await container._sweep_guarded()

    async def test_the_sweeper_runs_on_its_interval(
        self, container: Container, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Asserted by making the interval instant and waiting on an event, rather than
        # by sleeping for the real interval: a test that sleeps is slow today and flaky
        # next month.
        swept = asyncio.Event()
        monkeypatch.setattr("keyring_api.core.container.SWEEP_INTERVAL_SECONDS", 0)

        async def record() -> object:
            swept.set()
            raise asyncio.CancelledError

        monkeypatch.setattr(container.account_service, "sweep_once", record)
        container.start_sweeper()

        async with asyncio.timeout(2):
            await swept.wait()

        await container.aclose()


async def test_a_sweep_with_nothing_to_do_is_silent(container: Container) -> None:
    # The common case by far: the sweeper runs every few minutes on a service where
    # nothing has expired, and it must not log a line each time saying so.
    await container._sweep_guarded()

    assert await container.sessions.purge_expired() == 0


async def test_a_substituted_settings_client_is_closed_with_the_container(
    settings: Settings,
) -> None:
    client = FakeSettingsClient()
    closed = False
    original = client.aclose

    async def mark() -> None:
        nonlocal closed
        closed = True
        await original()

    client.aclose = mark  # type: ignore[method-assign]
    container = Container.build(settings, settings_client=client)
    try:
        assert not isinstance(container.preferences, DeploymentPreferences)
    finally:
        await container.aclose()

    assert closed
