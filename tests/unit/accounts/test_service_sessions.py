"""Session resolution and logout.

This is the highest-risk code in the project, so the tests are weighted towards the
failures that are silent. A download that breaks tells you. An authentication bug tells
whoever finds it first.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from keyring_api.accounts.service import AccountService
from keyring_api.accounts.tokens import hash_token, new_token
from keyring_api.core.config import Settings
from keyring_api.core.preferences import REFUSED, Preferences
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.errors import AuthenticationError, PreferencesUnavailableError
from keyring_api.domain.sessions import Session, new_session_id
from tests.fakes.clock import FakeClock
from tests.unit.accounts._helpers import CALLER, EMAIL, PASSWORD, build_service, onboard
from tests.unit.accounts._helpers import clock as clock  # noqa: PLC0414
from tests.unit.accounts._helpers import service as service  # noqa: PLC0414
from tests.unit.accounts._helpers import settings as settings  # noqa: PLC0414

if TYPE_CHECKING:
    from keyring_api.storage.database import Database


class FixedPreferences:
    """Always return the same choices, so a test can change the deployment independently."""

    def __init__(self, preferences: Preferences) -> None:
        self._preferences = preferences
        self.asked: list[str] = []

    async def for_account(self, account_id: str, /) -> Preferences:
        self.asked.append(account_id)
        return self._preferences

    async def aclose(self) -> None:
        return


class ExplodingPreferences:
    """settings-api refused this service's grant."""

    async def for_account(self, _account_id: str, /) -> Preferences:
        raise PreferencesUnavailableError(REFUSED)

    async def aclose(self) -> None:
        return


class TestSessionResolution:
    async def test_a_session_token_resolves_to_its_account(self, service: AccountService) -> None:
        account_id = await onboard(service)
        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        session = await service.resolve_session(result.token)

        assert session.account_id == account_id

    async def test_an_unknown_token_is_refused(self, service: AccountService) -> None:
        with pytest.raises(AuthenticationError):
            await service.resolve_session("made-up")

    async def test_an_expired_session_is_refused(
        self, service: AccountService, clock: FakeClock, settings: Settings
    ) -> None:
        await onboard(service)
        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        clock.advance(timedelta(seconds=settings.session_ttl_seconds))

        with pytest.raises(AuthenticationError):
            await service.resolve_session(result.token)

    async def test_using_a_session_extends_its_idle_window(
        self, service: AccountService, clock: FakeClock, settings: Settings
    ) -> None:
        await onboard(service)
        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        clock.advance(timedelta(seconds=settings.session_ttl_seconds / 2))
        await service.resolve_session(result.token)
        clock.advance(timedelta(seconds=settings.session_ttl_seconds / 2 + 1))

        assert (await service.resolve_session(result.token)).session_id == result.session_id

    async def test_a_session_whose_account_has_been_deleted_is_refused(
        self, service: AccountService
    ) -> None:
        # The cascade should have taken the session with it; this is the belt to that
        # braces, because a session pointing at nothing must not resolve to anything.
        account_id = await onboard(service)
        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
        await service._accounts.delete(account_id)

        with pytest.raises(AuthenticationError):
            await service.resolve_session(result.token)

    async def test_a_session_belonging_to_a_disabled_account_is_refused(
        self, service: AccountService
    ) -> None:
        # Disabling an account has to end its existing sessions, not merely stop new
        # logins -- otherwise the person you just disabled stays signed in.
        account_id = await onboard(service)
        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        await service.set_status(account_id, AccountStatus.DISABLED)

        with pytest.raises(AuthenticationError):
            await service.resolve_session(result.token)


class TestLogout:
    async def test_logging_out_ends_that_session(self, service: AccountService) -> None:
        await onboard(service)
        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        await service.logout(result.session_id)

        with pytest.raises(AuthenticationError):
            await service.resolve_session(result.token)

    async def test_logging_out_leaves_other_devices_signed_in(
        self, service: AccountService
    ) -> None:
        await onboard(service)
        laptop = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
        phone = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        await service.logout(laptop.session_id)

        assert (await service.resolve_session(phone.token)).session_id == phone.session_id

    async def test_logging_out_everywhere_ends_every_session(self, service: AccountService) -> None:
        account_id = await onboard(service)
        laptop = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
        phone = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        assert await service.logout_everywhere(account_id) == 2

        for result in (laptop, phone):
            with pytest.raises(AuthenticationError):
                await service.resolve_session(result.token)


class TestStampedIdleTtl:
    async def test_a_login_stamps_the_idle_ttl_used_at_create(
        self, database: Database, clock: FakeClock, settings: Settings
    ) -> None:
        chosen = Preferences(
            session_ttl_seconds=60,
            session_absolute_ttl_seconds=3_600,
            max_sessions=5,
        )
        service = build_service(
            database=database, clock=clock, settings=settings, preferences=FixedPreferences(chosen)
        )
        await onboard(service)

        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
        session = await service.resolve_session(result.token)

        assert session.idle_ttl_seconds == 60
        assert result.expires_at == clock.now() + timedelta(seconds=60)

    async def test_touching_a_session_keeps_the_stamped_ttl_when_the_deployment_changes(
        self, database: Database, clock: FakeClock, settings: Settings
    ) -> None:
        # A later settings change must not silently lengthen or shorten a live session.
        chosen = Preferences(
            session_ttl_seconds=60,
            session_absolute_ttl_seconds=3_600,
            max_sessions=5,
        )
        service = build_service(
            database=database, clock=clock, settings=settings, preferences=FixedPreferences(chosen)
        )
        await onboard(service)
        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
        settings.session_ttl_seconds = 1

        clock.advance(timedelta(seconds=2))
        refreshed = await service.resolve_session(result.token)

        assert refreshed.session_id == result.session_id
        assert refreshed.expires_at == clock.now() + timedelta(seconds=60)

    async def test_a_session_without_a_stamp_keeps_using_the_deployment_ttl(
        self, database: Database, clock: FakeClock, settings: Settings
    ) -> None:
        service = build_service(database=database, clock=clock, settings=settings)
        account_id = await onboard(service)
        token = new_token()
        now = clock.now()
        await service._sessions.add(
            Session(
                session_id=new_session_id(),
                account_id=account_id,
                token_hash=hash_token(token),
                created_at=now,
                last_used_at=now,
                expires_at=now + timedelta(hours=1),
                absolute_expires_at=now + timedelta(days=90),
                idle_ttl_seconds=None,
            )
        )

        refreshed = await service.resolve_session(token)

        assert refreshed.idle_ttl_seconds is None
        assert refreshed.expires_at == now + timedelta(seconds=settings.session_ttl_seconds)

    async def test_a_failed_login_never_asks_for_preferences(
        self, database: Database, clock: FakeClock, settings: Settings
    ) -> None:
        chosen = FixedPreferences(
            Preferences(
                session_ttl_seconds=60,
                session_absolute_ttl_seconds=3_600,
                max_sessions=5,
            )
        )
        service = build_service(
            database=database, clock=clock, settings=settings, preferences=chosen
        )
        await onboard(service)

        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password="wrong password", caller=CALLER)

        assert chosen.asked == []

    async def test_a_refused_grant_fails_login(
        self, database: Database, clock: FakeClock, settings: Settings
    ) -> None:
        service = build_service(
            database=database,
            clock=clock,
            settings=settings,
            preferences=ExplodingPreferences(),
        )
        await onboard(service)

        with pytest.raises(PreferencesUnavailableError, match=REFUSED):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
