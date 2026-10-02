"""Proving the password again inside a session, and the notice that a session began.

``confirm_password`` is what a credential change asks for when the account wants
re-authentication. It is the same guess a login is, so it is held to the same defences;
the tests here are mostly about a stolen session token trying to turn it into a password
oracle.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.errors import AuthenticationError
from keyring_api.notifications.templates import NEW_SESSION_SUBJECT
from tests.fakes.email import RecordingSender
from tests.fakes.preferences import ChosenPreferences
from tests.unit.accounts._helpers import CALLER, EMAIL, PASSWORD, build_service, onboard
from tests.unit.accounts._helpers import clock as clock  # noqa: PLC0414
from tests.unit.accounts._helpers import service as service  # noqa: PLC0414
from tests.unit.accounts._helpers import settings as settings  # noqa: PLC0414

if TYPE_CHECKING:
    from keyring_api.accounts.service import AccountService
    from keyring_api.core.config import Settings
    from keyring_api.storage.database import Database
    from tests.fakes.clock import FakeClock


class TestConfirmPassword:
    async def test_the_right_password_is_accepted(self, service: AccountService) -> None:
        account_id = await onboard(service)

        await service.confirm_password(account_id, PASSWORD)

    async def test_a_wrong_password_is_refused_like_a_failed_login(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)

        with pytest.raises(AuthenticationError, match="email or password is incorrect"):
            await service.confirm_password(account_id, "not the password")

    async def test_wrong_passwords_lock_the_account(
        self, service: AccountService, settings: Settings
    ) -> None:
        """The bug, named: re-authentication as an unlimited password oracle.

        Whoever holds a stolen session token could otherwise guess the password through
        a credential route as fast as the hasher allows, with no lockout ever tripping.
        """
        account_id = await onboard(service)
        for _ in range(settings.lockout_threshold):
            with pytest.raises(AuthenticationError):
                await service.confirm_password(account_id, "not the password")

        with pytest.raises(AuthenticationError):
            await service.confirm_password(account_id, PASSWORD)
        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

    async def test_the_right_password_clears_earlier_failures(
        self, service: AccountService, settings: Settings
    ) -> None:
        account_id = await onboard(service)
        for _ in range(settings.lockout_threshold - 1):
            with pytest.raises(AuthenticationError):
                await service.confirm_password(account_id, "not the password")

        await service.confirm_password(account_id, PASSWORD)
        with pytest.raises(AuthenticationError):
            await service.confirm_password(account_id, "not the password")

        await service.confirm_password(account_id, PASSWORD)

    async def test_a_disabled_account_is_refused_even_with_the_right_password(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)
        await service.set_status(account_id, AccountStatus.DISABLED)

        with pytest.raises(AuthenticationError):
            await service.confirm_password(account_id, PASSWORD)

    async def test_an_account_that_is_gone_is_refused(self, service: AccountService) -> None:
        with pytest.raises(AuthenticationError):
            await service.confirm_password("acct_never", PASSWORD)

    async def test_a_lock_set_elsewhere_holds_here(
        self, service: AccountService, clock: FakeClock
    ) -> None:
        account_id = await onboard(service)
        account = await service._accounts.get(account_id)
        assert account is not None
        await service._accounts.save(replace(account, locked_until=clock.now().replace(year=2100)))

        with pytest.raises(AuthenticationError):
            await service.confirm_password(account_id, PASSWORD)


class TestNewSessionNotice:
    @pytest.fixture
    def recorder(self) -> RecordingSender:
        return RecordingSender()

    def mailing(
        self,
        *,
        database: Database,
        clock: FakeClock,
        settings: Settings,
        recorder: RecordingSender,
        **chosen: bool,
    ) -> AccountService:
        return build_service(
            database=database,
            clock=clock,
            settings=settings,
            sender=recorder,
            preferences=ChosenPreferences(settings, **chosen),
        )

    async def test_a_login_is_announced_to_somebody_who_asked(
        self, database: Database, clock: FakeClock, settings: Settings, recorder: RecordingSender
    ) -> None:
        service = self.mailing(
            database=database,
            clock=clock,
            settings=settings,
            recorder=recorder,
            notify_on_new_session=True,
        )
        await onboard(service)
        await service._outbox.drain()
        recorder.sent.clear()

        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
        await service._outbox.drain()

        assert [message.subject for message in recorder.sent] == [NEW_SESSION_SUBJECT]
        assert recorder.sent[0].to_address == EMAIL
        assert result.token not in recorder.sent[0].body
        assert result.session_id not in recorder.sent[0].body
        assert result.account_id not in recorder.sent[0].body

    @pytest.mark.parametrize(
        "chosen",
        [
            {},
            {"notify_on_new_session": False},
            {"notify_on_new_session": True, "email_notifications": False},
        ],
    )
    async def test_nothing_is_sent_to_somebody_who_did_not(
        self,
        database: Database,
        clock: FakeClock,
        settings: Settings,
        recorder: RecordingSender,
        chosen: dict[str, bool],
    ) -> None:
        """The bug, named: a new mail on every login for people who never asked for one.

        Unchosen is what keyring did before this setting existed, which was to send nothing;
        and the master switch silences the notice even when the notice itself is on.
        """
        service = self.mailing(
            database=database, clock=clock, settings=settings, recorder=recorder, **chosen
        )
        await onboard(service)
        await service._outbox.drain()
        recorder.sent.clear()

        await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
        await service._outbox.drain()

        assert recorder.sent == []

    async def test_a_failed_login_announces_nothing(
        self, database: Database, clock: FakeClock, settings: Settings, recorder: RecordingSender
    ) -> None:
        """The bug, named: login as a way for a stranger to mail somebody."""
        service = self.mailing(
            database=database,
            clock=clock,
            settings=settings,
            recorder=recorder,
            notify_on_new_session=True,
        )
        await onboard(service)
        await service._outbox.drain()
        recorder.sent.clear()

        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password="not the password", caller=CALLER)
        await service._outbox.drain()

        assert recorder.sent == []
