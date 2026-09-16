"""Deletion, email delivery, admin-issued reset, and the lockout timing oracle.

This is the highest-risk code in the project, so the tests are weighted towards the
failures that are silent. A download that breaks tells you. An authentication bug tells
whoever finds it first.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest

from keyring_api.accounts.hashing import Argon2PasswordHasher
from keyring_api.accounts.ratelimit import InMemoryRateLimiter
from keyring_api.accounts.service import AccountService
from keyring_api.accounts.tokens import hash_token, new_token
from keyring_api.core.config import Settings
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.errors import (
    AuthenticationError,
    InvalidGrantError,
    RateLimitedError,
)
from keyring_api.domain.grants import Grant, GrantPurpose, new_grant_id
from tests.fakes.clock import FakeClock
from tests.fakes.email import ExplodingSender, RecordingSender
from tests.unit.accounts._helpers import CALLER, EMAIL, PASSWORD, build_service, onboard
from tests.unit.accounts._helpers import clock as clock  # noqa: PLC0414
from tests.unit.accounts._helpers import service as service  # noqa: PLC0414
from tests.unit.accounts._helpers import settings as settings  # noqa: PLC0414

if TYPE_CHECKING:
    from keyring_api.storage.database import Database


class TestDeletion:
    async def test_deleting_an_account_removes_it(self, service: AccountService) -> None:
        account_id = await onboard(service)

        assert await service.delete_account(account_id)

        assert await service._accounts.get(account_id) is None

    async def test_deleting_takes_every_session_with_it(self, service: AccountService) -> None:
        account_id = await onboard(service)
        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        await service.delete_account(account_id)

        with pytest.raises(AuthenticationError):
            await service.resolve_session(result.token)

    async def test_deleting_takes_outstanding_grants_with_it(self, service: AccountService) -> None:
        account_id = await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        await service.delete_account(account_id)

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="a new passphrase", caller=CALLER
            )

    async def test_a_reset_grant_that_names_no_account_is_refused(
        self, service: AccountService, clock: FakeClock
    ) -> None:
        # The mirror of the invite case: a stored reset that names no account cannot say
        # whose password to set, and the only default available would be one taken from
        # the request. Refused with the same error a stranger's guess gets.
        await onboard(service)
        token = new_token()
        now = clock.now()
        await service._grants.add(
            Grant(
                grant_id=new_grant_id(),
                purpose=GrantPurpose.PASSWORD_RESET,
                token_hash=hash_token(token),
                created_at=now,
                expires_at=now + timedelta(hours=1),
                email=EMAIL,
            )
        )

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=token, new_password="a new passphrase", caller=CALLER
            )

    async def test_the_address_can_be_invited_again_afterwards(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)

        await service.delete_account(account_id)

        assert (await service.issue_invite(email=EMAIL)).token

    async def test_deleting_an_unknown_account_reports_that_nothing_went(
        self, service: AccountService
    ) -> None:
        assert not await service.delete_account("acct_nope")


class TestSweeping:
    async def test_sweeping_drops_expired_sessions_grants_and_rate_limit_records(
        self, service: AccountService, clock: FakeClock, settings: Settings
    ) -> None:
        await onboard(service)
        await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)
        await service.request_password_reset(email=EMAIL, caller=CALLER)

        clock.advance(timedelta(seconds=settings.session_absolute_ttl_seconds * 2))

        swept = await service.sweep_once()

        assert swept.sessions == 1
        assert swept.grants >= 1
        assert swept.rate_limit_records >= 1


class TestEmailDelivery:
    """Delivery of invite and reset tokens, and the properties it must not break."""

    @pytest.fixture
    def recorder(self) -> RecordingSender:
        return RecordingSender()

    @pytest.fixture
    def mailing_service(
        self,
        database: Database,
        clock: FakeClock,
        settings: Settings,
        recorder: RecordingSender,
    ) -> AccountService:
        return build_service(database=database, clock=clock, settings=settings, sender=recorder)

    async def test_an_invite_is_mailed_to_the_address_it_was_issued_for(
        self, mailing_service: AccountService, recorder: RecordingSender
    ) -> None:
        await mailing_service.issue_invite(email=EMAIL)
        await mailing_service._outbox.drain()

        assert [message.to_address for message in recorder.sent] == [EMAIL]

    async def test_the_mailed_invite_carries_the_token(
        self, mailing_service: AccountService, recorder: RecordingSender
    ) -> None:
        invite = await mailing_service.issue_invite(email=EMAIL)
        await mailing_service._outbox.drain()

        assert invite.token in recorder.sent[0].body

    async def test_a_reset_is_mailed_to_the_account_holder(
        self, mailing_service: AccountService, recorder: RecordingSender
    ) -> None:
        await onboard(mailing_service)
        # Drain before clearing: onboarding queues an invite mail, and a message still in
        # flight would land after the clear and be counted as the reset.
        await mailing_service._outbox.drain()
        recorder.sent.clear()

        await mailing_service.request_password_reset(email=EMAIL, caller=CALLER)
        await mailing_service._outbox.drain()

        assert [message.to_address for message in recorder.sent] == [EMAIL]

    async def test_no_mail_is_sent_for_an_address_with_no_account(
        self, mailing_service: AccountService, recorder: RecordingSender
    ) -> None:
        # Not because it would leak -- the response is identical either way -- but
        # because mailing a stranger "someone tried to reset your password" for an
        # account they do not have is how a service becomes a spam vector.
        await mailing_service.request_password_reset(email="nobody@example.com", caller=CALLER)
        await mailing_service._outbox.drain()

        assert recorder.sent == []

    async def test_the_service_reports_that_it_delivers_email(
        self, mailing_service: AccountService, service: AccountService
    ) -> None:
        # The API reads this to decide whether to return an invite token in its response.
        assert mailing_service.delivers_email
        assert not service.delivers_email

    async def test_one_address_cannot_be_mailed_without_limit(
        self, mailing_service: AccountService, recorder: RecordingSender, settings: Settings
    ) -> None:
        # The per-caller limit stops one attacker. This stops many callers, or one behind
        # changing addresses, using password reset to flood somebody else's inbox -- an
        # attack that costs the attacker nothing and lands entirely on a third party.
        await onboard(mailing_service)
        await mailing_service._outbox.drain()
        recorder.sent.clear()

        for index in range(settings.email.max_messages_per_address_per_window + 3):
            await mailing_service.request_password_reset(email=EMAIL, caller=f"10.0.0.{index}")
        await mailing_service._outbox.drain()

        assert len(recorder.sent) == settings.email.max_messages_per_address_per_window

    async def test_a_flooded_address_still_gets_the_same_answer(
        self, mailing_service: AccountService, settings: Settings
    ) -> None:
        # Refused silently. Raising, or returning anything different, would tell the
        # caller the address is real -- exactly what the identical response elsewhere in
        # this flow exists to hide.
        await onboard(mailing_service)
        for index in range(settings.email.max_messages_per_address_per_window + 2):
            await mailing_service.request_password_reset(email=EMAIL, caller=f"10.0.0.{index}")

        refused = await mailing_service.request_password_reset(email=EMAIL, caller="10.1.1.1")
        unknown = await mailing_service.request_password_reset(
            email="nobody@example.com", caller="10.1.1.2"
        )

        assert refused is None
        assert unknown is None

    async def test_the_recipient_limit_holds_no_plaintext_addresses(
        self, mailing_service: AccountService
    ) -> None:
        # The limiter is an in-memory map keyed by whatever it is given. Keyed by the
        # address itself, it would be a list of everyone who has an account here.
        await onboard(mailing_service)
        await mailing_service.request_password_reset(email=EMAIL, caller=CALLER)

        limiter = mailing_service._limiter
        assert isinstance(limiter, InMemoryRateLimiter)
        assert not any(EMAIL in caller for _, caller in limiter._attempts)

    async def test_a_delivery_failure_does_not_fail_the_request(
        self, database: Database, clock: FakeClock, settings: Settings
    ) -> None:
        # A broken SMTP configuration must not turn password reset into a 500 -- and must
        # certainly not make a request for a real address behave differently from one for
        # an unknown address.
        failing = build_service(
            database=database, clock=clock, settings=settings, sender=ExplodingSender()
        )
        await onboard(failing)

        assert await failing.request_password_reset(email=EMAIL, caller=CALLER) is not None
        await failing._outbox.drain()


class TestAdminIssuedReset:
    """An administrator minting a reset for somebody who cannot get in."""

    @pytest.fixture
    def recorder(self) -> RecordingSender:
        return RecordingSender()

    @pytest.fixture
    def mailing_service(
        self,
        database: Database,
        clock: FakeClock,
        settings: Settings,
        recorder: RecordingSender,
    ) -> AccountService:
        return build_service(database=database, clock=clock, settings=settings, sender=recorder)

    async def test_it_mints_a_token_that_actually_resets_the_password(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)
        account = await service._accounts.get(account_id)
        assert account is not None

        grant = await service.issue_reset_for(account)
        await service.redeem_password_reset(
            token=grant.token, new_password="a new passphrase", caller=CALLER
        )

        assert (await service.login(email=EMAIL, password="a new passphrase", caller=CALLER)).token

    async def test_it_bypasses_the_per_caller_rate_limit(
        self, service: AccountService, settings: Settings
    ) -> None:
        # The per-caller limit exists to stop a stranger probing addresses. The caller
        # here is already authenticated and already holds a permission that says they may
        # do this; the audit log is what holds them to it.
        # Kept below the per-recipient mail cap on purpose -- that one still applies, and
        # it is the subject of the next test. This asserts only that the *caller* limit
        # does not.
        assert (
            settings.rate_limit.reset_attempts < settings.email.max_messages_per_address_per_window
        )
        account_id = await onboard(service)
        account = await service._accounts.get(account_id)
        assert account is not None
        for _ in range(settings.rate_limit.reset_attempts):
            await service.issue_reset_for(account)

        assert (await service.issue_reset_for(account)).token

    async def test_it_still_respects_the_per_recipient_mail_cap(
        self, mailing_service: AccountService, settings: Settings
    ) -> None:
        # So an administrator cannot be used -- deliberately or by a stuck script -- to
        # flood somebody's inbox, which is the one thing the per-caller limit would not
        # have stopped here.
        account_id = await onboard(mailing_service)
        account = await mailing_service._accounts.get(account_id)
        assert account is not None
        for _ in range(settings.email.max_messages_per_address_per_window):
            await mailing_service.issue_reset_for(account)

        with pytest.raises(RateLimitedError):
            await mailing_service.issue_reset_for(account)

    async def test_it_invalidates_any_earlier_link(self, service: AccountService) -> None:
        # Two live links means the older one is still a password sitting in an inbox.
        account_id = await onboard(service)
        account = await service._accounts.get(account_id)
        assert account is not None
        first = await service.issue_reset_for(account)

        await service.issue_reset_for(account)

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=first.token, new_password="a new passphrase", caller=CALLER
            )


class TestTheLockoutTimingOracle:
    """A locked or disabled account must cost the same as a wrong password.

    The identical error message closes the *content* oracle. It does nothing about the
    clock: this branch was the only one that could return without hashing, so a login
    that came back in microseconds while every other outcome took ~50ms said both that
    the address has an account and that the account is locked or disabled.
    """

    async def test_a_locked_account_still_costs_a_verification(
        self, service: AccountService, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Asserted by observing the call rather than timing it -- a wall-clock assertion
        # would be measuring the CI runner.
        await onboard(service)
        for _ in range(settings.lockout_threshold):
            with pytest.raises(AuthenticationError):
                await service.login(email=EMAIL, password="wrong password", caller=CALLER)

        verifications: list[str] = []
        original = service._hasher.verify

        def record(stored_hash: str, password: str) -> bool:
            verifications.append(password)
            return original(stored_hash, password)

        monkeypatch.setattr(service._hasher, "verify", record)

        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        assert verifications == [PASSWORD]

    async def test_a_disabled_account_still_costs_a_verification(
        self, service: AccountService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        account_id = await onboard(service)
        await service.set_status(account_id, AccountStatus.DISABLED)

        verifications: list[str] = []
        original = service._hasher.verify

        def record(stored_hash: str, password: str) -> bool:
            verifications.append(password)
            return original(stored_hash, password)

        monkeypatch.setattr(service._hasher, "verify", record)

        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        assert verifications == [PASSWORD]

    async def test_every_failing_branch_does_exactly_one_argon2_verification(
        self, service: AccountService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Counted at the Argon2 level, not at our wrapper: verify_dummy is *implemented
        # by* calling verify, so spying on the wrapper reports one operation as two.
        # What matters is the number of actual hash computations, because that is what
        # the clock measures.
        #
        # Unknown address, wrong password, locked, disabled: four different reasons, one
        # unit of work each. Two would be an oracle in the other direction.
        hasher = service._hasher
        assert isinstance(hasher, Argon2PasswordHasher)
        account_id = await onboard(service)
        await service.set_status(account_id, AccountStatus.DISABLED)

        computations: list[str] = []
        argon2 = type(hasher._hasher)
        real = argon2.verify

        def record(inner: Any, stored_hash: str, password: str) -> bool:
            computations.append(password)
            return bool(real(inner, stored_hash, password))

        monkeypatch.setattr(argon2, "verify", record)

        for email in (EMAIL, "nobody@example.com"):
            computations.clear()
            with pytest.raises(AuthenticationError):
                await service.login(email=email, password=PASSWORD, caller=CALLER)
            assert len(computations) == 1, f"{email} did {len(computations)}"
