"""Invites and login: the two ways an account starts a session.

This is the highest-risk code in the project, so the tests are weighted towards the
failures that are silent. A download that breaks tells you. An authentication bug tells
whoever finds it first.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from keyring_api.accounts.hashing import Argon2PasswordHasher
from keyring_api.accounts.service import AccountService, LoginResult
from keyring_api.accounts.tokens import hash_token, new_token
from keyring_api.core.config import Argon2Settings, Settings
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.errors import (
    AccountExistsError,
    AuthenticationError,
    InvalidEmailError,
    InvalidGrantError,
    InvalidPasswordError,
    RateLimitedError,
)
from keyring_api.domain.grants import Grant, GrantPurpose, new_grant_id
from tests.fakes.clock import FakeClock
from tests.unit.accounts._helpers import CALLER, EMAIL, FOUNDER_EMAIL, PASSWORD, create, onboard
from tests.unit.accounts._helpers import clock as clock  # noqa: PLC0414
from tests.unit.accounts._helpers import service as service  # noqa: PLC0414
from tests.unit.accounts._helpers import settings as settings  # noqa: PLC0414


class TestInvites:
    async def test_an_invite_yields_a_token_that_is_not_stored(
        self, service: AccountService
    ) -> None:
        # The caller gets the only copy. A grant row is worthless to anyone who reads
        # the database, which is the whole reason it is hashed.
        invite = await service.issue_invite(email=EMAIL)

        stored = await service._grants.get_by_token_hash(hash_token(invite.token))
        assert stored is not None
        assert invite.token not in str(stored)

    async def test_redeeming_an_invite_creates_an_account_that_can_log_in(
        self, service: AccountService
    ) -> None:
        await onboard(service)

        assert (await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)).token

    async def test_the_new_account_gets_the_address_the_invite_was_issued_to(
        self, service: AccountService
    ) -> None:
        # The address comes from the invite, never from the redeeming request. Taking it
        # from the request would let anyone holding an invite claim any address.
        invite = await service.issue_invite(email=EMAIL)

        account = await service.redeem_invite(token=invite.token, password=PASSWORD, caller=CALLER)

        assert account.email == EMAIL

    async def test_an_invite_is_normalized_the_same_way_a_login_is(
        self, service: AccountService
    ) -> None:
        invite = await service.issue_invite(email="  Person@Example.COM ")

        account = await service.redeem_invite(token=invite.token, password=PASSWORD, caller=CALLER)

        assert account.email == EMAIL

    async def test_an_invite_to_an_unusable_address_is_refused(
        self, service: AccountService
    ) -> None:
        with pytest.raises(InvalidEmailError):
            await service.issue_invite(email="not-an-address")

    async def test_an_invite_to_an_address_that_already_has_an_account_is_refused(
        self, service: AccountService
    ) -> None:
        # Safe to be explicit here: only an administrator can reach this path, so there
        # is no stranger to leak the answer to.
        await onboard(service)

        with pytest.raises(AccountExistsError):
            await service.issue_invite(email=EMAIL)

    async def test_an_invite_cannot_be_redeemed_twice(self, service: AccountService) -> None:
        invite = await service.issue_invite(email=EMAIL)
        await service.redeem_invite(token=invite.token, password=PASSWORD, caller=CALLER)

        with pytest.raises(InvalidGrantError):
            await service.redeem_invite(token=invite.token, password=PASSWORD, caller=CALLER)

    async def test_an_expired_invite_cannot_be_redeemed(
        self, service: AccountService, clock: FakeClock, settings: Settings
    ) -> None:
        invite = await service.issue_invite(email=EMAIL)

        clock.advance(timedelta(seconds=settings.invite_ttl_seconds))

        with pytest.raises(InvalidGrantError):
            await service.redeem_invite(token=invite.token, password=PASSWORD, caller=CALLER)

    async def test_an_unknown_invite_fails_the_same_way_a_used_one_does(
        self, service: AccountService
    ) -> None:
        # An attacker holding a guessed token must not learn whether it ever existed.
        with pytest.raises(InvalidGrantError):
            await service.redeem_invite(token="made-up", password=PASSWORD, caller=CALLER)

    async def test_a_reset_token_cannot_be_redeemed_as_an_invite(
        self, service: AccountService
    ) -> None:
        # Purposes are checked, so a token minted for one flow cannot be presented at
        # the other's endpoint.
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        with pytest.raises(InvalidGrantError):
            await service.redeem_invite(token=reset.token, password="new password", caller=CALLER)

    async def test_an_invite_with_no_address_is_refused_rather_than_defaulted(
        self, service: AccountService, clock: FakeClock
    ) -> None:
        # A stored grant that names no address cannot say what account to create. The
        # only default available would be an address the caller supplied, which is the
        # one thing this flow must never take from the request.
        #
        # The grant names an existing account because grants are foreign-keyed to one --
        # which is the point: even a grant attached to a real account cannot stand in for
        # the address it does not carry.
        existing = await create(service, FOUNDER_EMAIL)
        token = new_token()
        now = clock.now()
        await service._grants.add(
            Grant(
                grant_id=new_grant_id(),
                purpose=GrantPurpose.INVITE,
                token_hash=hash_token(token),
                created_at=now,
                expires_at=now + timedelta(hours=1),
                account_id=existing,
            )
        )

        with pytest.raises(InvalidGrantError):
            await service.redeem_invite(token=token, password=PASSWORD, caller=CALLER)

    async def test_a_weak_password_is_refused_before_an_account_exists(
        self, service: AccountService
    ) -> None:
        # And the invite survives, so the person can try again rather than needing a new
        # one from an administrator.
        invite = await service.issue_invite(email=EMAIL)

        with pytest.raises(InvalidPasswordError):
            await service.redeem_invite(token=invite.token, password="short", caller=CALLER)

        assert (
            await service.redeem_invite(token=invite.token, password=PASSWORD, caller=CALLER)
        ).email == EMAIL

    async def test_redemption_is_rate_limited(
        self, service: AccountService, settings: Settings
    ) -> None:
        # This endpoint takes a token from an anonymous caller, which makes it a place
        # to guess tokens if nothing counts the guesses.
        for _ in range(settings.rate_limit.invite_attempts):
            with pytest.raises(InvalidGrantError):
                await service.redeem_invite(token="guess", password=PASSWORD, caller=CALLER)

        with pytest.raises(RateLimitedError):
            await service.redeem_invite(token="guess", password=PASSWORD, caller=CALLER)


class TestLogin:
    async def test_a_correct_password_returns_a_session_token(
        self, service: AccountService
    ) -> None:
        await onboard(service)

        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        assert isinstance(result, LoginResult)
        assert result.token

    async def test_the_session_token_is_not_stored(self, service: AccountService) -> None:
        await onboard(service)

        result = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        session = await service._sessions.get_by_token_hash(hash_token(result.token))
        assert session is not None
        assert result.token not in str(session)

    async def test_a_wrong_password_is_refused(self, service: AccountService) -> None:
        await onboard(service)

        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password="wrong password", caller=CALLER)

    async def test_an_unknown_address_fails_identically_to_a_wrong_password(
        self, service: AccountService
    ) -> None:
        # The single most important test in this file. If these two differ in *any*
        # observable way -- message, type, status -- the service will happily tell a
        # stranger which of your family have accounts.
        await onboard(service)

        with pytest.raises(AuthenticationError) as unknown:
            await service.login(email="nobody@example.com", password=PASSWORD, caller=CALLER)
        with pytest.raises(AuthenticationError) as wrong:
            await service.login(email=EMAIL, password="wrong password", caller=CALLER)

        assert type(unknown.value) is type(wrong.value)
        assert str(unknown.value) == str(wrong.value)

    async def test_an_unknown_address_still_costs_a_password_verification(
        self, service: AccountService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Asserted by observing the call rather than by timing it: a wall-clock
        # assertion would be flaky on a loaded CI runner, and would be measuring the
        # runner rather than the code.
        called: list[str] = []

        def record(password: str) -> bool:
            called.append(password)
            return False

        monkeypatch.setattr(service._hasher, "verify_dummy", record)

        with pytest.raises(AuthenticationError):
            await service.login(email="nobody@example.com", password=PASSWORD, caller=CALLER)

        assert called == [PASSWORD]

    async def test_a_disabled_account_cannot_log_in_even_with_the_right_password(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)
        await service.set_status(account_id, AccountStatus.DISABLED)

        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

    async def test_disabling_an_account_that_does_not_exist_is_a_no_op(
        self, service: AccountService
    ) -> None:
        # Reachable whenever an administrator's request races a deletion. It must not
        # resurrect the account as a disabled row.
        await service.set_status("acct_nope", AccountStatus.DISABLED)

        assert await service._accounts.get("acct_nope") is None

    async def test_repeated_failures_lock_the_account(
        self, service: AccountService, settings: Settings
    ) -> None:
        await onboard(service)

        for _ in range(settings.lockout_threshold):
            with pytest.raises(AuthenticationError):
                await service.login(email=EMAIL, password="wrong password", caller=CALLER)

        # Now even the right password is refused, which is the point.
        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

    async def test_a_lockout_lifts_by_itself(
        self, service: AccountService, settings: Settings, clock: FakeClock
    ) -> None:
        # A lock that needs an administrator to clear turns a mistyped password into a
        # support ticket at three in the morning.
        await onboard(service)
        for _ in range(settings.lockout_threshold):
            with pytest.raises(AuthenticationError):
                await service.login(email=EMAIL, password="wrong password", caller=CALLER)

        clock.advance(timedelta(seconds=settings.lockout_seconds))

        assert (await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)).token

    async def test_a_successful_login_clears_the_failure_count(
        self, service: AccountService, settings: Settings
    ) -> None:
        await onboard(service)
        for _ in range(settings.lockout_threshold - 1):
            with pytest.raises(AuthenticationError):
                await service.login(email=EMAIL, password="wrong password", caller=CALLER)

        await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        # One more failure must not now be the one that locks the account.
        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password="wrong password", caller=CALLER)
        assert (await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)).token

    async def test_login_is_rate_limited_per_caller(
        self, service: AccountService, settings: Settings
    ) -> None:
        for _ in range(settings.rate_limit.login_attempts):
            with pytest.raises(AuthenticationError):
                await service.login(email="nobody@example.com", password=PASSWORD, caller=CALLER)

        with pytest.raises(RateLimitedError):
            await service.login(email="nobody@example.com", password=PASSWORD, caller=CALLER)

    async def test_the_rate_limit_does_not_follow_the_account_to_another_caller(
        self, service: AccountService, settings: Settings
    ) -> None:
        # Keyed by caller, not by account. Keying it by account would let an attacker
        # lock a real person out of logging in at all, just by failing on their behalf --
        # so an exhausted caller must not be able to stop a legitimate one elsewhere.
        await onboard(service)
        for _ in range(settings.rate_limit.login_attempts):
            with pytest.raises(AuthenticationError):
                await service.login(email="nobody@example.com", password=PASSWORD, caller=CALLER)
        with pytest.raises(RateLimitedError):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        assert (await service.login(email=EMAIL, password=PASSWORD, caller="9.9.9.9")).token

    async def test_a_password_hashed_under_older_parameters_is_upgraded_on_login(
        self, service: AccountService
    ) -> None:
        # The only moment the plaintext is available. Without this, everyone who never
        # changes their password stays on the parameters they signed up under forever.
        account_id = await onboard(service)
        expensive = Argon2PasswordHasher(
            Argon2Settings(time_cost=4, memory_cost_kib=64, parallelism=1)
        )
        service._hasher = expensive
        before = await service._accounts.get(account_id)
        assert before is not None

        await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        after = await service._accounts.get(account_id)
        assert after is not None
        assert after.password_hash != before.password_hash
        assert not expensive.needs_rehash(after.password_hash)

    async def test_the_oldest_session_is_dropped_when_the_cap_is_reached(
        self, service: AccountService, settings: Settings
    ) -> None:
        # An unbounded session list is memory an authenticated caller allocates for free.
        await onboard(service)
        for _ in range(settings.max_sessions_per_account + 1):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        account_id = await onboard(service, "other@example.com")
        assert await service._sessions.count_for_account(account_id) == 0
