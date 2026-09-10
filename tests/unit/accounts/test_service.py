"""The account service: invites, login, logout, reset, and deletion.

This is the highest-risk code in the project, so the tests are weighted towards the
failures that are silent. A download that breaks tells you. An authentication bug tells
whoever finds it first.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from keyring_api.accounts.hashing import Argon2PasswordHasher
from keyring_api.accounts.ratelimit import InMemoryRateLimiter
from keyring_api.accounts.service import AccountService, LoginResult
from keyring_api.accounts.store import (
    InMemoryAccountStore,
    InMemoryGrantStore,
    InMemorySessionStore,
)
from keyring_api.accounts.tokens import hash_token, new_token
from keyring_api.core.config import Argon2Settings, RateLimitSettings, Settings
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
from keyring_api.notifications.outbox import Outbox
from keyring_api.notifications.senders import DisabledEmailSender
from tests.fakes.clock import FakeClock
from tests.fakes.email import ExplodingSender, RecordingSender

EMAIL = "person@example.com"
PASSWORD = "correct horse battery staple"
CALLER = "1.2.3.4"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        argon2=Argon2Settings(time_cost=1, memory_cost_kib=8, parallelism=1),
        # The two guessing defences are deliberately far apart here so a test can
        # exercise either one without the other tripping first and masking it.
        lockout_threshold=4,
        rate_limit=RateLimitSettings(login_attempts=8, reset_attempts=3, invite_attempts=3),
    )


@pytest.fixture
def service(clock: FakeClock, settings: Settings) -> AccountService:
    return AccountService(
        accounts=InMemoryAccountStore(),
        sessions=InMemorySessionStore(clock=clock),
        grants=InMemoryGrantStore(),
        hasher=Argon2PasswordHasher(settings.argon2),
        limiter=InMemoryRateLimiter(clock=clock),
        outbox=Outbox(DisabledEmailSender()),
        clock=clock,
        settings=settings,
    )


FOUNDER_EMAIL = "founder@example.com"


async def create(service: AccountService, email: str, password: str = PASSWORD) -> str:
    """Invite an address and redeem it. Returns the new account id."""
    invite = await service.issue_invite(email=email)
    account = await service.redeem_invite(token=invite.token, password=password, caller=CALLER)
    return account.account_id


async def onboard(service: AccountService, email: str = EMAIL, password: str = PASSWORD) -> str:
    """Create the account under test, behind a founder account.

    The founder exists because the *first* account a service ever creates becomes the
    owner, and the last-owner guard refuses to delete or demote the only one. These tests
    are about sessions, resets and deletion mechanics rather than about ownership, so the
    account under test is deliberately an ordinary member -- which is also what every
    account except the first actually is.

    Ownership itself is tested in tests/unit/accounts/test_roles_store.py and
    tests/integration/test_admin_accounts.py.
    """
    if await service._accounts.count() == 0:
        await create(service, FOUNDER_EMAIL)

    return await create(service, email, password)


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
        token = new_token()
        now = clock.now()
        await service._grants.add(
            Grant(
                grant_id=new_grant_id(),
                purpose=GrantPurpose.INVITE,
                token_hash=hash_token(token),
                created_at=now,
                expires_at=now + timedelta(hours=1),
                account_id="acct_1",
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


class TestPasswordChange:
    async def test_changing_a_password_requires_the_current_one(
        self, service: AccountService
    ) -> None:
        # Otherwise a stolen session is an account takeover rather than a session
        # someone can revoke.
        account_id = await onboard(service)

        with pytest.raises(AuthenticationError):
            await service.change_password(
                account_id, current_password="wrong", new_password="a new passphrase"
            )

    async def test_the_new_password_works_and_the_old_one_stops(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)

        await service.change_password(
            account_id, current_password=PASSWORD, new_password="a new passphrase"
        )

        assert (await service.login(email=EMAIL, password="a new passphrase", caller=CALLER)).token
        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

    async def test_a_weak_new_password_is_refused(self, service: AccountService) -> None:
        account_id = await onboard(service)

        with pytest.raises(InvalidPasswordError):
            await service.change_password(
                account_id, current_password=PASSWORD, new_password="short"
            )

    async def test_every_other_session_is_revoked(self, service: AccountService) -> None:
        # If an attacker's session survived a password change, the action taken to lock
        # them out would have done nothing about the thing they actually hold.
        account_id = await onboard(service)
        attacker = await service.login(email=EMAIL, password=PASSWORD, caller="6.6.6.6")
        current = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        await service.change_password(
            account_id,
            current_password=PASSWORD,
            new_password="a new passphrase",
            keep_session_id=current.session_id,
        )

        with pytest.raises(AuthenticationError):
            await service.resolve_session(attacker.token)

    async def test_the_session_it_was_changed_from_survives(self, service: AccountService) -> None:
        # Signing someone out of the tab they just changed their password in is a
        # confusing way to confirm it worked.
        account_id = await onboard(service)
        current = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        await service.change_password(
            account_id,
            current_password=PASSWORD,
            new_password="a new passphrase",
            keep_session_id=current.session_id,
        )

        assert (await service.resolve_session(current.token)).session_id == current.session_id

    async def test_outstanding_reset_tokens_are_revoked(self, service: AccountService) -> None:
        # An attacker who requested a reset before being locked out otherwise still
        # holds a working link afterwards.
        account_id = await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        await service.change_password(
            account_id, current_password=PASSWORD, new_password="a new passphrase"
        )

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="attacker's choice", caller=CALLER
            )


class TestPasswordReset:
    async def test_requesting_a_reset_for_a_real_account_yields_a_token(
        self, service: AccountService
    ) -> None:
        await onboard(service)

        assert await service.request_password_reset(email=EMAIL, caller=CALLER) is not None

    async def test_requesting_a_reset_for_an_unknown_address_yields_nothing(
        self, service: AccountService
    ) -> None:
        # None, not an error. The API renders the same "if that address exists, we have
        # sent a link" either way, so the caller learns nothing.
        assert (
            await service.request_password_reset(email="nobody@example.com", caller=CALLER) is None
        )

    async def test_an_unusable_address_also_yields_nothing_rather_than_a_validation_error(
        self, service: AccountService
    ) -> None:
        # A distinct error for a malformed address is a smaller oracle than one for a
        # missing account, but it is still one: it tells a caller which shapes this
        # service considers real.
        assert await service.request_password_reset(email="not-an-address", caller=CALLER) is None

    async def test_redeeming_a_reset_sets_the_new_password(self, service: AccountService) -> None:
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        await service.redeem_password_reset(
            token=reset.token, new_password="a new passphrase", caller=CALLER
        )

        assert (
            await service.login(email=EMAIL, password="a new passphrase", caller=CALLER)
        ).account_id

    async def test_a_reset_can_only_be_used_once(self, service: AccountService) -> None:
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None
        await service.redeem_password_reset(
            token=reset.token, new_password="a new passphrase", caller=CALLER
        )

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="another passphrase", caller=CALLER
            )

    async def test_an_expired_reset_cannot_be_used(
        self, service: AccountService, clock: FakeClock, settings: Settings
    ) -> None:
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        clock.advance(timedelta(seconds=settings.reset_ttl_seconds))

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="a new passphrase", caller=CALLER
            )

    async def test_a_reset_revokes_every_session(self, service: AccountService) -> None:
        # Reset is the flow someone runs *because* they think they have been
        # compromised. Leaving the attacker's session alive defeats the entire exercise.
        await onboard(service)
        attacker = await service.login(email=EMAIL, password=PASSWORD, caller="6.6.6.6")
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        await service.redeem_password_reset(
            token=reset.token, new_password="a new passphrase", caller=CALLER
        )

        with pytest.raises(AuthenticationError):
            await service.resolve_session(attacker.token)

    async def test_a_second_reset_request_invalidates_the_first_link(
        self, service: AccountService
    ) -> None:
        # Two live links means the older one is still a password sitting in an inbox
        # after the person has already used the newer one.
        await onboard(service)
        first = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert first is not None

        await service.request_password_reset(email=EMAIL, caller=CALLER)

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=first.token, new_password="a new passphrase", caller=CALLER
            )

    async def test_an_invite_cannot_be_redeemed_as_a_reset(self, service: AccountService) -> None:
        invite = await service.issue_invite(email="new@example.com")

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=invite.token, new_password="a new passphrase", caller=CALLER
            )

    async def test_a_weak_new_password_is_refused_and_the_token_survives(
        self, service: AccountService
    ) -> None:
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        with pytest.raises(InvalidPasswordError):
            await service.redeem_password_reset(
                token=reset.token, new_password="short", caller=CALLER
            )

        assert (
            await service.redeem_password_reset(
                token=reset.token, new_password="a new passphrase", caller=CALLER
            )
        ).email == EMAIL

    async def test_reset_requests_are_rate_limited(
        self, service: AccountService, settings: Settings
    ) -> None:
        # Unlimited reset requests are unlimited mail sent to someone else's inbox.
        await onboard(service)

        for _ in range(settings.rate_limit.reset_attempts):
            await service.request_password_reset(email=EMAIL, caller=CALLER)

        with pytest.raises(RateLimitedError):
            await service.request_password_reset(email=EMAIL, caller=CALLER)

    async def test_a_reset_for_an_account_that_vanished_mid_flow_fails_cleanly(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None
        await service._accounts.delete(account_id)

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="a new passphrase", caller=CALLER
            )


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
        self, clock: FakeClock, settings: Settings, recorder: RecordingSender
    ) -> AccountService:
        return AccountService(
            accounts=InMemoryAccountStore(),
            sessions=InMemorySessionStore(clock=clock),
            grants=InMemoryGrantStore(),
            hasher=Argon2PasswordHasher(settings.argon2),
            limiter=InMemoryRateLimiter(clock=clock),
            outbox=Outbox(recorder),
            clock=clock,
            settings=settings,
        )

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
        self, clock: FakeClock, settings: Settings
    ) -> None:
        # A broken SMTP configuration must not turn password reset into a 500 -- and must
        # certainly not make a request for a real address behave differently from one for
        # an unknown address.
        failing = AccountService(
            accounts=InMemoryAccountStore(),
            sessions=InMemorySessionStore(clock=clock),
            grants=InMemoryGrantStore(),
            hasher=Argon2PasswordHasher(settings.argon2),
            limiter=InMemoryRateLimiter(clock=clock),
            outbox=Outbox(ExplodingSender()),
            clock=clock,
            settings=settings,
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
        self, clock: FakeClock, settings: Settings, recorder: RecordingSender
    ) -> AccountService:
        return AccountService(
            accounts=InMemoryAccountStore(),
            sessions=InMemorySessionStore(clock=clock),
            grants=InMemoryGrantStore(),
            hasher=Argon2PasswordHasher(settings.argon2),
            limiter=InMemoryRateLimiter(clock=clock),
            outbox=Outbox(recorder),
            clock=clock,
            settings=settings,
        )

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
