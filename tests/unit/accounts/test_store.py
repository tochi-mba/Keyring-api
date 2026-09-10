"""The account, session and grant stores.

In-memory for v1 (ADR-0004). The tests are written against the ports rather than the
dictionaries, so the Postgres adapter that replaces these has a suite waiting for it.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from keyring_api.accounts.store import (
    AccountStore,
    GrantStore,
    InMemoryAccountStore,
    InMemoryGrantStore,
    InMemorySessionStore,
    SessionStore,
)
from keyring_api.domain.accounts import Account, new_account_id
from keyring_api.domain.errors import AccountExistsError
from keyring_api.domain.grants import Grant, GrantPurpose, new_grant_id
from keyring_api.domain.sessions import Session, new_session_id
from tests.fakes.clock import EPOCH, FakeClock


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def make_account(email: str = "person@example.com", **overrides: object) -> Account:
    defaults: dict[str, object] = {
        "account_id": new_account_id(),
        "email": email,
        "password_hash": "$argon2id$fake",
        "created_at": EPOCH,
        "updated_at": EPOCH,
    }
    return Account(**{**defaults, **overrides})  # type: ignore[arg-type]


def make_session(account_id: str, token_hash: str = "hash", **overrides: object) -> Session:
    defaults: dict[str, object] = {
        "session_id": new_session_id(),
        "account_id": account_id,
        "token_hash": token_hash,
        "created_at": EPOCH,
        "last_used_at": EPOCH,
        "expires_at": EPOCH + timedelta(hours=1),
        "absolute_expires_at": EPOCH + timedelta(days=1),
    }
    return Session(**{**defaults, **overrides})  # type: ignore[arg-type]


def make_grant(token_hash: str = "hash", **overrides: object) -> Grant:
    defaults: dict[str, object] = {
        "grant_id": new_grant_id(),
        "purpose": GrantPurpose.INVITE,
        "token_hash": token_hash,
        "created_at": EPOCH,
        "expires_at": EPOCH + timedelta(hours=1),
        "email": "person@example.com",
    }
    return Grant(**{**defaults, **overrides})  # type: ignore[arg-type]


class TestAccountStore:
    @pytest.fixture
    def store(self) -> InMemoryAccountStore:
        return InMemoryAccountStore()

    async def test_it_satisfies_the_port(self, store: InMemoryAccountStore) -> None:
        checked: AccountStore = store

        assert isinstance(checked, AccountStore)

    async def test_an_added_account_can_be_read_back_by_id(
        self, store: InMemoryAccountStore
    ) -> None:
        account = make_account()

        await store.add(account)

        assert await store.get(account.account_id) == account

    async def test_an_unknown_id_reads_back_as_absent_rather_than_raising(
        self, store: InMemoryAccountStore
    ) -> None:
        # The caller decides what a missing account means, and at a login it must mean
        # the same thing as a wrong password.
        assert await store.get("acct_nope") is None

    async def test_an_account_can_be_found_by_the_address_someone_logs_in_with(
        self, store: InMemoryAccountStore
    ) -> None:
        account = make_account("Person@Example.com".lower())

        await store.add(account)

        assert await store.get_by_email("person@example.com") == account

    async def test_a_second_account_for_the_same_address_is_refused(
        self, store: InMemoryAccountStore
    ) -> None:
        await store.add(make_account())

        with pytest.raises(AccountExistsError):
            await store.add(make_account())

    async def test_saving_replaces_the_stored_account(self, store: InMemoryAccountStore) -> None:
        account = make_account()
        await store.add(account)

        await store.save(account.with_failure(now=EPOCH, lockout_threshold=5, lockout_seconds=60))

        stored = await store.get(account.account_id)
        assert stored is not None
        assert stored.failed_attempts == 1

    async def test_deleting_removes_it_from_both_lookups(self, store: InMemoryAccountStore) -> None:
        # The address index is a second copy of the same fact; leaving it behind would
        # make the address permanently un-invitable.
        account = make_account()
        await store.add(account)

        assert await store.delete(account.account_id)
        assert await store.get(account.account_id) is None
        assert await store.get_by_email(account.email) is None

    async def test_deleting_an_unknown_account_reports_that_nothing_went(
        self, store: InMemoryAccountStore
    ) -> None:
        assert not await store.delete("acct_nope")

    async def test_it_counts_what_it_holds(self, store: InMemoryAccountStore) -> None:
        await store.add(make_account("a@example.com"))
        await store.add(make_account("b@example.com"))

        assert await store.count() == 2


class TestSessionStore:
    @pytest.fixture
    def store(self, clock: FakeClock) -> InMemorySessionStore:
        return InMemorySessionStore(clock=clock)

    async def test_it_satisfies_the_port(self, store: InMemorySessionStore) -> None:
        checked: SessionStore = store

        assert isinstance(checked, SessionStore)

    async def test_a_session_is_found_by_the_hash_of_the_presented_token(
        self, store: InMemorySessionStore
    ) -> None:
        # Lookup is by hash, never by token: the token is not stored, so there is
        # nothing else it could be looked up by.
        session = make_session("acct_1", token_hash="abc")
        await store.add(session)

        assert await store.get_by_token_hash("abc") == session

    async def test_an_unknown_token_finds_nothing(self, store: InMemorySessionStore) -> None:
        assert await store.get_by_token_hash("nope") is None

    async def test_revoking_one_session_leaves_the_others_alone(
        self, store: InMemorySessionStore
    ) -> None:
        kept = make_session("acct_1", token_hash="kept")
        revoked = make_session("acct_1", token_hash="revoked")
        await store.add(kept)
        await store.add(revoked)

        assert await store.revoke(revoked.session_id)

        assert await store.get_by_token_hash("revoked") is None
        assert await store.get_by_token_hash("kept") == kept

    async def test_revoking_an_unknown_session_reports_that_nothing_went(
        self, store: InMemorySessionStore
    ) -> None:
        assert not await store.revoke("sess_nope")

    async def test_saving_records_a_session_s_last_use(self, store: InMemorySessionStore) -> None:
        # Every authenticated request touches its session; without this the idle window
        # would be measured from login rather than from last use.
        session = make_session("acct_1", token_hash="abc")
        await store.add(session)

        used = session.touched(
            now=EPOCH + timedelta(minutes=10), idle_ttl_seconds=3_600, absolute_expires_at=None
        )
        await store.save(used)

        assert await store.get_by_token_hash("abc") == used

    async def test_revoking_everything_for_an_account_spares_other_accounts(
        self, store: InMemorySessionStore
    ) -> None:
        # This is what "log out everywhere" and "password changed" both run. Catching
        # one session too few leaves an attacker logged in; one too many logs out a
        # bystander.
        mine = make_session("acct_1", token_hash="mine")
        also_mine = make_session("acct_1", token_hash="also-mine")
        theirs = make_session("acct_2", token_hash="theirs")
        for session in (mine, also_mine, theirs):
            await store.add(session)

        assert await store.revoke_all("acct_1") == 2

        assert await store.get_by_token_hash("theirs") == theirs
        assert await store.get_by_token_hash("mine") is None

    async def test_revoking_everything_except_one_keeps_the_caller_logged_in(
        self, store: InMemorySessionStore
    ) -> None:
        # A password change should not log the person out of the browser tab they just
        # changed it in.
        current = make_session("acct_1", token_hash="current")
        other = make_session("acct_1", token_hash="other")
        await store.add(current)
        await store.add(other)

        assert await store.revoke_all("acct_1", except_session_id=current.session_id) == 1

        assert await store.get_by_token_hash("current") == current
        assert await store.get_by_token_hash("other") is None

    async def test_an_expired_session_is_not_returned(
        self, store: InMemorySessionStore, clock: FakeClock
    ) -> None:
        # Expiry has to be enforced on read, not only by the sweeper. A session that has
        # passed its deadline must stop working the moment it does, whether or not
        # anything has swept since.
        await store.add(make_session("acct_1", token_hash="abc"))

        clock.advance(timedelta(hours=2))

        assert await store.get_by_token_hash("abc") is None

    async def test_sweeping_drops_expired_sessions_and_reports_how_many(
        self, store: InMemorySessionStore, clock: FakeClock
    ) -> None:
        await store.add(make_session("acct_1", token_hash="old"))
        await store.add(
            make_session(
                "acct_1",
                token_hash="new",
                expires_at=EPOCH + timedelta(days=10),
                absolute_expires_at=EPOCH + timedelta(days=20),
            )
        )

        clock.advance(timedelta(hours=2))

        assert await store.purge_expired() == 1
        assert await store.count_for_account("acct_1") == 1

    async def test_counting_a_session_for_an_account_ignores_expired_ones(
        self, store: InMemorySessionStore, clock: FakeClock
    ) -> None:
        # The per-account session cap must not be filled by sessions that no longer
        # work, or a person who logs in from enough devices is locked out for a fortnight.
        await store.add(make_session("acct_1"))

        clock.advance(timedelta(hours=2))

        assert await store.count_for_account("acct_1") == 0

    async def test_the_oldest_session_can_be_dropped_to_make_room(
        self, store: InMemorySessionStore
    ) -> None:
        oldest = make_session("acct_1", token_hash="oldest")
        newer = make_session("acct_1", token_hash="newer", created_at=EPOCH + timedelta(hours=1))
        await store.add(oldest)
        await store.add(newer)

        assert await store.drop_oldest("acct_1") == 1

        assert await store.get_by_token_hash("oldest") is None
        assert await store.get_by_token_hash("newer") == newer

    async def test_dropping_the_oldest_of_nothing_is_not_an_error(
        self, store: InMemorySessionStore
    ) -> None:
        assert await store.drop_oldest("acct_1") == 0


class TestGrantStore:
    @pytest.fixture
    def store(self) -> InMemoryGrantStore:
        return InMemoryGrantStore()

    async def test_it_satisfies_the_port(self, store: InMemoryGrantStore) -> None:
        checked: GrantStore = store

        assert isinstance(checked, GrantStore)

    async def test_a_grant_is_found_by_the_hash_of_the_presented_token(
        self, store: InMemoryGrantStore
    ) -> None:
        grant = make_grant(token_hash="abc")
        await store.add(grant)

        assert await store.get_by_token_hash("abc") == grant

    async def test_an_unknown_token_finds_nothing(self, store: InMemoryGrantStore) -> None:
        assert await store.get_by_token_hash("nope") is None

    async def test_an_expired_grant_is_still_returned_so_the_caller_can_reject_it(
        self, store: InMemoryGrantStore
    ) -> None:
        # Unlike sessions. Redeeming is a single decision point that already has to
        # distinguish used from unused, so it makes that judgement in one place --
        # is_redeemable -- rather than having half of it silently applied on read.
        grant = make_grant(token_hash="abc", expires_at=EPOCH)
        await store.add(grant)

        assert await store.get_by_token_hash("abc") == grant

    async def test_redeeming_is_atomic_so_two_requests_cannot_both_win(
        self, store: InMemoryGrantStore
    ) -> None:
        # Two clicks on the same reset link, or a token leaked and raced. Exactly one
        # must succeed, and read-then-write in the caller cannot guarantee that.
        grant = make_grant(token_hash="abc")
        await store.add(grant)

        assert await store.redeem("abc", now=EPOCH) is not None
        assert await store.redeem("abc", now=EPOCH) is None

    async def test_redeeming_an_expired_grant_fails(self, store: InMemoryGrantStore) -> None:
        await store.add(make_grant(token_hash="abc", expires_at=EPOCH))

        assert await store.redeem("abc", now=EPOCH) is None

    async def test_redeeming_an_unknown_token_fails(self, store: InMemoryGrantStore) -> None:
        assert await store.redeem("nope", now=EPOCH) is None

    async def test_revoking_an_account_s_resets_leaves_its_invites_alone(
        self, store: InMemoryGrantStore
    ) -> None:
        # Every outstanding reset dies when a password changes. An invite is a different
        # purpose and a different lifecycle, and must not be collateral.
        reset = make_grant(
            token_hash="reset",
            purpose=GrantPurpose.PASSWORD_RESET,
            account_id="acct_1",
            email=None,
        )
        invite = make_grant(token_hash="invite", account_id="acct_1")
        await store.add(reset)
        await store.add(invite)

        assert await store.revoke_all_for_account("acct_1", GrantPurpose.PASSWORD_RESET) == 1

        redeemed = await store.redeem("reset", now=EPOCH)
        assert redeemed is None
        assert await store.redeem("invite", now=EPOCH) is not None

    async def test_revoking_spares_other_accounts(self, store: InMemoryGrantStore) -> None:
        await store.add(
            make_grant(
                token_hash="theirs",
                purpose=GrantPurpose.PASSWORD_RESET,
                account_id="acct_2",
                email=None,
            )
        )

        assert await store.revoke_all_for_account("acct_1", GrantPurpose.PASSWORD_RESET) == 0

    async def test_sweeping_drops_expired_grants(self, store: InMemoryGrantStore) -> None:
        await store.add(make_grant(token_hash="old", expires_at=EPOCH))
        await store.add(make_grant(token_hash="new", expires_at=EPOCH + timedelta(days=1)))

        assert await store.purge_expired(now=EPOCH + timedelta(hours=1)) == 1
        assert await store.get_by_token_hash("old") is None

    async def test_deleting_an_account_takes_its_grants_with_it(
        self, store: InMemoryGrantStore
    ) -> None:
        await store.add(make_grant(token_hash="mine", account_id="acct_1"))
        await store.add(make_grant(token_hash="theirs", account_id="acct_2"))

        assert await store.delete_for_account("acct_1") == 1
        assert await store.get_by_token_hash("theirs") is not None
