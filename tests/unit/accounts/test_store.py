"""The account, session and grant stores.

Written against the ports rather than the SQL, so a Postgres adapter would inherit this
suite unchanged.

Two things changed shape when these moved out of memory, and both show up in the setup
here. Sessions and grants are foreign-keyed to an account, so a test has to say which
account they belong to rather than inventing an id -- an orphaned session is a live
credential that nothing will ever revoke. And the per-account session cap is now the
store's job rather than the caller's, because a caller doing it in two steps loses the
race; see :class:`TestSessionCap`.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from keyring_api.accounts.sql_store import SqlAccountStore, SqlGrantStore, SqlSessionStore
from keyring_api.accounts.store import AccountStore, GrantStore, SessionStore
from keyring_api.domain.accounts import Account, AccountStatus, new_account_id
from keyring_api.domain.errors import AccountExistsError
from keyring_api.domain.grants import Grant, GrantPurpose, new_grant_id
from keyring_api.domain.sessions import Session, new_session_id
from tests.fakes.clock import EPOCH, FakeClock

if TYPE_CHECKING:
    from keyring_api.storage.database import Database


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


@pytest.fixture
async def accounts(database: Database) -> SqlAccountStore:
    """An account store already holding ``acct_1`` and ``acct_2``.

    Sessions and grants reference an account row, so they need one to exist. Two, so a
    test can check that an operation on one account spares the other.
    """
    store = SqlAccountStore(database=database)
    for account_id in ("acct_1", "acct_2"):
        await store.add(make_account(f"{account_id}@example.com", account_id=account_id))
    return store


class TestAccountStore:
    @pytest.fixture
    def store(self, database: Database) -> SqlAccountStore:
        return SqlAccountStore(database=database)

    async def test_it_satisfies_the_port(self, store: SqlAccountStore) -> None:
        checked: AccountStore = store

        assert isinstance(checked, AccountStore)

    async def test_an_added_account_can_be_read_back_by_id(self, store: SqlAccountStore) -> None:
        account = make_account()

        await store.add(account)

        assert await store.get(account.account_id) == account

    async def test_an_unknown_id_reads_back_as_absent_rather_than_raising(
        self, store: SqlAccountStore
    ) -> None:
        # The caller decides what a missing account means, and at a login it must mean
        # the same thing as a wrong password.
        assert await store.get("acct_nope") is None

    async def test_an_account_can_be_found_by_the_address_someone_logs_in_with(
        self, store: SqlAccountStore
    ) -> None:
        account = make_account("Person@Example.com".lower())

        await store.add(account)

        assert await store.get_by_email("person@example.com") == account

    async def test_an_unknown_address_finds_nothing(self, store: SqlAccountStore) -> None:
        assert await store.get_by_email("nobody@example.com") is None

    async def test_a_second_account_for_the_same_address_is_refused(
        self, store: SqlAccountStore
    ) -> None:
        await store.add(make_account())

        with pytest.raises(AccountExistsError):
            await store.add(make_account())

    async def test_a_refused_duplicate_leaves_the_first_account_intact(
        self, store: SqlAccountStore
    ) -> None:
        first = make_account()
        await store.add(first)

        with pytest.raises(AccountExistsError):
            await store.add(make_account())

        assert await store.get(first.account_id) == first
        assert await store.count() == 1

    async def test_saving_replaces_the_stored_account(self, store: SqlAccountStore) -> None:
        account = make_account()
        await store.add(account)

        await store.save(account.with_failure(now=EPOCH, lockout_threshold=5, lockout_seconds=60))

        stored = await store.get(account.account_id)
        assert stored is not None
        assert stored.failed_attempts == 1

    async def test_saving_round_trips_every_field(self, store: SqlAccountStore) -> None:
        """The row-mapper in both directions, including the nullable and enum columns."""
        account = make_account(
            status=AccountStatus.DISABLED,
            failed_attempts=3,
            locked_until=EPOCH + timedelta(minutes=15),
            roles=("admin", "auditor"),
        )
        await store.add(account)

        assert await store.get(account.account_id) == account

    async def test_roles_come_back_in_the_order_they_were_given(
        self, store: SqlAccountStore
    ) -> None:
        account = make_account(roles=("auditor", "admin", "member"))
        await store.add(account)

        stored = await store.get(account.account_id)
        assert stored is not None
        assert stored.roles == ("auditor", "admin", "member")

    async def test_a_role_named_twice_is_held_once(self, store: SqlAccountStore) -> None:
        # Holding a role twice is not a thing; the union of permissions is identical
        # either way, and storing it twice would only make the duplicate visible in a
        # listing. Normalized on the way in rather than left for a reader to wonder at.
        account = make_account(roles=("admin", "admin", "auditor"))
        await store.add(account)

        stored = await store.get(account.account_id)
        assert stored is not None
        assert stored.roles == ("admin", "auditor")

    async def test_deleting_removes_it_from_both_lookups(self, store: SqlAccountStore) -> None:
        # The address is a second way to reach the same row; leaving it behind would
        # make the address permanently un-invitable.
        account = make_account()
        await store.add(account)

        assert await store.delete(account.account_id)
        assert await store.get(account.account_id) is None
        assert await store.get_by_email(account.email) is None

    async def test_deleting_an_unknown_account_reports_that_nothing_went(
        self, store: SqlAccountStore
    ) -> None:
        assert not await store.delete("acct_nope")

    async def test_it_counts_what_it_holds(self, store: SqlAccountStore) -> None:
        await store.add(make_account("a@example.com"))
        await store.add(make_account("b@example.com"))

        assert await store.count() == 2

    async def test_an_empty_store_counts_zero(self, store: SqlAccountStore) -> None:
        assert await store.count() == 0

    async def test_deleting_an_account_takes_its_sessions_with_it(
        self, accounts: SqlAccountStore, database: Database, clock: FakeClock
    ) -> None:
        """The cascade is the schema's, not a sequence somebody has to remember.

        An orphaned session row is a live credential that nothing will ever revoke,
        because nothing knows it is there.
        """
        sessions = SqlSessionStore(database=database, clock=clock)
        await sessions.add(make_session("acct_1", token_hash="doomed"))
        await sessions.add(make_session("acct_2", token_hash="spared"))

        await accounts.delete("acct_1")

        assert await sessions.get_by_token_hash("doomed") is None
        assert await sessions.get_by_token_hash("spared") is not None

    async def test_deleting_an_account_takes_its_grants_with_it(
        self, accounts: SqlAccountStore, database: Database
    ) -> None:
        grants = SqlGrantStore(database=database)
        await grants.add(make_grant(token_hash="doomed", account_id="acct_1"))
        await grants.add(make_grant(token_hash="spared", account_id="acct_2"))

        await accounts.delete("acct_1")

        assert await grants.get_by_token_hash("doomed") is None
        assert await grants.get_by_token_hash("spared") is not None


class TestSessionStore:
    @pytest.fixture
    def store(
        self,
        database: Database,
        clock: FakeClock,
        accounts: SqlAccountStore,  # noqa: ARG002 -- the accounts these sessions belong to
    ) -> SqlSessionStore:
        return SqlSessionStore(database=database, clock=clock)

    async def test_it_satisfies_the_port(self, store: SqlSessionStore) -> None:
        checked: SessionStore = store

        assert isinstance(checked, SessionStore)

    async def test_a_session_is_found_by_the_hash_of_the_presented_token(
        self, store: SqlSessionStore
    ) -> None:
        # Lookup is by hash, never by token: the token is not stored, so there is
        # nothing else it could be looked up by.
        session = make_session("acct_1", token_hash="abc")
        await store.add(session)

        assert await store.get_by_token_hash("abc") == session

    async def test_an_unknown_token_finds_nothing(self, store: SqlSessionStore) -> None:
        assert await store.get_by_token_hash("nope") is None

    async def test_revoking_one_session_leaves_the_others_alone(
        self, store: SqlSessionStore
    ) -> None:
        kept = make_session("acct_1", token_hash="kept")
        revoked = make_session("acct_1", token_hash="revoked")
        await store.add(kept)
        await store.add(revoked)

        assert await store.revoke(revoked.session_id)

        assert await store.get_by_token_hash("revoked") is None
        assert await store.get_by_token_hash("kept") == kept

    async def test_revoking_an_unknown_session_reports_that_nothing_went(
        self, store: SqlSessionStore
    ) -> None:
        assert not await store.revoke("sess_nope")

    async def test_saving_records_a_session_s_last_use(self, store: SqlSessionStore) -> None:
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
        self, store: SqlSessionStore
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
        self, store: SqlSessionStore
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
        self, store: SqlSessionStore, clock: FakeClock
    ) -> None:
        # Expiry has to be enforced on read, not only by the sweeper. A session that has
        # passed its deadline must stop working the moment it does, whether or not
        # anything has swept since.
        await store.add(make_session("acct_1", token_hash="abc"))

        clock.advance(timedelta(hours=2))

        assert await store.get_by_token_hash("abc") is None

    async def test_a_session_past_only_its_absolute_deadline_is_not_returned(
        self, store: SqlSessionStore, clock: FakeClock
    ) -> None:
        """Both deadlines are enforced, not whichever one the query happened to mention."""
        await store.add(
            make_session(
                "acct_1",
                token_hash="abc",
                expires_at=EPOCH + timedelta(days=30),
                absolute_expires_at=EPOCH + timedelta(hours=1),
            )
        )

        clock.advance(timedelta(hours=2))

        assert await store.get_by_token_hash("abc") is None

    async def test_sweeping_drops_expired_sessions_and_reports_how_many(
        self, store: SqlSessionStore, clock: FakeClock
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
        self, store: SqlSessionStore, clock: FakeClock
    ) -> None:
        # The per-account session cap must not be filled by sessions that no longer
        # work, or a person who logs in from enough devices is locked out for a fortnight.
        await store.add(make_session("acct_1"))

        clock.advance(timedelta(hours=2))

        assert await store.count_for_account("acct_1") == 0

    async def test_the_oldest_session_can_be_dropped_to_make_room(
        self, store: SqlSessionStore
    ) -> None:
        oldest = make_session("acct_1", token_hash="oldest")
        newer = make_session("acct_1", token_hash="newer", created_at=EPOCH + timedelta(hours=1))
        await store.add(oldest)
        await store.add(newer)

        assert await store.drop_oldest("acct_1") == 1

        assert await store.get_by_token_hash("oldest") is None
        assert await store.get_by_token_hash("newer") == newer

    async def test_dropping_the_oldest_of_nothing_is_not_an_error(
        self, store: SqlSessionStore
    ) -> None:
        assert await store.drop_oldest("acct_1") == 0


class TestSessionCap:
    """Storing a session and enforcing the cap, as one operation.

    This used to be a loop in the caller -- count, drop the oldest, count again -- and
    the tests below are the reason it is not any more.
    """

    @pytest.fixture
    def store(
        self,
        database: Database,
        clock: FakeClock,
        accounts: SqlAccountStore,  # noqa: ARG002 -- the accounts these sessions belong to
    ) -> SqlSessionStore:
        return SqlSessionStore(database=database, clock=clock)

    async def test_it_stores_the_session(self, store: SqlSessionStore) -> None:
        await store.add_within_cap(make_session("acct_1", token_hash="abc"), cap=5)

        assert await store.get_by_token_hash("abc") is not None

    async def test_it_drops_nothing_while_there_is_room(self, store: SqlSessionStore) -> None:
        assert await store.add_within_cap(make_session("acct_1", token_hash="a"), cap=3) == 0
        assert await store.add_within_cap(make_session("acct_1", token_hash="b"), cap=3) == 0

    async def test_it_drops_the_oldest_once_the_cap_is_reached(
        self, store: SqlSessionStore
    ) -> None:
        for index in range(3):
            await store.add_within_cap(
                make_session(
                    "acct_1",
                    token_hash=f"s{index}",
                    created_at=EPOCH + timedelta(minutes=index),
                ),
                cap=3,
            )

        dropped = await store.add_within_cap(
            make_session("acct_1", token_hash="newest", created_at=EPOCH + timedelta(hours=1)),
            cap=3,
        )

        assert dropped == 1
        assert await store.get_by_token_hash("s0") is None
        assert await store.get_by_token_hash("newest") is not None

    async def test_it_spares_other_accounts(self, store: SqlSessionStore) -> None:
        await store.add_within_cap(make_session("acct_2", token_hash="theirs"), cap=1)

        await store.add_within_cap(make_session("acct_1", token_hash="mine"), cap=1)

        assert await store.get_by_token_hash("theirs") is not None

    async def test_concurrent_logins_cannot_exceed_the_cap(
        self, store: SqlSessionStore, database: Database
    ) -> None:
        """The race the old count-then-drop loop lost.

        Twenty logins arriving at once, each of which would have read "there is room"
        before any of them wrote. The cap is a cap or it is a suggestion.
        """
        await asyncio.gather(
            *(
                store.add_within_cap(
                    make_session(
                        "acct_1",
                        token_hash=f"token-{index}",
                        created_at=EPOCH + timedelta(seconds=index),
                    ),
                    cap=5,
                )
                for index in range(20)
            )
        )

        rows = await database.fetch_all(
            "SELECT session_id FROM sessions WHERE account_id = 'acct_1'"
        )
        assert len(rows) == 5

    async def test_the_survivors_are_the_newest(self, store: SqlSessionStore) -> None:
        for index in range(6):
            await store.add_within_cap(
                make_session(
                    "acct_1",
                    token_hash=f"s{index}",
                    created_at=EPOCH + timedelta(minutes=index),
                ),
                cap=2,
            )

        assert await store.get_by_token_hash("s5") is not None
        assert await store.get_by_token_hash("s4") is not None
        assert await store.get_by_token_hash("s3") is None


class TestGrantStore:
    @pytest.fixture
    def store(
        self,
        database: Database,
        accounts: SqlAccountStore,  # noqa: ARG002 -- the accounts these grants belong to
    ) -> SqlGrantStore:
        return SqlGrantStore(database=database)

    async def test_it_satisfies_the_port(self, store: SqlGrantStore) -> None:
        checked: GrantStore = store

        assert isinstance(checked, GrantStore)

    async def test_a_grant_is_found_by_the_hash_of_the_presented_token(
        self, store: SqlGrantStore
    ) -> None:
        grant = make_grant(token_hash="abc")
        await store.add(grant)

        assert await store.get_by_token_hash("abc") == grant

    async def test_an_unknown_token_finds_nothing(self, store: SqlGrantStore) -> None:
        assert await store.get_by_token_hash("nope") is None

    async def test_an_expired_grant_is_still_returned_so_the_caller_can_reject_it(
        self, store: SqlGrantStore
    ) -> None:
        # Unlike sessions. Redeeming is a single decision point that already has to
        # distinguish used from unused, so it makes that judgement in one place --
        # is_redeemable -- rather than having half of it silently applied on read.
        grant = make_grant(token_hash="abc", expires_at=EPOCH)
        await store.add(grant)

        assert await store.get_by_token_hash("abc") == grant

    async def test_a_redeemed_grant_round_trips_its_redemption(self, store: SqlGrantStore) -> None:
        await store.add(make_grant(token_hash="abc"))

        redeemed = await store.redeem("abc", now=EPOCH)

        assert redeemed is not None
        assert redeemed.redeemed_at == EPOCH
        assert await store.get_by_token_hash("abc") == redeemed

    async def test_redeeming_is_atomic_so_two_requests_cannot_both_win(
        self, store: SqlGrantStore
    ) -> None:
        # Two clicks on the same reset link, or a token leaked and raced. Exactly one
        # must succeed, and read-then-write in the caller cannot guarantee that.
        grant = make_grant(token_hash="abc")
        await store.add(grant)

        assert await store.redeem("abc", now=EPOCH) is not None
        assert await store.redeem("abc", now=EPOCH) is None

    async def test_twenty_simultaneous_redemptions_produce_exactly_one_winner(
        self, store: SqlGrantStore
    ) -> None:
        """The same property, put under actual concurrency rather than in sequence."""
        await store.add(make_grant(token_hash="abc"))

        results = await asyncio.gather(*(store.redeem("abc", now=EPOCH) for _ in range(20)))

        assert sum(1 for result in results if result is not None) == 1

    async def test_redeeming_an_expired_grant_fails(self, store: SqlGrantStore) -> None:
        await store.add(make_grant(token_hash="abc", expires_at=EPOCH))

        assert await store.redeem("abc", now=EPOCH) is None

    async def test_redeeming_a_revoked_grant_fails(self, store: SqlGrantStore) -> None:
        await store.add(
            make_grant(
                token_hash="abc",
                purpose=GrantPurpose.PASSWORD_RESET,
                account_id="acct_1",
                email=None,
            )
        )
        await store.revoke_all_for_account("acct_1", GrantPurpose.PASSWORD_RESET)

        assert await store.redeem("abc", now=EPOCH) is None

    async def test_redeeming_an_unknown_token_fails(self, store: SqlGrantStore) -> None:
        assert await store.redeem("nope", now=EPOCH) is None

    async def test_revoking_an_account_s_resets_leaves_its_invites_alone(
        self, store: SqlGrantStore
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

    async def test_revoking_twice_reports_nothing_the_second_time(
        self, store: SqlGrantStore
    ) -> None:
        await store.add(
            make_grant(
                token_hash="reset",
                purpose=GrantPurpose.PASSWORD_RESET,
                account_id="acct_1",
                email=None,
            )
        )
        await store.revoke_all_for_account("acct_1", GrantPurpose.PASSWORD_RESET)

        assert await store.revoke_all_for_account("acct_1", GrantPurpose.PASSWORD_RESET) == 0

    async def test_revoking_spares_other_accounts(self, store: SqlGrantStore) -> None:
        await store.add(
            make_grant(
                token_hash="theirs",
                purpose=GrantPurpose.PASSWORD_RESET,
                account_id="acct_2",
                email=None,
            )
        )

        assert await store.revoke_all_for_account("acct_1", GrantPurpose.PASSWORD_RESET) == 0

    async def test_sweeping_drops_expired_grants(self, store: SqlGrantStore) -> None:
        await store.add(make_grant(token_hash="old", expires_at=EPOCH))
        await store.add(make_grant(token_hash="new", expires_at=EPOCH + timedelta(days=1)))

        assert await store.purge_expired(now=EPOCH + timedelta(hours=1)) == 1
        assert await store.get_by_token_hash("old") is None

    async def test_deleting_an_account_takes_its_grants_with_it(self, store: SqlGrantStore) -> None:
        await store.add(make_grant(token_hash="mine", account_id="acct_1"))
        await store.add(make_grant(token_hash="theirs", account_id="acct_2"))

        assert await store.delete_for_account("acct_1") == 1
        assert await store.get_by_token_hash("theirs") is not None
