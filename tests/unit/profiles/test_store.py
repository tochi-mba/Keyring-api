"""The profile store, and the isolation that is built into its signatures.

Profiles are foreign-keyed to an account, so these tests create the accounts they hang
off rather than inventing ids -- which is the point: a profile whose owner does not exist
is credential metadata nothing can reach and nothing will collect.

:class:`TestConnections` is the part that is new. A connection used to be a field inside
its profile, and adding one was read-modify-write on the whole record.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from keyring_api.accounts.sql_store import SqlAccountStore
from keyring_api.domain.accounts import Account
from keyring_api.domain.errors import (
    LimitExceededError,
    ProfileExistsError,
    ProfileNotFoundError,
)
from keyring_api.domain.profiles import (
    Connection,
    ConnectionStatus,
    CredentialKind,
    Profile,
    new_profile_id,
)
from keyring_api.profiles.sql_store import SqlProfileStore
from keyring_api.profiles.store import ProfileStore
from tests.fakes.clock import EPOCH

if TYPE_CHECKING:
    from keyring_api.storage.database import Database

ACCOUNTS = ("acct_1", "acct_a", "acct_b")
CAP = 20
"""A cap high enough to be out of the way; the cap itself is tested in TestCaps."""


def make_profile(
    account_id: str = "acct_1", name: str = "personal", **overrides: object
) -> Profile:
    defaults: dict[str, object] = {
        "profile_id": new_profile_id(),
        "account_id": account_id,
        "name": name,
        "created_at": EPOCH,
        "updated_at": EPOCH,
    }
    return Profile(**{**defaults, **overrides})  # type: ignore[arg-type]


def make_connection(service: str = "spotify", **overrides: object) -> Connection:
    defaults: dict[str, object] = {
        "service": service,
        "kind": CredentialKind.API_KEY,
        "status": ConnectionStatus.ACTIVE,
        "created_at": EPOCH,
        "updated_at": EPOCH,
    }
    return Connection(**{**defaults, **overrides})  # type: ignore[arg-type]


@pytest.fixture
async def store(database: Database) -> SqlProfileStore:
    accounts = SqlAccountStore(database=database)
    for account_id in ACCOUNTS:
        await accounts.add(
            Account(
                account_id=account_id,
                email=f"{account_id}@example.com",
                password_hash="$argon2id$fake",
                created_at=EPOCH,
                updated_at=EPOCH,
            )
        )
    return SqlProfileStore(database=database)


async def test_it_satisfies_the_port(store: SqlProfileStore) -> None:
    checked: ProfileStore = store

    assert isinstance(checked, ProfileStore)


async def test_a_stored_profile_reads_back(store: SqlProfileStore) -> None:
    profile = make_profile()
    await store.add(profile, cap=CAP)

    assert await store.get("acct_1", "personal") == profile


async def test_an_unknown_profile_reads_back_as_absent(store: SqlProfileStore) -> None:
    assert await store.get("acct_1", "personal") is None


async def test_one_account_cannot_read_another_s_profile(store: SqlProfileStore) -> None:
    # Absent, not forbidden. A distinguishable "not yours" would tell one person that
    # another person has a profile by that name.
    await store.add(make_profile("acct_a", "personal"), cap=CAP)

    assert await store.get("acct_b", "personal") is None


async def test_two_accounts_can_each_have_a_profile_of_the_same_name(
    store: SqlProfileStore,
) -> None:
    # "personal" is the name everybody picks. Names are scoped to the account, and would
    # be useless if the first person to use one took it from everybody else.
    await store.add(make_profile("acct_a", "personal"), cap=CAP)
    await store.add(make_profile("acct_b", "personal"), cap=CAP)

    assert await store.count_for_account("acct_a") == 1
    assert await store.count_for_account("acct_b") == 1


async def test_one_account_cannot_have_two_profiles_of_the_same_name(
    store: SqlProfileStore,
) -> None:
    await store.add(make_profile(), cap=CAP)

    with pytest.raises(ProfileExistsError):
        await store.add(make_profile(), cap=CAP)


async def test_a_refused_duplicate_leaves_the_first_profile_intact(
    store: SqlProfileStore,
) -> None:
    first = make_profile()
    await store.add(first, cap=CAP)

    with pytest.raises(ProfileExistsError):
        await store.add(make_profile(), cap=CAP)

    assert await store.get("acct_1", "personal") == first


async def test_profiles_are_listed_oldest_first(store: SqlProfileStore) -> None:
    await store.add(make_profile("acct_1", "second", created_at=EPOCH + timedelta(days=1)), cap=CAP)
    await store.add(make_profile("acct_1", "first"), cap=CAP)

    assert [profile.name for profile in await store.list_for_account("acct_1")] == [
        "first",
        "second",
    ]


async def test_listing_shows_only_this_account_s_profiles(store: SqlProfileStore) -> None:
    await store.add(make_profile("acct_a", "mine"), cap=CAP)
    await store.add(make_profile("acct_b", "theirs"), cap=CAP)

    assert [profile.name for profile in await store.list_for_account("acct_a")] == ["mine"]


async def test_listing_every_profile_crosses_accounts_because_the_health_check_needs_it(
    store: SqlProfileStore,
) -> None:
    await store.add(make_profile("acct_a", "mine"), cap=CAP)
    await store.add(make_profile("acct_b", "theirs"), cap=CAP)

    assert len(await store.all_profiles()) == 2


async def test_deleting_removes_it(store: SqlProfileStore) -> None:
    await store.add(make_profile(), cap=CAP)

    assert await store.delete("acct_1", "personal")
    assert await store.get("acct_1", "personal") is None


async def test_deleting_someone_else_s_profile_does_nothing(store: SqlProfileStore) -> None:
    # The most important isolation test here: a read that leaks is bad, a *write* that
    # crosses accounts destroys somebody else's data.
    await store.add(make_profile("acct_a", "personal"), cap=CAP)

    assert not await store.delete("acct_b", "personal")
    assert await store.get("acct_a", "personal") is not None


async def test_deleting_an_unknown_profile_reports_that_nothing_went(
    store: SqlProfileStore,
) -> None:
    assert not await store.delete("acct_1", "personal")


async def test_deleting_an_account_takes_only_its_own_profiles(store: SqlProfileStore) -> None:
    await store.add(make_profile("acct_a", "one"), cap=CAP)
    await store.add(make_profile("acct_a", "two"), cap=CAP)
    await store.add(make_profile("acct_b", "one"), cap=CAP)

    assert await store.delete_for_account("acct_a") == 2
    assert await store.count_for_account("acct_b") == 1


async def test_deleting_the_account_row_takes_its_profiles(
    store: SqlProfileStore, database: Database
) -> None:
    """The cascade, rather than a second call somebody has to remember."""
    await store.add(make_profile("acct_a", "one"), cap=CAP)

    await SqlAccountStore(database=database).delete("acct_a")

    assert await store.count_for_account("acct_a") == 0


class TestConnections:
    """A connection is a row, and this is what that bought."""

    async def test_a_connection_round_trips_every_field(self, store: SqlProfileStore) -> None:
        await store.add(make_profile(), cap=CAP)
        connection = make_connection(
            "spotify",
            kind=CredentialKind.OAUTH2_AUTHORIZATION_CODE,
            status=ConnectionStatus.EXPIRED,
            expires_at=EPOCH + timedelta(hours=1),
            scopes=("read", "write"),
            stores_totp_seed=True,
            last_error="the provider said no",
        )

        await store.put_connection("acct_1", "personal", connection, cap=CAP, now=EPOCH)

        stored = await store.get("acct_1", "personal")
        assert stored is not None
        assert stored.connection("spotify") == connection

    async def test_a_connection_with_no_scopes_or_expiry_round_trips_too(
        self, store: SqlProfileStore
    ) -> None:
        await store.add(make_profile(), cap=CAP)

        await store.put_connection("acct_1", "personal", make_connection(), cap=CAP, now=EPOCH)

        stored = await store.get("acct_1", "personal")
        assert stored is not None
        held = stored.connection("spotify")
        assert held is not None
        assert held.expires_at is None
        assert held.scopes == ()
        assert held.last_error is None

    async def test_a_profile_can_be_created_with_connections_already_on_it(
        self, store: SqlProfileStore
    ) -> None:
        await store.add(
            make_profile(connections=(make_connection("spotify"), make_connection("tmdb"))), cap=CAP
        )

        stored = await store.get("acct_1", "personal")
        assert stored is not None
        assert {item.service for item in stored.connections} == {"spotify", "tmdb"}

    async def test_removing_a_connection_removes_its_row(
        self, store: SqlProfileStore, database: Database
    ) -> None:
        await store.add(make_profile(connections=(make_connection("spotify"),)), cap=CAP)

        assert await store.remove_connection("acct_1", "personal", "spotify", now=EPOCH)

        assert await database.fetch_all("SELECT service FROM connections") == []

    async def test_removing_a_connection_that_is_not_there_reports_that_nothing_went(
        self, store: SqlProfileStore
    ) -> None:
        await store.add(make_profile(), cap=CAP)

        assert not await store.remove_connection("acct_1", "personal", "spotify", now=EPOCH)

    async def test_replacing_one_connection_leaves_the_others_alone(
        self, store: SqlProfileStore
    ) -> None:
        await store.add(
            make_profile(connections=(make_connection("spotify"), make_connection("tmdb"))),
            cap=CAP,
        )

        await store.put_connection(
            "acct_1",
            "personal",
            make_connection("spotify", status=ConnectionStatus.REVOKED),
            cap=CAP,
            now=EPOCH,
        )

        stored = await store.get("acct_1", "personal")
        assert stored is not None
        assert {item.service for item in stored.connections} == {"spotify", "tmdb"}
        spotify = stored.connection("spotify")
        assert spotify is not None
        assert spotify.status is ConnectionStatus.REVOKED

    async def test_replacing_a_connection_keeps_the_date_it_was_first_made(
        self, store: SqlProfileStore
    ) -> None:
        """A refresh replaces a connection several times a day.

        Resetting created_at each time would make "connected since" mean "last
        refreshed", which is a different fact and a less useful one.
        """
        await store.add(make_profile(connections=(make_connection("spotify"),)), cap=CAP)
        later = EPOCH + timedelta(days=30)

        stored = await store.put_connection(
            "acct_1",
            "personal",
            make_connection("spotify", created_at=later, updated_at=later),
            cap=CAP,
            now=later,
        )

        assert stored.created_at == EPOCH
        assert stored.updated_at == later

    async def test_writing_to_a_profile_that_is_gone_is_refused(
        self, store: SqlProfileStore
    ) -> None:
        # Callers reach this after a network round trip, so the profile really can have
        # been deleted since they read it. The token just obtained is discarded.
        with pytest.raises(ProfileNotFoundError):
            await store.put_connection("acct_1", "personal", make_connection(), cap=CAP, now=EPOCH)

    async def test_writing_a_connection_touches_the_profile(self, store: SqlProfileStore) -> None:
        await store.add(make_profile(), cap=CAP)
        later = EPOCH + timedelta(hours=1)

        await store.put_connection("acct_1", "personal", make_connection(), cap=CAP, now=later)

        stored = await store.get("acct_1", "personal")
        assert stored is not None
        assert stored.updated_at == later

    async def test_removing_a_connection_touches_the_profile(self, store: SqlProfileStore) -> None:
        await store.add(make_profile(connections=(make_connection(),)), cap=CAP)
        later = EPOCH + timedelta(hours=1)

        await store.remove_connection("acct_1", "personal", "spotify", now=later)

        stored = await store.get("acct_1", "personal")
        assert stored is not None
        assert stored.updated_at == later

    async def test_deleting_a_profile_takes_its_connections(
        self, store: SqlProfileStore, database: Database
    ) -> None:
        await store.add(make_profile(connections=(make_connection(),)), cap=CAP)

        await store.delete("acct_1", "personal")

        assert await database.fetch_all("SELECT service FROM connections") == []

    async def test_two_accounts_can_connect_the_same_service_in_a_profile_of_one_name(
        self, store: SqlProfileStore
    ) -> None:
        await store.add(
            make_profile("acct_a", "personal", connections=(make_connection(),)), cap=CAP
        )
        await store.add(
            make_profile("acct_b", "personal", connections=(make_connection(),)), cap=CAP
        )

        mine = await store.get("acct_a", "personal")
        theirs = await store.get("acct_b", "personal")
        assert mine is not None
        assert theirs is not None
        assert len(mine.connections) == 1
        assert len(theirs.connections) == 1

    async def test_concurrent_saves_of_different_connections_do_not_lose_each_other(
        self, store: SqlProfileStore
    ) -> None:
        """The lost update this table exists to prevent.

        Held inside the profile, each of these read the profile, added its own connection
        to what it had read, and wrote back a record missing every other one. As rows,
        each write names one connection and touches nothing else, and all five survive.
        """
        await store.add(make_profile(), cap=CAP)
        services = ("spotify", "tmdb", "trakt", "plex", "lastfm")

        await asyncio.gather(
            *(
                store.put_connection(
                    "acct_1", "personal", make_connection(service), cap=CAP, now=EPOCH
                )
                for service in services
            )
        )

        stored = await store.get("acct_1", "personal")
        assert stored is not None
        assert {item.service for item in stored.connections} == set(services)


class TestCaps:
    """Both caps are enforced by the store, because a caller cannot enforce them.

    A caller counts and then writes, and two requests arriving together both read a count
    from before either of them wrote. The window is small and the consequence is only a
    resource bound overshot -- which is why it is worth fixing here rather than defending
    at length elsewhere.
    """

    async def test_a_profile_past_the_cap_is_refused(self, store: SqlProfileStore) -> None:
        await store.add(make_profile("acct_1", "one"), cap=2)
        await store.add(make_profile("acct_1", "two"), cap=2)

        with pytest.raises(LimitExceededError):
            await store.add(make_profile("acct_1", "three"), cap=2)

    async def test_the_cap_is_per_account(self, store: SqlProfileStore) -> None:
        await store.add(make_profile("acct_a", "one"), cap=1)

        await store.add(make_profile("acct_b", "one"), cap=1)

    async def test_concurrent_creations_cannot_exceed_the_cap(self, store: SqlProfileStore) -> None:
        await asyncio.gather(
            *(store.add(make_profile("acct_1", f"p{index}"), cap=3) for index in range(10)),
            return_exceptions=True,
        )

        assert await store.count_for_account("acct_1") == 3

    async def test_a_connection_past_the_cap_is_refused(self, store: SqlProfileStore) -> None:
        await store.add(make_profile(), cap=CAP)
        await store.put_connection("acct_1", "personal", make_connection("a"), cap=2, now=EPOCH)
        await store.put_connection("acct_1", "personal", make_connection("b"), cap=2, now=EPOCH)

        with pytest.raises(LimitExceededError):
            await store.put_connection("acct_1", "personal", make_connection("c"), cap=2, now=EPOCH)

    async def test_replacing_a_connection_is_never_refused_by_the_cap(
        self, store: SqlProfileStore
    ) -> None:
        # Otherwise a full profile could not refresh any of its own tokens.
        await store.add(make_profile(), cap=CAP)
        await store.put_connection("acct_1", "personal", make_connection("a"), cap=1, now=EPOCH)

        await store.put_connection(
            "acct_1",
            "personal",
            make_connection("a", status=ConnectionStatus.REVOKED),
            cap=1,
            now=EPOCH,
        )

    async def test_concurrent_connections_cannot_exceed_the_cap(
        self, store: SqlProfileStore
    ) -> None:
        await store.add(make_profile(), cap=CAP)

        await asyncio.gather(
            *(
                store.put_connection(
                    "acct_1", "personal", make_connection(f"s{index}"), cap=3, now=EPOCH
                )
                for index in range(10)
            ),
            return_exceptions=True,
        )

        stored = await store.get("acct_1", "personal")
        assert stored is not None
        assert len(stored.connections) == 3
