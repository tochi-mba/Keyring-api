"""The profile store, and the isolation that is built into its signatures."""

from __future__ import annotations

from datetime import timedelta

import pytest

from keyring_api.domain.errors import ProfileExistsError
from keyring_api.domain.profiles import Profile, new_profile_id
from keyring_api.profiles.store import InMemoryProfileStore, ProfileStore
from tests.fakes.clock import EPOCH


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


@pytest.fixture
def store() -> InMemoryProfileStore:
    return InMemoryProfileStore()


async def test_it_satisfies_the_port(store: InMemoryProfileStore) -> None:
    checked: ProfileStore = store

    assert isinstance(checked, ProfileStore)


async def test_a_stored_profile_reads_back(store: InMemoryProfileStore) -> None:
    profile = make_profile()
    await store.add(profile)

    assert await store.get("acct_1", "personal") == profile


async def test_an_unknown_profile_reads_back_as_absent(store: InMemoryProfileStore) -> None:
    assert await store.get("acct_1", "personal") is None


async def test_one_account_cannot_read_another_s_profile(store: InMemoryProfileStore) -> None:
    # Absent, not forbidden. A distinguishable "not yours" would tell one person that
    # another person has a profile by that name.
    await store.add(make_profile("acct_a", "personal"))

    assert await store.get("acct_b", "personal") is None


async def test_two_accounts_can_each_have_a_profile_of_the_same_name(
    store: InMemoryProfileStore,
) -> None:
    # "personal" is the name everybody picks. Names are scoped to the account, and would
    # be useless if the first person to use one took it from everybody else.
    await store.add(make_profile("acct_a", "personal"))
    await store.add(make_profile("acct_b", "personal"))

    assert await store.count_for_account("acct_a") == 1
    assert await store.count_for_account("acct_b") == 1


async def test_one_account_cannot_have_two_profiles_of_the_same_name(
    store: InMemoryProfileStore,
) -> None:
    await store.add(make_profile())

    with pytest.raises(ProfileExistsError):
        await store.add(make_profile())


async def test_profiles_are_listed_oldest_first(store: InMemoryProfileStore) -> None:
    await store.add(make_profile("acct_1", "second", created_at=EPOCH + timedelta(days=1)))
    await store.add(make_profile("acct_1", "first"))

    assert [profile.name for profile in await store.list_for_account("acct_1")] == [
        "first",
        "second",
    ]


async def test_listing_shows_only_this_account_s_profiles(store: InMemoryProfileStore) -> None:
    await store.add(make_profile("acct_a", "mine"))
    await store.add(make_profile("acct_b", "theirs"))

    assert [profile.name for profile in await store.list_for_account("acct_a")] == ["mine"]


async def test_saving_replaces_the_stored_profile(store: InMemoryProfileStore) -> None:
    from keyring_api.domain.profiles import Connection, ConnectionStatus, CredentialKind

    profile = make_profile()
    await store.add(profile)

    await store.save(
        profile.with_connection(
            Connection(
                service="spotify",
                kind=CredentialKind.API_KEY,
                status=ConnectionStatus.ACTIVE,
                created_at=EPOCH,
                updated_at=EPOCH,
            ),
            now=EPOCH,
        )
    )

    stored = await store.get("acct_1", "personal")
    assert stored is not None
    assert stored.connection("spotify") is not None


async def test_deleting_removes_it(store: InMemoryProfileStore) -> None:
    await store.add(make_profile())

    assert await store.delete("acct_1", "personal")
    assert await store.get("acct_1", "personal") is None


async def test_deleting_someone_else_s_profile_does_nothing(
    store: InMemoryProfileStore,
) -> None:
    # The most important isolation test here: a read that leaks is bad, a *write* that
    # crosses accounts destroys somebody else's data.
    await store.add(make_profile("acct_a", "personal"))

    assert not await store.delete("acct_b", "personal")
    assert await store.get("acct_a", "personal") is not None


async def test_deleting_an_unknown_profile_reports_that_nothing_went(
    store: InMemoryProfileStore,
) -> None:
    assert not await store.delete("acct_1", "personal")


async def test_deleting_an_account_takes_only_its_own_profiles(
    store: InMemoryProfileStore,
) -> None:
    await store.add(make_profile("acct_a", "one"))
    await store.add(make_profile("acct_a", "two"))
    await store.add(make_profile("acct_b", "one"))

    assert await store.delete_for_account("acct_a") == 2
    assert await store.count_for_account("acct_b") == 1
