"""The SQL secret store.

The cryptography is tested in ``test_envelope.py``; what is tested here is that this
store uses it correctly and that a row is worthless without the master key -- that
nothing legible reaches the file, that one account cannot address another's material,
and that the store fails closed when it has no key at all.

The tests that used to assert file modes are gone with the files. In their place is
:class:`TestNothingLegibleOnDisk`, which reads the raw database and looks for the
plaintext -- a cruder question than "is this file 0600", and a more direct one.
"""

from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from keyring_api.accounts.sql_store import SqlAccountStore
from keyring_api.domain.accounts import Account
from keyring_api.domain.errors import CredentialUnavailableError, VaultSealedError
from keyring_api.secrets.base import Secret, SecretStore
from keyring_api.secrets.sql import SqlSecretStore
from tests.fakes.clock import EPOCH, FakeClock

if TYPE_CHECKING:
    from keyring_api.storage.database import Database

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
ACCOUNT = "acct_1"
SECRET: Secret = {"access_token": "abc", "refresh_token": "def"}


@pytest.fixture
async def store(database: Database) -> SqlSecretStore:
    """A store, and the two accounts whose material it holds.

    Credential material is foreign-keyed to its account, so the accounts have to exist.
    That key is what makes deleting an account take its credentials with it in the same
    transaction, rather than in a second call that can fail on its own.
    """
    accounts = SqlAccountStore(database=database)
    for account_id in (ACCOUNT, "acct_2"):
        await accounts.add(
            Account(
                account_id=account_id,
                email=f"{account_id}@example.com",
                password_hash="$argon2id$fake",
                created_at=EPOCH,
                updated_at=EPOCH,
            )
        )
    return SqlSecretStore(database=database, master_key=KEY, clock=FakeClock())


class TestPort:
    def test_it_satisfies_the_port(self, store: SqlSecretStore) -> None:
        checked: SecretStore = store

        assert isinstance(checked, SecretStore)


class TestRoundTrip:
    async def test_a_stored_secret_reads_back_unchanged(self, store: SqlSecretStore) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        assert await store.get(ACCOUNT, "personal", "spotify") == SECRET

    async def test_an_absent_secret_reads_back_as_none(self, store: SqlSecretStore) -> None:
        assert await store.get(ACCOUNT, "personal", "nothing-here") is None

    async def test_storing_twice_replaces_rather_than_appends(
        self, store: SqlSecretStore, database: Database
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", {"access_token": "first"})
        await store.put(ACCOUNT, "personal", "spotify", {"access_token": "second"})

        assert await store.get(ACCOUNT, "personal", "spotify") == {"access_token": "second"}
        assert len(await database.fetch_all("SELECT service FROM secrets")) == 1

    async def test_deleting_removes_it(self, store: SqlSecretStore) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        assert await store.delete(ACCOUNT, "personal", "spotify") is True
        assert await store.get(ACCOUNT, "personal", "spotify") is None

    async def test_deleting_something_absent_reports_that_nothing_went(
        self, store: SqlSecretStore
    ) -> None:
        assert await store.delete(ACCOUNT, "personal", "never-stored") is False

    @settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=20),
            st.one_of(st.text(max_size=100), st.integers(), st.booleans(), st.none()),
            max_size=6,
        )
    )
    async def test_any_json_shaped_secret_round_trips(
        self, store: SqlSecretStore, secret: dict[str, object]
    ) -> None:
        await store.put(ACCOUNT, "personal", "arbitrary", secret)

        assert await store.get(ACCOUNT, "personal", "arbitrary") == secret


class TestNothingLegibleOnDisk:
    """The whole point of the vault, asserted against the bytes of the file.

    Deliberately cruder than checking the columns: this reads the database as bytes, the
    way a stolen backup would, and looks for the credential in it.
    """

    async def test_the_plaintext_is_nowhere_in_the_file(
        self, store: SqlSecretStore, database: Database
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", {"access_token": "sekrit-value-xyz"})
        # WAL: the row may still be in the sidecar rather than the main file, so check
        # everything the database has written.
        await database.run(lambda connection: connection.execute("PRAGMA wal_checkpoint(FULL)"))

        for path in database.path.parent.iterdir():
            assert b"sekrit-value-xyz" not in path.read_bytes(), path

    async def test_the_columns_hold_ciphertext_not_the_secret(
        self, store: SqlSecretStore, database: Database
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", {"access_token": "sekrit-value-xyz"})

        row = await database.fetch_one("SELECT ciphertext, wrapped_key FROM secrets")

        assert row is not None
        assert b"sekrit-value-xyz" not in row["ciphertext"]
        assert b"sekrit-value-xyz" not in row["wrapped_key"]

    async def test_each_secret_gets_its_own_data_key(
        self, store: SqlSecretStore, database: Database
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        await store.put(ACCOUNT, "personal", "tmdb", SECRET)

        rows = await database.fetch_all("SELECT wrapped_key FROM secrets")

        assert len({row["wrapped_key"] for row in rows}) == 2

    async def test_a_rewrite_gets_a_fresh_key_and_nonce(
        self, store: SqlSecretStore, database: Database
    ) -> None:
        """Never two different plaintexts under one key and nonce, which AES-GCM forbids."""
        await store.put(ACCOUNT, "personal", "spotify", {"access_token": "first"})
        before = await database.fetch_one("SELECT wrapped_key, nonce FROM secrets")

        await store.put(ACCOUNT, "personal", "spotify", {"access_token": "second"})
        after = await database.fetch_one("SELECT wrapped_key, nonce FROM secrets")

        assert before is not None
        assert after is not None
        assert before["wrapped_key"] != after["wrapped_key"]
        assert before["nonce"] != after["nonce"]

    async def test_a_wrong_master_key_fails_rather_than_returning_nonsense(
        self, store: SqlSecretStore, database: Database
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        impostor = SqlSecretStore(database=database, master_key=OTHER_KEY, clock=FakeClock())

        with pytest.raises(CredentialUnavailableError):
            await impostor.get(ACCOUNT, "personal", "spotify")

    async def test_a_tampered_row_is_refused(
        self, store: SqlSecretStore, database: Database
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        row = await database.fetch_one("SELECT ciphertext FROM secrets")
        assert row is not None
        flipped = bytes([row["ciphertext"][0] ^ 0x01, *row["ciphertext"][1:]])
        await database.execute("UPDATE secrets SET ciphertext = ?", (flipped,))

        with pytest.raises(CredentialUnavailableError):
            await store.get(ACCOUNT, "personal", "spotify")


class TestSealedVault:
    @pytest.fixture
    def sealed(
        self,
        database: Database,
        store: SqlSecretStore,  # noqa: ARG002 -- creates the accounts the rows need
    ) -> SqlSecretStore:
        return SqlSecretStore(database=database, master_key=None, clock=FakeClock())

    async def test_reading_from_a_sealed_vault_fails_with_the_fix(
        self, sealed: SqlSecretStore
    ) -> None:
        with pytest.raises(VaultSealedError, match="KEYRING_MASTER_KEY"):
            await sealed.get(ACCOUNT, "personal", "spotify")

    async def test_writing_to_a_sealed_vault_fails(self, sealed: SqlSecretStore) -> None:
        """Never a plaintext fallback, and never a silently discarded write."""
        with pytest.raises(VaultSealedError):
            await sealed.put(ACCOUNT, "personal", "spotify", SECRET)

    async def test_a_sealed_vault_stores_nothing(
        self, sealed: SqlSecretStore, database: Database
    ) -> None:
        with pytest.raises(VaultSealedError):
            await sealed.put(ACCOUNT, "personal", "spotify", SECRET)

        assert await database.fetch_all("SELECT service FROM secrets") == []

    async def test_a_sealed_vault_reports_itself_sealed(self, sealed: SqlSecretStore) -> None:
        assert sealed.is_sealed is True

    async def test_an_unsealed_vault_does_not(self, store: SqlSecretStore) -> None:
        assert store.is_sealed is False

    async def test_a_sealed_vault_can_still_delete(self, sealed: SqlSecretStore) -> None:
        """Deleting needs no key: throwing away ciphertext does not require reading it.

        It matters for the cascade -- an account must be deletable while the vault is
        sealed, rather than leaving material behind until somebody finds the key.
        """
        assert await sealed.delete(ACCOUNT, "personal", "spotify") is False
        assert await sealed.delete_profile(ACCOUNT, "personal") == 0


class TestIsolation:
    async def test_one_account_cannot_read_another_s_secret(self, store: SqlSecretStore) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        assert await store.get("acct_2", "personal", "spotify") is None

    async def test_the_same_name_in_two_accounts_is_two_secrets(
        self, store: SqlSecretStore
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", {"access_token": "mine"})
        await store.put("acct_2", "personal", "spotify", {"access_token": "theirs"})

        assert await store.get(ACCOUNT, "personal", "spotify") == {"access_token": "mine"}
        assert await store.get("acct_2", "personal", "spotify") == {"access_token": "theirs"}

    async def test_deleting_the_account_takes_every_secret_it_owns(
        self, store: SqlSecretStore, database: Database
    ) -> None:
        """The cascade, and it is the schema's rather than a second call.

        This used to be an explicit sweep the admin service ran after deleting the
        account row, with a documented lesser harm if it failed: material left behind
        with nothing referencing it, unreachable through the API and still decryptable.
        """
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        await store.put(ACCOUNT, "work", "tmdb", SECRET)
        await store.put("acct_2", "personal", "spotify", SECRET)

        await SqlAccountStore(database=database).delete(ACCOUNT)

        assert await store.get(ACCOUNT, "personal", "spotify") is None
        assert await store.get(ACCOUNT, "work", "tmdb") is None
        assert await store.get("acct_2", "personal", "spotify") == SECRET

    async def test_material_cannot_be_stored_for_an_account_that_does_not_exist(
        self, store: SqlSecretStore
    ) -> None:
        # The other half of the key. Orphaned material is not merely collected on the way
        # out -- it cannot be created.
        with pytest.raises(sqlite3.IntegrityError):
            await store.put("acct_nobody", "personal", "spotify", SECRET)

    async def test_deleting_a_profile_takes_only_that_profile_s_secrets(
        self, store: SqlSecretStore
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        await store.put(ACCOUNT, "personal", "tmdb", SECRET)
        await store.put(ACCOUNT, "work", "tmdb", SECRET)

        assert await store.delete_profile(ACCOUNT, "personal") == 2
        assert await store.get(ACCOUNT, "work", "tmdb") == SECRET

    async def test_deleting_a_profile_does_not_reach_another_account(
        self, store: SqlSecretStore
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        await store.put("acct_2", "personal", "spotify", SECRET)

        assert await store.delete_profile("acct_2", "personal") == 1
        assert await store.get(ACCOUNT, "personal", "spotify") == SECRET

    async def test_deleting_a_profile_with_nothing_stored_is_not_an_error(
        self, store: SqlSecretStore
    ) -> None:
        assert await store.delete_profile(ACCOUNT, "never-used") == 0


class TestDurability:
    """The property the file store had and the in-memory stores did not."""

    async def test_a_secret_survives_a_restart(
        self, database: Database, store: SqlSecretStore
    ) -> None:
        from keyring_api.storage.database import Database as Db
        from keyring_api.storage.migrator import migrate

        path = database.path
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        await database.aclose()

        reopened = Db(path)
        migrate(reopened, now=FakeClock().now())
        try:
            restored = SqlSecretStore(database=reopened, master_key=KEY, clock=FakeClock())

            assert await restored.get(ACCOUNT, "personal", "spotify") == SECRET
        finally:
            await reopened.aclose()
