"""The encrypted secret store.

The cryptography is `cryptography`'s. What is tested here is that this service uses it
correctly: that a wrong key fails rather than returning plausible nonsense, that files
are not world-readable, that one account cannot address another's material, and that the
store fails closed when it has no key at all.
"""

from __future__ import annotations

import base64
import json
import stat
from typing import TYPE_CHECKING

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from keyring_api.domain.errors import CredentialUnavailableError, VaultSealedError
from keyring_api.secrets.base import Secret, SecretStore
from keyring_api.secrets.encrypted_file import EncryptedFileSecretStore

if TYPE_CHECKING:
    from pathlib import Path

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
ACCOUNT = "acct_1"
SECRET: Secret = {"access_token": "abc", "refresh_token": "def"}


@pytest.fixture
def store(tmp_path: Path) -> EncryptedFileSecretStore:
    return EncryptedFileSecretStore(root=tmp_path / "secrets", master_key=KEY)


class TestPort:
    def test_it_satisfies_the_port(self, store: EncryptedFileSecretStore) -> None:
        checked: SecretStore = store

        assert isinstance(checked, SecretStore)


class TestRoundTrip:
    async def test_a_stored_secret_reads_back_unchanged(
        self, store: EncryptedFileSecretStore
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        assert await store.get(ACCOUNT, "personal", "spotify") == SECRET

    async def test_an_absent_secret_reads_back_as_none(
        self, store: EncryptedFileSecretStore
    ) -> None:
        assert await store.get(ACCOUNT, "personal", "spotify") is None

    async def test_storing_twice_replaces_rather_than_appends(
        self, store: EncryptedFileSecretStore
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        replacement: Secret = {"api_key": "new"}
        await store.put(ACCOUNT, "personal", "spotify", replacement)

        assert await store.get(ACCOUNT, "personal", "spotify") == {"api_key": "new"}

    async def test_deleting_removes_it(self, store: EncryptedFileSecretStore) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        assert await store.delete(ACCOUNT, "personal", "spotify")

        assert await store.get(ACCOUNT, "personal", "spotify") is None

    async def test_deleting_something_absent_reports_that_nothing_went(
        self, store: EncryptedFileSecretStore
    ) -> None:
        assert not await store.delete(ACCOUNT, "personal", "spotify")

    # The fixture is not reset between generated inputs, which is fine here: each
    # example writes to the same path and put() replaces rather than appends, so
    # reusing the directory is the behaviour under test rather than contamination.
    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(
        secret=st.dictionaries(
            st.text(min_size=1, max_size=40),
            st.text(max_size=200) | st.integers() | st.booleans() | st.none(),
            max_size=10,
        )
    )
    async def test_any_json_shaped_secret_round_trips(
        self, tmp_path: Path, secret: dict[str, object]
    ) -> None:
        # Credential shapes differ per kind and will keep growing. The store must not
        # care what is in the envelope.
        store = EncryptedFileSecretStore(root=tmp_path / "hypothesis", master_key=KEY)
        await store.put(ACCOUNT, "personal", "service", secret)

        assert await store.get(ACCOUNT, "personal", "service") == secret


class TestEncryption:
    async def test_the_plaintext_is_not_on_disk(
        self, store: EncryptedFileSecretStore, tmp_path: Path
    ) -> None:
        leaky: Secret = {"refresh_token": "hunter2"}
        await store.put(ACCOUNT, "personal", "spotify", leaky)

        on_disk = (tmp_path / "secrets").rglob("*")
        contents = b"".join(path.read_bytes() for path in on_disk if path.is_file())

        assert b"hunter2" not in contents

    async def test_each_secret_gets_its_own_data_key(self, store: EncryptedFileSecretStore) -> None:
        # Envelope encryption: the master key wraps a per-secret data key, so the master
        # key itself is used for a few bytes at a time rather than for every credential
        # in the vault, and re-keying later means rewrapping rather than re-encrypting.
        await store.put(ACCOUNT, "personal", "one", SECRET)
        await store.put(ACCOUNT, "personal", "two", SECRET)

        first = json.loads(store.path_for(ACCOUNT, "personal", "one").read_text())
        second = json.loads(store.path_for(ACCOUNT, "personal", "two").read_text())

        assert first["wrapped_key"] != second["wrapped_key"]

    async def test_the_same_plaintext_encrypts_differently_every_time(
        self, store: EncryptedFileSecretStore
    ) -> None:
        # A fresh nonce per write. Reusing one with AES-GCM is catastrophic, and the
        # visible symptom would be exactly this: identical ciphertext.
        await store.put(ACCOUNT, "personal", "one", SECRET)
        first = store.path_for(ACCOUNT, "personal", "one").read_text()

        await store.put(ACCOUNT, "personal", "one", SECRET)

        assert store.path_for(ACCOUNT, "personal", "one").read_text() != first

    async def test_a_wrong_master_key_fails_rather_than_returning_nonsense(
        self, store: EncryptedFileSecretStore, tmp_path: Path
    ) -> None:
        # AES-GCM is authenticated, so this is a clean failure rather than garbage. The
        # test exists because the alternative -- a store that silently returns a
        # corrupted credential -- would be discovered as a mysterious failure at the
        # third-party service, days later.
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        wrong = EncryptedFileSecretStore(root=tmp_path / "secrets", master_key=OTHER_KEY)

        with pytest.raises(CredentialUnavailableError):
            await wrong.get(ACCOUNT, "personal", "spotify")

    async def test_a_tampered_file_is_refused(self, store: EncryptedFileSecretStore) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        path = store.path_for(ACCOUNT, "personal", "spotify")
        envelope = json.loads(path.read_text())
        envelope["ciphertext"] = base64.b64encode(b"replaced ciphertext").decode()
        path.write_text(json.dumps(envelope))

        with pytest.raises(CredentialUnavailableError):
            await store.get(ACCOUNT, "personal", "spotify")

    async def test_a_file_that_is_not_an_envelope_is_refused(
        self, store: EncryptedFileSecretStore
    ) -> None:
        # Truncated by a full disk, half-written by a crash, or edited by hand.
        path = store.path_for(ACCOUNT, "personal", "spotify")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json")

        with pytest.raises(CredentialUnavailableError):
            await store.get(ACCOUNT, "personal", "spotify")

    async def test_an_envelope_missing_a_field_is_refused(
        self, store: EncryptedFileSecretStore
    ) -> None:
        path = store.path_for(ACCOUNT, "personal", "spotify")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"ciphertext": "abc"}))

        with pytest.raises(CredentialUnavailableError):
            await store.get(ACCOUNT, "personal", "spotify")


class TestSealedVault:
    @pytest.fixture
    def sealed(self, tmp_path: Path) -> EncryptedFileSecretStore:
        return EncryptedFileSecretStore(root=tmp_path / "secrets", master_key=None)

    async def test_reading_from_a_sealed_vault_fails_with_the_fix(
        self, sealed: EncryptedFileSecretStore
    ) -> None:
        # A distinct error from a decryption failure, because the remedies differ: this
        # one is an operator forgetting an environment variable, the other means the key
        # and the data disagree.
        with pytest.raises(VaultSealedError, match="KEYRING_MASTER_KEY"):
            await sealed.get(ACCOUNT, "personal", "spotify")

    async def test_writing_to_a_sealed_vault_fails(self, sealed: EncryptedFileSecretStore) -> None:
        # It must not write plaintext as a fallback, and it must not silently discard
        # the credential either. Both are worse than refusing.
        with pytest.raises(VaultSealedError):
            await sealed.put(ACCOUNT, "personal", "spotify", SECRET)

    async def test_a_sealed_vault_reports_itself_sealed(
        self, sealed: EncryptedFileSecretStore, store: EncryptedFileSecretStore
    ) -> None:
        assert sealed.is_sealed
        assert not store.is_sealed


class TestFilePermissions:
    async def test_a_secret_file_is_readable_only_by_its_owner(
        self, store: EncryptedFileSecretStore
    ) -> None:
        # The encryption protects against a stolen disk. The mode protects against every
        # other process and user on the box, which is the far likelier reader.
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        mode = store.path_for(ACCOUNT, "personal", "spotify").stat().st_mode

        assert stat.S_IMODE(mode) == 0o600

    async def test_the_directories_are_owner_only_too(
        self, store: EncryptedFileSecretStore, tmp_path: Path
    ) -> None:
        # A world-readable directory leaks which services each person has connected,
        # even when every file inside it is unreadable.
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        assert stat.S_IMODE((tmp_path / "secrets").stat().st_mode) == 0o700

    async def test_a_rewrite_does_not_loosen_the_mode(
        self, store: EncryptedFileSecretStore
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        replacement: Secret = {"api_key": "new"}
        await store.put(ACCOUNT, "personal", "spotify", replacement)

        mode = store.path_for(ACCOUNT, "personal", "spotify").stat().st_mode
        assert stat.S_IMODE(mode) == 0o600


class TestIsolation:
    async def test_one_account_cannot_read_another_s_secret(
        self, store: EncryptedFileSecretStore
    ) -> None:
        await store.put("acct_a", "personal", "spotify", SECRET)

        assert await store.get("acct_b", "personal", "spotify") is None

    @pytest.mark.parametrize(
        "hostile",
        ["../../etc", "..", "a/b", "a\\b", ".", "", "acct_1/../acct_2", "\x00"],
    )
    async def test_an_identifier_that_could_escape_its_directory_is_refused(
        self, store: EncryptedFileSecretStore, hostile: str
    ) -> None:
        # These identifiers are internal today, but "internal" is a property of the
        # current callers rather than of the store. Refusing here means a future
        # endpoint that passes a name straight through cannot turn into a path traversal.
        with pytest.raises(ValueError, match="identifier"):
            store.path_for(hostile, "personal", "spotify")

    async def test_every_resolved_path_stays_under_the_root(
        self, store: EncryptedFileSecretStore, tmp_path: Path
    ) -> None:
        path = store.path_for(ACCOUNT, "personal", "spotify")

        assert path.resolve().is_relative_to((tmp_path / "secrets").resolve())

    async def test_deleting_an_account_takes_every_secret_it_owns(
        self, store: EncryptedFileSecretStore
    ) -> None:
        await store.put("acct_a", "personal", "spotify", SECRET)
        await store.put("acct_a", "work", "tmdb", SECRET)
        await store.put("acct_b", "personal", "spotify", SECRET)

        assert await store.delete_account("acct_a") == 2

        assert await store.get("acct_b", "personal", "spotify") == SECRET

    async def test_deleting_a_profile_takes_only_that_profile_s_secrets(
        self, store: EncryptedFileSecretStore
    ) -> None:
        await store.put(ACCOUNT, "personal", "spotify", SECRET)
        await store.put(ACCOUNT, "work", "spotify", SECRET)

        assert await store.delete_profile(ACCOUNT, "personal") == 1

        assert await store.get(ACCOUNT, "work", "spotify") == SECRET

    async def test_deleting_an_account_with_nothing_stored_is_not_an_error(
        self, store: EncryptedFileSecretStore
    ) -> None:
        assert await store.delete_account("acct_nobody") == 0


class TestWriteFailures:
    async def test_a_failed_write_leaves_no_staging_file_behind(
        self, store: EncryptedFileSecretStore, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # A staging file that survives a crashed write is ciphertext lying around under
        # a name nothing will ever clean up -- accumulating, one failure at a time.
        from pathlib import Path as RealPath

        def fail(_self: RealPath, _target: RealPath) -> None:
            disk_full = "no space left on device"
            raise OSError(disk_full)

        monkeypatch.setattr(RealPath, "replace", fail)

        with pytest.raises(OSError, match="no space"):
            await store.put(ACCOUNT, "personal", "spotify", SECRET)

        staged = list((tmp_path / "secrets").rglob(".staging-*"))
        assert staged == []

    async def test_a_failed_write_does_not_destroy_the_previous_credential(
        self, store: EncryptedFileSecretStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Written to a temporary file and renamed into place, so a crash mid-write
        # leaves the old credential readable rather than a truncated file that will not
        # decrypt -- which would be indistinguishable from a lost credential.
        from pathlib import Path as RealPath

        await store.put(ACCOUNT, "personal", "spotify", SECRET)

        def fail(_self: RealPath, _target: RealPath) -> None:
            disk_full = "no space left on device"
            raise OSError(disk_full)

        monkeypatch.setattr(RealPath, "replace", fail)
        with pytest.raises(OSError, match="no space"):
            await store.put(ACCOUNT, "personal", "spotify", {"api_key": "new"})

        monkeypatch.undo()
        assert await store.get(ACCOUNT, "personal", "spotify") == SECRET

    async def test_an_envelope_field_of_the_wrong_type_is_refused(
        self, store: EncryptedFileSecretStore
    ) -> None:
        # A hand-edited or half-migrated file whose fields are numbers rather than
        # base64 text must be a clean refusal, not a TypeError escaping the store.
        path = store.path_for(ACCOUNT, "personal", "spotify")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"wrapped_key": 1, "key_nonce": 2, "nonce": 3, "ciphertext": 4}))

        with pytest.raises(CredentialUnavailableError):
            await store.get(ACCOUNT, "personal", "spotify")
