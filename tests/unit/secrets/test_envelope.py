"""The envelope crypto on its own, with no storage anywhere near it.

Separated from the file store so these tests say what the *cryptography* guarantees,
rather than what one backend does with it. Both secret stores use this module, so a
property proved here is proved for both.
"""

from __future__ import annotations

import os
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given
from hypothesis import strategies as st

from keyring_api.domain.errors import CredentialUnavailableError, VaultSealedError
from keyring_api.secrets.base import Secret
from keyring_api.secrets.envelope import (
    DATA_KEY_BYTES,
    ENVELOPE_VERSION,
    NONCE_BYTES,
    Envelope,
    open_envelope,
    require_master,
    seal,
)

SECRET: Secret = {"api_key": "the-key", "note": "keep this"}


@pytest.fixture
def master() -> AESGCM:
    return AESGCM(bytes(range(32)))


class TestRoundTrip:
    def test_a_sealed_secret_opens_unchanged(self, master: AESGCM) -> None:
        assert open_envelope(seal(SECRET, master=master), master=master) == SECRET

    def test_it_stamps_the_format_version(self, master: AESGCM) -> None:
        assert seal(SECRET, master=master).version == ENVELOPE_VERSION

    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=20),
            st.one_of(st.text(max_size=200), st.integers(), st.booleans(), st.none()),
            max_size=8,
        )
    )
    def test_any_json_shaped_secret_survives(self, secret: dict[str, object]) -> None:
        master = AESGCM(bytes(range(32)))

        assert open_envelope(seal(secret, master=master), master=master) == secret


class TestSecrecy:
    def test_the_plaintext_is_not_in_the_ciphertext(self, master: AESGCM) -> None:
        envelope = seal({"api_key": "sekrit-value"}, master=master)

        assert b"sekrit-value" not in envelope.ciphertext
        assert b"sekrit-value" not in envelope.wrapped_key

    def test_each_secret_gets_its_own_data_key(self, master: AESGCM) -> None:
        first = seal(SECRET, master=master)
        second = seal(SECRET, master=master)

        assert first.wrapped_key != second.wrapped_key

    def test_the_same_plaintext_encrypts_differently_every_time(self, master: AESGCM) -> None:
        """A fresh nonce per encryption, which is what AES-GCM requires to stay secure."""
        first = seal(SECRET, master=master)
        second = seal(SECRET, master=master)

        assert first.ciphertext != second.ciphertext
        assert first.nonce != second.nonce

    def test_the_nonces_are_the_specified_width(self, master: AESGCM) -> None:
        envelope = seal(SECRET, master=master)

        assert len(envelope.nonce) == NONCE_BYTES
        assert len(envelope.key_nonce) == NONCE_BYTES

    def test_the_data_key_is_the_full_width(self, master: AESGCM) -> None:
        envelope = seal(SECRET, master=master)
        data_key = master.decrypt(envelope.key_nonce, envelope.wrapped_key, None)

        assert len(data_key) == DATA_KEY_BYTES


class TestRefusal:
    """Every way this can fail is the same failure, and none of them return nonsense."""

    def test_a_wrong_master_key_is_refused(self, master: AESGCM) -> None:
        envelope = seal(SECRET, master=master)

        with pytest.raises(CredentialUnavailableError):
            open_envelope(envelope, master=AESGCM(bytes(reversed(range(32)))))

    def test_a_tampered_ciphertext_is_refused(self, master: AESGCM) -> None:
        envelope = seal(SECRET, master=master)
        flipped = bytes([envelope.ciphertext[0] ^ 0x01, *envelope.ciphertext[1:]])

        with pytest.raises(CredentialUnavailableError):
            open_envelope(replace(envelope, ciphertext=flipped), master=master)

    def test_a_tampered_wrapped_key_is_refused(self, master: AESGCM) -> None:
        envelope = seal(SECRET, master=master)
        flipped = bytes([envelope.wrapped_key[0] ^ 0x01, *envelope.wrapped_key[1:]])

        with pytest.raises(CredentialUnavailableError):
            open_envelope(replace(envelope, wrapped_key=flipped), master=master)

    def test_a_swapped_nonce_is_refused(self, master: AESGCM) -> None:
        envelope = seal(SECRET, master=master)

        with pytest.raises(CredentialUnavailableError):
            open_envelope(replace(envelope, nonce=os.urandom(NONCE_BYTES)), master=master)

    def test_a_payload_that_is_not_json_is_refused(self, master: AESGCM) -> None:
        """Correctly encrypted, and still not a secret.

        Reachable only by someone holding the master key, which makes it the operator's
        own mistake rather than an attack -- and the right answer to an operator's mistake
        is a clean error, not a dictionary of garbage handed onward to a provider.
        """
        data_key = os.urandom(DATA_KEY_BYTES)
        key_nonce = os.urandom(NONCE_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        envelope = Envelope(
            version=ENVELOPE_VERSION,
            wrapped_key=master.encrypt(key_nonce, data_key, None),
            key_nonce=key_nonce,
            nonce=nonce,
            ciphertext=AESGCM(data_key).encrypt(nonce, b"not json at all", None),
        )
        # The unwrap and the decrypt both succeed here; only json.loads fails. Getting
        # this wrong -- a mismatched key_nonce, say -- makes the test pass by failing
        # one step earlier, and it would keep passing with the JSON handling removed.
        assert master.decrypt(envelope.key_nonce, envelope.wrapped_key, None) == data_key

        with pytest.raises(CredentialUnavailableError):
            open_envelope(envelope, master=master)

    def test_the_error_does_not_carry_the_material(self, master: AESGCM) -> None:
        envelope = seal({"api_key": "sekrit-value"}, master=master)

        with pytest.raises(CredentialUnavailableError) as raised:
            open_envelope(envelope, master=AESGCM(bytes(reversed(range(32)))))

        assert "sekrit" not in str(raised.value)


class TestSealedVault:
    def test_no_key_means_refusal_carrying_the_fix(self) -> None:
        with pytest.raises(VaultSealedError, match="KEYRING_MASTER_KEY"):
            require_master(None)

    def test_a_key_is_handed_straight_back(self, master: AESGCM) -> None:
        assert require_master(master) is master
