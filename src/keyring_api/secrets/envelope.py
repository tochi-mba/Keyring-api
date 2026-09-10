"""Envelope encryption: the crypto, with nowhere to put anything.

Pure functions. Nothing here opens a file or a database, which is the point -- the
cryptography is the part that must be right, and it is easier to be sure of when it is
separated from where the bytes end up.

**Why an envelope rather than encrypting straight with the master key.** A fresh data key
per secret means the master key is used for 32 bytes per credential instead of for every
credential in the vault, which bounds how much material any one key protects. It also
makes re-keying a matter of rewrapping a few short data keys rather than decrypting and
re-encrypting the whole vault.

**Why every failure is one error.** A wrong key, a truncated ciphertext, a tampered nonce
and a malformed payload all raise :class:`CredentialUnavailableError`. AES-GCM
authenticates, so a wrong key fails cleanly rather than producing plausible nonsense --
which matters, because material that decrypted to garbage would surface days later as an
inexplicable rejection at the third-party service.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keyring_api.domain.errors import CredentialUnavailableError, VaultSealedError

if TYPE_CHECKING:
    from keyring_api.secrets.base import Secret

DATA_KEY_BYTES = 32
NONCE_BYTES = 12
"""96 bits, the size AES-GCM is specified for. A fresh one per encryption, never reused."""

ENVELOPE_VERSION = 1
"""Recorded with every secret so a future format change is recognised rather than guessed."""

UNREADABLE = "stored credential material could not be read"
SEALED_MESSAGE = "the credential vault is sealed: set KEYRING_MASTER_KEY"


def require_master(master: AESGCM | None) -> AESGCM:
    """Return the master cipher, or refuse to do anything without one.

    Refusing is the only acceptable answer. Writing plaintext as a fallback would put
    credentials in the clear; discarding the write silently would lose a credential the
    caller believes was stored.

    Raises:
        VaultSealedError: no usable key is configured.
    """
    if master is None:
        raise VaultSealedError(SEALED_MESSAGE)
    return master


@dataclass(frozen=True, slots=True)
class Envelope:
    """One encrypted secret: the wrapped data key, and what it protects.

    Four opaque byte strings and a version. Nothing here is meaningful without the master
    key, which is what makes it safe to hand to any storage backend -- a file, a row, a
    backup somebody mishandles.
    """

    version: int
    wrapped_key: bytes
    key_nonce: bytes
    nonce: bytes
    ciphertext: bytes


def seal(secret: Secret, *, master: AESGCM) -> Envelope:
    """Encrypt a secret under a fresh data key, wrapped by the master key."""
    data_key = os.urandom(DATA_KEY_BYTES)
    key_nonce = os.urandom(NONCE_BYTES)
    payload_nonce = os.urandom(NONCE_BYTES)

    return Envelope(
        version=ENVELOPE_VERSION,
        wrapped_key=master.encrypt(key_nonce, data_key, None),
        key_nonce=key_nonce,
        nonce=payload_nonce,
        ciphertext=AESGCM(data_key).encrypt(payload_nonce, json.dumps(secret).encode(), None),
    )


def open_envelope(envelope: Envelope, *, master: AESGCM) -> Secret:
    """Unwrap the data key and decrypt the payload.

    Raises:
        CredentialUnavailableError: for every way this can fail. See the module docstring
            for why they are not distinguished.
    """
    try:
        data_key = master.decrypt(envelope.key_nonce, envelope.wrapped_key, None)
        plaintext = AESGCM(data_key).decrypt(envelope.nonce, envelope.ciphertext, None)
        decoded: Secret = json.loads(plaintext)
    except (InvalidTag, TypeError, ValueError) as exc:
        raise CredentialUnavailableError(UNREADABLE) from exc

    return decoded
