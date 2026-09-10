"""Encrypted credential storage on the local filesystem.

Layout::

    <root>/<account_id>/<profile>/<service>.json

Each file is an envelope: a per-secret data key, itself encrypted ("wrapped") by the
master key from the environment, alongside the ciphertext that data key protects. Both
layers are AES-256-GCM.

**Why envelope encryption rather than encrypting straight with the master key.** The
master key is then used for 32 bytes per secret instead of for every credential in the
vault, which bounds how much material a single key protects; and re-keying later means
rewrapping a few data keys rather than decrypting and re-encrypting every credential.

**Why the file mode matters as much as the cipher.** Encryption defends against a stolen
disk or a mishandled backup. Mode 0600 defends against every other process and user on
the machine, which is by far the likelier reader. The directories are 0700 too: a
world-readable directory leaks which services each person has connected even when every
file in it is unreadable.

**What is deliberately not defended against.** The server can decrypt everything, because
unattended OAuth refresh requires it -- see ADR-0006. Nothing here changes that.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import re
import tempfile
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keyring_api.domain.errors import CredentialUnavailableError, VaultSealedError

if TYPE_CHECKING:
    from pathlib import Path

    from keyring_api.secrets.base import Secret

DATA_KEY_BYTES = 32
NONCE_BYTES = 12
"""96 bits, the size AES-GCM is specified for. A fresh one per encryption, never reused."""

SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700

ENVELOPE_VERSION = 1
"""Recorded in every file so a future format change can be recognised rather than guessed."""

SEALED_MESSAGE = "the credential vault is sealed: set KEYRING_MASTER_KEY"

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._@+-]{1,128}$")
"""What may become a path segment.

A dot is allowed but a segment that is only dots is not, so ``.`` and ``..`` are
excluded while ``spotify.com`` is not. Separators, NULs and control characters cannot
match at all.
"""


def check_identifier(value: str, *, what: str) -> str:
    """Validate one path segment, or refuse.

    These identifiers come from internal callers today. "Internal" is a property of the
    current callers rather than of this store, though, so the check lives here: a future
    endpoint that passes a name straight through must not be able to turn into a path
    traversal because of where it was called from.

    Raises:
        ValueError: if the value could escape its directory or is otherwise unusable.
    """
    if not _SAFE_IDENTIFIER.match(value) or set(value) == {"."}:
        msg = f"{what} is not a usable identifier"
        raise ValueError(msg)
    return value


class EncryptedFileSecretStore:
    """Envelope-encrypted secrets, one file each."""

    def __init__(self, *, root: Path, master_key: bytes | None) -> None:
        self._root = root
        self._master = AESGCM(master_key) if master_key is not None else None
        self._lock = asyncio.Lock()

    @property
    def is_sealed(self) -> bool:
        return self._master is None

    def path_for(self, account_id: str, profile: str, service: str) -> Path:
        """Where one secret lives. Validates every segment before building the path."""
        return (
            self._root
            / check_identifier(account_id, what="account")
            / check_identifier(profile, what="profile")
            / f"{check_identifier(service, what='service')}.json"
        )

    async def get(self, account_id: str, profile: str, service: str) -> Secret | None:
        master = self._require_key()
        path = self.path_for(account_id, profile, service)

        async with self._lock:
            if not path.exists():
                return None
            raw = path.read_text()

        return _open_envelope(raw, master=master)

    async def put(self, account_id: str, profile: str, service: str, secret: Secret) -> None:
        master = self._require_key()
        path = self.path_for(account_id, profile, service)
        envelope = _seal_envelope(secret, master=master)

        async with self._lock:
            _make_private_dirs(path.parent, root=self._root)
            _write_private(path, envelope)

    async def delete(self, account_id: str, profile: str, service: str) -> bool:
        path = self.path_for(account_id, profile, service)

        async with self._lock:
            if not path.exists():
                return False
            path.unlink()
            return True

    async def delete_profile(self, account_id: str, profile: str) -> int:
        directory = (
            self._root
            / check_identifier(account_id, what="account")
            / check_identifier(profile, what="profile")
        )
        async with self._lock:
            return _remove_tree(directory)

    async def delete_account(self, account_id: str) -> int:
        directory = self._root / check_identifier(account_id, what="account")

        async with self._lock:
            return _remove_tree(directory)

    def _require_key(self) -> AESGCM:
        """Return the master cipher, or refuse to do anything without one.

        Refusing is the only acceptable answer. Writing plaintext as a fallback would
        put credentials on disk unencrypted; discarding the write silently would lose a
        credential the caller believes was stored.
        """
        if self._master is None:
            raise VaultSealedError(SEALED_MESSAGE)
        return self._master


def _seal_envelope(secret: Secret, *, master: AESGCM) -> str:
    """Encrypt a secret under a fresh data key, wrapped by the master key."""
    data_key = os.urandom(DATA_KEY_BYTES)
    key_nonce = os.urandom(NONCE_BYTES)
    payload_nonce = os.urandom(NONCE_BYTES)

    ciphertext = AESGCM(data_key).encrypt(payload_nonce, json.dumps(secret).encode(), None)
    wrapped = master.encrypt(key_nonce, data_key, None)

    return json.dumps(
        {
            "version": ENVELOPE_VERSION,
            "wrapped_key": _b64(wrapped),
            "key_nonce": _b64(key_nonce),
            "nonce": _b64(payload_nonce),
            "ciphertext": _b64(ciphertext),
        }
    )


def _open_envelope(raw: str, *, master: AESGCM) -> Secret:
    """Unwrap the data key and decrypt the payload.

    Every failure -- malformed JSON, a missing field, a wrong key, a tampered
    ciphertext -- becomes one error. AES-GCM authenticates, so a wrong key is a clean
    failure rather than plausible-looking nonsense; that matters, because a store that
    silently returned corrupted material would surface days later as a mysterious
    rejection at the third-party service.
    """
    try:
        envelope = json.loads(raw)
        data_key = master.decrypt(
            _unb64(envelope["key_nonce"]), _unb64(envelope["wrapped_key"]), None
        )
        plaintext = AESGCM(data_key).decrypt(
            _unb64(envelope["nonce"]), _unb64(envelope["ciphertext"]), None
        )
        decoded: Secret = json.loads(plaintext)
    except (
        InvalidTag,
        KeyError,
        TypeError,
        ValueError,
        binascii.Error,
    ) as exc:
        msg = "stored credential material could not be read"
        raise CredentialUnavailableError(msg) from exc

    return decoded


def _make_private_dirs(directory: Path, *, root: Path) -> None:
    """Create the directory chain owner-only, including the root itself."""
    for path in (root, *_chain_between(root, directory)):
        path.mkdir(mode=SECRET_DIR_MODE, exist_ok=True)
        # mkdir's mode is masked by the process umask, so it is set explicitly after.
        path.chmod(SECRET_DIR_MODE)


def _chain_between(root: Path, directory: Path) -> list[Path]:
    """The directories from ``root`` down to ``directory``, outermost first."""
    relative = directory.relative_to(root)
    return [root.joinpath(*relative.parts[: index + 1]) for index in range(len(relative.parts))]


def _write_private(path: Path, contents: str) -> None:
    """Write owner-only, atomically.

    Written to a temporary file in the same directory and renamed into place, so a crash
    mid-write leaves the previous credential intact rather than a truncated file that
    will not decrypt. The mode is set on the temporary file *before* the rename, so
    there is no instant at which the final path exists while readable by anyone else.
    """
    handle, staging_name = tempfile.mkstemp(dir=path.parent, prefix=".staging-")
    staging = path.parent / staging_name.rsplit("/", 1)[-1]
    try:
        with os.fdopen(handle, "w") as staged:
            staged.write(contents)
        staging.chmod(SECRET_FILE_MODE)
        staging.replace(path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise


def _remove_tree(directory: Path) -> int:
    """Delete a directory of secrets. Returns how many secret files went."""
    if not directory.is_dir():
        return 0

    removed = 0
    for path in sorted(directory.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
            removed += 1
        else:
            path.rmdir()
    directory.rmdir()
    return removed


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _unb64(encoded: object) -> bytes:
    if not isinstance(encoded, str):
        msg = "envelope field is not base64 text"
        raise TypeError(msg)
    return base64.b64decode(encoded, validate=True)
