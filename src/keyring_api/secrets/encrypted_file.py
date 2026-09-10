"""Encrypted credential storage on the local filesystem.

Layout::

    <root>/<account_id>/<profile>/<service>.json

Each file holds one :class:`~keyring_api.secrets.envelope.Envelope`, base64'd into JSON.
The cryptography itself lives in that module; what is here is the part about *files* --
where they go, who may read them, and how a write survives a crash halfway through.

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

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keyring_api.domain.errors import CredentialUnavailableError
from keyring_api.secrets.envelope import (
    UNREADABLE,
    Envelope,
    open_envelope,
    require_master,
    seal,
)

if TYPE_CHECKING:
    from pathlib import Path

    from keyring_api.secrets.base import Secret

SECRET_FILE_MODE = 0o600
SECRET_DIR_MODE = 0o700

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
        master = require_master(self._master)
        path = self.path_for(account_id, profile, service)

        async with self._lock:
            if not path.exists():
                return None
            raw = path.read_text()

        return open_envelope(_decode(raw), master=master)

    async def put(self, account_id: str, profile: str, service: str, secret: Secret) -> None:
        master = require_master(self._master)
        path = self.path_for(account_id, profile, service)
        envelope = _encode(seal(secret, master=master))

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


def _encode(envelope: Envelope) -> str:
    """Render an envelope as the JSON that goes on disk."""
    return json.dumps(
        {
            "version": envelope.version,
            "wrapped_key": _b64(envelope.wrapped_key),
            "key_nonce": _b64(envelope.key_nonce),
            "nonce": _b64(envelope.nonce),
            "ciphertext": _b64(envelope.ciphertext),
        }
    )


def _decode(raw: str) -> Envelope:
    """Parse the JSON on disk back into an envelope.

    A malformed file becomes the same error a wrong key does. A caller cannot act on the
    difference, and distinguishing them would say which of the two happened to somebody
    who supplied neither.
    """
    try:
        parsed = json.loads(raw)
        return Envelope(
            version=int(parsed["version"]),
            wrapped_key=_unb64(parsed["wrapped_key"]),
            key_nonce=_unb64(parsed["key_nonce"]),
            nonce=_unb64(parsed["nonce"]),
            ciphertext=_unb64(parsed["ciphertext"]),
        )
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise CredentialUnavailableError(UNREADABLE) from exc


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
