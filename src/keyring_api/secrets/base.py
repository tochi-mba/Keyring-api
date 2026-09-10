"""The secret store port.

Deliberately narrow, and deliberately shaped around ``(account, profile, service)``.
Every read and every write names an account, so there is no call that could accidentally
reach across one -- the isolation is in the signature rather than in a check the caller
has to remember.

Secrets are opaque JSON-shaped mappings. The store neither knows nor cares what a
credential kind looks like, which is what lets a new kind be added without touching
storage at all.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

Secret = dict[str, object]
"""One credential's stored material. Shape is the credential kind's business."""


@runtime_checkable
class SecretStore(Protocol):
    """Encrypted storage for credential material."""

    @property
    def is_sealed(self) -> bool:
        """Whether the store currently has no usable key.

        Reported by ``/healthy`` so a missing key is visible as a misconfiguration
        rather than discovered as an inexplicable failure at the first credential use.
        """
        ...

    async def get(self, account_id: str, profile: str, service: str) -> Secret | None:
        """Return stored material, or ``None`` if there is none.

        Raises:
            VaultSealedError: no usable key is configured.
            CredentialUnavailableError: the stored material will not decrypt.
        """
        ...

    async def put(self, account_id: str, profile: str, service: str, secret: Secret) -> None:
        """Encrypt and store material, replacing anything already there.

        Raises:
            VaultSealedError: no usable key is configured. Never falls back to plaintext.
        """
        ...

    async def delete(self, account_id: str, profile: str, service: str) -> bool:
        """Remove stored material. Returns whether there was any."""
        ...

    async def delete_profile(self, account_id: str, profile: str) -> int:
        """Remove every secret in one profile. Returns how many went."""
        ...

    async def delete_account(self, account_id: str) -> int:
        """Remove every secret an account owns. Returns how many went.

        Deleting an account must leave nothing behind. Per-account data keys would allow
        cryptographic shredding instead, but at this scale that is key-management
        complexity bought for a property that deleting the files already provides
        (ADR-0005).
        """
        ...
