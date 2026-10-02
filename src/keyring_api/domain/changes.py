"""What happened to a stored credential, and who made it happen.

Two closed vocabularies, shared by the layer that decides whether a change may go ahead and
the layer that writes the notice about it. Neither names a service, a profile or a value:
a notice goes to a mailbox, and whoever reads that mailbox must not learn from it what the
account holds.
"""

from __future__ import annotations

from enum import StrEnum


class CredentialChange(StrEnum):
    """What was done to a stored credential."""

    STORED = "stored"
    """Added, or written over one that was already there. One word for both, because the
    OAuth callback cannot cheaply tell them apart and a notice that says "added or replaced"
    asks the same question of the reader either way: was that you?"""

    REMOVED = "removed"
    """Deleted from the vault, alone or with the profile that held it."""


class ChangeOrigin(StrEnum):
    """Who asked for the change."""

    PERSON = "person"
    """The account's own session. The only origin that can prove the password again."""

    SERVICE = "service"
    """A service holding a user token the person minted for it. It cannot prove the password
    -- it never sees it -- so an account that asks for re-authentication refuses it."""

    PROVIDER = "provider"
    """An OAuth consent finishing at the callback. The authority is the single-use state the
    flow began with; whether that beginning needed the password was decided then."""

    ADMINISTRATOR = "administrator"
    """Somebody holding ``profiles:delete_any``. Answerable to the audit log rather than to the
    person's password, which they do not have."""
