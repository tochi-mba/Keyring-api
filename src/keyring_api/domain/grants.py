"""Invites and password resets.

Both are the same thing: a single-use, expiring, high-entropy token that authorises one
specific action, stored only as a hash. Modelling them once means the rules that are
easy to get wrong -- expiry, single use, revocation on password change -- are written
once and tested once, rather than twice with a subtle difference between them.

What is never stored is the token itself. A grant row is worthless to anyone who reads
the database, which matters most for reset tokens: a reset token is a password until it
expires.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

GRANT_ID_PREFIX = "grant_"


class GrantPurpose(StrEnum):
    """What redeeming this token is allowed to do.

    Recorded and checked, so a token minted for one purpose cannot be presented at the
    endpoint for the other -- an invite is not a password reset for an existing account.
    """

    INVITE = "invite"
    # S105 flags the member name as a hardcoded password. It is an enum label that is
    # written into a stored row and compared against, not a secret.
    PASSWORD_RESET = "password_reset"  # noqa: S105


def new_grant_id() -> str:
    """Return a fresh grant id. Identifies the row; never the token."""
    return f"{GRANT_ID_PREFIX}{uuid.uuid4().hex}"


@dataclass(frozen=True, slots=True)
class Grant:
    """One outstanding invite or reset token."""

    grant_id: str
    purpose: GrantPurpose
    token_hash: str
    created_at: datetime
    expires_at: datetime
    email: str | None = None
    """The address an invite was issued to. Becomes the new account's address."""

    account_id: str | None = None
    """The account a reset applies to."""

    redeemed_at: datetime | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        if self.email is None and self.account_id is None:
            msg = "a grant must name either an email or an account"
            raise ValueError(msg)

    def is_redeemable(self, *, now: datetime) -> bool:
        """Whether this token may still be used.

        One predicate for all three failure modes -- unused, unexpired, unrevoked -- so
        a caller cannot check two of them and forget the third.
        """
        return self.redeemed_at is None and not self.revoked and now < self.expires_at

    def redeemed(self, *, now: datetime) -> Grant:
        """Mark this token used. The store decides who wins a race to redeem it."""
        return replace(self, redeemed_at=now)

    def revoked_now(self) -> Grant:
        """Invalidate this token without redeeming it.

        Every outstanding reset for an account is revoked when its password changes.
        Without that, an attacker who requested a reset before being locked out still
        holds a working link afterwards.
        """
        return replace(self, revoked=True)
