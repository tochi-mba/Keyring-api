"""What an account is, and the rules an address and a password have to satisfy.

Pure data and pure rules. Hashing lives in the accounts layer, because it needs a
library and a cost configuration; deciding whether a password is *allowed* lives here,
because it is a policy and policies belong where they can be read.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

from keyring_api.domain.errors import InvalidEmailError, InvalidPasswordError

if TYPE_CHECKING:
    from datetime import datetime

MIN_PASSWORD_LENGTH = 8
"""NIST SP 800-63B's floor. Length is the requirement; composition rules are not."""

MAX_PASSWORD_LENGTH = 1024
"""A ceiling, because Argon2 will faithfully hash a megabyte if asked to.

Hashing is deliberately expensive, which makes an unbounded password an unauthenticated
request that costs the server as much CPU as the caller cares to ask for.
"""

MAX_EMAIL_LENGTH = 254
"""RFC 5321's limit on a path. Stored, indexed, and echoed into log records."""

ACCOUNT_ID_PREFIX = "acct_"

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
"""Deliberately loose.

The only address validation that is ever correct is sending mail to it. This rejects
what cannot be stored or compared -- no ``@``, embedded whitespace, a bare hostname --
and leaves the rest to the invite actually arriving.
"""


class AccountStatus(StrEnum):
    """Whether an account may authenticate at all."""

    ACTIVE = "active"
    DISABLED = "disabled"
    """Set by an administrator. Distinct from a lockout, which expires by itself."""


def new_account_id() -> str:
    """Return a fresh, opaque account id.

    Opaque on purpose: this value goes into log records and into the ``sub`` claim of
    every token another service verifies. An email address in either place would put
    personal data everywhere the logs and the tokens go.
    """
    return f"{ACCOUNT_ID_PREFIX}{uuid.uuid4().hex}"


def normalize_email(raw: str) -> str:
    """Reduce an address to the single form it is stored and compared as.

    Lowercased in full. RFC 5321 makes the local part case-sensitive, but no mail
    provider treats it that way, and honouring the letter of the spec here would let one
    person hold two accounts and be unable to explain why their login sometimes fails.

    Raises:
        InvalidEmailError: if the address cannot be stored or compared as given.
    """
    address = raw.strip().lower()

    if len(address) > MAX_EMAIL_LENGTH:
        msg = f"email address must be at most {MAX_EMAIL_LENGTH} characters"
        raise InvalidEmailError(msg)

    if not _EMAIL.match(address):
        # Covers the empty string, a missing @, and anything with embedded whitespace --
        # including a newline, which is rejected rather than stripped so an address
        # assembled from a header-injection attempt does not quietly become valid.
        msg = "email address is not a usable address"
        raise InvalidEmailError(msg)

    return address


def check_password_policy(password: str) -> None:
    """Accept or reject a proposed password.

    Length is the whole policy. Forced composition rules -- an uppercase, a digit, a
    symbol -- measurably push people towards ``Password1!`` and a sticky note, which is
    why SP 800-63B stopped recommending them.

    Raises:
        InvalidPasswordError: if the password does not meet the policy.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        msg = f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        raise InvalidPasswordError(msg)

    if len(password) > MAX_PASSWORD_LENGTH:
        msg = f"password must be at most {MAX_PASSWORD_LENGTH} characters"
        raise InvalidPasswordError(msg)

    if not password.strip():
        msg = "password must not be entirely whitespace"
        raise InvalidPasswordError(msg)


@dataclass(frozen=True, slots=True)
class Account:
    """A person who logs in.

    Frozen. The stores hand out shared references, and a mutable account would let one
    request's failed login alter the object another request is in the middle of reading.
    Every transition returns a new account instead.
    """

    account_id: str
    email: str
    password_hash: str
    created_at: datetime
    updated_at: datetime
    status: AccountStatus = AccountStatus.ACTIVE
    failed_attempts: int = 0
    locked_until: datetime | None = None

    def is_locked(self, *, now: datetime) -> bool:
        """Whether the account is currently within a lockout window."""
        return self.locked_until is not None and now < self.locked_until

    def with_failure(
        self, *, now: datetime, lockout_threshold: int, lockout_seconds: float
    ) -> Account:
        """Record a failed authentication, locking the account if that was one too many.

        The lock is a fixed window rather than an escalating one: it exists to make
        online guessing impractical, and an escalating lock hands an attacker a way to
        keep a real person locked out indefinitely.
        """
        attempts = self.failed_attempts + 1
        locked_until = (
            now + timedelta(seconds=lockout_seconds)
            if attempts >= lockout_threshold
            else self.locked_until
        )
        return replace(self, failed_attempts=attempts, locked_until=locked_until, updated_at=now)

    def with_success(self) -> Account:
        """Clear the failure count and any lock, after an authentication that worked."""
        return replace(self, failed_attempts=0, locked_until=None)
