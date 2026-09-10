"""Domain error vocabulary.

These describe what went wrong in business terms. Translating them into HTTP status
codes is the API layer's job -- nothing here knows what a status code is.

One rule shapes this whole module: **an error must not reveal whether something
exists.** There is no `AccountNotFoundError` raised at a login, no
`ProfileBelongsToSomeoneElseError`. A caller who supplies the wrong password and a
caller who names an account that was never created get the same
:class:`AuthenticationError`, and a caller reaching for another account's profile gets
the same :class:`ProfileNotFoundError` they would get for a name nobody has used. The
alternative leaks the membership of the service to anyone with a browser.
"""

from __future__ import annotations


class DomainError(Exception):
    """Base class for every error this package raises deliberately."""


class AuthenticationError(DomainError):
    """A credential was not accepted.

    Deliberately undifferentiated. Whether the account is unknown, the password is
    wrong, the session has expired or the account is locked, the caller is told the same
    thing, because each distinction is an oracle. The specific reason goes to the logs,
    where only the operator reads it.
    """


class AccountLockedError(AuthenticationError):
    """Too many failed attempts for this account, recently.

    A subclass of :class:`AuthenticationError` so a handler that forgets to catch it
    still renders the indistinguishable response rather than a distinctive one.
    """


class AccountExistsError(DomainError):
    """An account already exists for this address.

    Only ever raised on the administrative invite path, never in response to anything a
    stranger can send.
    """


class InvalidPasswordError(DomainError, ValueError):
    """A proposed password does not meet the policy.

    Also a :class:`ValueError` so callers validating input with generic machinery catch
    it without importing this module.
    """


class InvalidEmailError(DomainError, ValueError):
    """A proposed email address cannot be stored as given."""


class InvalidGrantError(DomainError):
    """An invite or reset token is unknown, expired, or already used.

    One error for all three, for the same reason as :class:`AuthenticationError`: an
    attacker holding a guessed token learns nothing from the difference between "no such
    token" and "that token was already redeemed".
    """


class InvalidProfileNameError(DomainError, ValueError):
    """A profile name cannot be stored as given."""


class ProfileNotFoundError(DomainError):
    """No profile of that name is owned by this account.

    Raised identically whether the profile does not exist or belongs to somebody else.
    """


class ProfileExistsError(DomainError):
    """This account already has a profile with that name."""


class ConnectionNotFoundError(DomainError):
    """The profile has no connection to that service."""


class CredentialUnavailableError(DomainError):
    """A credential exists but cannot currently be produced in usable form.

    The vault is sealed, the stored material will not decrypt, or a refresh failed.
    Carries the fix, because the caller is a service that will surface it to a person.
    """


class VaultSealedError(CredentialUnavailableError):
    """No usable master key is configured, so nothing can be read or written.

    Distinct from a decryption failure: this is an operator's misconfiguration and has a
    specific remedy, whereas a decryption failure means the key and the data disagree.
    """


class InvalidOAuthStateError(DomainError):
    """An OAuth callback arrived with state that is unknown, expired, used, or tampered with.

    Treated as one error because an attacker who forges a callback must not learn which
    of those it was.
    """


class LimitExceededError(DomainError):
    """A per-account limit would be exceeded. Names the limit, so a caller can act on it."""


class RateLimitedError(DomainError):
    """Too many attempts against a rate-limited endpoint."""

    def __init__(self, message: str, *, retry_after_seconds: float) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
