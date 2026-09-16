"""Everything this library raises deliberately.

The split that matters is between the caller being wrong and keyring being unavailable.

* :class:`AuthenticationError` is the caller's token, or the calling service's token, being
  refused. It always carries one fixed message, whichever rule did the refusing, because each
  distinction a caller can tell apart is an oracle that helps somebody forge the next token.
  Consuming services render it as a 401.
* :class:`KeyringUnreachableError` is keyring's keys, or keyring itself, being unavailable.
  The token may be perfectly good. Consuming services render it as a 503 -- telling somebody
  to log in again because keyring was briefly down would be advice that does not help.

The credential errors are keyring's answers on its internal surface, each of which points at
a different person: the operator (:class:`KeyringRejectedError`), the person who has not
connected a service (:class:`CredentialNotFoundError`), or the person whose stored grant has
stopped working (:class:`CredentialUnavailableError`).
"""

from __future__ import annotations

BAD_TOKEN = "the token was not accepted"  # noqa: S105 -- a message, not a credential
"""The one thing every token refusal says."""

BAD_SERVICE = "service credentials were not accepted"
"""The one thing every service-token refusal says."""


class KeyringClientError(Exception):
    """Base class for every error this library raises deliberately."""


class AuthenticationError(KeyringClientError):
    """A token was not accepted. Deliberately undifferentiated; the reason goes to the log."""


class KeyringUnreachableError(KeyringClientError):
    """Keyring, or its published keys, could not be reached. Not the caller's fault."""


class KeyringRejectedError(KeyringClientError):
    """Keyring's internal surface answered 401.

    Keyring does not say which of the two credentials it refused. A caller that has just
    verified the user token itself knows the answer is its *own* service token, which is an
    operator's problem rather than something the person can fix by signing in again.
    """


class CredentialNotFoundError(KeyringClientError):
    """No such profile, or no such connection on it, for the person the token names."""


class CredentialUnavailableError(KeyringClientError):
    """Keyring holds the connection and could not make it usable.

    The vault is sealed, the grant was revoked at the provider, or a refresh failed. The
    message is keyring's own ``detail``, which is written to name the fix.
    """
