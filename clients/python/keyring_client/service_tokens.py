"""Which service a static bearer token belongs to.

Keyring's internal surface, and settings-api's, take **two** credentials: the calling
service's own token, proving which service is asking, and the end user's signed token,
proving who it is asking for. This module is the first half.

The comparison does not stop early. A loop that returned on the first match would leak, in
its timing, roughly where in the configured list the caller sits. Each comparison is
:func:`hmac.compare_digest` over bytes -- bytes rather than ``str``, because ``compare_digest``
raises on a non-ASCII string, and a header is caller-supplied.

A token shorter than :data:`MIN_SERVICE_TOKEN_CHARS`, or two services sharing one, is refused
when the authenticator is built. The first is a placeholder somebody forgot to replace; the
second makes whichever name matched first decide what the caller may do, so the weaker of the
two grants is reachable with the other's token.
"""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from keyring_client._log import StdlibLogger
from keyring_client.errors import BAD_SERVICE, AuthenticationError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from keyring_client._log import Logger

MIN_SERVICE_TOKEN_CHARS = 32
"""Short enough to generate with one command, long enough that guessing is not a strategy."""

BEARER_PREFIX = "Bearer "


def check_service_token(value: str) -> str:
    """Return ``value`` if it is fit to be a service token, or raise.

    For configuration validators, so a deployment finds out at startup rather than at the
    first internal call.

    Raises:
        ValueError: shorter than the minimum, or with surrounding whitespace.
    """
    if value.strip() != value:
        msg = "a service token must not have surrounding whitespace"
        raise ValueError(msg)
    if len(value) < MIN_SERVICE_TOKEN_CHARS:
        msg = f"a service token must be at least {MIN_SERVICE_TOKEN_CHARS} characters"
        raise ValueError(msg)
    return value


class ServiceAuthenticator:
    """Turns a presented service token into the name of the service it was configured for."""

    def __init__(self, tokens: Mapping[str, str], *, logger: Logger | None = None) -> None:
        """Build from ``{service name: token}``.

        Raises:
            ValueError: a token is malformed, or two services share one.
        """
        for token in tokens.values():
            check_service_token(token)
        if len(set(tokens.values())) != len(tokens):
            msg = "two services share a service token; each needs its own"
            raise ValueError(msg)
        # Encoded once here rather than per request. Nothing renders this object.
        self._tokens = tuple((name, token.encode()) for name, token in tokens.items())
        self._log: Logger = logger if logger is not None else StdlibLogger(__name__)

    @property
    def configured(self) -> tuple[str, ...]:
        """Every configured service name, sorted, for readiness checks and diagnostics."""
        return tuple(sorted(name for name, _ in self._tokens))

    def identify(self, presented: str | None) -> str:
        """The service this bare token belongs to.

        Raises:
            AuthenticationError: no token, or one that matches no configured service.
        """
        if not presented:
            self._log.info("service_token_rejected", reason="missing")
            raise AuthenticationError(BAD_SERVICE)

        candidate = presented.encode()
        matched: str | None = None
        for name, configured in self._tokens:
            # No break. See the module docstring.
            if hmac.compare_digest(candidate, configured):
                matched = name

        if matched is None:
            self._log.info("service_token_rejected", reason="unknown")
            raise AuthenticationError(BAD_SERVICE)
        return matched

    def identify_authorization(self, authorization: str | None) -> str:
        """The service behind an ``Authorization: Bearer <token>`` header value.

        Raises:
            AuthenticationError: no header, another scheme, or an unknown token.
        """
        if authorization is None or not authorization.startswith(BEARER_PREFIX):
            self._log.info("service_token_rejected", reason="scheme")
            raise AuthenticationError(BAD_SERVICE)
        return self.identify(authorization[len(BEARER_PREFIX) :])
