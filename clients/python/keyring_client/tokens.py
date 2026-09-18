"""Turning a keyring token into an identity, or into one undifferentiated refusal.

This mirrors what keyring does when it verifies a token it minted itself
(``keyring_api.accounts.signing.TokenSigner.verify``), because the minting half and the
verifying half have to agree about what a valid token is. Five rules carry the weight, and
each is a vulnerability when dropped rather than a matter of taste:

**The algorithm is pinned to RS256.** Leaving it open is the classic JWT failure: ``alg:
none`` with no signature, or HS256 signed with the public key anybody can fetch from the
JWKS endpoint.

**The issuer is pinned.** A token signed by a second keyring -- a staging one, somebody's
laptop -- is not a token for this deployment, however valid its signature.

**Every claim keyring puts in a token is required.** PyJWT checks most claims only when they
are present, so a token that omits one passes the check for it.

**Expiry is checked against the injected clock.** PyJWT's ``verify_exp`` and ``verify_iat``
are both off, because both read the wall clock; ``iat`` in particular would refuse every good
token in a test that pinned the clock to next Tuesday. ``exp`` is re-checked here.

**The audience decides nothing until it is verified.** PyJWT only checks an audience it is
handed, and the only place to learn which one a token claims is the token, so the unverified
claim says *what to check* and the caller's :class:`AudiencePolicy` is applied to the verified
copy that comes back.

Every refusal is the same :class:`~keyring_client.errors.AuthenticationError` with the same
message. The reason goes to the log, where an operator reads it and a forger does not.
:class:`~keyring_client.errors.KeyringUnreachableError` passes through untouched: it is our
failure, not the caller's.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, Protocol, runtime_checkable

import jwt

from keyring_client._log import StdlibLogger
from keyring_client.errors import BAD_TOKEN, AuthenticationError

if TYPE_CHECKING:
    from keyring_client._log import Logger
    from keyring_client.clock import Clock
    from keyring_client.jwks import JwksClient

ALGORITHM = "RS256"
"""The only algorithm a token may be signed with."""

REQUIRED_CLAIMS = ("exp", "iat", "iss", "sub", "aud")
"""Exactly what keyring puts in a token. No email, no roles, no profile."""

AUDIENCE_SEPARATOR = "."


@runtime_checkable
class AudiencePolicy(Protocol):
    """Which verified audiences a service answers to."""

    def accepts(self, audience: str) -> bool:
        """Whether a token minted for ``audience`` is one for this service."""
        ...


@dataclass(frozen=True, slots=True)
class ExactAudience:
    """One audience, spelled exactly: ``example-tool`` accepts that and nothing else."""

    name: str

    def __post_init__(self) -> None:
        check_audience_name(self.name)

    def accepts(self, audience: str) -> bool:
        return audience == self.name


@dataclass(frozen=True, slots=True)
class AudienceFamily:
    """An audience and its compartments: ``user`` accepts ``user`` and ``user.<anything>``.

    The separator is required, which is what stops ``example`` accepting ``example-toolkit``.
    What a compartment grants is the consuming service's decision (user-api's scopes,
    settings-api's namespaces), so this only says whether the token belongs to the family and
    hands back the compartment it named.
    """

    prefix: str

    def __post_init__(self) -> None:
        check_audience_name(self.prefix)

    def accepts(self, audience: str) -> bool:
        return audience == self.prefix or audience.startswith(self.prefix + AUDIENCE_SEPARATOR)

    def compartment_of(self, audience: str) -> str | None:
        """``health`` for ``user.health``; ``None`` for ``user`` or for a foreign audience."""
        head, separator, compartment = audience.partition(AUDIENCE_SEPARATOR)
        if not separator or head != self.prefix:
            return None
        return compartment


def check_audience_name(value: str) -> str:
    """Return ``value`` if it could head an audience, or raise.

    Surrounding whitespace is refused because ``" settings"`` pasted out of a YAML block
    matches no audience keyring ever mints, and every request becomes a 401 with nothing in
    the configuration looking wrong. A dot is refused because it is the compartment separator.

    Raises:
        ValueError: empty, untrimmed, or containing a dot.
    """
    if not value or value.strip() != value or AUDIENCE_SEPARATOR in value:
        msg = f"audience {value!r} must be non-empty, trimmed, and contain no dot"
        raise ValueError(msg)
    return value


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    """What a verified token says: whose it is, and which audience it was minted for."""

    account_id: str
    """The verified ``sub``: keyring's opaque account id, the only identity a service learns."""

    audience: str
    """The verified ``aud``. Server-derived provenance, never read from a request body."""


class TokenVerifier:
    """Checks tokens keyring minted, against keys keyring published."""

    def __init__(
        self,
        *,
        jwks: JwksClient,
        issuer: str,
        clock: Clock,
        logger: Logger | None = None,
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer
        self._clock = clock
        self._log: Logger = logger if logger is not None else StdlibLogger(__name__)

    async def verify(self, token: str, *, audience: AudiencePolicy) -> VerifiedToken:
        """Check a token and say who it is for.

        Raises:
            AuthenticationError: a bad signature, another algorithm, another issuer, an
                audience ``audience`` refuses, an expired token, a missing claim, a malformed
                token, or a key id that is not keyring's. One message for all of them.
            KeyringUnreachableError: the keys could not be fetched. Deliberately not caught.
        """
        kid = self._kid_of(token)
        key = await self._jwks.key_for(kid)
        asserted = self._audience_of(token)

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[ALGORITHM],
                audience=asserted,
                issuer=self._issuer,
                options={
                    "require": list(REQUIRED_CLAIMS),
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except jwt.InvalidTokenError as exc:
            self._refuse("decode", kid=kid, error=type(exc).__name__)

        expires = claims["exp"]
        if isinstance(expires, bool) or not isinstance(expires, int | float):
            self._refuse("expiry_shape", kid=kid)
        if self._clock.now().timestamp() >= expires:
            self._refuse("expired", kid=kid)

        account_id = claims["sub"]
        if not isinstance(account_id, str) or not account_id:
            self._refuse("subject", kid=kid)

        verified_audience: str = claims["aud"]
        if not audience.accepts(verified_audience):
            self._refuse("audience", kid=kid)

        return VerifiedToken(account_id=account_id, audience=verified_audience)

    def _refuse(self, reason: str, **fields: str) -> NoReturn:
        """Log why, and refuse in the words every other refusal uses."""
        self._log.info("token_rejected", reason=reason, **fields)
        raise AuthenticationError(BAD_TOKEN)

    def _kid_of(self, token: str) -> str:
        """The key id from the unverified header, which chooses the key that does the checking.

        Keyring always sets one. A token without it is refused rather than tried against a
        default key, because choosing the key on the sender's behalf is doing their search.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            self._refuse("header")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            self._refuse("kid")
        return kid

    def _audience_of(self, token: str) -> str:
        """The audience a token claims, unverified, as a single string and never a list.

        A token naming several audiences is one whose holder is entitled somewhere else as
        well, and "which of them did you mean" would have to be answered by guessing.
        """
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            self._refuse("payload")
        asserted = unverified.get("aud")
        if not isinstance(asserted, str):
            self._refuse("audience_shape")
        return asserted
