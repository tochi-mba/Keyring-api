"""Short-lived signed tokens, and the public keys that verify them.

A person authenticates to keyring with an opaque session token. Another *service* --
media-tool, say -- needs to know who a request is for without asking keyring on every
request, so keyring mints a short-lived signed token and publishes its public key at a
JWKS endpoint. The consuming service verifies locally.

Two decisions, and the tension between them is the whole design:

**Signed rather than opaque, for service-to-service.** An opaque token would mean a
network call to keyring on every single request another service serves. Signed means
none.

**Fifteen minutes rather than fifteen hours.** A signed token cannot be revoked -- that
is what makes it verifiable offline. The expiry is therefore the only revocation
mechanism there is, and it bounds how long a logged-out session keeps working somewhere
else. Short enough to matter, long enough that minting is not on the hot path.

RS256 rather than EdDSA, which would be smaller and faster, because RS256 is what every
JWT library on every runtime supports. This service exists to be consumed by things not
written yet.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from keyring_api.core.logging import get_logger
from keyring_api.domain.errors import AuthenticationError

if TYPE_CHECKING:
    from pathlib import Path

    from keyring_api.core.clock import Clock

logger = get_logger(__name__)

ALGORITHM = "RS256"
KEY_SIZE_BITS = 2048
PUBLIC_EXPONENT = 65537

KEY_FILE_MODE = 0o600
KEY_DIR_MODE = 0o700
"""The private key is the authority behind every token another service trusts."""

TOKEN_TYPE = "Bearer"  # noqa: S105 -- the scheme name, not a credential

BAD_TOKEN = "the token was not accepted"  # noqa: S105 -- a message, not a credential
"""One message for every verification failure. Which one it was is nobody's business."""


class TokenSigner:
    """Mints access tokens and publishes the key that verifies them."""

    def __init__(self, *, key_path: Path, issuer: str, clock: Clock) -> None:
        self._issuer = issuer
        self._clock = clock
        self._private = _load_or_create_key(key_path)
        self._key_id = _thumbprint(self._private.public_key())

    def issue(self, *, account_id: str, audience: str, ttl_seconds: float) -> str:
        """Mint a token asserting that the bearer is acting for ``account_id``.

        The subject is the opaque account id, never an email address: this token is
        handed to another service, logged there, and possibly cached -- none of which
        should spread somebody's address around.
        """
        now = self._clock.now()
        claims = {
            "iss": self._issuer,
            "sub": account_id,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        }
        return jwt.encode(
            claims,
            self._private_pem(),
            algorithm=ALGORITHM,
            headers={"kid": self._key_id},
        )

    def verify(self, token: str, *, audience: str) -> str:
        """Check a token this service issued and return its subject.

        Present so keyring can authenticate a token it minted when a service presents
        one back on the internal credential endpoint. The algorithm is pinned: leaving
        it open is the classic JWT failure, where a caller supplies ``alg: none`` or
        downgrades RS256 to HS256 and signs with the public key.

        Expiry is checked against the injected clock rather than PyJWT's own reading of
        the wall clock. That is the codebase invariant -- nothing reads the time
        directly -- and it is what makes the expiry rule testable at all: with PyJWT
        doing it, a test could only assert that a token minted now is valid now.

        Every failure becomes one :class:`AuthenticationError`. That is not only for
        the caller's benefit: it keeps PyJWT's exception types from becoming part of the
        API layer's vocabulary, which an import-linter contract forbids and which would
        make swapping the JWT library a change to the HTTP handlers.

        Raises:
            AuthenticationError: expired, wrong audience, wrong issuer, unsigned, or
                missing a required claim -- undifferentiated, because a caller holding a
                forged token learns nothing useful from which.
        """
        try:
            claims = jwt.decode(
                token,
                self._public_pem(),
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=self._issuer,
                options={
                    "require": ["exp", "iat", "iss", "sub", "aud"],
                    # Checked below against the injected clock instead. PyJWT would read
                    # the wall clock, which breaks the codebase invariant and makes the
                    # expiry rule untestable without waiting.
                    "verify_exp": False,
                },
            )
        except jwt.InvalidTokenError as exc:
            raise AuthenticationError(BAD_TOKEN) from exc

        if self._clock.now().timestamp() >= float(claims["exp"]):
            raise AuthenticationError(BAD_TOKEN)

        subject: str = claims["sub"]
        return subject

    def jwks(self) -> dict[str, Any]:
        """The public key, in the form a verifying service expects.

        Only the public half. A JWKS document is meant to be fetched by anything that
        needs to verify, so this endpoint is deliberately unauthenticated -- and
        deliberately contains nothing that could sign.
        """
        numbers = self._private.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": ALGORITHM,
                    "kid": self._key_id,
                    "n": _b64url(numbers.n),
                    "e": _b64url(numbers.e),
                }
            ]
        }

    def _private_pem(self) -> bytes:
        return self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def _public_pem(self) -> bytes:
        return self._private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def _load_or_create_key(path: Path) -> rsa.RSAPrivateKey:
    """Read the signing key, generating one on first start.

    Persisted rather than generated per process for a reason that is easy to miss: a key
    that changes on restart invalidates every token in flight and forces every consuming
    service to re-fetch the JWKS at exactly the moment this service is coming back up.
    """
    if path.exists():
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(loaded, rsa.RSAPrivateKey):
            msg = f"the signing key at {path} is not an RSA private key"
            raise TypeError(msg)
        return loaded

    key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_SIZE_BITS)
    path.parent.mkdir(mode=KEY_DIR_MODE, parents=True, exist_ok=True)
    path.parent.chmod(KEY_DIR_MODE)
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(KEY_FILE_MODE)

    logger.info("signing_key_created", path=str(path))
    return key


def _thumbprint(public_key: rsa.RSAPublicKey) -> str:
    """A stable key id derived from the key itself.

    Derived rather than random so it survives a restart: a consuming service caches the
    JWKS by ``kid``, and a new id on every boot would mean a cache miss and a re-fetch
    each time.
    """
    numbers = public_key.public_numbers()
    material = f"{numbers.n}:{numbers.e}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


def _b64url(value: int) -> str:
    """Encode a JWK integer: big-endian bytes, base64url, no padding."""
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()
