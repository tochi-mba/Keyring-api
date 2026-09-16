"""Test doubles every consuming service shares, so the fakes cannot drift apart.

Six services each grew a fake keyring of their own, and they disagreed about what keyring
returns -- one of them was built against a stand-in that echoed whatever it was given, and
shipped a credential parser for a response shape keyring has never produced. This module is
the one fake, and it refuses what the real keyring refuses:

* The signing key is a real RSA key, generated **once per process**; a 2048-bit key takes a
  tenth of a second, and a suite that mints hundreds of tokens would otherwise spend its time
  doing arithmetic that proves nothing.
* :class:`FakeKeyring` serves a real JWKS document and keyring's two internal endpoints over
  an :class:`httpx.MockTransport`, answering in keyring's real response shapes. It checks
  the service token, verifies the user token's signature, issuer and audience (which must be
  the calling service's name, as keyring requires), and takes the account from the token.
* :func:`forge_hs256` and :func:`forge_unsigned` are assembled by hand, because PyJWT refuses
  to *produce* them. That refusal protects a signer and does nothing for a verifier.
* Tokens default to a decade-long lifetime: tests that move the clock months forward would
  otherwise watch every good token expire, and the failure reads as an authorisation bug.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from keyring_client.credentials import CREDENTIALS_PATH, FORM_SECRETS_PATH, USER_TOKEN_HEADER
from keyring_client.jwks import JWKS_PATH

if TYPE_CHECKING:
    from collections.abc import Mapping

ISSUER = "https://keyring.test"
BASE_URL = "https://keyring.test"
JWKS_URL = BASE_URL + JWKS_PATH

EPOCH = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
DECADE_SECONDS = 10 * 365 * 24 * 3_600

DEFAULT_SERVICE = "example-service"
DEFAULT_SERVICE_TOKEN = "example-service-token-0123456789abcdef"  # noqa: S105 -- a fixture

SEALED_DETAIL = "the vault is sealed; set KEYRING_MASTER_KEY"

SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ROTATED_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

_PATH_SEGMENTS = 6
"""``/v1/internal/<kind>/<profile>/<service>`` split on ``/``, leading empty segment included."""


class FakeClock:
    """A :class:`~keyring_client.clock.Clock` that only moves when a test tells it to."""

    def __init__(self, start: datetime = EPOCH) -> None:
        self._start = start
        self._now = start

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return (self._now - self._start).total_seconds()

    def advance(self, delta: timedelta | float) -> None:
        """Move time forward by a timedelta or a number of seconds."""
        self._now += delta if isinstance(delta, timedelta) else timedelta(seconds=delta)


def _b64(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def _segment(payload: Mapping[str, Any]) -> bytes:
    packed = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(packed).rstrip(b"=")


def thumbprint(key: rsa.RSAPrivateKey = SIGNING_KEY) -> str:
    """A key id derived from the key, the way keyring derives its own."""
    numbers = key.public_key().public_numbers()
    return hashlib.sha256(f"{numbers.n}:{numbers.e}".encode()).hexdigest()[:16]


def jwks(*keys: rsa.RSAPrivateKey) -> dict[str, Any]:
    """A JWKS document naming each key, in the shape keyring publishes."""
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": thumbprint(key),
                "n": _b64(key.public_key().public_numbers().n),
                "e": _b64(key.public_key().public_numbers().e),
            }
            for key in (keys or (SIGNING_KEY,))
        ]
    }


def private_pem(key: rsa.RSAPrivateKey = SIGNING_KEY) -> bytes:
    """The private half, PEM-encoded, for signing tokens by hand."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_pem(key: rsa.RSAPrivateKey = SIGNING_KEY) -> bytes:
    """The public half, exactly as an attacker gets it from the JWKS endpoint."""
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# One parameter per claim, so a test can bend exactly one and leave the rest alone.
def mint(  # noqa: PLR0913
    *,
    account_id: str = "account-a",
    audience: str = DEFAULT_SERVICE,
    issuer: str = ISSUER,
    issued_at: datetime = EPOCH,
    ttl_seconds: float = DECADE_SECONDS,
    key: rsa.RSAPrivateKey = SIGNING_KEY,
    kid: str | None = None,
    omit: str | None = None,
    claims: Mapping[str, Any] | None = None,
) -> str:
    """Mint a token the way keyring's ``issue_service_token`` does.

    Args:
        account_id: the ``sub``.
        audience: the ``aud``.
        issuer: the ``iss``.
        issued_at: the ``iat``, and the start of the lifetime.
        ttl_seconds: how long after ``issued_at`` the token expires.
        key: which private key signs it.
        kid: the header's key id, when it should not be the signing key's own.
        omit: drop one required claim, for the missing-claim tests.
        claims: replace claims with values keyring would never mint -- a list audience, an
            empty subject, a string expiry.
    """
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": account_id,
        "aud": audience,
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    if omit is not None:
        payload.pop(omit)
    payload.update(claims or {})
    return jwt.encode(
        payload, private_pem(key), algorithm="RS256", headers={"kid": kid or thumbprint(key)}
    )


def _forged_payload(account_id: str, audience: str, issuer: str) -> bytes:
    return _segment(
        {
            "iss": issuer,
            "sub": account_id,
            "aud": audience,
            "iat": int(EPOCH.timestamp()),
            "exp": int(EPOCH.timestamp()) + DECADE_SECONDS,
        }
    )


def forge_hs256(
    *, account_id: str = "account-a", audience: str = DEFAULT_SERVICE, issuer: str = ISSUER
) -> str:
    """HS256, signed with the published public key: the algorithm-confusion attack."""
    header = _segment({"alg": "HS256", "typ": "JWT", "kid": thumbprint()})
    signing_input = header + b"." + _forged_payload(account_id, audience, issuer)
    digest = hmac.new(public_pem(), signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + base64.urlsafe_b64encode(digest).rstrip(b"=")).decode()


def forge_unsigned(
    *, account_id: str = "account-a", audience: str = DEFAULT_SERVICE, issuer: str = ISSUER
) -> str:
    """``alg: none`` with an empty signature: the other half of the same attack."""
    header = _segment({"alg": "none", "typ": "JWT", "kid": thumbprint()})
    return (header + b"." + _forged_payload(account_id, audience, issuer) + b".").decode()


class FakeKeyring:
    """Keyring's JWKS document and internal surface, in memory, refusing what keyring refuses.

    Counts JWKS fetches, because several properties of a verifier are statements about how
    many times it asked keyring, and records every internal call for assertions about the
    headers a client sent.
    """

    def __init__(
        self,
        *keys: rsa.RSAPrivateKey,
        issuer: str = ISSUER,
        service_tokens: Mapping[str, str] | None = None,
    ) -> None:
        self.keys = list(keys) or [SIGNING_KEY]
        self.issuer = issuer
        configured = {DEFAULT_SERVICE: DEFAULT_SERVICE_TOKEN} if service_tokens is None else {}
        self.service_tokens = {**configured, **(service_tokens or {})}
        self.fetches = 0
        self.status = 200
        self.body: dict[str, Any] | None = None
        self.error: Exception | None = None
        self.sealed = False
        self.internal_calls: list[httpx.Request] = []
        self._credentials: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._form_secrets: dict[tuple[str, str, str], dict[str, str]] = {}

    def rotate(self, key: rsa.RSAPrivateKey = ROTATED_KEY) -> None:
        """Replace the published key, as keyring would on a key replacement."""
        self.keys = [key]

    def mint(self, *, account_id: str = "account-a", audience: str = DEFAULT_SERVICE) -> str:
        """A token this keyring would accept: its issuer, its current key."""
        return mint(account_id=account_id, audience=audience, issuer=self.issuer, key=self.keys[0])

    # One argument per part of a stored connection.
    def connect(  # noqa: PLR0913
        self,
        *,
        account_id: str,
        profile: str,
        service: str,
        headers: Mapping[str, str],
        query_params: Mapping[str, str] | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        """Store what ``resolve_credential`` returns for one person, profile and service."""
        self._credentials[(account_id, profile, service)] = {
            "service": service,
            "headers": dict(headers),
            "query_params": dict(query_params or {}),
            "expires_at": None if expires_at is None else expires_at.isoformat(),
        }

    def connect_form(
        self, *, account_id: str, profile: str, service: str, fields: Mapping[str, str]
    ) -> None:
        """Store what ``resolve_form_secrets`` returns for one person, profile and service."""
        self._form_secrets[(account_id, profile, service)] = dict(fields)

    def transport(self) -> httpx.MockTransport:
        """An httpx transport serving this keyring. Hand-written; no mocking library."""
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode().split("?", 1)[0]
        if path == JWKS_PATH:
            return self._serve_jwks()
        if path.startswith((CREDENTIALS_PATH + "/", FORM_SECRETS_PATH + "/")):
            return self._serve_internal(request, path)
        return _problem(httpx.codes.NOT_FOUND, "not found")

    def _serve_jwks(self) -> httpx.Response:
        self.fetches += 1
        if self.error is not None:
            raise self.error
        document = self.body if self.body is not None else jwks(*self.keys)
        return httpx.Response(self.status, json=document)

    def _serve_internal(self, request: httpx.Request, path: str) -> httpx.Response:
        self.internal_calls.append(request)
        if self.error is not None:
            raise self.error

        segments = path.split("/")
        if len(segments) != _PATH_SEGMENTS:
            return _problem(httpx.codes.NOT_FOUND, "not found")
        kind, profile, service = (unquote(part) for part in segments[3:])

        caller = self._calling_service(request.headers.get("Authorization"))
        account = None if caller is None else self._account_for(request, audience=caller)
        if account is None:
            return _problem(httpx.codes.UNAUTHORIZED, "the user token was not accepted")
        if self.sealed:
            return _problem(httpx.codes.SERVICE_UNAVAILABLE, SEALED_DETAIL)

        stored = (account, profile, service)
        if kind == "credentials" and stored in self._credentials:
            return httpx.Response(200, json=self._credentials[stored])
        if kind == "form-secrets" and stored in self._form_secrets:
            fields = self._form_secrets[stored]
            return httpx.Response(200, json={"service": service, "fields": fields})
        return _problem(httpx.codes.NOT_FOUND, "no such profile")

    def _calling_service(self, authorization: str | None) -> str | None:
        presented = (authorization or "").removeprefix("Bearer ").encode()
        matched = None
        for name, token in self.service_tokens.items():
            if hmac.compare_digest(presented, token.encode()):
                matched = name
        return matched

    def _account_for(self, request: httpx.Request, *, audience: str) -> str | None:
        """The ``sub`` of a user token keyring would accept from this calling service."""
        token = request.headers.get(USER_TOKEN_HEADER, "")
        published = {thumbprint(key): key for key in self.keys}
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            if not isinstance(kid, str) or kid not in published:
                return None
            claims = jwt.decode(
                token,
                public_pem(published[kid]),
                algorithms=["RS256"],
                audience=audience,
                issuer=self.issuer,
                # Expiry is the verifier's business and the verifier's clock; the fake has none.
                options={"verify_exp": False, "verify_iat": False},
            )
        except (jwt.InvalidTokenError, KeyError):
            return None
        subject: str = claims["sub"]
        return subject


def _problem(status: int, detail: str) -> httpx.Response:
    return httpx.Response(
        status,
        json={"type": "about:blank", "status": status, "detail": detail},
        headers={"Content-Type": "application/problem+json"},
    )
