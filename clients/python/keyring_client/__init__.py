"""What every service in the LUCY family uses to believe a keyring token and fetch a credential.

Four pieces, each lifted from the best of the copies the family grew independently, and kept
in one place so that the rules by which a token is believed can never again differ between
two services:

* :class:`JwksClient` -- keyring's public keys, fetched lazily, cached, single-flighted,
  rate limited on an unknown key id, and served stale through a short outage.
* :class:`TokenVerifier` -- RS256 only, issuer pinned, every required claim present, expiry
  checked on an injected clock, and one undifferentiated refusal.
* :class:`ServiceAuthenticator` -- which service a static token belongs to, compared in
  constant time without an early return.
* :class:`CredentialClient` -- keyring's two internal endpoints, with both credentials
  attached and every failure translated into something a caller can act on.

Test doubles live in :mod:`keyring_client.testing`, and they are real: a real RSA key, a real
JWKS document, and a fake keyring that refuses what the real one refuses.
"""

from __future__ import annotations

from keyring_client._log import Logger, StdlibLogger
from keyring_client.clock import Clock, SystemClock
from keyring_client.credentials import (
    CREDENTIALS_PATH,
    FORM_SECRETS_PATH,
    USER_TOKEN_HEADER,
    CredentialClient,
    FormSecrets,
    ResolvedCredential,
)
from keyring_client.errors import (
    BAD_SERVICE,
    BAD_TOKEN,
    AuthenticationError,
    CredentialNotFoundError,
    CredentialUnavailableError,
    KeyringClientError,
    KeyringRejectedError,
    KeyringUnreachableError,
)
from keyring_client.jwks import JWKS_PATH, KEYS_STALE, KEYS_UNAVAILABLE, JwksClient, jwks_url
from keyring_client.service_tokens import (
    MIN_SERVICE_TOKEN_CHARS,
    ServiceAuthenticator,
    check_service_token,
)
from keyring_client.tokens import (
    ALGORITHM,
    REQUIRED_CLAIMS,
    AudienceFamily,
    AudiencePolicy,
    ExactAudience,
    TokenVerifier,
    VerifiedToken,
)

__all__ = [
    "ALGORITHM",
    "BAD_SERVICE",
    "BAD_TOKEN",
    "CREDENTIALS_PATH",
    "FORM_SECRETS_PATH",
    "JWKS_PATH",
    "KEYS_STALE",
    "KEYS_UNAVAILABLE",
    "MIN_SERVICE_TOKEN_CHARS",
    "REQUIRED_CLAIMS",
    "USER_TOKEN_HEADER",
    "AudienceFamily",
    "AudiencePolicy",
    "AuthenticationError",
    "Clock",
    "CredentialClient",
    "CredentialNotFoundError",
    "CredentialUnavailableError",
    "ExactAudience",
    "FormSecrets",
    "JwksClient",
    "KeyringClientError",
    "KeyringRejectedError",
    "KeyringUnreachableError",
    "Logger",
    "ResolvedCredential",
    "ServiceAuthenticator",
    "StdlibLogger",
    "SystemClock",
    "TokenVerifier",
    "VerifiedToken",
    "check_service_token",
    "jwks_url",
]

__version__ = "0.1.0"
