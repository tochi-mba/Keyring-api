"""Generating, storing and comparing bearer tokens.

Every token this service issues -- session, invite, password reset, OAuth state -- is
made here, and none of them is ever stored. Only a hash is kept, so a copy of the
database yields nothing that can be presented back.

The hash is SHA-256, deliberately, and this is the one place where using a fast hash is
the correct answer. These tokens are 256 bits of uniform randomness: there is no
dictionary to run against them, so an expensive hash buys no additional resistance while
costing a deliberately slow computation on every authenticated request. Passwords are
the opposite case -- low entropy, guessable -- and are hashed with Argon2 in
:mod:`keyring_api.accounts.hashing`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

MIN_TOKEN_ENTROPY_BYTES = 32
"""256 bits. Enough that guessing is not a threat model, only theft is."""


def new_token() -> str:
    """Return a fresh bearer token.

    URL-safe because these travel in reset links and OAuth redirects, where a ``+`` or
    ``/`` would be mangled by something along the way and produce a token that is
    invalid for reasons nobody can see.
    """
    return secrets.token_urlsafe(MIN_TOKEN_ENTROPY_BYTES)


def hash_token(token: str) -> str:
    """Return the stored form of a token."""
    return hashlib.sha256(token.encode()).hexdigest()


def tokens_match(presented: str, stored_hash: str) -> bool:
    """Whether a presented token corresponds to a stored hash.

    Compared with :func:`hmac.compare_digest` rather than ``==``. A short-circuiting
    comparison leaks, in its timing, how many leading characters were right, which over
    enough attempts is a way to construct a valid token one character at a time.
    """
    return hmac.compare_digest(hash_token(presented), stored_hash)
