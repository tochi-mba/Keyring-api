"""The error vocabulary, and the one property that matters about it."""

from __future__ import annotations

import pytest

from keyring_api.domain.errors import (
    AccountLockedError,
    AuthenticationError,
    CredentialUnavailableError,
    DomainError,
    RateLimitedError,
    VaultSealedError,
)


def test_a_lockout_is_an_authentication_failure_first() -> None:
    # A handler that catches AuthenticationError and forgets AccountLockedError still
    # renders the indistinguishable response. If lockouts were a sibling error, that
    # omission would produce a distinctive one -- an oracle telling an attacker that the
    # account exists and that their guessing is working.
    assert issubclass(AccountLockedError, AuthenticationError)


def test_a_sealed_vault_is_a_credential_failure_first() -> None:
    # Same reasoning: a caller handling "cannot give you a credential" handles both.
    assert issubclass(VaultSealedError, CredentialUnavailableError)


def test_every_error_shares_one_base_a_handler_can_catch() -> None:
    assert issubclass(AuthenticationError, DomainError)


def test_a_rate_limit_carries_how_long_to_wait() -> None:
    # Without it the caller can only guess, and a client that guesses badly either gives
    # up on a working service or hammers it until the window resets.
    error = RateLimitedError("too many attempts", retry_after_seconds=42.0)

    with pytest.raises(RateLimitedError) as caught:
        raise error

    assert caught.value.retry_after_seconds == 42.0
