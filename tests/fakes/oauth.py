"""A fake OAuth token endpoint.

Hand-written and satisfying the real ``TokenEndpoint`` protocol, so a change to the port
makes this fail to type-check rather than silently drift. It records what it was asked
for, which is how the tests assert that a refresh actually happened without measuring a
wall clock or watching a socket.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from keyring_api.domain.errors import CredentialUnavailableError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from keyring_api.credentials.providers import OAuthProvider
    from keyring_api.secrets.base import Secret


@dataclass
class FakeTokenEndpoint:
    """Answers token requests from a script."""

    access_token: str = "access-1"
    refresh_token: str = "refresh-1"
    expires_in: int = 3600
    fail_with: str | None = None
    """When set, every call refuses -- as a real provider does for a revoked grant."""

    omit_refresh_token: bool = False
    """Mimics the many providers that return no refresh token on renewal."""

    granted_scope: str | None = None
    """Mimics a provider granting less than was asked for, which they routinely do."""

    during_call: Callable[[], Awaitable[None]] | None = None
    """Awaited while the "provider" is answering.

    A provider call is the one place this service is guaranteed to be suspended for a
    while, so it is the window in which a concurrent revoke or delete lands. This hook
    lets a test drop something into that window without replacing a method on the fake
    and losing the protocol conformance that makes the fake worth having.
    """

    exchanges: list[str] = field(default_factory=list)
    refreshes: list[str] = field(default_factory=list)
    closed: bool = False

    async def exchange_code(
        self, provider: OAuthProvider, *, code: str, redirect_uri: str
    ) -> Secret:
        self.exchanges.append(code)
        await self._maybe_interleave()
        self._maybe_fail(provider)
        return self._token_pair()

    async def refresh(self, provider: OAuthProvider, *, refresh_token: str) -> Secret:
        self.refreshes.append(refresh_token)
        await self._maybe_interleave()
        self._maybe_fail(provider)

        renewed = self._token_pair()
        if self.omit_refresh_token:
            # The real client puts the old one back; the endpoint itself does not.
            del renewed["refresh_token"]
            renewed["refresh_token"] = refresh_token
        return renewed

    async def aclose(self) -> None:
        self.closed = True

    async def _maybe_interleave(self) -> None:
        """Let a test act while the provider is "answering"."""
        if self.during_call is not None:
            await self.during_call()

    def _maybe_fail(self, provider: OAuthProvider) -> None:
        if self.fail_with is not None:
            message = f"{provider.service} refused: {self.fail_with}"
            raise CredentialUnavailableError(message)

    def _token_pair(self) -> Secret:
        pair: Secret = {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
        }
        if self.granted_scope is not None:
            pair["scope"] = self.granted_scope
        return pair
