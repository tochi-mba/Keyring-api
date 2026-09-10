"""The composition root.

Every adapter is chosen and wired here, once, and handed to the app. Nothing else
constructs its own dependencies -- which is what makes the whole service testable by
substitution, and what keeps "which store" and "which hasher" configuration decisions
rather than code.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from keyring_api.accounts.hashing import Argon2PasswordHasher
from keyring_api.accounts.ratelimit import InMemoryRateLimiter
from keyring_api.accounts.roles import InMemoryRoleStore
from keyring_api.accounts.service import AccountService
from keyring_api.accounts.signing import TokenSigner
from keyring_api.accounts.store import (
    InMemoryAccountStore,
    InMemoryGrantStore,
    InMemorySessionStore,
)
from keyring_api.admin.service import Actor, AdminService
from keyring_api.audit.log import InMemoryAuditLog
from keyring_api.core.clock import SystemClock
from keyring_api.core.logging import get_logger
from keyring_api.credentials.oauth_client import HttpTokenEndpoint
from keyring_api.credentials.providers import load_providers
from keyring_api.credentials.service import CredentialService
from keyring_api.credentials.state import InMemoryOAuthStateStore
from keyring_api.notifications.outbox import Outbox
from keyring_api.notifications.senders import build_sender
from keyring_api.profiles.store import InMemoryProfileStore
from keyring_api.secrets.encrypted_file import EncryptedFileSecretStore

if TYPE_CHECKING:
    from keyring_api.core.clock import Clock
    from keyring_api.core.config import Settings

logger = get_logger(__name__)

SWEEP_INTERVAL_SECONDS = 300.0
"""How often expired sessions, grants and rate-limit records are evicted."""


@dataclass(slots=True)
class Container:
    """Everything the API needs, already wired together."""

    settings: Settings
    clock: Clock
    accounts: InMemoryAccountStore
    sessions: InMemorySessionStore
    grants: InMemoryGrantStore
    limiter: InMemoryRateLimiter
    profiles: InMemoryProfileStore
    secrets: EncryptedFileSecretStore
    outbox: Outbox
    roles: InMemoryRoleStore
    audit: InMemoryAuditLog
    account_service: AccountService
    credential_service: CredentialService
    admin_service: AdminService
    signer: TokenSigner
    tokens: HttpTokenEndpoint
    started_monotonic: float
    _sweeper: asyncio.Task[None] | None = None

    @classmethod
    def build(cls, settings: Settings, *, clock: Clock | None = None) -> Container:
        """Construct every adapter named by ``settings``."""
        clock = clock or SystemClock()
        accounts = InMemoryAccountStore()
        sessions = InMemorySessionStore(clock=clock)
        grants = InMemoryGrantStore()
        limiter = InMemoryRateLimiter(clock=clock)
        profiles = InMemoryProfileStore()
        secrets = EncryptedFileSecretStore(
            root=settings.secret_dir, master_key=settings.master_key_bytes()
        )
        tokens = HttpTokenEndpoint(timeout_seconds=settings.oauth_http_timeout_seconds)
        outbox = Outbox(build_sender(settings.email))
        roles = InMemoryRoleStore()
        audit = InMemoryAuditLog(clock=clock)

        account_service = AccountService(
            accounts=accounts,
            sessions=sessions,
            grants=grants,
            hasher=Argon2PasswordHasher(settings.argon2),
            limiter=limiter,
            outbox=outbox,
            clock=clock,
            settings=settings,
        )
        credential_service = CredentialService(
            profiles=profiles,
            secrets=secrets,
            states=InMemoryOAuthStateStore(clock=clock),
            tokens=tokens,
            providers=load_providers(settings.oauth_providers_path),
            clock=clock,
            settings=settings,
        )

        return cls(
            settings=settings,
            clock=clock,
            accounts=accounts,
            sessions=sessions,
            grants=grants,
            limiter=limiter,
            profiles=profiles,
            secrets=secrets,
            tokens=tokens,
            outbox=outbox,
            signer=TokenSigner(
                key_path=settings.signing_key_path, issuer=settings.issuer, clock=clock
            ),
            roles=roles,
            audit=audit,
            account_service=account_service,
            credential_service=credential_service,
            admin_service=AdminService(
                accounts=accounts,
                roles=roles,
                audit=audit,
                account_service=account_service,
                credential_service=credential_service,
                clock=clock,
            ),
            started_monotonic=clock.monotonic(),
        )

    @property
    def uptime_seconds(self) -> float:
        return self.clock.monotonic() - self.started_monotonic

    def start_sweeper(self) -> None:
        """Begin evicting expired sessions, grants and rate-limit records."""
        self._sweeper = asyncio.create_task(self._sweep_forever(), name="retention-sweeper")

    async def aclose(self) -> None:
        """Shut everything down in dependency order."""
        if self._sweeper is not None:
            self._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sweeper
            self._sweeper = None

        # Drained before the HTTP client closes: a queued reset link dropped by a
        # restart is a person waiting for mail that will never arrive.
        await self.outbox.aclose()
        await self.tokens.aclose()

    async def actor_for(self, account_id: str, roles: tuple[str, ...]) -> Actor:
        """Resolve an account's roles into what it may do, right now.

        Resolved per request rather than cached on the session, so revoking a role takes
        effect on that account's very next request rather than whenever it next logs in.
        """
        return Actor(account_id=account_id, permissions=await self.roles.resolve(roles))

    async def _sweep_forever(self) -> None:
        while True:
            await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
            await self._sweep_guarded()

    async def _sweep_guarded(self) -> None:
        """Run one sweep, surviving any failure.

        A sweep failure must not kill the sweeper: the next tick tries again. Without
        this the first transient error would silently stop all retention, and expired
        sessions would accumulate until someone noticed the memory.
        """
        try:
            swept = await self.account_service.sweep_once()
        except Exception:
            logger.exception("sweep_failed")
            return

        flows = await self.credential_service.sweep_once()

        if swept.sessions or swept.grants or flows:
            logger.info("swept", sessions=swept.sessions, grants=swept.grants, oauth_flows=flows)
