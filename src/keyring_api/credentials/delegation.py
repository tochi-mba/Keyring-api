"""Exchange never forwards authority: every token is minted for a single audience."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from keyring_api.audit.log import AuditAction
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.delegation import OfflineGrant
from keyring_api.domain.errors import (
    AuthenticationError,
    InsufficientPermissionError,
    ProfileNotFoundError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.accounts.signing import TokenSigner
    from keyring_api.accounts.store import AccountStore
    from keyring_api.audit.log import AuditLog
    from keyring_api.core.clock import Clock
    from keyring_api.core.config import Settings
    from keyring_api.profiles.delegations import DelegationStore
    from keyring_api.profiles.store import ProfileStore

BAD_DELEGATION = "the delegation was not accepted"


@dataclass(frozen=True, slots=True)
class ExchangedToken:
    """Fresh downstream authority; never written into the grant or audit store."""

    token: str
    expires_in: int
    expires_at: datetime


class DelegationService:
    """Service allowlists are checked afresh on each exchange, including offline grants."""

    def __init__(  # noqa: PLR0913 -- explicit ports at the composition root
        self,
        *,
        store: DelegationStore,
        profiles: ProfileStore,
        accounts: AccountStore,
        signer: TokenSigner,
        audit: AuditLog,
        settings: Settings,
        clock: Clock,
    ) -> None:
        self._store = store
        self._profiles = profiles
        self._accounts = accounts
        self._signer = signer
        self._audit = audit
        self._settings = settings
        self._clock = clock

    def _allow(self, service: str, audiences: tuple[str, ...]) -> None:
        allowed = self._settings.exchange_audiences.get(service, ())
        if not audiences or not set(audiences) <= set(allowed):
            msg = "the service may not exchange for that audience"
            raise InsufficientPermissionError(msg)

    async def _profile(self, account_id: str, profile: str) -> None:
        if await self._profiles.get(account_id, profile) is None:
            msg = "no profile of that name"
            raise ProfileNotFoundError(msg)

    async def create(
        self,
        account_id: str,
        profile: str,
        *,
        service: str,
        audiences: tuple[str, ...],
        ttl_seconds: int,
    ) -> OfflineGrant:
        await self._profile(account_id, profile)
        self._allow(service, audiences)
        now = self._clock.now()
        grant = OfflineGrant(
            grant_id="dgt_" + secrets.token_urlsafe(32),
            account_id=account_id,
            profile=profile,
            service=service,
            audiences=tuple(sorted(set(audiences))),
            created_at=now,
            expires_at=now
            + timedelta(seconds=min(ttl_seconds, self._settings.offline_grant_max_ttl_seconds)),
        )
        await self._store.add(
            grant,
            cap=self._settings.max_offline_grants_per_profile,
            now=now,
        )
        await self._audit.record(
            AuditAction.DELEGATION_CREATED,
            actor_id=account_id,
            target_id=account_id,
            detail=f"offline grant {grant.grant_id}",
        )
        return grant

    async def list(self, account_id: str, profile: str) -> list[OfflineGrant]:
        await self._profile(account_id, profile)
        return await self._store.list_for_profile(account_id, profile)

    async def revoke(self, account_id: str, profile: str, grant_id: str) -> None:
        await self._profile(account_id, profile)
        if not await self._store.revoke(account_id, profile, grant_id, now=self._clock.now()):
            msg = "no offline grant with that id"
            raise ProfileNotFoundError(msg)
        await self._audit.record(
            AuditAction.DELEGATION_REVOKED,
            actor_id=account_id,
            target_id=account_id,
            detail=f"offline grant {grant_id}",
        )

    async def exchange(
        self,
        service: str,
        *,
        audience: str,
        ttl_seconds: int,
        user_token: str | None,
        grant_id: str | None,
    ) -> ExchangedToken:
        if (user_token is None) == (grant_id is None):
            raise AuthenticationError(BAD_DELEGATION)
        self._allow(service, (audience,))
        if user_token is not None:
            claims = self._signer.verify_access(user_token, audience=service)
            account_id, deadline = claims.account_id, claims.expires_at
        else:
            grant = await self._store.for_exchange(str(grant_id), service)
            if grant is None or grant.revoked_at is not None or audience not in grant.audiences:
                raise AuthenticationError(BAD_DELEGATION)
            account_id, deadline = grant.account_id, grant.expires_at
        account = await self._accounts.get(account_id)
        if account is None or account.status is not AccountStatus.ACTIVE:
            raise AuthenticationError(BAD_DELEGATION)
        now = self._clock.now()
        ttl = min(
            ttl_seconds,
            self._settings.access_token_ttl_seconds,
            int((deadline - now).total_seconds()),
        )
        if ttl <= 0:
            raise AuthenticationError(BAD_DELEGATION)
        token = self._signer.issue(account_id=account_id, audience=audience, ttl_seconds=ttl)
        await self._audit.record(
            AuditAction.TOKEN_EXCHANGED,
            actor_id=f"service:{service}",
            target_id=account_id,
            detail=f"audience {audience}; grant {grant_id or 'foreground'}",
        )
        return ExchangedToken(token, ttl, (now + timedelta(seconds=ttl)).replace(microsecond=0))
