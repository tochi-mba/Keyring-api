"""The credential service: what actually answers "give me a usable credential".

Three responsibilities, and the boundaries between them matter:

* **Profiles and connections.** Create, list, delete. Every method takes an account id,
  so nothing here can address another account's data.
* **Storing credentials.** Direct entry for API keys and passwords; the OAuth flow for
  everything that offers one. Values go in and never come back out.
* **Producing credentials.** Read the stored material, refresh it if it is due, write the
  renewed token back, and hand the caller a credential object bound to a consumption
  port -- never the raw secret.

The refresh is the part worth reading twice. It happens *before* expiry, by a margin, so
a caller never has to handle a 401-then-retry; the renewed token is written back inside
the same call, so the next request does not repeat the work; and a refresh failure marks
the connection rather than deleting it, because a provider being down for five minutes
must not destroy a refresh token that will work again afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from keyring_api.core.logging import get_logger
from keyring_api.credentials.kinds import (
    ApiKeyCredential,
    OAuth2Credential,
    PasswordCredential,
)
from keyring_api.credentials.state import FlowBinding
from keyring_api.domain.errors import (
    ConnectionNotFoundError,
    CredentialUnavailableError,
    InvalidOAuthStateError,
    LimitExceededError,
    ProfileNotFoundError,
)
from keyring_api.domain.profiles import (
    Connection,
    ConnectionStatus,
    CredentialKind,
    Profile,
    new_profile_id,
    normalize_profile_name,
    normalize_service_name,
)

if TYPE_CHECKING:
    from datetime import datetime

    from keyring_api.core.clock import Clock
    from keyring_api.core.config import Settings
    from keyring_api.credentials.oauth_client import TokenEndpoint
    from keyring_api.credentials.providers import OAuthProvider
    from keyring_api.credentials.state import OAuthStateStore
    from keyring_api.profiles.store import ProfileStore
    from keyring_api.secrets.base import Secret, SecretStore

logger = get_logger(__name__)

NO_SUCH_PROFILE = "no profile by that name"
"""Identical whether the profile does not exist or belongs to somebody else."""

NO_SUCH_CONNECTION = "this profile is not connected to that service"
UNKNOWN_PROVIDER = "no OAuth provider is configured for that service"


@dataclass(frozen=True, slots=True)
class Authorization:
    """Where to send someone to consent, and how long they have to do it."""

    authorization_url: str
    expires_at: datetime


class CredentialService:
    """Owns profiles, connections, and the credentials behind them."""

    def __init__(  # noqa: PLR0913 -- six injected collaborators; see AccountService
        self,
        *,
        profiles: ProfileStore,
        secrets: SecretStore,
        states: OAuthStateStore,
        tokens: TokenEndpoint,
        providers: dict[str, OAuthProvider],
        clock: Clock,
        settings: Settings,
    ) -> None:
        self._profiles = profiles
        self._secrets = secrets
        self._states = states
        self._tokens = tokens
        self._providers = providers
        self._clock = clock
        self._settings = settings

    # -- Profiles ----------------------------------------------------------------------

    async def create_profile(self, account_id: str, name: str) -> Profile:
        """Create a named credential set.

        Raises:
            InvalidProfileNameError: the name cannot be stored or addressed.
            ProfileExistsError: this account already has one by that name.
            LimitExceededError: this account is at its profile cap.
        """
        normalized = normalize_profile_name(name)

        if await self._profiles.count_for_account(account_id) >= (
            self._settings.max_profiles_per_account
        ):
            msg = f"at most {self._settings.max_profiles_per_account} profiles per account"
            raise LimitExceededError(msg)

        now = self._clock.now()
        profile = Profile(
            profile_id=new_profile_id(),
            account_id=account_id,
            name=normalized,
            created_at=now,
            updated_at=now,
        )
        await self._profiles.add(profile)
        logger.info("profile_created", profile=normalized)
        return profile

    async def list_profiles(self, account_id: str) -> list[Profile]:
        """Every profile this account owns."""
        return await self._profiles.list_for_account(account_id)

    async def get_profile(self, account_id: str, name: str) -> Profile:
        """One of this account's profiles.

        Raises:
            ProfileNotFoundError: unknown, or owned by somebody else -- identically, so
                one person cannot discover that another has a profile by that name.
        """
        profile = await self._profiles.get(account_id, normalize_profile_name(name))
        if profile is None:
            raise ProfileNotFoundError(NO_SUCH_PROFILE)
        return profile

    async def delete_profile(self, account_id: str, name: str) -> bool:
        """Delete a profile and every credential in it."""
        normalized = normalize_profile_name(name)

        if not await self._profiles.delete(account_id, normalized):
            return False

        # The secrets go with it. A profile record without its secrets would be tidy;
        # secrets without their profile record would be credential material nothing
        # knows about and nothing will ever clean up.
        await self._secrets.delete_profile(account_id, normalized)
        logger.info("profile_deleted", profile=normalized)
        return True

    async def delete_account_data(self, account_id: str) -> None:
        """Remove every profile and secret an account owns, for a cascading delete."""
        await self._profiles.delete_for_account(account_id)
        await self._secrets.delete_account(account_id)

    # -- Storing credentials -----------------------------------------------------------

    # PLR0913: the address is three positional parts and the credential is three more.
    # Bundling either half into an object would add a type that exists only to be
    # unpacked on the next line.
    async def put_direct_credential(  # noqa: PLR0913
        self,
        account_id: str,
        profile_name: str,
        service_name: str,
        *,
        kind: CredentialKind,
        secret: Secret,
        stores_totp_seed: bool = False,
    ) -> Connection:
        """Store a credential the person typed in: an API key, or a form login.

        Used only where a service offers no OAuth. Prefer OAuth wherever it exists: a
        scoped, revocable grant beats a stored password, which the operator cannot
        revoke at all -- only the person changing it at the service can.

        Raises:
            ProfileNotFoundError: no such profile for this account.
            LimitExceededError: the profile is at its connection cap.
            VaultSealedError: no master key is configured.
        """
        profile = await self.get_profile(account_id, profile_name)
        service = normalize_service_name(service_name)
        self._check_connection_cap(profile, service)

        now = self._clock.now()
        await self._secrets.put(account_id, profile.name, service, secret)

        connection = Connection(
            service=service,
            kind=kind,
            status=ConnectionStatus.ACTIVE,
            created_at=now,
            updated_at=now,
            # Never inferred from the presence of a seed in the request: storing one
            # beside the password collapses that person's second factor into the same
            # place as their first, so it has to be a decision somebody made.
            stores_totp_seed=stores_totp_seed,
        )
        await self._profiles.save(profile.with_connection(connection, now=now))

        logger.info("credential_stored", profile=profile.name, service=service, kind=kind.value)
        return connection

    async def begin_authorization(
        self, account_id: str, profile_name: str, service_name: str, *, redirect_uri: str
    ) -> Authorization:
        """Start an OAuth flow and return the URL to send the person to.

        No secret crosses this API at any point in the flow: the person consents at the
        provider, and the token comes back to us server-to-server from the token
        endpoint.

        Raises:
            ProfileNotFoundError: no such profile for this account.
            CredentialUnavailableError: no provider is configured for that service.
        """
        profile = await self.get_profile(account_id, profile_name)
        service = normalize_service_name(service_name)
        provider = self._provider_for(service)
        self._check_connection_cap(profile, service)

        state = await self._states.issue(
            FlowBinding(
                account_id=account_id,
                profile=profile.name,
                service=service,
                kind=CredentialKind.OAUTH2_AUTHORIZATION_CODE,
                redirect_uri=redirect_uri,
            ),
            ttl_seconds=self._settings.oauth_state_ttl_seconds,
        )

        now = self._clock.now()
        pending = Connection(
            service=service,
            kind=CredentialKind.OAUTH2_AUTHORIZATION_CODE,
            status=ConnectionStatus.PENDING,
            created_at=now,
            updated_at=now,
            scopes=provider.scopes,
        )
        await self._profiles.save(profile.with_connection(pending, now=now))

        logger.info("authorization_started", profile=profile.name, service=service)
        return Authorization(
            authorization_url=provider.authorization_url(redirect_uri=redirect_uri, state=state),
            expires_at=now + timedelta(seconds=self._settings.oauth_state_ttl_seconds),
        )

    async def complete_authorization(self, *, state: str, code: str) -> Connection:
        """Finish an OAuth flow from the provider's callback.

        The account, profile and service all come from the stored state, never from the
        callback's parameters. Without that binding, a crafted callback could attach a
        credential to somebody else's profile.

        Raises:
            InvalidOAuthStateError: unknown, expired, or already used.
            CredentialUnavailableError: the provider refused the exchange.
        """
        flow = await self._states.redeem(state)
        if flow is None:
            msg = "this authorization link is invalid or has expired"
            raise InvalidOAuthStateError(msg)

        binding = flow.binding
        profile = await self._profiles.get(binding.account_id, binding.profile)
        if profile is None:
            # The profile was deleted while the person was consenting at the provider.
            msg = "the profile this authorization was for no longer exists"
            raise InvalidOAuthStateError(msg)

        provider = self._provider_for(binding.service)
        secret = await self._tokens.exchange_code(
            provider, code=code, redirect_uri=binding.redirect_uri
        )

        return await self._store_oauth_secret(profile, binding.service, secret, provider=provider)

    # -- Producing credentials ---------------------------------------------------------

    async def resolve_http_auth(
        self, account_id: str, profile_name: str, service_name: str
    ) -> ApiKeyCredential | OAuth2Credential:
        """Return something a caller can attach to an HTTP request.

        The credential object is returned, never the stored material. A caller asks it
        for headers and gets headers; it has no way to obtain the token itself, which is
        what keeps every consumer from becoming a place a credential can leak.

        Raises:
            ProfileNotFoundError / ConnectionNotFoundError: no such profile or service.
            CredentialUnavailableError: the credential cannot be made usable.
        """
        profile, connection, secret = await self._load(account_id, profile_name, service_name)

        if connection.kind is CredentialKind.API_KEY:
            return ApiKeyCredential(secret)

        if connection.kind is CredentialKind.OAUTH2_AUTHORIZATION_CODE:
            return OAuth2Credential(
                secret,
                refresh=lambda: self._refresh(profile, connection, secret),
                needs_refresh=connection.needs_refresh(
                    now=self._clock.now(),
                    margin_seconds=self._settings.oauth_refresh_margin_seconds,
                ),
            )

        msg = f"the {connection.service} credential is a form login, not an HTTP credential"
        raise CredentialUnavailableError(msg)

    async def resolve_form_secrets(
        self, account_id: str, profile_name: str, service_name: str
    ) -> PasswordCredential:
        """Return something a browser recipe can type into a login form.

        Raises:
            ProfileNotFoundError / ConnectionNotFoundError: no such profile or service.
            CredentialUnavailableError: the credential is not a form login.
        """
        _, connection, secret = await self._load(account_id, profile_name, service_name)

        if connection.kind is not CredentialKind.PASSWORD:
            msg = f"the {connection.service} credential is not a form login"
            raise CredentialUnavailableError(msg)

        return PasswordCredential(secret, now=lambda: self._clock.now().timestamp())

    async def revoke_connection(
        self, account_id: str, profile_name: str, service_name: str
    ) -> bool:
        """Remove a connection and its stored credential."""
        profile = await self.get_profile(account_id, profile_name)
        service = normalize_service_name(service_name)

        if profile.connection(service) is None:
            return False

        await self._secrets.delete(account_id, profile.name, service)
        await self._profiles.save(profile.without_connection(service, now=self._clock.now()))
        logger.info("connection_revoked", profile=profile.name, service=service)
        return True

    # -- Retention ---------------------------------------------------------------------

    async def sweep_once(self) -> int:
        """Drop abandoned authorization flows. Returns how many went."""
        return await self._states.purge_expired()

    # -- Internals ---------------------------------------------------------------------

    async def _load(
        self, account_id: str, profile_name: str, service_name: str
    ) -> tuple[Profile, Connection, Secret]:
        """Find the profile, the connection, and the stored material behind it."""
        profile = await self.get_profile(account_id, profile_name)
        service = normalize_service_name(service_name)

        connection = profile.connection(service)
        if connection is None:
            raise ConnectionNotFoundError(NO_SUCH_CONNECTION)

        if connection.status is ConnectionStatus.PENDING:
            msg = f"the {service} connection was never completed; authorize it again"
            raise CredentialUnavailableError(msg)

        secret = await self._secrets.get(account_id, profile.name, service)
        if secret is None:
            # The connection record and the vault disagree. Reported as unusable rather
            # than treated as absent, because silently pretending there is no connection
            # would hide a real inconsistency.
            msg = f"the {service} credential is missing from the vault"
            raise CredentialUnavailableError(msg)

        return profile, connection, secret

    async def _refresh(self, profile: Profile, connection: Connection, secret: Secret) -> Secret:
        """Renew an access token and write it back.

        Written back in the same call, so the next request does not repeat the work; a
        failure marks the connection rather than deleting it, because a provider outage
        must not destroy a refresh token that will work again in five minutes.
        """
        refresh_token = secret.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            await self._record_failure(profile, connection, "no refresh token was stored")
            msg = (
                f"the {connection.service} connection cannot be renewed without anyone "
                "present; it must be authorised again"
            )
            raise CredentialUnavailableError(msg)

        provider = self._provider_for(connection.service)
        try:
            renewed = await self._tokens.refresh(provider, refresh_token=refresh_token)
        except CredentialUnavailableError as exc:
            await self._record_failure(profile, connection, str(exc))
            raise

        await self._store_oauth_secret(profile, connection.service, renewed, provider=provider)
        logger.info("credential_refreshed", profile=profile.name, service=connection.service)
        return renewed

    async def _store_oauth_secret(
        self, profile: Profile, service: str, secret: Secret, *, provider: OAuthProvider
    ) -> Connection:
        """Persist a token pair and mark the connection active."""
        now = self._clock.now()
        await self._secrets.put(profile.account_id, profile.name, service, secret)

        expires_in = secret.get("expires_in")
        existing = profile.connection(service)
        connection = Connection(
            service=service,
            kind=CredentialKind.OAUTH2_AUTHORIZATION_CODE,
            status=ConnectionStatus.ACTIVE,
            created_at=existing.created_at if existing else now,
            updated_at=now,
            expires_at=now + timedelta(seconds=int(expires_in))
            if isinstance(expires_in, int)
            else None,
            scopes=_granted_scopes(secret, provider),
            # Cleared: whatever failed last time evidently is not failing now, and a
            # stale error on a working connection sends people to fix nothing.
            last_error=None,
        )
        await self._profiles.save(profile.with_connection(connection, now=now))
        return connection

    async def _record_failure(self, profile: Profile, connection: Connection, reason: str) -> None:
        """Mark a connection as needing attention, keeping its stored credential."""
        logger.warning(
            "credential_refresh_failed", profile=profile.name, service=connection.service
        )
        await self._profiles.save(
            profile.with_connection(
                connection.with_error(reason, now=self._clock.now()), now=self._clock.now()
            )
        )

    def _provider_for(self, service: str) -> OAuthProvider:
        """Look up a configured provider, or say plainly that there is none."""
        provider = self._providers.get(service)
        if provider is None:
            msg = f"{UNKNOWN_PROVIDER}: {service}"
            raise CredentialUnavailableError(msg)
        return provider

    def _check_connection_cap(self, profile: Profile, service: str) -> None:
        """Refuse a new connection past the cap, but never refuse replacing one."""
        if profile.connection(service) is not None:
            return

        if len(profile.connections) >= self._settings.max_connections_per_profile:
            msg = f"at most {self._settings.max_connections_per_profile} connections per profile"
            raise LimitExceededError(msg)


def _granted_scopes(secret: Secret, provider: OAuthProvider) -> tuple[str, ...]:
    """What the provider actually granted, which is not always what was asked for."""
    granted = secret.get("scope")
    if isinstance(granted, str) and granted:
        return tuple(granted.split())
    return provider.scopes
