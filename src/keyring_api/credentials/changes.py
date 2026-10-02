"""Who may change a stored credential, and who hears about it.

:class:`~keyring_api.credentials.service.CredentialService` is the mechanism: it stores and
removes. This is the policy around every change a *person or a service* asks for -- adding
or replacing a credential, starting the OAuth consent that will replace one, removing one
alone or with its profile -- and it applies two of that person's settings:

**``require_reauth_for_credential_changes``.** On, a change needs the account password
again, even inside a live session. It is the control that stops a stolen session token
becoming every account that session can reach. Three consequences follow, and each is the
point rather than a side effect:

* A service cannot satisfy it. A service holds a user token, never the password, so with
  the setting on the delegated routes are refused outright. The service most likely to
  want this off is the one about to write a credential, which is also why settings-api
  lets only the owner turn it off.
* A password sent with the request is always checked, whatever the setting says. That is
  what makes an outage safe: settings-api down means the setting is *unknown*, the entry
  refuses rather than falling back, and a request that carries the right password has
  already satisfied it either way -- so it proceeds without anything being guessed. One
  that does not is refused.
* A wrong password counts toward the account's lockout, exactly as at login.

**``notify_on_credential_change``**, under ``email_notifications``. On, the owner is
mailed after the change: what kind, when and by whom, never which credential and never any
part of one.

Unchosen, both are off, which is what keyring did before it read them. Refreshing a token
is neither checked nor announced: nobody asked for it, and it replaces a credential with
the same grant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from keyring_api.core.logging import get_logger
from keyring_api.core.preferences import NOT_GUESSED
from keyring_api.domain.changes import ChangeOrigin, CredentialChange
from keyring_api.domain.errors import (
    PreferencesUnavailableError,
    ProfileNotFoundError,
    ReauthenticationRequiredError,
)
from keyring_api.notifications.templates import credential_change_message

if TYPE_CHECKING:
    from keyring_api.accounts.service import AccountService
    from keyring_api.accounts.store import AccountStore
    from keyring_api.core.clock import Clock
    from keyring_api.core.preferences import Preferences, PreferenceSource
    from keyring_api.credentials.service import Authorization, CredentialService
    from keyring_api.domain.profiles import Connection, CredentialKind
    from keyring_api.notifications.outbox import Outbox
    from keyring_api.secrets.base import Secret

logger = get_logger(__name__)

SEND_YOUR_PASSWORD = (
    "this account asks for its password before a stored credential changes: "  # noqa: S105
    "send current_password with the request"
)
SERVICES_CANNOT = (
    "this account asks for its password before a stored credential changes, and a service "
    "cannot give it: the person must make this change with their own session"
)


@dataclass(frozen=True, slots=True)
class Requester:
    """Who is asking for a change, and the password they sent, if any.

    ``password`` is kept out of ``repr`` so the object can never carry it into a log line
    or a traceback.
    """

    origin: ChangeOrigin
    password: str | None = field(default=None, repr=False)

    @classmethod
    def person(cls, password: str | None) -> Requester:
        """The account's own session, with the password re-entered or not."""
        return cls(ChangeOrigin.PERSON, password)

    @classmethod
    def service(cls) -> Requester:
        """A service holding the person's user token. It never has the password."""
        return cls(ChangeOrigin.SERVICE)

    @classmethod
    def administrator(cls) -> Requester:
        """An administrator already checked for ``profiles:delete_any`` and audited."""
        return cls(ChangeOrigin.ADMINISTRATOR)


class CredentialChanges:
    """Checks a change against the owner's settings, makes it, and tells them."""

    # PLR0913: six injected collaborators, keyword-only; see AccountService.
    def __init__(  # noqa: PLR0913
        self,
        *,
        credentials: CredentialService,
        accounts: AccountStore,
        account_service: AccountService,
        preferences: PreferenceSource,
        outbox: Outbox,
        clock: Clock,
    ) -> None:
        self._credentials = credentials
        self._accounts = accounts
        self._account_service = account_service
        self._preferences = preferences
        self._outbox = outbox
        self._clock = clock

    # PLR0913: the address is three parts and the credential three more, as in
    # CredentialService.put_direct_credential, plus who is asking.
    async def store_direct(  # noqa: PLR0913
        self,
        account_id: str,
        profile_name: str,
        service_name: str,
        *,
        kind: CredentialKind,
        secret: Secret,
        stores_totp_seed: bool = False,
        requester: Requester,
    ) -> Connection:
        """Add or replace an API key or a form login.

        Raises:
            ReauthenticationRequiredError / AuthenticationError /
                PreferencesUnavailableError: see :meth:`_admit`.
            and whatever :meth:`CredentialService.put_direct_credential` raises.
        """
        preferences = await self._admit(account_id, requester)
        connection = await self._credentials.put_direct_credential(
            account_id,
            profile_name,
            service_name,
            kind=kind,
            secret=secret,
            stores_totp_seed=stores_totp_seed,
        )
        await self._announce(account_id, preferences, CredentialChange.STORED, requester.origin)
        return connection

    async def begin_authorization(
        self,
        account_id: str,
        profile_name: str,
        service_name: str,
        *,
        redirect_uri: str,
        requester: Requester,
    ) -> Authorization:
        """Start the OAuth consent that will add or replace a credential.

        Checked here rather than at the callback, because here is where somebody is
        present with a session or a token; the callback is a browser redirect carrying only
        the state this hands out. Nothing is stored yet, so nothing is announced yet.
        """
        await self._admit(account_id, requester)
        return await self._credentials.begin_authorization(
            account_id, profile_name, service_name, redirect_uri=redirect_uri
        )

    async def complete_authorization(self, *, state: str, code: str) -> Connection:
        """Finish an OAuth consent, and announce the credential it stored.

        The person's settings are read after the state is redeemed -- that is how whose
        flow it is becomes known -- and before the code is exchanged, so a settings-api
        that refuses this service stores nothing rather than storing and then failing.
        """
        binding = await self._credentials.redeem_authorization(state)
        preferences = await self._preferences.for_account(binding.account_id)
        connection = await self._credentials.finish_authorization(binding, code=code)
        await self._announce(
            binding.account_id, preferences, CredentialChange.STORED, ChangeOrigin.PROVIDER
        )
        return connection

    async def remove_connection(
        self, account_id: str, profile_name: str, service_name: str, *, requester: Requester
    ) -> bool:
        """Remove one connection and its credential. Returns whether there was one."""
        preferences = await self._admit(account_id, requester)
        removed = await self._credentials.revoke_connection(account_id, profile_name, service_name)
        if removed:
            await self._announce(
                account_id, preferences, CredentialChange.REMOVED, requester.origin
            )
        return removed

    async def remove_profile(self, account_id: str, name: str, *, requester: Requester) -> bool:
        """Remove a profile and every credential in it. Returns whether there was one.

        A profile with no connections holds no credential, so deleting it is not a
        credential change: it is neither checked nor announced.
        """
        try:
            profile = await self._credentials.get_profile(account_id, name)
        except ProfileNotFoundError:
            return False

        preferences = await self._admit(account_id, requester) if profile.connections else None
        removed = await self._credentials.delete_profile(account_id, name)
        if removed and preferences is not None:
            await self._announce(
                account_id, preferences, CredentialChange.REMOVED, requester.origin
            )
        return removed

    async def _admit(self, account_id: str, requester: Requester) -> Preferences:
        """Refuse the change unless the owner's settings allow it, and return those settings.

        Raises:
            PreferencesUnavailableError: settings-api refused this service; or it cannot
                say whether the password is needed, and none was sent.
            AuthenticationError: a password was sent and it is wrong, or the account is
                locked or disabled.
            ReauthenticationRequiredError: the account wants the password and none was
                sent -- or the requester is a service, which can never send it.
        """
        preferences = await self._preferences.for_account(account_id)
        if requester.origin is ChangeOrigin.ADMINISTRATOR:
            return preferences

        if requester.password is not None:
            # Checked whatever the setting says. A password somebody bothered to send and
            # got wrong is worth refusing on, and a right one satisfies the setting whether
            # it is on, off, or unknowable during an outage.
            await self._account_service.confirm_password(account_id, requester.password)
            return preferences

        required = preferences.require_reauth_for_credential_changes
        if required is None:
            logger.warning("credential_change_refused", reason="reauth_setting_unknown")
            raise PreferencesUnavailableError(NOT_GUESSED)
        if required:
            logger.info("credential_change_refused", reason="reauth_required")
            service = requester.origin is ChangeOrigin.SERVICE
            raise ReauthenticationRequiredError(SERVICES_CANNOT if service else SEND_YOUR_PASSWORD)
        return preferences

    async def _announce(
        self,
        account_id: str,
        preferences: Preferences,
        change: CredentialChange,
        origin: ChangeOrigin,
    ) -> None:
        """Mail the owner about a change they asked to hear about.

        Queued, never awaited, so a mail provider being slow or down can neither slow nor
        fail the change itself. An account gone by now has nobody left to tell.
        """
        account = (
            await self._accounts.get(account_id)
            if preferences.announces_credential_changes
            else None
        )
        if account is not None:
            self._outbox.enqueue(
                credential_change_message(
                    to_address=account.email, change=change, origin=origin, at=self._clock.now()
                )
            )


__all__ = [
    "SEND_YOUR_PASSWORD",
    "SERVICES_CANNOT",
    "CredentialChanges",
    "Requester",
]
