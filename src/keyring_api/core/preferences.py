"""What one person has chosen, and what keyring does when it cannot ask.

The deployment's configuration says how long a session lasts and how many there may be,
for everybody. settings-api holds what each person has chosen within that, and this
module is the one place the two meet: it turns an account id -- after a password check
has succeeded, before a session exists -- into the idle TTL, absolute ceiling and
session cap that login stamps on the new session. The same read answers the three
questions a credential change asks: whether this person wants mail from keyring at all,
whether they want to hear about a new session or a credential change, and whether a
credential change needs their password again.

keyring is the issuer, so the chicken-and-egg is resolved here rather than by naming an
account to settings-api. Once the password has succeeded this service mints a short-lived
token with ``aud = keyring`` and presents it as the user token alongside its own service
token. settings-api verifies it against the JWKS it already holds. Nothing circular:
settings-api never calls keyring.

Nothing is read at startup, and with no settings-api configured every person gets the
configuration as it stands -- exactly what keyring did before it read anybody's settings
at all: no notices, and no second password prompt for a credential change.

Five rules shape it.

**A person may narrow a ceiling and never raise it.** Idle TTL, the absolute ceiling and
the session cap are clamped to the catalogue bounds and to this deployment's
``KEYRING_`` values. A person cannot raise ``lockout_threshold`` or any rate limit; those
stay with the operator.

**Resolve at create, not at touch.** ``resolve_session`` has a live session but must not
silently lengthen or shorten it because the person changed a setting. The idle TTL used
at create is stamped on the session, and a later change applies to sessions created
afterwards. Sessions that predate the stamp keep the deployment TTL.

**An outage degrades to the deployment.** ``session_ttl_days``,
``session_absolute_ttl_days`` and ``max_sessions`` are ``use_default``. The conservative
value is *not* the safest one: a person who chose a one-day idle timeout gets fourteen
days (or whatever this deployment is configured for) until settings-api is back. Refusing
would make settings-api a hard dependency of every login in the family. The three mail
switches are ``use_default`` too: they land on settings-api's declared fallback, or, before
keyring has ever had an answer, on what this deployment does without them.

**Re-authentication is never guessed.** ``require_reauth_for_credential_changes`` is
``refuse``: a person who turned it on must not find it off because settings-api was
down. During an outage it reads as *unknown* (``None``), never as either answer, and
the credential change that needs it is refused unless the request already carries the
password -- which satisfies the setting whichever way it is set, so nothing is guessed.
Login never reads it, so an outage cannot fail a login over it.

**A refusal is not an outage.** settings-api answering 401 or 403 means this service is
misconfigured -- a missing grant, a wrong token -- and serving defaults would hide that
behind behaviour that happens to work. Login fails instead.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Protocol

from keyring_api.core.logging import get_logger
from keyring_api.domain.errors import PreferencesUnavailableError
from settings_client import (
    HttpSettingsClient,
    SettingsRefused,
    SettingsRejected,
    SettingsUnavailable,
)

if TYPE_CHECKING:
    from keyring_api.core.config import Settings
    from settings_client import ResolvedSettings, SettingsClient

logger = get_logger(__name__)

NAMESPACE = "keyring"
"""This service's catalogue namespace, and the audience a settings round-trip token carries."""

SETTINGS_TOKEN_TTL_SECONDS = 60
"""Long enough for one resolve, short enough that a leaked copy is already dead."""

SECONDS_PER_DAY = 24 * 3_600
SESSION_TTL_DAYS_MIN = 1
SESSION_TTL_DAYS_MAX = 90
SESSION_ABSOLUTE_TTL_DAYS_MIN = 1
SESSION_ABSOLUTE_TTL_DAYS_MAX = 365
MAX_SESSIONS_MIN = 1
MAX_SESSIONS_MAX = 20

EMAIL_NOTIFICATIONS = "email_notifications"
NOTIFY_ON_NEW_SESSION = "notify_on_new_session"
NOTIFY_ON_CREDENTIAL_CHANGE = "notify_on_credential_change"
REQUIRE_REAUTH = "require_reauth_for_credential_changes"

REFUSED = "settings-api did not accept this service's request for your settings"
NOT_GUESSED = "one of your settings could not be read from settings-api and must not be guessed"


class SettingsTokenIssuer(Protocol):
    """Mints the short-lived user token a settings-api resolve needs.

    :class:`~keyring_api.accounts.signing.TokenSigner` is the production implementation.
    The protocol lives here so this module does not import ``accounts``, which already
    imports ``core``.
    """

    def issue(self, *, account_id: str, audience: str, ttl_seconds: float) -> str:
        """A signed token asserting that the bearer is acting for ``account_id``."""
        ...


@dataclass(frozen=True, slots=True)
class Preferences:
    """One person's choices, as this service applies them to one login."""

    session_ttl_seconds: int
    """How long a session this person creates may sit unused before it stops working."""

    session_absolute_ttl_seconds: int
    """The longest that session may live, however often it is used."""

    max_sessions: int
    """How many sessions this person may hold at once, inside the operator cap."""

    email_notifications: bool = True
    """The master switch. Off, keyring sends this person no notice of any kind.

    Invites and password resets are not notices -- somebody asked for each one -- and are
    not governed by it.
    """

    notify_on_new_session: bool = False
    """Whether a login on this account is announced by mail. Subordinate to the switch."""

    notify_on_credential_change: bool = False
    """Whether adding, replacing or removing a stored credential is. Also subordinate."""

    require_reauth_for_credential_changes: bool | None = False
    """Whether a credential change needs the account password again.

    ``None`` means settings-api could not say, and this entry refuses rather than falling
    back. The caller must not read ``None`` as either answer.
    """

    @property
    def announces_new_sessions(self) -> bool:
        """Whether a new session on this account is mailed to its owner."""
        return self.email_notifications and self.notify_on_new_session

    @property
    def announces_credential_changes(self) -> bool:
        """Whether a credential written or removed on this account is mailed to its owner."""
        return self.email_notifications and self.notify_on_credential_change


class PreferenceSource(Protocol):
    """Where a login's session lifetimes and cap come from, and a credential change's rules."""

    async def for_account(self, account_id: str, /) -> Preferences:
        """The preferences of one account.

        Raises:
            PreferencesUnavailableError: settings-api refused this service, or cannot
                read a setting that must not be guessed and that every caller needs.
                Re-authentication is the exception: it comes back as ``None`` instead, so
                a login, which never needs it, is not failed for it.
        """
        ...

    async def aclose(self) -> None:
        """Release whatever this holds open."""
        ...


def deployment_preferences(settings: Settings) -> Preferences:
    """What everybody gets when nobody's own choices are known: the configuration as it is.

    The mail and re-authentication fields keep their declared defaults, which are what
    keyring did before it had them: it announced nothing and asked for no second password.
    """
    return Preferences(
        session_ttl_seconds=settings.session_ttl_seconds,
        session_absolute_ttl_seconds=settings.session_absolute_ttl_seconds,
        max_sessions=settings.max_sessions_per_account,
    )


class DeploymentPreferences:
    """Everybody gets the configuration: what keyring did before it read settings-api."""

    def __init__(self, settings: Settings) -> None:
        """Bind the configuration everybody gets."""
        self._preferences = deployment_preferences(settings)

    async def for_account(self, _account_id: str, /) -> Preferences:
        """Return the configuration; the account is ignored."""
        return self._preferences

    async def aclose(self) -> None:
        """Nothing is held open."""


class SettingsApiPreferences:
    """Each person's own choices, read from settings-api, inside the deployment's ceilings."""

    def __init__(
        self, *, client: SettingsClient, settings: Settings, issuer: SettingsTokenIssuer
    ) -> None:
        """Bind the client, the issuer that mints the round-trip token, and the ceilings."""
        self._client = client
        self._settings = settings
        self._issuer = issuer
        self._deployment = deployment_preferences(settings)

    async def for_account(self, account_id: str, /) -> Preferences:
        """Mint a short-lived ``keyring``-audience token and read this person's settings."""
        user_token = self._issuer.issue(
            account_id=account_id,
            audience=NAMESPACE,
            ttl_seconds=SETTINGS_TOKEN_TTL_SECONDS,
        )
        try:
            resolved = await self._client.resolve(NAMESPACE, user_token=user_token)
        except SettingsUnavailable:
            # Never answered, so not even settings-api's own defaults are known. The
            # configuration stands in. A person who chose one day gets fourteen. Except
            # for re-authentication, which refuses rather than falling back: nobody here
            # knows whether this person turned it on, so it is unknown, not off.
            logger.warning("settings_unavailable", namespace=NAMESPACE)
            return replace(self._deployment, require_reauth_for_credential_changes=None)
        except SettingsRejected as error:
            # The status only: settings-api's own detail names grants and namespaces, which
            # an operator reads in its log rather than a caller reading it in ours.
            logger.warning("settings_rejected", namespace=NAMESPACE, status_code=error.status_code)
            raise PreferencesUnavailableError(REFUSED) from error

        if resolved.stale:
            logger.info("settings_stale", namespace=NAMESPACE)

        try:
            return self._apply(resolved)
        except SettingsRefused as error:
            # Re-authentication refuses, and is read apart so it comes back unknown. No
            # other ``keyring`` entry this service reads refuses today. If one ever does,
            # carrying on with the configuration in its place is exactly the guess that
            # flag exists to prevent.
            logger.warning("settings_refused", namespace=NAMESPACE, key=error.key)
            raise PreferencesUnavailableError(NOT_GUESSED) from error

    async def aclose(self) -> None:
        """Close the settings-api client."""
        await self._client.aclose()

    def __repr__(self) -> str:
        """Name the namespace, never the client, the token or the URL."""
        return f"{type(self).__name__}(namespace={NAMESPACE!r})"

    def _apply(self, resolved: ResolvedSettings) -> Preferences:
        """Turn one person's resolved namespace into what a login is stamped with."""
        deployment = self._deployment
        idle_days = _whole_number(resolved, "session_ttl_days", minimum=1)
        absolute_days = _whole_number(resolved, "session_absolute_ttl_days", minimum=1)
        max_sessions = _whole_number(resolved, "max_sessions", minimum=1)
        idle = _narrow_ttl(
            deployment.session_ttl_seconds,
            idle_days,
            minimum_days=SESSION_TTL_DAYS_MIN,
            maximum_days=SESSION_TTL_DAYS_MAX,
        )
        absolute = _narrow_ttl(
            deployment.session_absolute_ttl_seconds,
            absolute_days,
            minimum_days=SESSION_ABSOLUTE_TTL_DAYS_MIN,
            maximum_days=SESSION_ABSOLUTE_TTL_DAYS_MAX,
        )
        # keyring refuses absolute below idle at startup. A person can still set the two
        # independently, and failing login over that would make settings-api a hard
        # dependency of authentication. Keep the session valid: idle wins.
        absolute = max(absolute, idle)
        return Preferences(
            session_ttl_seconds=idle,
            session_absolute_ttl_seconds=absolute,
            max_sessions=_narrow_count(
                deployment.max_sessions,
                max_sessions,
                minimum=MAX_SESSIONS_MIN,
                maximum=MAX_SESSIONS_MAX,
            ),
            email_notifications=_switch(
                resolved, EMAIL_NOTIFICATIONS, default=deployment.email_notifications
            ),
            notify_on_new_session=_switch(
                resolved, NOTIFY_ON_NEW_SESSION, default=deployment.notify_on_new_session
            ),
            notify_on_credential_change=_switch(
                resolved,
                NOTIFY_ON_CREDENTIAL_CHANGE,
                default=deployment.notify_on_credential_change,
            ),
            require_reauth_for_credential_changes=_reauthentication(resolved),
        )


def build_preference_source(
    settings: Settings,
    *,
    client: SettingsClient | None = None,
    issuer: SettingsTokenIssuer | None = None,
) -> PreferenceSource:
    """Choose where preferences come from, and say which in the log.

    Args:
        settings: the configuration, which also says whether settings-api is in use.
        client: substituted by tests with :class:`settings_client.testing.FakeSettingsClient`,
            and used in place of building one from ``settings``.
        issuer: mints the short-lived user token a resolve needs. Required when
            settings-api is in use; ignored when everybody gets the configuration.
    """
    if client is None:
        configured = settings.settings_api
        if configured is None:
            logger.info("per_person_settings_off")
            return DeploymentPreferences(settings)
        if issuer is None:
            msg = "issuer is required when settings-api is in use"
            raise ValueError(msg)
        base_url, token = configured
        client = HttpSettingsClient(base_url=base_url, service_token=token.get_secret_value())
    elif issuer is None:
        msg = "issuer is required when settings-api is in use"
        raise ValueError(msg)

    logger.info("per_person_settings_on", namespace=NAMESPACE)
    return SettingsApiPreferences(client=client, settings=settings, issuer=issuer)


def _narrow_ttl(
    deployment: int,
    chosen_days: int | None,
    *,
    minimum_days: int,
    maximum_days: int,
) -> int:
    """The deployment's TTL in seconds, or the person's if they asked for less.

    Catalogue bounds are applied first so a value settings-api should not have stored
    cannot outrun them; the deployment then caps any raise.
    """
    if chosen_days is None:
        return deployment
    seconds = max(minimum_days, min(chosen_days, maximum_days)) * SECONDS_PER_DAY
    return min(deployment, seconds)


def _narrow_count(deployment: int, chosen: int | None, *, minimum: int, maximum: int) -> int:
    """The deployment's cap, or the person's if they asked for less."""
    if chosen is None:
        return deployment
    return min(deployment, max(minimum, min(chosen, maximum)))


def _whole_number(resolved: ResolvedSettings, key: str, *, minimum: int) -> int | None:
    """``key`` as a whole number no smaller than ``minimum``, or ``None`` if there is none.

    A deployment running an older settings-api may not have the key, and a value of the
    wrong shape is settings-api's bug rather than a reason to fail somebody's login.
    Either way the configuration stands in. The key is logged; the value never is.
    """
    value = resolved.get(key, None)
    if isinstance(value, int) and not isinstance(value, bool) and value >= minimum:
        return value
    if value is not None:
        logger.warning("setting_unusable", namespace=NAMESPACE, key=key)
    return None


def _switch(resolved: ResolvedSettings, key: str, *, default: bool) -> bool:
    """``key`` as an on/off choice, or this deployment's answer if there is no usable one.

    Missing, or not a boolean, is the same as ``_whole_number``'s case: an older
    settings-api, or a bug in it, and neither is a reason to fail somebody's login.
    """
    value = resolved.get(key, None)
    if isinstance(value, bool):
        return value
    if value is not None:
        logger.warning("setting_unusable", namespace=NAMESPACE, key=key)
    return default


def _reauthentication(resolved: ResolvedSettings) -> bool | None:
    """Whether a credential change needs the password again, or ``None`` for unknown.

    Unlike the switches, a value that cannot be used is *unknown* rather than the
    deployment's answer: the deployment's answer is the permissive one, and landing on it
    is exactly what this entry refuses to do. Only a settings-api with no such entry at
    all -- one that could never have stored a choice -- gives the deployment's answer,
    which is off: keyring asked for no second password before this setting existed.
    """
    try:
        value = resolved.get(REQUIRE_REAUTH, False)
    except SettingsRefused:
        logger.info("setting_refused", namespace=NAMESPACE, key=REQUIRE_REAUTH)
        return None
    if isinstance(value, bool):
        return value
    logger.warning("setting_unusable", namespace=NAMESPACE, key=REQUIRE_REAUTH)
    return None


__all__ = [
    "EMAIL_NOTIFICATIONS",
    "MAX_SESSIONS_MAX",
    "NAMESPACE",
    "NOTIFY_ON_CREDENTIAL_CHANGE",
    "NOTIFY_ON_NEW_SESSION",
    "NOT_GUESSED",
    "REFUSED",
    "REQUIRE_REAUTH",
    "SECONDS_PER_DAY",
    "SESSION_ABSOLUTE_TTL_DAYS_MAX",
    "SESSION_TTL_DAYS_MAX",
    "SETTINGS_TOKEN_TTL_SECONDS",
    "DeploymentPreferences",
    "PreferenceSource",
    "Preferences",
    "SettingsApiPreferences",
    "SettingsTokenIssuer",
    "build_preference_source",
    "deployment_preferences",
]
