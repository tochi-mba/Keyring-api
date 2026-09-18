"""Application configuration.

Every knob is an environment variable prefixed ``KEYRING_``; nested settings use a
double underscore (``KEYRING_ARGON2__TIME_COST``). Unknown variables under the prefix are
rejected rather than ignored (see :func:`check_for_unknown_env_vars`), so a typo in a
deployment surfaces at startup instead of silently leaving a security-relevant default
in place.

Two absences are deliberate and load-bearing. There is no setting that enables open
registration — every account is invited — and there is no setting that disables
authentication. Both would be single-variable routes to an unlocked vault.
"""

from __future__ import annotations

import base64
import binascii
import os
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from keyring_client import check_service_token

if TYPE_CHECKING:
    from collections.abc import Mapping

ENV_PREFIX = "KEYRING_"
ENV_NESTED_DELIMITER = "__"

MASTER_KEY_BYTES = 32
"""AES-256-GCM. Not configurable: a shorter key is a weaker vault, not a preference."""

MIN_SERVICE_TOKEN_CHARS = 32
"""The shortest service token accepted at startup.

``keyring_client.check_service_token`` applies the same rule on the consuming side, and a test
holds the two numbers together so neither can drift.
"""

MAX_EXCHANGE_AUDIENCE_CHARS = 128

PositiveInt = Annotated[int, Field(gt=0)]
PositiveFloat = Annotated[float, Field(gt=0)]


def _validated_settings_api_token(value: SecretStr | None) -> SecretStr | None:
    """Refuse a token settings-api would never accept, without echoing it.

    Runs after wrapping as ``SecretStr``, so a validation error's input is the secret
    (asterisks), not the presented string.
    """
    if value is not None:
        check_service_token(value.get_secret_value())
    return value


SettingsApiToken = Annotated[SecretStr | None, AfterValidator(_validated_settings_api_token)]


class LogFormat(StrEnum):
    JSON = "json"
    CONSOLE = "console"


class EmailBackend(StrEnum):
    """How invite and reset links reach the person they are for."""

    DISABLED = "disabled"
    """The default. The operator delivers tokens by hand (ADR-0009)."""

    FILE = "file"
    """Write messages to a directory. Development, and inspecting what would be sent."""

    SMTP = "smtp"
    """Send for real. Every provider a small deployment would pick speaks it."""


class EmailSettings(BaseSettings):
    """Where invite and reset links go.

    Disabled by default and safe to leave that way: a credential vault that cannot start
    without an SMTP server is a credential vault nobody can start.

    There is deliberately no setting that disables TLS certificate verification. The
    absence is the feature -- it is the one knob that turns a working configuration into
    a silently intercepted one, and it exists in most mail libraries because somebody
    once had a self-signed certificate.
    """

    model_config = SettingsConfigDict(extra="forbid")

    backend: EmailBackend = EmailBackend.DISABLED

    host: str = ""
    port: PositiveInt = 587
    """587 with STARTTLS is what every provider here documents; 465 is implicit TLS."""

    username: str = ""
    password: SecretStr | None = None

    use_starttls: bool = True
    use_implicit_tls: bool = False
    """Set for port 465. Mutually exclusive with STARTTLS; validated below."""

    from_address: str = ""
    from_name: str = "keyring"
    timeout_seconds: PositiveFloat = 10.0

    outbox_dir: Path = Path("var/outbox")
    """Where the file backend writes. Contains live links, so it is created 0700/0600."""

    @field_validator("outbox_dir")
    @classmethod
    def _resolve_outbox(cls, value: Path) -> Path:
        return value.expanduser().resolve()

    link_base_url: str = ""
    """Public base URL of whatever redeems these tokens.

    Left empty, messages carry the bare token for the person to paste. That is the honest
    default for a service with no web UI: inventing a link to a page that does not exist
    is worse than asking somebody to copy a string.
    """

    max_messages_per_address_per_window: PositiveInt = 5
    window_seconds: PositiveFloat = 3_600.0
    """Caps how often one address can be mailed, whoever asks.

    The per-caller limit stops one attacker; this stops many callers, or one behind
    changing addresses, from using password reset to flood somebody else's inbox. Keyed
    by a hash of the address, so the limiter never holds plaintext addresses in memory.
    """

    @model_validator(mode="after")
    def _check_transport(self) -> Self:
        """Refuse configurations that would authenticate in the clear, or not work.

        Checked at startup rather than at the first send: a deployment that believes it
        has mail configured and does not should find out while somebody is watching, not
        when a person's reset link fails to arrive.
        """
        if self.backend is not EmailBackend.SMTP:
            return self

        if not self.host or not self.from_address:
            msg = "email backend 'smtp' needs both host and from_address"
            raise ValueError(msg)

        if self.use_starttls and self.use_implicit_tls:
            msg = "use_starttls and use_implicit_tls are mutually exclusive"
            raise ValueError(msg)

        if self.password is not None and not (self.use_starttls or self.use_implicit_tls):
            # SMTP AUTH over a plaintext connection sends the password in base64, which
            # is not encryption. Anyone on the path gets the mailbox -- and a mailbox
            # that sends password resets is worth more than most of what it protects.
            msg = "refusing to send SMTP credentials without TLS: enable STARTTLS or implicit TLS"
            raise ValueError(msg)

        return self

    def from_header(self) -> str:
        """The From header value."""
        return f"{self.from_name} <{self.from_address}>" if self.from_name else self.from_address


class Argon2Settings(BaseSettings):
    """Password hashing cost.

    The defaults follow the RFC 9106 second recommended option (64 MiB, three passes),
    which is sized for a server that also has other work to do. Raising these makes
    every login slower for everyone and every offline guess slower for an attacker; the
    exchange rate is favourable, so raise them if the box can afford it.
    """

    model_config = SettingsConfigDict(extra="forbid")

    time_cost: PositiveInt = 3
    memory_cost_kib: PositiveInt = 64 * 1024
    parallelism: PositiveInt = 4
    hash_length: PositiveInt = 32
    salt_length: PositiveInt = 16

    @model_validator(mode="after")
    def _check_memory_covers_parallelism(self) -> Self:
        """Argon2 requires at least 8 KiB of memory per lane.

        Checked here so raising parallelism without raising memory fails at startup with
        a message naming the fix, rather than at the first login attempt with
        "Memory cost is too small" from inside the hashing library.
        """
        minimum = 8 * self.parallelism
        if self.memory_cost_kib < minimum:
            msg = (
                f"memory_cost_kib must be at least 8 KiB per lane ({minimum} for this parallelism)"
            )
            raise ValueError(msg)
        return self


class RateLimitSettings(BaseSettings):
    """How many attempts an unauthenticated caller gets before being told to wait.

    Scoped per endpoint rather than globally: a shared bucket means one person's
    forgotten password exhausts everyone's ability to log in.
    """

    model_config = SettingsConfigDict(extra="forbid")

    login_attempts: PositiveInt = 10
    login_window_seconds: PositiveFloat = 300.0

    reset_attempts: PositiveInt = 5
    reset_window_seconds: PositiveFloat = 3_600.0

    invite_attempts: PositiveInt = 10
    invite_window_seconds: PositiveFloat = 3_600.0


class Settings(BaseSettings):
    """The complete runtime configuration."""

    model_config = SettingsConfigDict(
        env_prefix="KEYRING_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="forbid",
    )

    # -- Identity ----------------------------------------------------------------------
    app_name: str = "keyring"
    environment: str = "local"
    issuer: str = "http://127.0.0.1:8001"
    """Goes into every issued token's ``iss`` claim; consuming services pin it.

    The loopback default is the one every sibling service defaults to as well, so a family
    started locally agrees about who signed a token without anybody setting anything. A
    deployment sets this to keyring's public URL, and every consumer's issuer to the same
    string.
    """

    # -- Observability -----------------------------------------------------------------
    log_level: str = "INFO"
    log_format: LogFormat = LogFormat.JSON

    # -- Serving -----------------------------------------------------------------------
    host: str = "127.0.0.1"
    """Loopback by default. This service belongs behind a TLS-terminating proxy."""

    port: PositiveInt = 8001

    # -- Login sessions ----------------------------------------------------------------
    session_ttl_seconds: PositiveInt = 14 * 24 * 3_600
    """Idle timeout. A session unused for this long stops working."""

    session_absolute_ttl_seconds: PositiveInt = 90 * 24 * 3_600
    """Hard ceiling. A session cannot be kept alive indefinitely by using it."""

    invite_ttl_seconds: PositiveInt = 7 * 24 * 3_600
    reset_ttl_seconds: PositiveInt = 3_600
    """Short on purpose: a reset link is a password in an inbox until it expires."""

    max_sessions_per_account: PositiveInt = 20

    lockout_threshold: PositiveInt = 10
    """Failed logins against one account before it is locked."""

    lockout_seconds: PositiveFloat = 900.0
    """How long a lockout lasts.

    Fixed rather than escalating. The lock exists to make online guessing impractical,
    and an escalating one hands an attacker a way to keep a real person locked out
    indefinitely by failing on their behalf.
    """

    # -- Service tokens ----------------------------------------------------------------
    access_token_ttl_seconds: PositiveInt = 900
    """Short-lived signed tokens other services verify locally against the JWKS.

    Fifteen minutes bounds how long a revoked session keeps working elsewhere, which is
    the price of not making a network call to keyring on every single request.
    """

    signing_key_path: Path = Path("var/keys/signing.pem")

    # -- OAuth -------------------------------------------------------------------------
    oauth_state_ttl_seconds: PositiveInt = 600
    oauth_refresh_margin_seconds: PositiveInt = 120
    """Refresh an access token this long before it expires, rather than after it fails."""

    oauth_http_timeout_seconds: PositiveFloat = 10.0

    oauth_providers_path: Path | None = None
    """Provider configuration. Must be mode 0600 -- it holds client secrets."""

    oauth_redirect_uri: str = "http://127.0.0.1:8001/v1/oauth/callback"
    """Where providers send the person back. Must match what is registered with each."""

    service_tokens: dict[str, SecretStr] = Field(default_factory=dict)
    """Other services allowed to ask for credentials, by name.

    A service must present both its own token *and* the end user's, and gets a
    credential only for that user. Without the pairing, any service that could reach
    keyring could request anybody's token -- the confused deputy, moved to the service
    boundary.

    The name is not decoration: a user token presented on ``/v1/internal`` must have been
    minted with exactly this name as its audience. Name each service the way its callers
    mint -- ``example-tool``, ``spotify-api`` -- and use the same name as that service's
    audience everywhere else it is checked, settings-api's grants included.
    """

    # -- Per-person settings -----------------------------------------------------------
    exchange_audiences: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    """Exact downstream audiences each configured service may exchange into; deny by default."""

    offline_grant_max_ttl_seconds: PositiveInt = 30 * 24 * 3600
    max_offline_grants_per_profile: PositiveInt = 100

    @model_validator(mode="after")
    def _check_exchange_audiences(self) -> Self:
        if not self.exchange_audiences.keys() <= self.service_tokens.keys():
            msg = "exchange_audiences names an unconfigured service"
            raise ValueError(msg)
        for audiences in self.exchange_audiences.values():
            if any(
                not name or name.strip() != name or len(name) > MAX_EXCHANGE_AUDIENCE_CHARS
                for name in audiences
            ):
                msg = "exchange audiences must be nonempty exact names up to 128 characters"
                raise ValueError(msg)
        return self

    settings_api_base_url: str | None = None
    """Where settings-api is. Unset, every person gets this configuration as it stands.

    Set, each login reads that person's ``keyring`` settings: idle TTL, absolute ceiling
    and session cap. The ceilings in this configuration still apply on top of what
    anybody chooses -- a person may narrow a cap and never raise it. The grant there
    needs ``audience_prefix`` ``keyring``: this service mints the user token it presents,
    with this service's own audience.
    """

    settings_api_token: SettingsApiToken = None
    """This service's entry in settings-api's ``SETTINGS_API_SERVICES``.

    At least 32 characters, the rule settings-api enforces on its side. Its grant there
    needs ``audience_prefix`` ``keyring`` -- this service's token audience, not a
    caller's.
    """

    # -- Storage -----------------------------------------------------------------------
    database_path: Path = Path("var/keyring.db")
    """The one file everything lives in, including the encrypted credential material.

    Never inside a directory any endpoint serves from. Back it up with ``VACUUM INTO``
    rather than ``cp`` -- see docs/operations.md for why copying a live WAL database is
    not a backup.
    """

    admin_token: SecretStr | None = None
    """Authorises the administrative endpoints -- issuing invites, disabling accounts.

    Administration is the operator, not an account. There is no ``is_admin`` flag that
    could be granted by mistake and no path by which a compromised account becomes one;
    the token comes from the environment, the same place the master key does. Unset
    means the administrative endpoints are unavailable rather than open.
    """

    master_key: SecretStr | None = None
    """Base64 of 32 random bytes, from the environment. See docs/operations.md.

    Optional so the service can start and report itself degraded rather than crash-loop
    with no diagnosis. Every credential operation fails cleanly while it is missing.
    """

    # -- Limits ------------------------------------------------------------------------
    max_profiles_per_account: PositiveInt = 20
    max_connections_per_profile: PositiveInt = 50

    # -- Nested ------------------------------------------------------------------------
    argon2: Argon2Settings = Field(default_factory=Argon2Settings)
    rate_limit: RateLimitSettings = Field(default_factory=RateLimitSettings)
    email: EmailSettings = Field(default_factory=EmailSettings)

    @field_validator("database_path", "signing_key_path", "oauth_providers_path")
    @classmethod
    def _resolve_path(cls, value: Path | None) -> Path | None:
        """Resolve early so a relative path cannot mean two places after a chdir."""
        return None if value is None else value.expanduser().resolve()

    @field_validator("master_key")
    @classmethod
    def _check_master_key(cls, value: SecretStr | None) -> SecretStr | None:
        """Reject a malformed key at startup rather than at the first write."""
        if value is None:
            return None

        try:
            raw = base64.b64decode(value.get_secret_value(), validate=True)
        except (binascii.Error, ValueError) as exc:
            msg = "master_key must be base64-encoded"
            raise ValueError(msg) from exc

        if len(raw) != MASTER_KEY_BYTES:
            msg = f"master_key must decode to exactly {MASTER_KEY_BYTES} bytes"
            raise ValueError(msg)

        return value

    @field_validator("service_tokens")
    @classmethod
    def _check_service_tokens(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        """Refuse a placeholder, a pasted newline, or two services sharing one token.

        A service token is the entire proof that a caller on ``/v1/internal`` is a service
        at all, and a deployment that pasted ``change-me`` looks exactly like a working one
        until somebody guesses it. Two services sharing a token would make whichever name
        matched decide the audience a user token must carry, so the weaker service could
        present the stronger one's tokens.
        """
        secrets = [token.get_secret_value() for token in value.values()]
        for secret in secrets:
            if secret.strip() != secret or len(secret) < MIN_SERVICE_TOKEN_CHARS:
                msg = (
                    f"each service token must be at least {MIN_SERVICE_TOKEN_CHARS} "
                    "characters, with no surrounding whitespace"
                )
                raise ValueError(msg)
        if len(set(secrets)) != len(secrets):
            msg = "two services share a service token; each needs its own"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _check_lifetimes(self) -> Self:
        if self.session_absolute_ttl_seconds < self.session_ttl_seconds:
            msg = "session_absolute_ttl_seconds must be at least session_ttl_seconds"
            raise ValueError(msg)

        if self.access_token_ttl_seconds <= self.oauth_refresh_margin_seconds:
            msg = "access_token_ttl_seconds must exceed the OAuth refresh margin"
            raise ValueError(msg)

        return self

    @field_validator("settings_api_base_url")
    @classmethod
    def _blank_settings_url_is_unset(cls, value: str | None) -> str | None:
        """``KEYRING_SETTINGS_API_BASE_URL=`` in a ``.env`` means off, not an empty URL."""
        return value or None

    @field_validator("settings_api_token", mode="before")
    @classmethod
    def _blank_settings_token_is_unset(cls, value: Any) -> Any:
        if value is None or value == "":
            return None
        if isinstance(value, SecretStr) and not value.get_secret_value():
            return None
        return value

    @model_validator(mode="after")
    def _check_settings_api_is_whole(self) -> Self:
        """Refuse half a settings-api configuration, and a token that could never work.

        A URL with no token would be refused on every call, and a token with no URL is a
        secret configured for nothing. Either is somebody's mistake, and startup is the
        cheapest place to hear about it.
        """
        if (self.settings_api_base_url is None) != (self.settings_api_token is None):
            msg = "settings_api_base_url and settings_api_token must be set together"
            raise ValueError(msg)
        return self

    @property
    def settings_api(self) -> tuple[str, SecretStr] | None:
        """Where settings-api is and how to authenticate to it, or ``None`` when unused.

        One value rather than two optional ones, so that nothing downstream has to
        re-establish that the pair is whole: :meth:`_check_settings_api_is_whole` already
        refused to construct settings where it is not.
        """
        if self.settings_api_base_url is None or self.settings_api_token is None:
            return None
        return self.settings_api_base_url, self.settings_api_token

    def master_key_bytes(self) -> bytes | None:
        """Return the decoded master key, or ``None`` when none is configured."""
        if self.master_key is None:
            return None
        return base64.b64decode(self.master_key.get_secret_value(), validate=True)


class UnknownSettingError(ValueError):
    """A ``KEYRING_``-prefixed variable is set that no setting corresponds to."""


class ConfigurationError(ValueError):
    """The configuration was rejected, and this is why -- without the values.

    pydantic's own :class:`~pydantic.ValidationError` renders the **input** beside each
    failure, and a startup crash is normally logged verbatim. For most settings that is
    helpful. For ``master_key``, ``admin_token`` and ``service_tokens`` it pastes the secret
    into the log -- the one place the ``SecretStr`` wrapper exists to keep it out of, and the
    wrapper does not help, because pydantic reports the raw input rather than the coerced
    value. So :func:`load_settings` re-raises this instead, carrying each failure's location
    and message only, with the chain cut so the original is not attached to the traceback.
    """


def describe_validation_error(exc: ValidationError) -> str:
    """Render a validation error as locations and messages only. Never the input."""
    problems = (
        f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
        for error in exc.errors()
    )
    return "invalid configuration: " + "; ".join(problems)


def known_env_names(model: type[BaseModel] = Settings, prefix: str = ENV_PREFIX) -> set[str]:
    """Every environment variable name this configuration understands.

    Walks nested settings models so ``KEYRING_ARGON2__TIME_COST`` is recognised
    alongside the flat names.
    """
    names: set[str] = set()
    for field_name, field in model.model_fields.items():
        env_name = f"{prefix}{field_name.upper()}"
        annotation = field.annotation
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            names |= known_env_names(annotation, f"{env_name}{ENV_NESTED_DELIMITER}")
        else:
            names.add(env_name)
    return names


def check_for_unknown_env_vars(environ: Mapping[str, str] | None = None) -> None:
    """Fail on a misspelled setting instead of quietly running with the default.

    pydantic-settings ignores prefixed variables it does not recognise, which for most
    services is a harmless convenience. Here it is not: ``KEYRING_SESION_TTL_SECONDS``
    would leave sessions on their default lifetime with nothing in the logs to say so,
    and the same typo in ``KEYRING_MASTER_KEY`` would start the service with no vault.

    Raises:
        UnknownSettingError: naming every unrecognised variable, so a deployment is
            fixed in one pass rather than one restart per typo.
    """
    present = environ if environ is not None else os.environ
    unknown = sorted(
        name for name in present if name.startswith(ENV_PREFIX) and name not in known_env_names()
    )
    if unknown:
        msg = f"unknown {ENV_PREFIX}* environment variables: {', '.join(unknown)}"
        raise UnknownSettingError(msg)


def load_settings() -> Settings:
    """Build settings from the environment and ``.env``.

    Raises:
        UnknownSettingError: a ``KEYRING_``-prefixed variable matches no setting.
        ConfigurationError: a setting was rejected. Names the setting and the rule, and
            never the value -- see the class.
    """
    check_for_unknown_env_vars()
    try:
        return Settings()
    except ValidationError as exc:
        raise ConfigurationError(describe_validation_error(exc)) from None
