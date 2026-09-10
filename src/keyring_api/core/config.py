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
from typing import TYPE_CHECKING, Annotated, Self

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from collections.abc import Mapping

ENV_PREFIX = "KEYRING_"
ENV_NESTED_DELIMITER = "__"

MASTER_KEY_BYTES = 32
"""AES-256-GCM. Not configurable: a shorter key is a weaker vault, not a preference."""

PositiveInt = Annotated[int, Field(gt=0)]
PositiveFloat = Annotated[float, Field(gt=0)]


class LogFormat(StrEnum):
    JSON = "json"
    CONSOLE = "console"


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
    issuer: str = "https://keyring.local"
    """Goes into every issued token's ``iss`` claim; consuming services pin it."""

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

    # -- Storage -----------------------------------------------------------------------
    secret_dir: Path = Path("var/secrets")
    """Encrypted credential files. Never inside a directory any endpoint serves from."""

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

    @field_validator("secret_dir", "signing_key_path")
    @classmethod
    def _resolve_path(cls, value: Path) -> Path:
        """Resolve early so a relative path cannot mean two places after a chdir."""
        return value.expanduser().resolve()

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

    @model_validator(mode="after")
    def _check_lifetimes(self) -> Self:
        if self.session_absolute_ttl_seconds < self.session_ttl_seconds:
            msg = "session_absolute_ttl_seconds must be at least session_ttl_seconds"
            raise ValueError(msg)

        if self.access_token_ttl_seconds <= self.oauth_refresh_margin_seconds:
            msg = "access_token_ttl_seconds must exceed the OAuth refresh margin"
            raise ValueError(msg)

        return self

    def master_key_bytes(self) -> bytes | None:
        """Return the decoded master key, or ``None`` when none is configured."""
        if self.master_key is None:
            return None
        return base64.b64decode(self.master_key.get_secret_value(), validate=True)


class UnknownSettingError(ValueError):
    """A ``KEYRING_``-prefixed variable is set that no setting corresponds to."""


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
    """Build settings from the environment and ``.env``."""
    check_for_unknown_env_vars()
    return Settings()
