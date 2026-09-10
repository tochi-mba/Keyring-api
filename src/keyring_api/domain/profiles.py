"""Profiles and connections: the named credential sets an account owns.

The vocabulary is settled deliberately, because two of these words were being used for
two things each:

* An **account** is a person who logs in.
* A **profile** is a named credential set that account owns -- "personal", "work".
* A **connection** is a profile's link to one service. It records *that* a credential
  exists and whether it is usable, never the credential itself.
* A **session** is a login session. Only that.

The split between a connection and its secret is the important one. Connection metadata
is readable over the API -- which services are linked, whether each is live, when it
expires -- and none of it is sensitive. The material lives in the secret store, and no
endpoint returns it.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

from keyring_api.domain.errors import InvalidProfileNameError

if TYPE_CHECKING:
    from datetime import datetime

PROFILE_ID_PREFIX = "prof_"
MAX_PROFILE_NAME_LENGTH = 64
MAX_SERVICE_NAME_LENGTH = 64

_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
"""Lowercase, no leading or trailing punctuation, and never only dots.

These names become path segments in the secret store, which validates them again --
belt and braces, in two layers that would each have to fail.
"""


class CredentialKind(StrEnum):
    """What sort of credential a connection holds.

    Kinds grow forever; what *consumes* them does not. Each kind maps onto one of the
    narrow consumption ports in :mod:`keyring_api.credentials`, which is what lets a new
    service be supported without any provider changing.
    """

    API_KEY = "api_key"
    """A static token attached to requests. Never expires by itself."""

    OAUTH2_AUTHORIZATION_CODE = "oauth2_authorization_code"
    """A user-consented token pair. Refreshed unattended, so it expires and renews."""

    PASSWORD = "password"  # noqa: S105 -- an enum label, not a credential
    """A username and password, optionally with a TOTP seed. For sites with no API.

    Stored only where a service offers no alternative. Unlike an OAuth grant, a stored
    password is not revocable by the operator -- only by the person changing it at the
    service -- which is why the API flags it distinctly and the docs say so plainly.
    """

    @property
    def can_refresh(self) -> bool:
        """Whether this kind renews itself with nobody present.

        Only the OAuth grant does. An API key does not expire, and a password cannot be
        renewed by anything but the person who owns it -- so an *expired* connection of
        either kind is finished, whereas an expired OAuth one is merely due.
        """
        return self is CredentialKind.OAUTH2_AUTHORIZATION_CODE


class ConnectionStatus(StrEnum):
    """Whether a connection can currently produce a usable credential."""

    ACTIVE = "active"
    """Usable now, or refreshable without anyone present."""

    PENDING = "pending"
    """Authorization started but not completed. No credential stored yet."""

    EXPIRED = "expired"
    """The stored credential is past its life and could not be renewed."""

    REVOKED = "revoked"
    """Withdrawn at the provider, or by us. Needs re-authorising."""


def new_profile_id() -> str:
    """Return a fresh profile id."""
    return f"{PROFILE_ID_PREFIX}{uuid.uuid4().hex}"


def normalize_profile_name(raw: str) -> str:
    """Reduce a profile name to the one form it is stored and addressed as.

    Lowercased, so "Personal" and "personal" cannot become two profiles that a person
    then has to tell apart in a list.

    Raises:
        InvalidProfileNameError: if the name cannot be stored or addressed.
    """
    return _normalize(raw, what="profile name", limit=MAX_PROFILE_NAME_LENGTH)


def normalize_service_name(raw: str) -> str:
    """Reduce a service name ("spotify", "tmdb") to its stored form.

    Raises:
        InvalidProfileNameError: if the name cannot be stored or addressed.
    """
    return _normalize(raw, what="service name", limit=MAX_SERVICE_NAME_LENGTH)


def _normalize(raw: str, *, what: str, limit: int) -> str:
    name = raw.strip().lower()

    if not name:
        msg = f"{what} must not be empty"
        raise InvalidProfileNameError(msg)

    if len(name) > limit:
        msg = f"{what} must be at most {limit} characters"
        raise InvalidProfileNameError(msg)

    if not _NAME.match(name):
        msg = (
            f"{what} may contain only lowercase letters, digits, dot, dash and "
            "underscore, and must start and end with a letter or digit"
        )
        raise InvalidProfileNameError(msg)

    return name


@dataclass(frozen=True, slots=True)
class Connection:
    """One profile's link to one service.

    Everything here is safe to return over the API. The credential itself is in the
    secret store, addressed by the same ``(account, profile, service)`` triple.
    """

    service: str
    kind: CredentialKind
    status: ConnectionStatus
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    """When the stored credential stops working. ``None`` for kinds that do not expire."""

    scopes: tuple[str, ...] = ()
    stores_totp_seed: bool = False
    """Flagged separately because storing a TOTP seed beside a password collapses that
    person's second factor into the same place as their first. Opt-in, and never
    inferred from the presence of a seed in a request."""

    last_error: str | None = None
    """Why the last refresh failed, if it did. Carries the fix, never the credential."""

    def needs_refresh(self, *, now: datetime, margin_seconds: float) -> bool:
        """Whether the credential should be renewed before it is next used.

        Renewed *before* expiry rather than after a failure: a refresh triggered by a
        401 means one request has already failed, and the caller has to know to retry.
        """
        if self.expires_at is None:
            return False
        return now >= self.expires_at - timedelta(seconds=margin_seconds)

    def is_usable(self, *, now: datetime) -> bool:
        """Whether this connection can produce a credential right now, or renew one."""
        if self.status is not ConnectionStatus.ACTIVE:
            return False
        # An expired access token is still usable when it can be refreshed; whether it
        # can is the credential kind's business, not this type's.
        return True if self.expires_at is None else self.kind.can_refresh or now < self.expires_at

    def with_error(self, message: str, *, now: datetime) -> Connection:
        """Record a failure without discarding the stored credential.

        A transient provider outage must not delete a refresh token that will work again
        in five minutes.
        """
        return replace(self, status=ConnectionStatus.EXPIRED, last_error=message, updated_at=now)


@dataclass(frozen=True, slots=True)
class Profile:
    """A named credential set owned by one account."""

    profile_id: str
    account_id: str
    name: str
    created_at: datetime
    updated_at: datetime
    connections: tuple[Connection, ...] = ()

    def connection(self, service: str) -> Connection | None:
        """Return the connection to ``service``, or ``None``."""
        return next((item for item in self.connections if item.service == service), None)

    def with_connection(self, connection: Connection, *, now: datetime) -> Profile:
        """Add or replace a connection, keeping the rest in place."""
        others = tuple(item for item in self.connections if item.service != connection.service)
        return replace(self, connections=(*others, connection), updated_at=now)

    def without_connection(self, service: str, *, now: datetime) -> Profile:
        """Remove a connection."""
        remaining = tuple(item for item in self.connections if item.service != service)
        return replace(self, connections=remaining, updated_at=now)
