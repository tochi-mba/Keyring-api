"""OAuth provider configuration, loaded from a file rather than written in code.

A new service is a config entry, not a code change. That is the same bet media-tool
makes with site recipes, and for the same reason: the thing that varies between services
is a handful of URLs and scopes, and putting them in code means a deployment cannot add
a provider without a release.

The file holds client secrets, so it is treated as a credential in its own right: it is
refused unless it is owner-only. Failing to start is a worse morning than a permissions
warning nobody reads, but it is a far better morning than a client secret that has been
group-readable for six months.

Owner-only is read from the file's mode, and only POSIX has one. On Windows the check is
skipped and the skip is logged, rather than every file being refused -- see
:func:`_mode_to_check`.
"""

from __future__ import annotations

import json
import os
import stat
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from keyring_api.core.logging import get_logger
from keyring_api.domain.errors import CredentialUnavailableError

if TYPE_CHECKING:
    from pathlib import Path

logger = get_logger(__name__)

MAX_PROVIDER_FILE_MODE = 0o600
"""Anything readable by group or other is refused."""


class OAuthProvider(BaseModel):
    """Everything needed to run one service's authorization-code flow."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    service: str = Field(description="The name a connection refers to this provider by.")
    authorize_url: HttpUrl = Field(description="Where the person is sent to consent.")
    token_url: HttpUrl = Field(description="Server-to-server endpoint for code and refresh.")
    client_id: str = Field(description="This deployment's registered client id.")
    client_secret: str = Field(description="The matching secret. Never leaves this process.")
    scopes: tuple[str, ...] = Field(
        default=(), description="Scopes to request. Fewer is better; ask for what you use."
    )
    audience: str | None = Field(
        default=None, description="Extra `audience` parameter, for providers that need one."
    )

    def authorization_url(self, *, redirect_uri: str, state: str) -> str:
        """Build the URL to send the person to.

        ``state`` is required, not optional, and is checked on the way back. Without it
        an attacker can complete a flow of their choosing in somebody else's session --
        the CSRF the parameter exists for.
        """
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            # Providers differ on whether they issue a refresh token by default;
            # asking for offline access is what makes unattended refresh possible at all.
            "access_type": "offline",
        }
        if self.scopes:
            query["scope"] = " ".join(self.scopes)
        if self.audience is not None:
            query["audience"] = self.audience

        return f"{self.authorize_url}?{urlencode(query)}"


def load_providers(path: Path | None) -> dict[str, OAuthProvider]:
    """Read the provider file, keyed by service name.

    Returns an empty mapping when no path is configured: a deployment that only stores
    API keys and passwords needs no OAuth providers, and should not have to invent a
    file to say so.

    Raises:
        CredentialUnavailableError: the file is unreadable, malformed, or -- on POSIX --
            readable by anyone but its owner.
    """
    if path is None:
        return {}

    if not path.exists():
        msg = f"OAuth provider file {path} does not exist"
        raise CredentialUnavailableError(msg)

    mode = _mode_to_check(path)
    if mode is not None and mode & ~MAX_PROVIDER_FILE_MODE:
        # This file holds client secrets. Refusing to start is a worse morning than a
        # warning; it is a much better one than six months of a group-readable secret.
        msg = f"OAuth provider file {path} must be mode 0600, found {mode:04o}"
        raise CredentialUnavailableError(msg)

    try:
        entries = json.loads(path.read_text(encoding="utf-8"))
        providers = [OAuthProvider.model_validate(entry) for entry in entries]
    except Exception as exc:
        msg = f"OAuth provider file {path} could not be read"
        raise CredentialUnavailableError(msg) from exc

    return {provider.service: provider for provider in providers}


def has_permission_bits() -> bool:
    """Whether this platform records who may read a file in POSIX permission bits.

    A function rather than a constant, so a test can pin either answer and run both
    branches of :func:`_mode_to_check` on whichever OS the suite is on.
    """
    return os.name == "posix"


def _mode_to_check(path: Path) -> int | None:
    """The mode the owner-only rule is checked against, or ``None`` where there is none.

    On POSIX the mode is the access control, so the rule is a comparison with it.

    Windows has no such thing. NTFS keeps no permission bits: ``os.chmod`` can only set or
    clear the read-only flag, and the mode reads back 0666, or 0444, whatever was asked
    for. Comparing it would refuse every provider file, and keyring run natively could
    never load an OAuth provider at all. Who may read the file there is decided by its ACL,
    which it inherits from the directory it sits in, and no mode can report that. So the
    comparison is skipped rather than faked, and each load says so in a warning that names
    the path and nothing read from the file -- a skipped check must not look like a passed
    one.
    """
    if not has_permission_bits():
        logger.warning(
            "oauth_provider_file_mode_unchecked",
            path=str(path),
            reason="the owner-only check is POSIX-only; on this platform the file's ACL applies",
        )
        return None
    return stat.S_IMODE(path.stat().st_mode)
