"""OAuth provider configuration, loaded from a file rather than written in code.

A new service is a config entry, not a code change. That is the same bet media-tool
makes with site recipes, and for the same reason: the thing that varies between services
is a handful of URLs and scopes, and putting them in code means a deployment cannot add
a provider without a release.

The file holds client secrets, so it is treated as a credential in its own right: it is
refused unless it is owner-only. Failing to start is a worse morning than a permissions
warning nobody reads, but it is a far better morning than a client secret that has been
group-readable for six months.
"""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from keyring_api.domain.errors import CredentialUnavailableError

if TYPE_CHECKING:
    from pathlib import Path

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
        CredentialUnavailableError: the file is unreadable, malformed, or readable by
            anyone but its owner.
    """
    if path is None:
        return {}

    if not path.exists():
        msg = f"OAuth provider file {path} does not exist"
        raise CredentialUnavailableError(msg)

    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & ~MAX_PROVIDER_FILE_MODE:
        # This file holds client secrets. Refusing to start is a worse morning than a
        # warning; it is a much better one than six months of a group-readable secret.
        msg = f"OAuth provider file {path} must be mode 0600, found {mode:04o}"
        raise CredentialUnavailableError(msg)

    try:
        entries = json.loads(path.read_text())
        providers = [OAuthProvider.model_validate(entry) for entry in entries]
    except Exception as exc:
        msg = f"OAuth provider file {path} could not be read"
        raise CredentialUnavailableError(msg) from exc

    return {provider.service: provider for provider in providers}
