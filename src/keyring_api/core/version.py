"""Resolving the running version.

Prefers installed distribution metadata, which is what a deployment actually shipped,
and falls back to the source constant when running from a checkout that was never
installed.
"""

from __future__ import annotations

from importlib import metadata

from keyring_api import __version__

DISTRIBUTION_NAME = "keyring-api"


def service_version() -> str:
    """Return the running version of the service."""
    try:
        return metadata.version(DISTRIBUTION_NAME)
    except metadata.PackageNotFoundError:
        return __version__
