"""Which version is running, and what happens when nothing installed says."""

from __future__ import annotations

from importlib import metadata

import pytest

import keyring_api
from keyring_api.core.version import service_version


def test_it_reports_the_installed_distribution_version() -> None:
    assert service_version() == metadata.version("keyring-api")


def test_it_falls_back_to_the_source_constant_when_nothing_is_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Running from a checkout that was never `pip install`ed is normal in development
    # and in a container that copies the source in; reporting no version at all would
    # make /healthy less useful exactly where it is read most.
    def absent(_name: str) -> str:
        raise metadata.PackageNotFoundError

    monkeypatch.setattr(metadata, "version", absent)

    assert service_version() == keyring_api.__version__
