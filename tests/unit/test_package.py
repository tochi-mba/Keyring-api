"""The package imports and reports a version.

Trivial on its face, but it is the test that fails first when the packaging metadata,
the source layout, and the installed distribution disagree with each other.
"""

from __future__ import annotations

import keyring_api


def test_the_package_exposes_a_version() -> None:
    assert keyring_api.__version__.count(".") == 2
