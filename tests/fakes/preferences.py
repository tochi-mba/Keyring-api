"""A preference source that answers with whatever the test says.

Hand-written and satisfying the real ``PreferenceSource`` protocol, so a change to the port
makes this fail to type-check rather than silently drift. For unit tests of what a service
does *with* a person's settings; how those settings are read from settings-api is
``tests/unit/core/test_preferences.py``'s business.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from keyring_api.core.preferences import deployment_preferences

if TYPE_CHECKING:
    from keyring_api.core.config import Settings
    from keyring_api.core.preferences import Preferences


class ChosenPreferences:
    """Every account gets the deployment's preferences, with the given fields changed."""

    def __init__(self, settings: Settings, **chosen: Any) -> None:
        self.preferences: Preferences = replace(deployment_preferences(settings), **chosen)

    async def for_account(self, _account_id: str, /) -> Preferences:
        return self.preferences

    async def aclose(self) -> None:
        return
