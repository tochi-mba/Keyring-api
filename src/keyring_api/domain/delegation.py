"""Revocable consent for one service to act for one profile in the background."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class OfflineGrant:
    """An opaque handle, never a bearer credential on its own."""

    grant_id: str
    account_id: str
    profile: str
    service: str
    audiences: tuple[str, ...]
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
