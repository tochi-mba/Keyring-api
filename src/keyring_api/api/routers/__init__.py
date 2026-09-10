"""Router registry.

Adding an API means writing a router module and adding it here. Everything
cross-cutting -- problem+json errors, the request id, the account binding, access
logging, the version prefix -- is inherited from the app factory, so a new endpoint
starts consistent with the existing ones rather than having to remember to be. See the
recipe in AGENTS.md.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from keyring_api.api.routers import auth, health

if TYPE_CHECKING:
    from fastapi import APIRouter

ROUTERS: tuple[APIRouter, ...] = (health.router, auth.router)
"""Every router the application serves, in the order they are mounted."""

__all__ = ["ROUTERS"]
