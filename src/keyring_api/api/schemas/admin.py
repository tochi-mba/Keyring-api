"""Wire models for the administrative surface.

Same rule as everywhere else, and it matters more here: **no response model carries
credential material.** An administrator can see that somebody has a Spotify connection
and that it has expired. There is no field, on any model in this file, that could hold
the token behind it -- and no endpoint that would fill one in if there were.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from keyring_api.audit.log import AuditAction
from keyring_api.domain.accounts import AccountStatus


class AccountSummary(BaseModel):
    """One account, as an administrator sees it."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "account_id": "acct_9f2c...",
                    "email": "person@example.com",
                    "status": "active",
                    "roles": ["member"],
                    "created_at": "2026-09-01T09:00:00Z",
                    "locked": False,
                }
            ]
        }
    )

    account_id: str = Field(description="Opaque, stable identifier.")
    email: str = Field(description="The address this account logs in with.")
    status: AccountStatus = Field(description="'active' or 'disabled'.")
    roles: list[str] = Field(description="Role names this account holds.")
    created_at: datetime = Field(description="When the account was created.")
    updated_at: datetime = Field(description="When it last changed.")
    locked: bool = Field(
        description="Whether it is inside a failed-login lockout. Lifts by itself."
    )


class AccountListResponse(BaseModel):
    """Every account."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"accounts": []}]})

    accounts: list[AccountSummary] = Field(description="Accounts, oldest first.")


class SetStatusRequest(BaseModel):
    """Disable or re-enable an account."""

    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [{"status": "disabled"}]}
    )

    status: AccountStatus = Field(
        description="Disabling also ends every live session for that account."
    )


class SetRolesRequest(BaseModel):
    """Replace an account's roles.

    A replacement rather than an add or a remove: "what should this account hold" is a
    question with one answer, whereas a sequence of adds and removes has an order, and
    an order has a race.
    """

    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [{"roles": ["member", "auditor"]}]}
    )

    roles: list[str] = Field(
        description=(
            "The complete set of role names this account should hold. You cannot grant "
            "a role whose permissions exceed your own."
        )
    )


class RoleResponse(BaseModel):
    """A role and what it allows."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "auditor",
                    "description": "Read-only: accounts, roles and the audit log.",
                    "permissions": ["accounts:read", "roles:read", "audit:read"],
                    "builtin": True,
                }
            ]
        }
    )

    name: str = Field(description="How the role is addressed.")
    description: str = Field(description="What it is for.")
    permissions: list[str] = Field(description="Exactly what it allows, sorted.")
    builtin: bool = Field(
        description="Built-in roles cannot be edited or deleted, so `member` stays what it says."
    )
    created_at: datetime | None = Field(default=None, description="Null for built-in roles.")
    updated_at: datetime | None = Field(default=None, description="Null for built-in roles.")


class RoleListResponse(BaseModel):
    """Every role, built-in first."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"roles": []}]})

    roles: list[RoleResponse] = Field(description="Built-in roles first, then custom ones.")


class WriteRoleRequest(BaseModel):
    """Create or replace a custom role."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    "name": "support",
                    "description": "Can help people who are locked out.",
                    "permissions": ["accounts:read", "accounts:revoke_sessions"],
                }
            ]
        },
    )

    name: str = Field(
        max_length=64,
        description="Lowercase letters, digits, dot, dash and underscore.",
    )
    permissions: list[str] = Field(
        description=(
            "Exactly what this role allows. Every value must be a known permission -- an "
            "unrecognised one is rejected rather than ignored. You cannot include a "
            "permission you do not hold yourself."
        )
    )
    description: str = Field(default="", max_length=200, description="What it is for.")


class UpdateRoleRequest(BaseModel):
    """Replace a custom role's permissions."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [{"permissions": ["accounts:read"], "description": "Read-only support."}]
        },
    )

    permissions: list[str] = Field(description="The complete new permission set.")
    description: str = Field(default="", max_length=200, description="What it is for.")


class PermissionInfo(BaseModel):
    """One permission a role can contain."""

    name: str = Field(description="The value to put in a role's `permissions`.")
    description: str = Field(description="What holding it allows.")


class PermissionListResponse(BaseModel):
    """Every permission this service understands.

    Exposed so an administrator building a custom role can see the full vocabulary rather
    than guessing at strings -- and so that the absence of a "read another account's
    credential" permission is visible rather than merely true.
    """

    model_config = ConfigDict(json_schema_extra={"examples": [{"permissions": []}]})

    permissions: list[PermissionInfo] = Field(description="Every permission, sorted by name.")


class AuditEntryResponse(BaseModel):
    """One recorded privileged action."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "entry_id": "9f2c...",
                    "at": "2026-09-10T12:00:00Z",
                    "action": "roles.assigned",
                    "actor_id": "acct_1111...",
                    "target_id": "acct_2222...",
                    "detail": "roles member, auditor",
                }
            ]
        }
    )

    entry_id: str = Field(description="Identifies this entry.")
    at: datetime = Field(description="When it happened.")
    action: AuditAction = Field(description="What was done.")
    actor_id: str = Field(
        description="Who did it. `break-glass` when the deployment's admin token was used."
    )
    target_id: str | None = Field(default=None, description="Which account it was done to.")
    detail: str = Field(description="A short summary. Never contains a secret.")


class AuditListResponse(BaseModel):
    """Recent privileged actions, newest first."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"entries": []}]})

    entries: list[AuditEntryResponse] = Field(description="Newest first.")


class ProfileSummary(BaseModel):
    """Another account's profile, as an administrator sees it.

    Names and states only. Which services somebody has connected and whether each works;
    never what is behind them.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"name": "personal", "connections": [{"service": "spotify", "status": "active"}]}
            ]
        }
    )

    name: str = Field(description="The profile's name.")
    connections: list[dict[str, str]] = Field(
        description="Each connection's service, kind and status. Never a credential."
    )
