"""Wire contracts for explicit, revocable delegation."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

Audience = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
]


class ExchangeRequest(BaseModel):
    """A user JWT in its header or an offline grant, but never both."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"audience": "user.home", "ttl_seconds": 300}]},
    )
    audience: Audience = Field(description="One exact audience in the calling service's allowlist.")
    ttl_seconds: int = Field(
        default=900,
        ge=1,
        le=86400,
        description="Requested lifetime, capped by server and delegation expiry.",
    )
    grant_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Offline grant handle; omit when sending X-Keyring-User-Token.",
    )


class ExchangeResponse(BaseModel):
    """A fresh short-lived token, never a caller token forwarded to another service."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "token": "ey...",
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "expires_at": "2026-09-17T12:00:00Z",
                }
            ]
        }
    )
    token: str = Field(description="Fresh token for the one requested downstream audience.")
    token_type: str = Field(default="Bearer", description="Authorization scheme.")
    expires_in: int = Field(description="Maximum remaining lifetime in seconds.")
    expires_at: datetime = Field(description="Absolute signed-token expiry.")


class CreateGrantRequest(BaseModel):
    """Consent for a service to act after this browser session ends."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"service": "lucy-api", "audiences": ["user.home"], "ttl_seconds": 2592000}
            ]
        },
    )
    service: Audience = Field(
        description="Configured service that must also prove its own credential."
    )
    audiences: list[Audience] = Field(
        min_length=1, max_length=100, description="Exact downstream audiences this grant permits."
    )
    ttl_seconds: int = Field(
        default=2592000,
        ge=1,
        le=31536000,
        description="Requested lifetime, capped by the operator's offline grant limit.",
    )


class GrantResponse(BaseModel):
    """Inspectable consent metadata; the handle alone carries no authority."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "examples": [
                {
                    "grant_id": "dgt_...",
                    "profile": "personal",
                    "service": "lucy-api",
                    "audiences": ["user.home"],
                    "created_at": "2026-09-17T12:00:00Z",
                    "expires_at": "2026-10-17T12:00:00Z",
                    "revoked_at": None,
                }
            ]
        },
    )
    grant_id: str = Field(description="Opaque grant handle, bound to its account and service.")
    profile: str = Field(description="Profile under which consent was given.")
    service: str = Field(description="Only this authenticated service may use the grant.")
    audiences: list[str] = Field(description="Downstream audiences explicitly consented to.")
    created_at: datetime = Field(description="When consent was given.")
    expires_at: datetime = Field(description="When exchanges under this grant stop.")
    revoked_at: datetime | None = Field(description="Revocation time, or null while not revoked.")


class GrantListResponse(BaseModel):
    """Grants are bounded per profile and listed with expired or revoked history."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"grants": []}]})
    grants: list[GrantResponse] = Field(description="Every consent recorded for this profile.")
