"""Wire models for the authentication endpoints.

Every request body sets ``extra="forbid"``: an invented field is rejected rather than
ignored. On these endpoints in particular, a silently-ignored field is how a caller ends
up believing they sent something they did not.

No response model on this module carries a password, a token hash, or anything derived
from one. The only token that ever appears in a response is the session token minted by
``login``, which the caller has no other way of receiving.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from keyring_api.domain.accounts import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH

PasswordField = Field(
    min_length=MIN_PASSWORD_LENGTH,
    max_length=MAX_PASSWORD_LENGTH,
    description=(
        f"At least {MIN_PASSWORD_LENGTH} characters. There are no composition rules -- "
        "length is the whole policy."
    ),
)


class LoginRequest(BaseModel):
    """Credentials for ``login``."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"email": "person@example.com", "password": "correct horse battery staple"}
            ]
        },
    )

    email: str = Field(max_length=254, description="The address the account was invited at.")
    password: str = Field(
        min_length=1,
        max_length=MAX_PASSWORD_LENGTH,
        description="The account password.",
    )
    """Bounded but not policy-checked.

    Rejecting a *login* for being too short would tell a caller that the stored password
    is longer than what they sent, and would break every account whose password predates
    a raised minimum.
    """


class SessionResponse(BaseModel):
    """A newly opened session.

    ``token`` is the only copy that will ever exist -- the server keeps a hash. It
    cannot be re-read, and losing it means logging in again.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "session_id": "sess_9f2c...",
                    "token": "mS4a...",
                    "expires_at": "2026-09-24T12:00:00Z",
                }
            ]
        }
    )

    session_id: str = Field(description="Identifies this session, for revoking it later.")
    token: str = Field(description="Send as `Authorization: Bearer <token>`. Shown once.")
    expires_at: datetime = Field(description="When this session stops working if unused.")


class AccountResponse(BaseModel):
    """Who the caller is."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "account_id": "acct_9f2c...",
                    "email": "person@example.com",
                    "created_at": "2026-09-01T09:00:00Z",
                }
            ]
        }
    )

    account_id: str = Field(description="Opaque, stable identifier for this account.")
    email: str = Field(description="The address this account logs in with.")
    created_at: datetime = Field(description="When the account was created.")


class RedeemInviteRequest(BaseModel):
    """Turn an invite into an account.

    There is no ``email`` field, deliberately: the address comes from the invite. Taking
    it from the request would let anyone holding one invite claim any address.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"token": "Xf2...", "password": "a long passphrase"}]},
    )

    token: str = Field(max_length=512, description="The invite token you were sent.")
    password: str = PasswordField


class ChangePasswordRequest(BaseModel):
    """Replace a password, having proved the current one is known."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [{"current_password": "the old one", "new_password": "a new passphrase"}]
        },
    )

    current_password: str = Field(
        min_length=1, max_length=MAX_PASSWORD_LENGTH, description="The password in use now."
    )
    new_password: str = PasswordField


class RequestPasswordResetRequest(BaseModel):
    """Ask for a reset link."""

    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [{"email": "person@example.com"}]}
    )

    email: str = Field(max_length=254, description="The address to send a reset link to.")


class RedeemPasswordResetRequest(BaseModel):
    """Set a new password using a reset token."""

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"token": "Xf2...", "password": "a new passphrase"}]},
    )

    token: str = Field(max_length=512, description="The token from the reset link.")
    password: str = PasswordField


class AcknowledgedResponse(BaseModel):
    """A deliberately uninformative acknowledgement.

    Returned by ``request_password_reset`` whether or not the address has an account.
    The whole point is that the two cases are identical, so this model carries no field
    that could differ between them.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"detail": "if that address has an account, a reset link has been sent"}]
        }
    )

    detail: str = Field(description="A fixed message. Carries no information about the account.")


class RevokedResponse(BaseModel):
    """How many sessions a revocation ended."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"revoked": 3}]})

    revoked: int = Field(description="Number of sessions that were ended.")


class IssueInviteRequest(BaseModel):
    """Administrative: mint an invite for an address."""

    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [{"email": "newcomer@example.com"}]}
    )

    email: str = Field(max_length=254, description="Who the invite is for.")


class InviteResponse(BaseModel):
    """A freshly minted invite.

    ``token`` is present **only when this deployment cannot send mail**. With delivery
    configured the invite goes to the recipient and the token is omitted here, so it
    exists in exactly one place rather than in an inbox and an HTTP response both.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "grant_id": "grant_9f2c...",
                    "expires_at": "2026-09-17T12:00:00Z",
                    "delivered": True,
                    "token": None,
                }
            ]
        }
    )

    grant_id: str = Field(description="Identifies this invite in the logs.")
    expires_at: datetime = Field(description="After this, the invite stops working.")
    delivered: bool = Field(
        description="Whether the invite was emailed. When false, deliver `token` yourself."
    )
    token: str | None = Field(
        default=None,
        description=(
            "The invite token, present only when this deployment sends no mail. Shown "
            "once and never recoverable."
        ),
    )


class ServiceTokenRequest(BaseModel):
    """Ask for a token scoped to one other service."""

    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [{"audience": "example-tool"}]}
    )

    audience: str = Field(
        min_length=1,
        max_length=128,
        description=(
            "Which service the token is for. It will be rejected by any other service, "
            "so a token handed to one cannot be replayed at another."
        ),
    )
