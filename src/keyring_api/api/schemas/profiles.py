"""Wire models for profiles, connections and credential entry.

The rule that shapes every model here: **values go in, status comes out.** There is no
response model in this module with a field that could hold a secret, and a contract test
walks the generated OpenAPI schema asserting that -- so a field added later is caught by
the suite rather than by whoever is reading the logs.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from keyring_api.domain.profiles import ConnectionStatus, CredentialKind


class CreateProfileRequest(BaseModel):
    """Create a named credential set."""

    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [{"name": "personal"}]}
    )

    name: str = Field(
        max_length=64,
        description=(
            "Lowercase letters, digits, dot, dash and underscore. Scoped to your "
            "account, so 'personal' being taken by someone else does not affect you."
        ),
    )


class ConnectionResponse(BaseModel):
    """One service a profile is connected to.

    Status only. There is no field here that holds a credential, and no endpoint in this
    API returns one -- a stored secret leaves this service exactly once, as an
    Authorization header attached by the service that asked for it.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "service": "spotify",
                    "kind": "oauth2_authorization_code",
                    "status": "active",
                    "expires_at": "2026-09-10T13:00:00Z",
                    "scopes": ["user-read-private"],
                    "stores_totp_seed": False,
                    "last_error": None,
                }
            ]
        }
    )

    service: str = Field(description="Which service this connects to.")
    kind: CredentialKind = Field(description="What sort of credential is stored.")
    status: ConnectionStatus = Field(
        description=(
            "'active' means usable now or refreshable unattended. 'pending' means an "
            "authorization was started and never finished. 'expired' and 'revoked' both "
            "need the connection to be authorised again."
        )
    )
    created_at: datetime = Field(description="When this connection was first made.")
    updated_at: datetime = Field(description="When it was last stored or refreshed.")
    expires_at: datetime | None = Field(
        default=None,
        description="When the stored credential stops working. Null if it does not expire.",
    )
    scopes: list[str] = Field(
        default_factory=list,
        description="What the provider actually granted, which can be less than was asked.",
    )
    stores_totp_seed: bool = Field(
        default=False,
        description=(
            "Whether a TOTP seed is stored alongside the password. Flagged because it "
            "means the second factor lives in the same place as the first."
        ),
    )
    last_error: str | None = Field(
        default=None,
        description="Why the last refresh failed, if it did. Names the fix, never the credential.",
    )


class ProfileResponse(BaseModel):
    """A credential set and what it is connected to."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "personal",
                    "created_at": "2026-09-01T09:00:00Z",
                    "connections": [
                        {
                            "service": "spotify",
                            "kind": "oauth2_authorization_code",
                            "status": "active",
                        }
                    ],
                }
            ]
        }
    )

    name: str = Field(description="How you address this profile.")
    created_at: datetime = Field(description="When it was created.")
    updated_at: datetime = Field(description="When it or one of its connections last changed.")
    connections: list[ConnectionResponse] = Field(
        default_factory=list, description="Every service this profile is connected to."
    )


class ProfileListResponse(BaseModel):
    """Every profile the calling account owns.

    A list rather than a page: profiles are capped per account, so the response is a
    predictable size -- which matters when an assistant is reading it into a context
    window.
    """

    model_config = ConfigDict(json_schema_extra={"examples": [{"profiles": []}]})

    profiles: list[ProfileResponse] = Field(description="Your profiles, oldest first.")


class PutApiKeyRequest(BaseModel):
    """Store an API key for a service.

    The value is written straight to the encrypted vault and never comes back out. It
    does not appear in any response, and the logging pipeline redacts it by field name.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {"api_key": "sk-...", "header": "Authorization", "template": "Bearer {value}"}
            ]
        },
    )

    api_key: str = Field(min_length=1, max_length=4096, description="The key itself.")
    header: str = Field(
        default="Authorization",
        max_length=64,
        description="Which header to attach it to. Some services want `X-API-Key`.",
    )
    template: str = Field(
        default="Bearer {value}",
        max_length=128,
        description="How the header value is built. `{value}` is the key.",
    )
    in_query: bool = Field(
        default=False,
        description="Set when the service wants the key as a query parameter instead.",
    )
    query_name: str = Field(
        default="api_key", max_length=64, description="Parameter name when `in_query` is set."
    )


class PutPasswordRequest(BaseModel):
    """Store a form login for a site with no API.

    Prefer OAuth wherever a service offers it. A stored password is not revocable by the
    operator -- only by you changing it at the service -- and many services' terms
    forbid a third party holding one at all.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"username": "person@example.com", "password": "..."}]},
    )

    username: str = Field(
        min_length=1, max_length=512, description="What to type in the username field."
    )
    password: str = Field(
        min_length=1, max_length=1024, description="What to type in the password field."
    )
    totp_seed: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "Optional base32 TOTP seed. Storing one puts your second factor in the same "
            "place as your first -- only send it if you have decided that is the trade "
            "you want."
        ),
    )


class AuthorizationResponse(BaseModel):
    """Where to send the person to consent.

    No credential crosses this API during the flow: the person authorises at the
    provider, and the token comes back to keyring server-to-server from the token
    endpoint.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "authorization_url": "https://accounts.example.com/authorize?...",
                    "expires_at": "2026-09-10T12:10:00Z",
                }
            ]
        }
    )

    authorization_url: str = Field(description="Open this in a browser to authorise.")
    expires_at: datetime = Field(description="After this the link stops working; start again.")


class ResolvedCredentialResponse(BaseModel):
    """What a consuming service gets: what to attach, not what is stored.

    Headers and query parameters, ready to use. The refresh token is not here, the
    stored password is not here, and nothing here can be exchanged for them.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "service": "spotify",
                    "headers": {"Authorization": "Bearer BQD..."},
                    "query_params": {},
                    "expires_at": "2026-09-10T13:00:00Z",
                }
            ]
        }
    )

    service: str = Field(description="Which service this credential is for.")
    headers: dict[str, str] = Field(description="Attach these to the outgoing request.")
    query_params: dict[str, str] = Field(description="Add these to the query string.")
    expires_at: datetime | None = Field(
        default=None,
        description="When this particular credential stops working. Ask again after it does.",
    )


class ResolvedFormSecretsResponse(BaseModel):
    """What a browser recipe gets: the values to type into a login form.

    This one *does* carry credential material, unavoidably -- a login form needs the
    password. It is the single endpoint in this API that returns one, it is restricted
    to internal service callers, and it is the reason those callers must present both
    their own token and the end user's.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"service": "somesite", "fields": {"username": "...", "password": "..."}}]
        }
    )

    service: str = Field(description="Which service this login is for.")
    fields: dict[str, str] = Field(
        description="Values to type. Includes a current `totp` code when a seed is stored."
    )


class ServiceTokenResponse(BaseModel):
    """A short-lived signed token another service can verify locally."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"token": "eyJhbGciOi...", "expires_in": 900, "token_type": "Bearer"}]
        }
    )

    token: str = Field(description="Send as `Authorization: Bearer <token>` to that service.")
    token_type: str = Field(description="Always `Bearer`.")
    expires_in: int = Field(description="Seconds until it stops being accepted.")
