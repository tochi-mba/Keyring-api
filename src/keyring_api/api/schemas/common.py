"""Wire models shared across endpoints.

Separate from the domain types on purpose: the HTTP contract is public -- its operation
ids become MCP tool names -- and must be able to evolve without dragging the domain with
it.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

PROBLEM_CONTENT_TYPE = "application/problem+json"


class FieldError(BaseModel):
    """One field-level validation failure."""

    location: str = Field(description="Dotted path to the offending field.")
    message: str = Field(description="What is wrong with it.")


class Problem(BaseModel):
    """An error, in the shape RFC 9457 defines.

    Every failure this service produces uses it, so a client -- or a model calling this
    as a tool -- has exactly one error shape to understand.

    ``detail`` is written for the caller and is deliberately vague wherever being
    specific would answer a question the caller has no right to ask: whether an address
    has an account, whether a token ever existed, whether another account owns a name.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "type": "https://keyring.invalid/problems/unauthorized",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "email or password is incorrect",
                    "request_id": "5c1f9f0f7f2f4e6c8a1b2c3d4e5f6a7b",
                }
            ]
        }
    )

    type: str = Field(description="A URI identifying the problem kind.")
    title: str = Field(description="Short, human-readable summary of the problem kind.")
    status: int = Field(description="The HTTP status code.")
    detail: str = Field(description="Explanation specific to this occurrence.")
    request_id: str | None = Field(
        default=None,
        description="Correlates this response with the server logs for the same request.",
    )
    errors: list[FieldError] | None = Field(
        default=None,
        description="Per-field detail, present only for validation failures.",
    )
