"""The health payloads.

Two of them, because liveness and readiness answer different questions for different
readers. Liveness is for an orchestrator deciding whether to restart this process;
readiness is for a load balancer deciding whether to send it traffic, and for a human
reading it at three in the morning.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class LivenessResponse(BaseModel):
    """What ``GET /healthy`` returns.

    Deliberately says nothing about dependencies. An orchestrator restarts a container
    whose liveness check fails, so a liveness endpoint that failed when keyring did would
    have healthy processes restarted, repeatedly, during somebody else's outage.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "status": "alive",
                    "version": "0.1.0",
                    "environment": "local",
                    "uptime_seconds": 12.34,
                }
            ]
        }
    )

    status: str = Field(description="Always 'alive'. This endpoint does no I/O and never fails.")
    version: str = Field(description="Running version of the service.")
    environment: str = Field(description="Which deployment this is.")
    uptime_seconds: float = Field(description="Seconds since the process started serving.")


class CheckResult(BaseModel):
    """One dependency's contribution to readiness."""

    status: str = Field(description="'ok' or 'degraded'.")
    detail: dict[str, object] = Field(
        default_factory=dict, description="Check-specific facts, such as whether the vault is open."
    )


class HealthResponse(BaseModel):
    """What ``GET /ready`` returns.

    Reported at both levels deliberately: the top-level status is what a load balancer
    reads, the per-check detail is what a human reads at three in the morning.

    Nothing here is sensitive. This endpoint requires no authentication, so every field on
    it is written on the assumption that a stranger can read it -- counts and yes/no
    answers, never an address, a name, or a path.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "status": "ok",
                    "version": "0.1.0",
                    "environment": "local",
                    "uptime_seconds": 12.34,
                    "checks": {
                        "accounts": {"status": "ok", "detail": {"accounts": 3}},
                        "vault": {"status": "ok", "detail": {"sealed": False}},
                    },
                }
            ]
        }
    )

    status: str = Field(description="'ok' when every check passed, otherwise 'degraded'.")
    version: str = Field(description="Running version of the service.")
    environment: str = Field(description="Which deployment this is.")
    uptime_seconds: float = Field(description="Seconds since the process started serving.")
    checks: dict[str, CheckResult] = Field(description="Per-dependency results.")
