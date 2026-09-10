"""Liveness and dependency health.

The one route that does not require authentication, because a load balancer cannot hold
a session. Everything it reports is therefore written on the assumption that a stranger
is reading it: counts and yes/no answers, never an address, a profile name, or a path.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from keyring_api.api.dependencies import ContainerDep
from keyring_api.api.schemas.health import CheckResult, HealthResponse
from keyring_api.core.version import service_version

router = APIRouter(tags=["health"])

STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"


@router.get(
    "/healthy",
    operation_id="get_health",
    summary="Report service health",
    description=(
        "Returns the service version, uptime, and the state of every dependency: the "
        "account store and the credential vault. Responds 200 when everything is usable "
        "and 503 when any check fails, with the same body shape either way. This is the "
        "only endpoint that does not require authentication, and it reports no personal "
        "data -- counts and yes/no answers only."
    ),
    response_model=HealthResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthResponse}},
)
async def get_health(container: ContainerDep, response: Response) -> HealthResponse:
    """Check every dependency and summarize."""
    sealed = container.settings.master_key_bytes() is None

    checks = {
        "accounts": CheckResult(
            status=STATUS_OK,
            detail={
                "accounts": await container.accounts.count(),
                "rate_limited_callers": await container.limiter.tracked_callers(),
            },
        ),
        "vault": CheckResult(
            # A sealed vault is degraded rather than dead: people can still log in and
            # read which connections exist, they just cannot use or add a credential.
            # Reporting it as healthy would hide a misconfiguration until the first
            # credential request failed for no visible reason.
            status=STATUS_DEGRADED if sealed else STATUS_OK,
            detail={
                "sealed": sealed,
                "fix": "set KEYRING_MASTER_KEY" if sealed else None,
            },
        ),
    }

    healthy = all(check.status == STATUS_OK for check in checks.values())
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status=STATUS_OK if healthy else STATUS_DEGRADED,
        version=service_version(),
        environment=container.settings.environment,
        uptime_seconds=round(container.uptime_seconds, 3),
        checks=checks,
    )
