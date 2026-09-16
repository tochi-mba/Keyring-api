"""Liveness and readiness.

The two routes that do not require authentication, because a load balancer cannot hold a
session. Everything they report is therefore written on the assumption that a stranger is
reading it: counts and yes/no answers, never an address, a profile name, or a path.

The split matters. ``/healthy`` says only that this process is running, and it must never
fail: an orchestrator restarts a container whose liveness check fails, so reporting
keyring's own dependencies there would have it restart a working process during an outage
of something else. ``/ready`` is where the vault, the accounts and the stored connections
are reported, one line each, so that an operator is told which of them is wrong.
"""

from __future__ import annotations

from fastapi import APIRouter, Response, status

from keyring_api.api.dependencies import ContainerDep
from keyring_api.api.schemas.health import CheckResult, HealthResponse, LivenessResponse
from keyring_api.core.version import service_version

router = APIRouter(tags=["health"])

STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"


@router.get(
    "/healthy",
    operation_id="get_health",
    summary="Check that the service process is running",
    description=(
        "Liveness only. It reports nothing about the vault, the database or anything "
        "else, because a liveness check that failed when a dependency did would have an "
        "orchestrator restart a healthy process during somebody else's outage. Needs no "
        "session. Use `check_readiness` to find out whether requests will actually work."
    ),
    response_model=LivenessResponse,
)
async def get_health(container: ContainerDep) -> LivenessResponse:
    """Report that this process is alive, whatever else is not."""
    return LivenessResponse(
        status="alive",
        version=service_version(),
        environment=container.settings.environment,
        uptime_seconds=round(container.uptime_seconds, 3),
    )


@router.get(
    "/ready",
    operation_id="check_readiness",
    summary="Check that every dependency this service needs is usable",
    description=(
        "Reports the account store, the credential vault, and whether any stored "
        "connection has stopped working. Answers 200 when everything is usable and 503 "
        "when any check fails, with the same body shape either way. Needs no session, and "
        "it reports no personal data -- counts and yes/no answers only."
    ),
    response_model=HealthResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthResponse}},
)
async def check_readiness(container: ContainerDep, response: Response) -> HealthResponse:
    """Check every dependency and summarize."""
    sealed = container.secrets.is_sealed
    connections = await _connection_health(container)

    checks = {
        "accounts": CheckResult(
            status=STATUS_OK,
            # Deliberately just a count of accounts. `rate_limited_callers` used to be
            # here and was an enumeration oracle: the per-recipient mail cap only creates
            # a limiter key for an address that HAS an account, so a stranger could
            # request a reset and watch this number to learn whether it went up by one
            # or by two. The identical response body was undone by a counter on an
            # unauthenticated endpoint.
            detail={"accounts": await container.accounts.count()},
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
        "connections": CheckResult(
            # Degraded when any stored credential has stopped working. This is where
            # the check earns its place: an expired Spotify grant shows up here, with
            # the fix, instead of as a job failing for no visible reason hours later.
            status=STATUS_DEGRADED if connections["unusable"] else STATUS_OK,
            detail=connections,
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


async def _connection_health(container: ContainerDep) -> dict[str, object]:
    """Count connections that can and cannot currently produce a credential.

    Counts only. This endpoint is unauthenticated, so it must not name a person, a
    profile, or which service somebody has connected -- only how many are unwell.
    """
    now = container.clock.now()
    total = 0
    unusable = 0

    for profile in await container.profiles.all_profiles():
        for connection in profile.connections:
            total += 1
            if not connection.is_usable(now=now):
                unusable += 1

    return {"total": total, "unusable": unusable}
