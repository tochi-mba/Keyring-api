"""A service records standing consent only for itself, and only while the person is present."""

from __future__ import annotations

from typing import TYPE_CHECKING

from keyring_api.audit.log import AuditAction
from tests.conftest import (
    SERVICE_NAME,
    SERVICE_TOKEN,
    auth,
    container_of,
    make_profile,
    onboard,
    service_call,
    service_token,
)

if TYPE_CHECKING:
    from fastapi import FastAPI
    from httpx import AsyncClient

GRANTS = "/v1/internal/profiles/personal/grants"


async def _present(client: AsyncClient, app: FastAPI) -> tuple[str, str]:
    """A person with a profile, and the user token the calling service holds for them."""
    container_of(app).settings.exchange_audiences = {
        SERVICE_NAME: (SERVICE_NAME, "user.home"),
        "other-tool": ("user.home",),
    }
    session = await onboard(client)
    await make_profile(client, session)
    return session, await service_token(client, session)


async def test_a_service_records_a_grant_for_itself_that_the_person_sees_and_it_can_exchange(
    client: AsyncClient, app: FastAPI
) -> None:
    session, user = await _present(client, app)
    created = await client.post(
        GRANTS,
        json={"audiences": [SERVICE_NAME, "user.home"], "ttl_seconds": 3600},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
    )
    assert created.status_code == 201, created.text
    grant = created.json()
    assert grant["service"] == SERVICE_NAME
    assert grant["audiences"] == sorted([SERVICE_NAME, "user.home"])
    listed = await client.get("/v1/profiles/personal/grants", headers=auth(session))
    assert listed.json() == {"grants": [grant]}
    # The grant mints for the service's own audience, which is how a woken job acts as the
    # person for the service that holds it, with nobody present.
    exchanged = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": SERVICE_NAME, "grant_id": grant["grant_id"]},
        headers=auth(SERVICE_TOKEN),
    )
    assert exchanged.status_code == 200, exchanged.text
    signer = container_of(app).signer
    assert signer.verify(exchanged.json()["token"], audience=SERVICE_NAME) == signer.verify(
        user, audience=SERVICE_NAME
    )


async def test_audiences_outside_the_service_allowlist_are_refused(
    client: AsyncClient, app: FastAPI
) -> None:
    _, user = await _present(client, app)
    refused = await client.post(
        GRANTS,
        json={"audiences": ["user.health"]},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
    )
    assert refused.status_code == 403


async def test_the_lifetime_is_capped_by_the_operator_limit(
    client: AsyncClient, app: FastAPI
) -> None:
    _, user = await _present(client, app)
    container_of(app).settings.offline_grant_max_ttl_seconds = 600
    created = await client.post(
        GRANTS,
        json={"audiences": ["user.home"], "ttl_seconds": 86400},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
    )
    body = created.json()
    from datetime import datetime

    lifetime = datetime.fromisoformat(body["expires_at"]) - datetime.fromisoformat(
        body["created_at"]
    )
    assert lifetime.total_seconds() == 600


async def test_a_grant_needs_the_service_credential_and_a_user_token_bound_to_it(
    client: AsyncClient, app: FastAPI
) -> None:
    session, user = await _present(client, app)
    no_user = await client.post(
        GRANTS, json={"audiences": ["user.home"]}, headers=auth(SERVICE_TOKEN)
    )
    assert no_user.status_code == 401
    no_service = await client.post(
        GRANTS,
        json={"audiences": ["user.home"]},
        headers=service_call(
            service_token_value="not-a-service-token-0123456789abcdef", user_token=user
        ),
    )
    assert no_service.status_code == 401
    elsewhere = await service_token(client, session, audience="unrelated")
    wrong_audience = await client.post(
        GRANTS,
        json={"audiences": ["user.home"]},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=elsewhere),
    )
    assert wrong_audience.status_code == 401


async def test_the_body_cannot_name_another_service_or_account(
    client: AsyncClient, app: FastAPI
) -> None:
    _, user = await _present(client, app)
    for extra in ({"service": "other-tool"}, {"account_id": "acct_someone"}):
        refused = await client.post(
            GRANTS,
            json={"audiences": ["user.home"], **extra},
            headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
        )
        assert refused.status_code == 422


async def test_a_missing_profile_is_404(client: AsyncClient, app: FastAPI) -> None:
    _, user = await _present(client, app)
    missing = await client.post(
        "/v1/internal/profiles/work/grants",
        json={"audiences": ["user.home"]},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
    )
    assert missing.status_code == 404


async def test_a_service_revokes_only_grants_it_holds(client: AsyncClient, app: FastAPI) -> None:
    session, user = await _present(client, app)
    calls = service_call(service_token_value=SERVICE_TOKEN, user_token=user)
    mine = (await client.post(GRANTS, json={"audiences": ["user.home"]}, headers=calls)).json()
    theirs = (
        await client.post(
            "/v1/profiles/personal/grants",
            json={"service": "other-tool", "audiences": ["user.home"]},
            headers=auth(session),
        )
    ).json()
    foreign = await client.delete(f"{GRANTS}/{theirs['grant_id']}", headers=calls)
    missing = await client.delete(f"{GRANTS}/dgt_nothing", headers=calls)
    assert foreign.status_code == missing.status_code == 404
    assert foreign.json()["detail"] == missing.json()["detail"]
    revoked = await client.delete(f"{GRANTS}/{mine['grant_id']}", headers=calls)
    assert revoked.status_code == 204
    refused = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "grant_id": mine["grant_id"]},
        headers=auth(SERVICE_TOKEN),
    )
    assert refused.status_code == 401
    listed = (await client.get("/v1/profiles/personal/grants", headers=auth(session))).json()
    by_id = {grant["grant_id"]: grant for grant in listed["grants"]}
    assert by_id[mine["grant_id"]]["revoked_at"] is not None
    assert by_id[theirs["grant_id"]]["revoked_at"] is None


async def test_the_audit_names_the_service_and_never_a_secret(
    client: AsyncClient, app: FastAPI
) -> None:
    session, user = await _present(client, app)
    calls = service_call(service_token_value=SERVICE_TOKEN, user_token=user)
    grant = (await client.post(GRANTS, json={"audiences": ["user.home"]}, headers=calls)).json()
    await client.delete(f"{GRANTS}/{grant['grant_id']}", headers=calls)
    records = await container_of(app).audit.recent()
    created = [r for r in records if r.action is AuditAction.DELEGATION_CREATED]
    revoked = [r for r in records if r.action is AuditAction.DELEGATION_REVOKED]
    assert f"created by {SERVICE_NAME}" in repr(created)
    assert f"revoked by {SERVICE_NAME}" in repr(revoked)
    details = repr(records)
    for secret in (session, user, SERVICE_TOKEN):
        assert secret not in details
