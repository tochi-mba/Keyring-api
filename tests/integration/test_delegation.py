"""Token exchange binds the caller, account, audience and lifetime before minting."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from keyring_api.audit.log import AuditAction
from keyring_api.domain.accounts import AccountStatus
from keyring_api.domain.errors import ProfileNotFoundError
from keyring_api.profiles.sql_delegations import SqlDelegationStore
from tests.conftest import (
    SERVICE_NAME,
    SERVICE_TOKEN,
    account_id_of,
    auth,
    build_settings,
    container_of,
    make_profile,
    onboard,
    put_api_key,
    service_call,
    service_token,
)
from tests.fakes.clock import FakeClock
from tests.integration.test_restart import running

if TYPE_CHECKING:
    from pathlib import Path

    from fastapi import FastAPI
    from httpx import AsyncClient


async def test_exchange_is_same_subject_exact_audience_and_short_lived(
    client: AsyncClient, app: FastAPI
) -> None:
    container = container_of(app)
    container.settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    session = await onboard(client)
    user = await service_token(client, session)
    response = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "ttl_seconds": 300},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert 0 < body["expires_in"] <= 300
    assert body["token_type"] == "Bearer"
    assert container.signer.verify(body["token"], audience="user.home") == container.signer.verify(
        user, audience=SERVICE_NAME
    )
    assert body["expires_at"]
    refused = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.health"},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
    )
    assert refused.status_code == 403


async def test_offline_grant_revocation_stops_exchange(client: AsyncClient, app: FastAPI) -> None:
    container_of(app).settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    session = await onboard(client)
    await make_profile(client, session)
    created = await client.post(
        "/v1/profiles/personal/grants",
        json={"service": SERVICE_NAME, "audiences": ["user.home"], "ttl_seconds": 3600},
        headers=auth(session),
    )
    assert created.status_code == 201, created.text
    grant_id = created.json()["grant_id"]
    profile = await client.get("/v1/profiles/personal", headers=auth(session))
    assert profile.json()["grants"] == [created.json()]
    listed = await client.get("/v1/profiles/personal/grants", headers=auth(session))
    assert listed.json() == {"grants": [created.json()]}
    exchanged = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "grant_id": grant_id},
        headers=auth(SERVICE_TOKEN),
    )
    assert exchanged.status_code == 200, exchanged.text
    revoked = await client.delete(f"/v1/profiles/personal/grants/{grant_id}", headers=auth(session))
    assert revoked.status_code == 204
    refused = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "grant_id": grant_id},
        headers=auth(SERVICE_TOKEN),
    )
    assert refused.status_code == 401


@pytest.mark.parametrize("user_audience", ["unrelated", "downstream-tool.other"])
async def test_exchange_does_not_accept_tokens_for_a_different_audience(
    client: AsyncClient, app: FastAPI, user_audience: str
) -> None:
    container_of(app).settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    session = await onboard(client)
    user = await service_token(client, session, user_audience)
    response = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home"},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
    )
    assert response.status_code == 401


@pytest.mark.parametrize("proof", ["missing", "both", "bad_service", "bad_user"])
async def test_exchange_requires_exactly_one_delegation_and_a_valid_service(
    client: AsyncClient, app: FastAPI, proof: str
) -> None:
    container_of(app).settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    session = await onboard(client)
    user = await service_token(client, session)
    headers = auth(SERVICE_TOKEN)
    body = {"audience": "user.home"}
    if proof == "both":
        headers["X-Keyring-User-Token"] = user
        body["grant_id"] = "guessed"
    elif proof == "bad_service":
        headers = service_call(service_token_value="bad", user_token=user)
    elif proof == "bad_user":
        headers["X-Keyring-User-Token"] = "bad"
    result = await client.post("/v1/internal/token-exchange", json=body, headers=headers)
    assert result.status_code == 401


async def test_grants_are_isolated_by_account_and_profile(
    client: AsyncClient, app: FastAPI
) -> None:
    container_of(app).settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    alice = await onboard(client)
    bob = await onboard(client, "bob@example.com")
    await make_profile(client, alice, "private")
    await make_profile(client, alice)
    await make_profile(client, bob)
    body = {"service": SERVICE_NAME, "audiences": ["user.home"]}
    created = await client.post("/v1/profiles/personal/grants", json=body, headers=auth(alice))
    grant_id = created.json()["grant_id"]
    for verb in ("get", "post", "delete"):
        path = "/v1/profiles/private/grants"
        if verb == "delete":
            path += f"/{grant_id}"
        response = await client.request(
            verb, path, json=body if verb == "post" else None, headers=auth(bob)
        )
        assert response.status_code == 404
    response = await client.delete(f"/v1/profiles/personal/grants/{grant_id}", headers=auth(bob))
    assert response.status_code == 404
    response = await client.delete(f"/v1/profiles/private/grants/{grant_id}", headers=auth(alice))
    assert response.status_code == 404
    response = await client.get("/v1/profiles/personal/grants", headers=auth(bob))
    assert response.json() == {"grants": []}


async def test_offline_grant_needs_its_service_and_consented_audience(
    client: AsyncClient, app: FastAPI
) -> None:
    container = container_of(app)
    container.settings.exchange_audiences = {SERVICE_NAME: ("user.home", "user.health")}
    session = await onboard(client)
    await make_profile(client, session)
    created = await client.post(
        "/v1/profiles/personal/grants",
        json={"service": SERVICE_NAME, "audiences": ["user.home"]},
        headers=auth(session),
    )
    grant_id = created.json()["grant_id"]
    for audience, handle in (("user.health", grant_id), ("user.home", "guessed")):
        response = await client.post(
            "/v1/internal/token-exchange",
            json={"audience": audience, "grant_id": handle},
            headers=auth(SERVICE_TOKEN),
        )
        assert response.status_code == 401
    assert await SqlDelegationStore(container.database).for_exchange(grant_id, "other") is None
    response = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "grant_id": grant_id},
    )
    assert response.status_code == 401
    container.settings.exchange_audiences = {}
    response = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "grant_id": grant_id},
        headers=auth(SERVICE_TOKEN),
    )
    assert response.status_code == 403


async def test_expiry_caps_foreground_and_offline_tokens_without_sleeping(
    client: AsyncClient, app: FastAPI
) -> None:
    container = container_of(app)
    container.settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    container.settings.offline_grant_max_ttl_seconds = 30
    session = await onboard(client)
    await make_profile(client, session)
    account_id = await account_id_of(client, session)
    clock = FakeClock()
    container.delegation_service._clock = clock
    container.signer._clock = clock
    user = container.signer.issue(account_id=account_id, audience=SERVICE_NAME, ttl_seconds=10)
    response = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "ttl_seconds": 86400},
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=user),
    )
    assert response.status_code == 200
    assert response.json()["expires_in"] == 10
    grant = await client.post(
        "/v1/profiles/personal/grants",
        json={"service": SERVICE_NAME, "audiences": ["user.home"], "ttl_seconds": 60},
        headers=auth(session),
    )
    grant_id = grant.json()["grant_id"]
    response = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "grant_id": grant_id},
        headers=auth(SERVICE_TOKEN),
    )
    assert response.json()["expires_in"] == 30
    clock.advance(30)
    response = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "grant_id": grant_id},
        headers=auth(SERVICE_TOKEN),
    )
    assert response.status_code == 401


@pytest.mark.parametrize("disabled", [True, False])
async def test_disabled_or_absent_accounts_cannot_exchange_or_read_metadata(
    client: AsyncClient, app: FastAPI, disabled: bool
) -> None:
    container = container_of(app)
    container.settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    session = await onboard(client)
    account_id = await account_id_of(client, session)
    if disabled:
        account = await container.accounts.get(account_id)
        await container.accounts.save(replace(account, status=AccountStatus.DISABLED))
    else:
        account_id = "acct_absent"
    user = container.signer.issue(account_id=account_id, audience=SERVICE_NAME, ttl_seconds=300)
    headers = service_call(service_token_value=SERVICE_TOKEN, user_token=user)
    response = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home"},
        headers=headers,
    )
    assert response.status_code == 401
    response = await client.get("/v1/internal/profiles/personal", headers=headers)
    assert response.status_code == 401


async def test_grant_creation_checks_consent_allowlist_and_storage_cap(
    client: AsyncClient, app: FastAPI
) -> None:
    container = container_of(app)
    container.settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    container.settings.max_offline_grants_per_profile = 1
    session = await onboard(client)
    await make_profile(client, session)
    rejected = await client.post(
        "/v1/profiles/personal/grants",
        json={"service": SERVICE_NAME, "audiences": ["user.health"]},
        headers=auth(session),
    )
    assert rejected.status_code == 403
    first = await client.post(
        "/v1/profiles/personal/grants",
        json={"service": SERVICE_NAME, "audiences": ["user.home", "user.home"]},
        headers=auth(session),
    )
    assert first.status_code == 201
    capped = await client.post(
        "/v1/profiles/personal/grants",
        json={"service": SERVICE_NAME, "audiences": ["user.home"]},
        headers=auth(session),
    )
    assert capped.status_code == 429
    revoked = await client.delete(
        f"/v1/profiles/personal/grants/{first.json()['grant_id']}", headers=auth(session)
    )
    assert revoked.status_code == 204
    replacement = await client.post(
        "/v1/profiles/personal/grants",
        json={"service": SERVICE_NAME, "audiences": ["user.home"]},
        headers=auth(session),
    )
    assert replacement.status_code == 201
    grants = await container.delegation_service.list(
        await account_id_of(client, session), "personal"
    )
    assert grants[0].audiences == ("user.home",)
    await client.delete("/v1/profiles/personal", headers=auth(session))
    store = SqlDelegationStore(container.database)
    assert await store.for_exchange(grants[0].grant_id, SERVICE_NAME) is None
    with pytest.raises(ProfileNotFoundError):
        await store.add(grants[0], cap=100, now=grants[0].created_at)


async def test_service_metadata_is_account_bound_and_contains_no_secret(
    client: AsyncClient, app: FastAPI
) -> None:
    alice = await onboard(client)
    bob = await onboard(client, "bob@example.com")
    await make_profile(client, alice)
    await put_api_key(client, alice, key="never-include-this-in-metadata")
    alice_jwt = await service_token(client, alice)
    response = await client.get(
        "/v1/internal/profiles/personal",
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=alice_jwt),
    )
    assert response.status_code == 200
    assert response.json()["connections"][0]["status"] == "active"
    assert "never-include-this-in-metadata" not in response.text
    bob_jwt = await service_token(client, bob)
    response = await client.get(
        "/v1/internal/profiles/personal",
        headers=service_call(service_token_value=SERVICE_TOKEN, user_token=bob_jwt),
    )
    assert response.status_code == 404
    assert container_of(app).settings.exchange_audiences == {}


async def test_grant_and_revocation_survive_restart_and_logout(tmp_path: Path) -> None:
    settings = build_settings(tmp_path, exchange_audiences={SERVICE_NAME: ["user.home"]})
    async with running(settings) as first:
        session = await onboard(first)
        await make_profile(first, session)
        response = await first.post(
            "/v1/profiles/personal/grants",
            json={"service": SERVICE_NAME, "audiences": ["user.home"]},
            headers=auth(session),
        )
        grant_id = response.json()["grant_id"]
        await first.post("/v1/auth/logout", headers=auth(session))
    async with running(settings) as second:
        response = await second.post(
            "/v1/internal/token-exchange",
            json={"audience": "user.home", "grant_id": grant_id},
            headers=auth(SERVICE_TOKEN),
        )
        assert response.status_code == 200


async def test_audit_records_exchange_and_grant_lifecycle_without_secrets(
    client: AsyncClient, app: FastAPI
) -> None:
    container = container_of(app)
    container.settings.exchange_audiences = {SERVICE_NAME: ("user.home",)}
    session = await onboard(client)
    await make_profile(client, session)
    grant = await client.post(
        "/v1/profiles/personal/grants",
        json={"service": SERVICE_NAME, "audiences": ["user.home"]},
        headers=auth(session),
    )
    grant_id = grant.json()["grant_id"]
    exchanged = await client.post(
        "/v1/internal/token-exchange",
        json={"audience": "user.home", "grant_id": grant_id},
        headers=auth(SERVICE_TOKEN),
    )
    for _ in range(2):
        response = await client.delete(
            f"/v1/profiles/personal/grants/{grant_id}", headers=auth(session)
        )
        assert response.status_code == 204
    records = await container.audit.recent()
    actions = [entry.action for entry in records]
    assert AuditAction.TOKEN_EXCHANGED in actions
    assert AuditAction.DELEGATION_CREATED in actions
    assert AuditAction.DELEGATION_REVOKED in actions
    details = repr(records)
    assert grant_id in details
    for secret in (session, SERVICE_TOKEN, exchanged.json()["token"], "person@example.com"):
        assert secret not in details
