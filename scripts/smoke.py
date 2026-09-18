"""End-to-end smoke test against a running keyring.

The test suite proves each behaviour in isolation. This proves the whole thing works when
it is actually running: a real process, real HTTP, real files on disk.

    make install
    export KEYRING_MASTER_KEY="$(python -c \
      'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
    export KEYRING_ADMIN_TOKEN=break-glass-token-for-smoke-test
    export KEYRING_PORT=8099
    export KEYRING_SERVICE_TOKENS='{"example-tool":"svc-token-for-the-smoke-test-0123456789"}'
    uv run keyring-api &
    python scripts/smoke.py

It checks the properties that would be worst to get wrong: that a stored key never appears
in a read-back but does reach a service acting for its owner; that both credentials are
required to get it; that one account cannot see another's profile; that 403 comes before
404; that self-promotion is refused and changes nothing; that the last owner cannot delete
themselves and the refusal destroys nothing; and that the audit log names opaque ids rather
than people.

Exits non-zero on any failure, so it is usable as a deployment check.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

BASE = "http://127.0.0.1:8099"
ADMIN = "break-glass-token-for-smoke-test"
SERVICE = "svc-token-for-the-smoke-test-0123456789"
OWNER_PASSWORD = "correct horse battery staple"  # noqa: S105 -- a test fixture
FAMILY_PASSWORD = "another long passphrase"  # noqa: S105 -- a test fixture
API_KEY = "THE-SECRET-KEY"

failures: list[str] = []


def call(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Make one request. Returns the status and the decoded body."""
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        request.add_header(name, value)

    try:
        with urllib.request.urlopen(request) as response:
            raw = response.read().decode()
            return response.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as error:
        raw = error.read().decode()
        return error.code, (json.loads(raw) if raw else {})


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def check(label: str, got: object, want: object) -> None:
    """Record one assertion, printing it either way."""
    passed = got == want
    print(f"  [{'ok  ' if passed else 'FAIL'}] {label}: {got!r} (want {want!r})")
    if not passed:
        failures.append(label)


def onboard(email: str, password: str, inviter: str) -> tuple[str, str]:
    """Invite, redeem and log in. Returns the session token and the account id."""
    _, invite = call("POST", "/v1/admin/invites", {"email": email}, bearer(inviter))
    call("POST", "/v1/auth/invites/redeem", {"token": invite["token"], "password": password})
    _, login = call("POST", "/v1/auth/login", {"email": email, "password": password})
    token: str = login["token"]
    _, me = call("GET", "/v1/auth/me", None, bearer(token))
    account_id: str = me["account_id"]
    return token, account_id


def main() -> int:
    print("\n== onboarding ==")
    owner, owner_id = onboard("owner@example.com", OWNER_PASSWORD, ADMIN)
    _, account = call("GET", f"/v1/admin/accounts/{owner_id}", None, bearer(owner))
    check("the first account is the owner", account["roles"], ["owner"])

    print("\n== credentials ==")
    call("POST", "/v1/profiles", {"name": "personal"}, bearer(owner))
    call(
        "PUT",
        "/v1/profiles/personal/connections/tmdb/api-key",
        {"api_key": API_KEY},
        bearer(owner),
    )
    _, profile = call("GET", "/v1/profiles/personal", None, bearer(owner))
    check("the key is absent from the read-back", API_KEY in json.dumps(profile), False)

    _, minted = call("POST", "/v1/auth/service-token", {"audience": "example-tool"}, bearer(owner))
    both = {**bearer(SERVICE), "X-Keyring-User-Token": minted["token"]}
    _, resolved = call("GET", "/v1/internal/credentials/personal/tmdb", None, both)
    check(
        "a service acting for its owner gets it",
        resolved.get("headers"),
        {"Authorization": f"Bearer {API_KEY}"},
    )
    check(
        "the service token alone is refused",
        call("GET", "/v1/internal/credentials/personal/tmdb", None, bearer(SERVICE))[0],
        401,
    )
    check(
        "the user token alone is refused",
        call(
            "GET",
            "/v1/internal/credentials/personal/tmdb",
            None,
            {"X-Keyring-User-Token": minted["token"]},
        )[0],
        401,
    )

    print("\n== rbac ==")
    family, family_id = onboard("family@example.com", FAMILY_PASSWORD, owner)
    check(
        "a member cannot list accounts",
        call("GET", "/v1/admin/accounts", None, bearer(family))[0],
        403,
    )
    check(
        "a member cannot see another's profile",
        call("GET", "/v1/profiles/personal", None, bearer(family))[0],
        404,
    )
    check(
        "no permission, unknown account",
        call("GET", "/v1/admin/accounts/acct_nope", None, bearer(family))[0],
        403,
    )
    check(
        "has permission, unknown account",
        call("GET", "/v1/admin/accounts/acct_nope", None, bearer(owner))[0],
        404,
    )

    call(
        "POST",
        "/v1/admin/roles",
        {
            "name": "assigner",
            "description": "assigns roles",
            "permissions": ["roles:assign", "roles:read", "accounts:read"],
        },
        bearer(owner),
    )
    call(
        "PUT",
        f"/v1/admin/accounts/{family_id}/roles",
        {"roles": ["member", "assigner"]},
        bearer(owner),
    )
    status, _ = call(
        "PUT", f"/v1/admin/accounts/{family_id}/roles", {"roles": ["owner"]}, bearer(family)
    )
    check("self-promotion to owner is refused", status, 403)
    _, after = call("GET", f"/v1/admin/accounts/{family_id}", None, bearer(owner))
    check("the attempt changed nothing", after["roles"], ["member", "assigner"])

    print("\n== the last owner ==")
    check(
        "the last owner cannot delete themselves",
        call("DELETE", f"/v1/admin/accounts/{owner_id}", None, bearer(owner))[0],
        409,
    )
    _, survived = call("GET", "/v1/profiles/personal", None, bearer(owner))
    check("the refusal destroyed nothing", len(survived["connections"]), 1)

    print("\n== audit ==")
    _, audit = call("GET", "/v1/admin/audit?limit=8", None, bearer(owner))
    for entry in audit["entries"]:
        actor = entry["actor_id"][:20]
        target = str(entry["target_id"])[:20]
        print(f"  {entry['action']:<26} actor={actor:<22} target={target:<22} {entry['detail']}")
    check("no address reaches the log", "@example.com" in json.dumps(audit), False)
    check(
        "a negative page size is refused",
        call("GET", "/v1/admin/audit?limit=-1", None, bearer(owner))[0],
        422,
    )

    print()
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        return 1
    print("ALL SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
