# The HTTP contract

One service, one `/openapi.json`, served at `/docs`. Everything under `/v1` requires
authentication; `/healthy` and `/.well-known/jwks.json` do not, for reasons given below.

Route `operation_id`s are **public API** — they become MCP tool names
([docs/mcp.md](mcp.md)) — and a contract test pins the exact set. Renaming one is a
breaking change.

## Errors

Every failure is RFC 9457 `application/problem+json`:

```json
{
  "type": "https://keyring.invalid/problems/unauthorized",
  "title": "Unauthorized",
  "status": 401,
  "detail": "email or password is incorrect",
  "request_id": "5c1f9f0f7f2f4e6c8a1b2c3d4e5f6a7b"
}
```

`request_id` is on every response, in the body and in the `X-Request-ID` header, and it is
what you quote when reporting a 500 — whose detail is deliberately withheld, because
exception text carries paths, hostnames and connection strings.

`detail` is vague wherever being specific would answer a question the caller has no right
to ask. That is not sloppiness:

| Situation | Response |
| --- | --- |
| Unknown address at login | 401, identical to a wrong password |
| Wrong password | 401, identical to an unknown address |
| Reset request for an unknown address | 200, identical to a real one |
| Profile owned by another account | 404, identical to one that never existed |
| Invite unknown / expired / already used | 400, all three identical |

## Endpoints

### Health and keys

| Operation | Route | Notes |
| --- | --- | --- |
| `get_health` | `GET /healthy` | Unauthenticated. Counts and yes/no only. 503 when degraded. |
| `get_jwks` | `GET /.well-known/jwks.json` | Unauthenticated. Public key material only. |

Both are open by necessity: a load balancer cannot hold a session, and a verifier has
nothing to authenticate with yet — which is the problem the JWKS document solves.

### Authentication

| Operation | Route |
| --- | --- |
| `login` | `POST /v1/auth/login` |
| `logout` | `POST /v1/auth/logout` |
| `logout_everywhere` | `POST /v1/auth/logout-everywhere` |
| `get_current_account` | `GET /v1/auth/me` |
| `redeem_invite` | `POST /v1/auth/invites/redeem` |
| `change_password` | `POST /v1/auth/password` |
| `request_password_reset` | `POST /v1/auth/password/reset-request` |
| `redeem_password_reset` | `POST /v1/auth/password/reset` |
| `issue_service_token` | `POST /v1/auth/service-token` |

`login` returns a token shown once — the server keeps only a hash. `change_password` and
`redeem_password_reset` revoke every other session and every outstanding reset link;
`change_password` keeps the calling session, so confirming it worked does not sign you out
of the tab you did it in.

### Profiles and connections

| Operation | Route |
| --- | --- |
| `list_profiles` | `GET /v1/profiles` |
| `create_profile` | `POST /v1/profiles` |
| `get_profile` | `GET /v1/profiles/{name}` |
| `delete_profile` | `DELETE /v1/profiles/{name}` |
| `put_api_key` | `PUT /v1/profiles/{name}/connections/{service}/api-key` |
| `put_password` | `PUT /v1/profiles/{name}/connections/{service}/password` |
| `authorize_connection` | `POST /v1/profiles/{name}/connections/{service}/authorize` |
| `delete_connection` | `DELETE /v1/profiles/{name}/connections/{service}` |
| `complete_authorization` | `GET /v1/oauth/callback` |

Reads report **status only**: which connections exist, what kind, whether active, when they
expire, and why the last refresh failed if it did. There is no endpoint that returns a
stored value, and a contract test walks every response schema to keep it that way.

Profile names are scoped to your account, so "personal" being taken by somebody else does
not affect you.

### Service-to-service

| Operation | Route |
| --- | --- |
| `resolve_credential` | `GET /v1/internal/credentials/{profile}/{service}` |
| `resolve_form_secrets` | `GET /v1/internal/form-secrets/{profile}/{service}` |

Both require two credentials: `Authorization: Bearer <service token>` **and**
`X-Keyring-User-Token: <the user's signed token>`. The account comes from the user's
token; no parameter names an account.

`resolve_form_secrets` is the one endpoint that returns credential material, because a
login form needs a password. That is exactly why it is behind two credentials, and why it
must never be exposed as an assistant tool.

### Administration

Authorised by **permissions**, not by being the operator. Every route names the permission
it needs; an authenticated caller who lacks it gets **403**, and gets the same 403 whether
or not the target exists — permission is always checked first, so the difference cannot be
used to enumerate account ids. See [ADR-0010](adr/0010-rbac.md).

| Operation | Route | Permission |
| --- | --- | --- |
| `list_permissions` | `GET /v1/admin/permissions` | `roles:read` |
| `list_roles` | `GET /v1/admin/roles` | `roles:read` |
| `create_role` | `POST /v1/admin/roles` | `roles:write` |
| `update_role` | `PUT /v1/admin/roles/{name}` | `roles:write` |
| `delete_role` | `DELETE /v1/admin/roles/{name}` | `roles:write` |
| `list_accounts` | `GET /v1/admin/accounts` | `accounts:read` |
| `get_account` | `GET /v1/admin/accounts/{id}` | `accounts:read` |
| `set_account_roles` | `PUT /v1/admin/accounts/{id}/roles` | `roles:assign` |
| `set_account_status` | `PUT /v1/admin/accounts/{id}/status` | `accounts:disable` |
| `revoke_account_sessions` | `POST /v1/admin/accounts/{id}/revoke-sessions` | `accounts:revoke_sessions` |
| `issue_account_password_reset` | `POST /v1/admin/accounts/{id}/password-reset` | `accounts:reset_password` |
| `delete_account` | `DELETE /v1/admin/accounts/{id}` | `accounts:delete` |
| `list_account_profiles` | `GET /v1/admin/accounts/{id}/profiles` | `profiles:read_any` |
| `delete_account_profile` | `DELETE /v1/admin/accounts/{id}/profiles/{name}` | `profiles:delete_any` |
| `issue_invite` | `POST /v1/admin/invites` | `accounts:invite` |
| `read_audit_log` | `GET /v1/admin/audit` | `audit:read` |

**Built-in roles.** `owner` (everything), `admin` (everything except `roles:write`),
`auditor` (read-only), `member` (nothing). Immutable, so `member` always means what it
says. Custom roles are yours to define.

**The first account ever created becomes the owner.** Every account after it gets `member`.

**Two rules stop privilege escalation**, and they are the same idea: you cannot grant a
role whose permissions exceed your own, and you cannot create or edit one either. Either
alone is bypassed by doing the other first.

**`KEYRING_ADMIN_TOKEN` is break-glass.** Presented as a bearer token on any admin route it
holds every permission, for when no owner can log in or none exists yet. It is audited as
`break-glass`, conspicuously. Unset means break-glass is refused — never waved through.

**No permission returns another account's credential.** `profiles:read_any` shows which
services somebody has connected and whether each works; there is no permission that shows
what is behind them, and `profiles:delete_any` destroys without reading.

## Worked example

```bash
BASE=http://127.0.0.1:8001

# Onboard (operator mints, person redeems)
INVITE=$(curl -sX POST $BASE/v1/admin/invites -H "Authorization: Bearer $KEYRING_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"email":"me@example.com"}' | jq -r .token)
curl -sX POST $BASE/v1/auth/invites/redeem -H 'Content-Type: application/json' \
  -d "{\"token\":\"$INVITE\",\"password\":\"a long passphrase\"}"

# Log in
TOKEN=$(curl -sX POST $BASE/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"a long passphrase"}' | jq -r .token)

# A profile, and an API key in it
curl -sX POST $BASE/v1/profiles -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"personal"}'
curl -sX PUT $BASE/v1/profiles/personal/connections/tmdb/api-key \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"api_key":"the-key"}'

# What exists -- note the key is not in the answer
curl -s $BASE/v1/profiles/personal -H "Authorization: Bearer $TOKEN"

# As a service, on that person's behalf
USER_TOKEN=$(curl -sX POST $BASE/v1/auth/service-token -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"audience":"media-tool"}' | jq -r .token)
curl -s $BASE/v1/internal/credentials/personal/tmdb \
  -H "Authorization: Bearer $MEDIA_TOOL_SERVICE_TOKEN" \
  -H "X-Keyring-User-Token: $USER_TOKEN"
# -> {"service":"tmdb","headers":{"Authorization":"Bearer the-key"},"query_params":{}}
```
