# The HTTP contract

One service, one `/openapi.json`, served at `/docs`. Everything under `/v1` requires a
credential except the routes that exist to obtain or recover one: `login`,
`redeem_invite`, `request_password_reset`, `redeem_password_reset`, and the OAuth
callback, which is authenticated by its single-use state rather than a header.
`/healthy`, `/ready` and `/.well-known/jwks.json` are open too, for reasons given below.

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
| `get_health` | `GET /healthy` | Unauthenticated liveness. No I/O, and it never fails. |
| `check_readiness` | `GET /ready` | Unauthenticated. Counts and yes/no only. 503 when degraded. |
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

**Re-entering the password.** If your account has `keyring.require_reauth_for_credential_changes`
on in settings-api, every route that adds, replaces or removes a credential needs your
account password again as `current_password`: a field in the body of `put_api_key` and
`put_password`, and the whole, optional body (`{"current_password": "..."}`) of
`authorize_connection`, `delete_connection` and `delete_profile`. Deleting a profile with no
connections is not a credential change and is not asked. The answers:

| Situation | Response |
| --- | --- |
| Setting on, no `current_password` | 403 |
| `current_password` sent and wrong (setting on or off) | 401, and it counts toward the lockout |
| settings-api cannot say, no `current_password` | 503 — the setting is never guessed |
| settings-api cannot say, right `current_password` | goes ahead |

The OAuth callback is not asked: the check is at `authorize_connection`, where you are present.
An administrator deleting somebody else's profile (`delete_account_profile`) is not asked
either -- they do not have the password, and the audit log holds them to account -- but one
deleting their *own* profile there is held to their own setting: 403 with it on, 503 while
settings-api cannot say, and `delete_profile` is the route that takes the password.
[ADR-0014](adr/0014-reauthentication-per-request.md) says why it is per request.

**Notices.** With `keyring.notify_on_credential_change` on (and `keyring.email_notifications`
not off), the account's address is mailed after a credential is added, replaced or removed,
by any route here, a service, the callback, or an administrator. With
`keyring.notify_on_new_session`, every login is. Neither notice names a credential, a
service or a profile, and neither carries a link or a token.

### Service-to-service

| Operation | Route |
| --- | --- |
| `resolve_credential` | `GET /v1/internal/credentials/{profile}/{service}` |
| `resolve_form_secrets` | `GET /v1/internal/form-secrets/{profile}/{service}` |
| `describe_delegated_profile` | `GET /v1/internal/profiles/{name}` |
| `authorize_delegated_connection` | `POST /v1/internal/profiles/{name}/connections/{connection}/authorize` |
| `delete_delegated_connection` | `DELETE /v1/internal/profiles/{name}/connections/{connection}` |
| `create_delegated_grant` | `POST /v1/internal/profiles/{name}/grants` |
| `revoke_delegated_grant` | `DELETE /v1/internal/profiles/{name}/grants/{grant_id}` |
| `exchange_user_token` | `POST /v1/internal/token-exchange` |

All of them require the calling service's own token, `Authorization: Bearer <service
token>`, from `KEYRING_SERVICE_TOKENS`. All but `exchange_user_token` also require
`X-Keyring-User-Token: <the user's signed token>`, minted with the calling service's name
as its audience. The account comes from the user's token; no parameter names an account.

`resolve_form_secrets` is the one endpoint that returns credential material, because a
login form needs a password. That is exactly why it is behind two credentials, and why it
must never be exposed as an assistant tool.

The `/v1/internal/profiles` routes let a service show a person their connections, start an
OAuth consent, or disconnect one, on that person's behalf. They return status and a consent
URL, never a stored value. A service never has the person's password, so for a person with
`keyring.require_reauth_for_credential_changes` on, `authorize_delegated_connection` and
`delete_delegated_connection` answer **403** and the person must do it with their own
session; while settings-api cannot say whether it is on, they answer **503**.

`create_delegated_grant` records standing consent for the **calling service only**, while
the person is present: their user token is the proof, and the body names only `audiences`
and `ttl_seconds` (default 3600), never a service or an account. It is the same grant
`create_offline_grant` makes — the same allowlist, the same lifetime cap, listed and
revocable by the person's own session — and its audit line names the service that recorded
it. It exists so a service can arrange to finish work after the person leaves ("tell me when
CI is green, then merge it") at the moment the person asks, rather than sending them to a
consent screen. `revoke_delegated_grant` withdraws one the calling service holds; another
service's grant, a foreign one and a missing one are the same 404.

### Token exchange and offline grants

| Operation | Route | Authenticated by |
| --- | --- | --- |
| `exchange_user_token` | `POST /v1/internal/token-exchange` | service token, plus a user token or a grant |
| `create_offline_grant` | `POST /v1/profiles/{name}/grants` | the person's session |
| `list_offline_grants` | `GET /v1/profiles/{name}/grants` | the person's session |
| `revoke_offline_grant` | `DELETE /v1/profiles/{name}/grants/{grant_id}` | the person's session |

A service that must call a sibling for a person exchanges its own authority for a new
token with the sibling's audience. It never forwards the token it was given. The body
names one `audience` and an optional `ttl_seconds` (default 900). Send either
`X-Keyring-User-Token` (a token whose audience is the calling service) or a `grant_id`,
never both. The answer is `{token, token_type, expires_in, expires_at}`.

- The audience must be in the calling service's `KEYRING_EXCHANGE_AUDIENCES` list, or the
  answer is **403**. Nothing is allowed by default.
- The new token lives no longer than the smallest of the requested lifetime,
  `KEYRING_ACCESS_TOKEN_TTL_SECONDS`, and whatever it was exchanged from.
- A bad user token, an unknown, revoked or expired grant, a grant for another service or
  audience, and a disabled account all answer the same **401**.

An **offline grant** is the person's consent for one service to exchange for a fixed set of
audiences while they are not signed in. `create_offline_grant` takes `service`,
`audiences` and `ttl_seconds` (default 30 days, capped by
`KEYRING_OFFLINE_GRANT_MAX_TTL_SECONDS`). Every audience must be in that service's
allowlist (**403** otherwise), and a profile holds at most
`KEYRING_MAX_OFFLINE_GRANTS_PER_PROFILE` (**429** past that). The `grant_id` it returns is
not a credential on its own: only the named service, presenting its own token, can use it.
Revoking stops future exchanges; tokens already minted run to their short expiry. Listing
shows expired and revoked grants too, so the consent history stays visible.

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

This assumes a local keyring started with `KEYRING_ADMIN_TOKEN` set, mail left disabled
(so the invite token comes back in the response), and
`KEYRING_SERVICE_TOKENS='{"example-tool":"<its token>"}'`, with that same token exported
as `EXAMPLE_TOOL_SERVICE_TOKEN`. It uses `jq`.

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
  -H 'Content-Type: application/json' -d '{"audience":"example-tool"}' | jq -r .token)
curl -s $BASE/v1/internal/credentials/personal/tmdb \
  -H "Authorization: Bearer $EXAMPLE_TOOL_SERVICE_TOKEN" \
  -H "X-Keyring-User-Token: $USER_TOKEN"
# -> {"service":"tmdb","headers":{"Authorization":"Bearer the-key"},"query_params":{},"expires_at":null}
```
