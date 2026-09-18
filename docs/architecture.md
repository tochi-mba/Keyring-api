# Architecture

keyring is one service: one process, one port, one OpenAPI document. Inside it, hexagonal
(ports and adapters) — dependencies point inward, and the direction is enforced by
import-linter contracts in `pyproject.toml` rather than by convention.

```
                    ┌──────────────────────────────────┐
   people  ────────▶│  api/          routers, schemas, │
   services ───────▶│                problem+json,     │
   administrators ─▶│                auth + permission │
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  admin/        accounts, roles,  │
                    │                others' profiles  │
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  credentials/  kinds, the four   │
                    │                consumption ports,│
                    │                OAuth, TOTP       │
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  profiles/     ProfileStore      │
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  accounts/     hashing, tokens,  │
                    │                sessions, roles,  │
                    │                JWT signing       │
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  notifications/ EmailSender +    │
                    │                 outbox, templates│
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  secrets/      SecretStore +      │
                    │                envelope crypto    │
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  audit/        privileged actions │
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  storage/      one SQLite file,   │
                    │                one thread         │
                    └───────────────┬──────────────────┘
                    ┌───────────────▼──────────────────┐
                    │  domain/       pure types & rules │
                    │                (imports nothing)  │
                    └──────────────────────────────────┘

  core/  config · clock · logging · request context · composition root
         (a shared kernel every layer may use, except domain)
```

`admin/` is its own layer rather than part of `accounts/` because an administrative delete
has to remove that account's *credentials* too. It began inside `accounts/`, the layering
contract rejected it, and the contract was right: a layer that must reach sideways is a
layer in the wrong place.

`storage/` sits at the bottom because it knows about rows and transactions and nothing
else -- not what an account is, not what a credential is. A second contract forbids `api/`,
`admin/` and `domain/` from importing it at all: a router that *could* write a query is a
router that will eventually contain one.

## The three ideas that shape everything

### 1. Isolation is in the signatures

Every store method takes an `account_id`, and it is not optional on any of them. A
cross-account read is not a bug that can be introduced — it cannot be expressed. The API
layer never accepts an account id as a parameter either: it comes from the session, or
from a verified service token, and from nowhere else.

The corollary is that "not yours" and "does not exist" must be the same answer. They are:
`ProfileNotFoundError` maps to **404, never 403**, and a test asserts the two error
messages are byte-identical.

### 2. Permissions govern administration, never credential access

RBAC decides who may invite, disable, delete, and inspect. It does not decide who may *use*
somebody else's credential, because nobody may: there is no such permission, and a domain
test asserts none exists.

The operator can already decrypt the vault — they hold the master key — so it can look as
though such a permission would concede nothing. It would concede a lot. Decrypting with the
master key needs shell access, leaves evidence, and cannot be delegated. A permission would
be remote, silent, browser-usable, and grantable. Same outcome, different threat.

`profiles:delete_any` exists because cleaning up after somebody who has left is a real need.
It destroys without reading, and that asymmetry is what makes it safe to hand out.

### 3. Credential kinds grow; consumption ports do not

There are only four questions any caller ever asks of a credential, so those four are the
ports ([ADR-0007](adr/0007-kinds-and-ports.md)). Adding a service later means adding a
kind and mapping it onto an existing port; no consumer changes.

`HttpAuth` is async because answering may require refreshing an expired token. The caller
attaches what it is handed and cannot tell whether a network round trip happened — which
is exactly the knowledge this service exists to hold in one place.

## Request flow: a person

```
POST /v1/auth/login
  → rate limit by caller address
  → look up by normalized address; if absent, hash a dummy password anyway
  → verify; on failure record it, lock the account at the threshold
  → mint a random token, store only its SHA-256 hash
  → 200 { session_id, token, expires_at }        the token is never stored

GET /v1/profiles          Authorization: Bearer <session token>
  → resolve the session (expiry enforced on read, idle window extended)
  → bind the account into the request context, for every later log line
  → read profiles for THAT account
  → 200 { profiles: [...] }                      status only, never a secret
```

## Request flow: an administrator

```
PUT /v1/admin/accounts/{id}/roles     Authorization: Bearer <session token>
  → resolve the session → the account → its roles → its permissions (fresh, every request)
  → require roles:assign                    ← 403 here, BEFORE the target is looked up
  → look the target account up              ← 404 only for callers who passed the above
  → resolve the granted roles to permissions
  → require that set ⊆ the actor's own      ← the escalation guard
  → write, with the last-owner check inside the store's transaction
  → record actor, action and target in the audit log
```

Permissions are resolved per request and never cached on the session or baked into a token,
which is what makes revoking a role take effect on that account's very next request.

## Request flow: another service

```
POST /v1/auth/service-token   { "audience": "example-tool" }   (as the person)
  → 200 { token }             RS256, ~15 min, audience-scoped

GET /v1/internal/credentials/personal/spotify
  Authorization:        Bearer <example-tool's own service token>
  X-Keyring-User-Token: <the person's signed token>
  → identify the calling service by constant-time comparison
  → verify the user token, audience must be that service
  → account id comes from the USER's token; no parameter can name an account
  → refresh the stored OAuth token if it is inside its margin, write it back
  → 200 { headers: { "Authorization": "Bearer ..." }, expires_at }
```

Both credentials are required because either alone is a hole. With only the service
token, anything that could reach keyring could request anybody's credential — the confused
deputy, moved from inside one process to the gap between two.

## How storage is serialized, and why it is not a lock

Everything is one SQLite file ([ADR-0012](adr/0012-sqlite.md)). Every call goes through a
single connection on a **single dedicated worker thread**, submitted as one whole callable
-- so a transaction is indivisible by construction rather than by convention.

The obvious alternative is `asyncio.to_thread` under an `asyncio.Lock`, and it is broken:
cancelling the awaiting task releases the lock but does not cancel the thread, so the next
caller enters the same connection while the first is still mid-transaction. A client
disconnecting cancels its request task, so that is an ordinary Tuesday. The single-worker
executor removes the failure rather than patching it, because serialization stops depending
on a lock that cancellation can drop.

The cost is worth knowing: **a cancelled request's write may still commit**, since the
queued callable runs to completion regardless of who is still waiting for it.

Four invariants live in that indivisibility, and each was a race that a caller doing it in
two steps would lose:

| Invariant | How |
| --- | --- |
| The last owner survives | The check and the write are one `BEGIN IMMEDIATE` transaction |
| A grant is redeemed once | One `UPDATE ... WHERE redeemed_at IS NULL RETURNING` |
| A held role cannot be deleted | `ON DELETE RESTRICT` on `account_roles.role_name` |
| Deleting an account takes everything | `ON DELETE CASCADE`, in one transaction |

One driver detail is load-bearing enough to state here: `PRAGMA foreign_keys` defaults to
off, is per-connection, and is a **silent no-op while a transaction is open**. Through a
driver that opens implicit transactions it can report success and leave every foreign key
in the schema decorative. The connection is therefore opened with explicit transaction
control, and the setting is read back and verified rather than assumed.

## Where each secret lives, and how long

| Thing | Stored as | Lifetime |
| --- | --- | --- |
| Password | Argon2id hash | until changed |
| Session token | SHA-256 hash | idle 14d, absolute 90d |
| Invite / reset token | SHA-256 hash | 7d / 1h, single use |
| OAuth state | SHA-256 hash | 10 min, single use |
| Service token | not stored — signed | ~15 min |
| OAuth access + refresh token | AES-256-GCM, envelope | until revoked at the provider |
| API key, password, TOTP seed | AES-256-GCM, envelope | until deleted |

Nothing a caller presents is stored in a form that could be presented back. A database
dump yields no usable session, invite or reset, and the credential rows need the master
key, which is not in the database. There is a test that writes a known secret, checkpoints
the write-ahead log, and scans every byte the database owns for it.

## Testing strategy

Unit tests own the 100%. Every collaborator that reaches the outside world is behind a
port with a hand-written fake in `tests/fakes/`, and the fakes satisfy the real
`Protocol`s — so a port change makes them fail to type-check rather than silently drift.

Integration tests drive the real ASGI app through `httpx`, with lifespan run for real, and
concentrate on what a caller can actually observe: status codes, response bodies, headers,
and above all whether two situations that must look identical do.

No test sleeps. Sessions, invites, resets, lockouts, OAuth state and token refresh are all
defined by expiry, and every one of those rules is exercised by moving a `FakeClock`.
