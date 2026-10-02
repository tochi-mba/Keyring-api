# Integrating with keyring

Keyring owns accounts, sessions, signed service tokens and third-party credentials.
Consumers use the HTTP contract and the Python client in `clients/python/keyring_client`.
They never import keyring's application or database modules.

## Two kinds of service integration

| Consumer | Token audience | Reads credentials from `/v1/internal` |
| --- | --- | --- |
| Settings-api | `settings` or `settings.<namespace>` | No |
| User-api | `user` or `user.<scope>` | No |
| Persona-api | `persona` or `persona.<scope>` | No |
| Example-tool | `example-tool` | Yes |
| Spotify-api | `spotify-api` | Yes |
| Web-search-api | `web-search-api` | Yes |
| Environments-api | `environments-api` | Yes |

Keyring can mint an audience without an entry in `KEYRING_SERVICE_TOKENS`.
That mapping authorizes **internal credential calls**; it is not an audience registry.
User-api, Persona-api and Settings-api need the public JWKS and issuer for local
verification and do not need a keyring service secret for that purpose.

## Identity flow

1. A person logs in at `POST /v1/auth/login` and receives a session token.
2. They call `POST /v1/auth/service-token`, with the session in
   `Authorization: Bearer <session token>` and a body such as
   `{"audience":"example-tool"}`.
3. The consuming service verifies the resulting short-lived RS256 token against
   `/.well-known/jwks.json`, pinning its configured issuer and audience. The verified
   `sub` is the account id. A request body must never choose that id.
4. If a credential is needed, the service forwards that same user token to keyring
   alongside its own service secret.

The local issuer default is `http://127.0.0.1:8001`. The issuer identifies who signed
the token; the JWKS URL says where to fetch keys. Behind a proxy or inside Docker,
these may differ. Always configure the issuer to equal `KEYRING_ISSUER` exactly.

## Configuring internal callers

Use a JSON mapping, with a different randomly generated secret of at least 32
characters per service:

```dotenv
KEYRING_SERVICE_TOKENS='{"example-tool":"<generated example-tool secret>","spotify-api":"<generated Spotify secret>"}'
```

The names are exact: a call authenticated as `spotify-api` must present a user token
with `aud = spotify-api`. If that service also calls Settings-api, its settings grant's
`audience_prefix` must match that name so the same user token works with both hubs.
The settings service secret is configured separately in Settings-api's grants.

Do not use `KEYRING_SERVICE_TOKENS__EXAMPLE_TOOL`. The mapping is supplied as JSON.
The example placeholders above must be replaced before deployment.

## Python client

Consumers install the client from a tagged git source, the way the rest of the family
does. No sibling checkout is needed:

```toml
[project]
dependencies = ["keyring-client"]

[tool.uv.sources]
keyring-client = { git = "https://github.com/tochi-mba/Keyring-api", subdirectory = "clients/python", tag = "keyring-client-v0.1.0" }
```

A client change is released by tagging `keyring-client-v<version>` here; consumers move
by bumping the tag and refreshing `uv.lock`. Never vendor a copy.

```python
from keyring_client import ExactAudience, JwksClient, SystemClock, TokenVerifier, jwks_url

clock = SystemClock()
jwks = JwksClient(url=jwks_url("http://127.0.0.1:8001"), clock=clock)
verifier = TokenVerifier(jwks=jwks, issuer="http://127.0.0.1:8001", clock=clock)
identity = await verifier.verify(user_token, audience=ExactAudience("example-tool"))
account_id = identity.account_id
# At application shutdown:
await jwks.aclose()
```

Use `AudienceFamily("user")` when the service implements compartment audiences.
The service remains responsible for interpreting and enforcing those compartments.
Build clients once in the composition root, supply the service's logger and clock,
and close them in the application lifespan: `JwksClient` and `CredentialClient` each
have an `aclose()`.

### Resolving credentials

`GET /v1/internal/credentials/{profile}/{service}` takes two headers:

```text
Authorization: Bearer <the calling service's secret>
X-Keyring-User-Token: <the person's signed token for the calling service>
```

Its response describes what to attach to an outgoing request:

```json
{
  "service": "example",
  "headers": {"Authorization": "Bearer <usable access token>"},
  "query_params": {},
  "expires_at": null
}
```

`CredentialClient.resolve_credential(user_token=..., profile=..., service=...)`
speaks this contract. `resolve_form_secrets(...)` calls
`/v1/internal/form-secrets/{profile}/{service}` and returns `service` and `fields`,
for example a username and password needed by a login form. Never expose form-secret
resolution as an assistant-facing tool.

Headers and query parameters **are secrets**, even when they are ready to attach.
Hold them for the operation, redact representations and logs, and never include them
in public job records or error responses. The client result types redact their values.

## Errors, key rotation and outages

- `AuthenticationError`: reject the token with one fixed message.
- `KeyringUnreachableError`: dependency failure; a valid token must not be called invalid
  just because its verification keys cannot be fetched.
- `KeyringRejectedError`: keyring rejected one of the internal call's two credentials.
- `CredentialNotFoundError`: this person has no matching profile or connection.
- `CredentialUnavailableError`: the stored connection cannot currently be used; the
  detail can explain that the vault is sealed or reconnection is needed.

The JWKS client starts lazily, coalesces concurrent requests, limits unknown-key
refreshes, and serves cached public keys for a bounded grace period during an outage.
A successful fetch that lacks the requested key is an authentication failure.
`healthy()` reports cached-key degradation separately from a cold fetch failure.

### Readiness

A consumer's own `/ready` should call `await jwks.healthy()`. It answers `(True, None)`
when a token could be verified now, and `(False, reason)` otherwise, where the reason says
whether cached keys are still being served through an outage. Report that; do not raise.

Do not point a consumer's readiness at keyring's `/ready`. That goes 503 when any one
person's stored connection stops working, which says nothing about whether this service
can verify tokens, and would take it out of rotation for somebody else's expired grant.

## Calling a sibling for a person

A service that must call another service for the person it is serving never forwards the
token it was given: that token's audience is the calling service, and the sibling would
refuse it anyway. It exchanges instead:

```text
POST /v1/internal/token-exchange
Authorization: Bearer <the calling service's secret>
X-Keyring-User-Token: <the person's token for the calling service>

{"audience": "user.home", "ttl_seconds": 300}
```

The answer is a fresh token for that one audience, for the same account, expiring no later
than the token it came from. Each audience a service may ask for is listed, exactly, in
keyring's configuration; nothing is allowed by default:

```dotenv
KEYRING_EXCHANGE_AUDIENCES='{"example-tool": ["user.home", "settings.example-tool"]}'
```

Every key there must also be a service in `KEYRING_SERVICE_TOKENS`, or keyring refuses to
start.

For work that runs while the person is not signed in, the person first records an
**offline grant** with their session (`POST /v1/profiles/{name}/grants`, naming the
service and the audiences). The service then sends `{"audience": ..., "grant_id": ...}`
with no user token. The grant expires, the person can revoke it, and it is useless to
anything but the service it names. [api.md](api.md#token-exchange-and-offline-grants)
has the full contract.

A service that lets a person manage connections through it uses the three
`/v1/internal/profiles/{name}` routes, with the same two headers as credential
resolution. They report status and start or remove a connection; they never return a
stored value. Starting or removing one answers 403 for a person who has
`keyring.require_reauth_for_credential_changes` on, because that needs their password and a
service never has it: send them to do it with their own session. It answers 503 while
settings-api cannot say whether the setting is on.

## Tests and persistence

Use `keyring_client.testing` for real RSA signatures, an injected clock and a fake HTTP
transport. Keep service-specific audience, error-mapping and account-isolation tests.
Keyring's `tests/integration/test_client_contract.py` compares the shared client and
fake with the real application so their wire contracts cannot silently diverge.

Accounts and sessions persist in SQLite. Restarting keyring does not sign everyone out.
Logging out ends a session; a service token already minted remains valid until its
expiry. Consumers own their data-erasure paths, and service tokens contain no roles.
