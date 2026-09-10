# keyring

Accounts, profiles and credentials — the vault the rest of your services authenticate
against.

One person logs in once. Their **profiles** ("personal", "work") hold the credentials for
third-party services, and any service that needs one asks keyring for a *usable*
credential at the moment it needs it: an OAuth token keyring has already refreshed, an
API key, or the fields to type into a login form. No other service stores a secret, and
no endpoint here ever hands a stored secret back out.

```
POST /v1/auth/login                                    -> an opaque session token
POST /v1/profiles                                      -> a named credential set
POST /v1/profiles/{name}/connections/{service}/authorize -> an OAuth consent URL
GET  /v1/profiles/{name}                               -> which connections exist, and whether they are live
```

## Quick start

```bash
make install
export KEYRING_MASTER_KEY="$(python -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
make run       # http://127.0.0.1:8001/docs
```

`make check` is the gate: format, lint, strict types, layering contracts, and the test
suite at 100% branch coverage.

## Where to read next

| Document | What it covers |
| --- | --- |
| [AGENTS.md](AGENTS.md) | How work is done here: the map, the invariants, the recipes. |
| [docs/architecture.md](docs/architecture.md) | Ports, adapters, and why the layering is enforced. |
| [docs/api.md](docs/api.md) | The HTTP contract. |
| [docs/operations.md](docs/operations.md) | Running it on the internet, and what that costs you. |
| [docs/adr/](docs/adr/) | The decisions, and what each one traded away. |

## What it is not

keyring stores credentials and nothing else. Browser profile directories, cookies, cache
and downloaded files belong to the service that uses them.

It has no unauthenticated mode and must sit behind TLS. Read
[docs/operations.md](docs/operations.md) before exposing it.
