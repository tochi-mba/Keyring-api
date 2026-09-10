# keyring

Accounts, profiles and credentials — the vault the rest of your services authenticate
against.

One person logs in once. Their **profiles** ("personal", "work") hold the credentials for
third-party services, and any service that needs one asks keyring for a *usable*
credential at the moment it needs it: an OAuth token keyring has already refreshed, an
API key, or the fields to type into a login form. No other service stores a secret, and
no endpoint here ever hands a stored secret back out.

```
POST /v1/auth/login                                      -> an opaque session token
POST /v1/profiles                                        -> a named credential set
POST /v1/profiles/{name}/connections/{service}/authorize -> an OAuth consent URL
GET  /v1/profiles/{name}                                 -> which connections exist, and whether they are live
GET  /v1/internal/credentials/{profile}/{service}        -> headers to attach, for a service acting for a person
```

## Quick start

```bash
make install
export KEYRING_MASTER_KEY="$(python -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
make run       # http://127.0.0.1:8001/docs
```

The first account you create becomes the **owner**; everyone after gets `member`. Roles are
data, so you can define whatever you need — and no role, not even owner, can read another
account's credentials.

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

## What it will not do

**No permission returns another account's credential.** Administrators can invite, disable,
delete, and see *which* services somebody has connected and whether each still works. They
cannot see or use what is behind them. That line is the point of the design, not an
oversight — [ADR-0010](docs/adr/0010-rbac.md) explains why it holds even though the operator
can already decrypt the vault with the master key.

**It stores credentials and nothing else.** Browser profile directories, cookies, cache and
downloaded files belong to the service that uses them ([ADR-0002](docs/adr/0002-credentials-only.md)).

**It has no unauthenticated mode** and must sit behind TLS. Read
[docs/operations.md](docs/operations.md) before exposing it.

## Things worth knowing before you run this for other people

The server can read every credential in it. Unattended token refresh requires decrypting
without the owner present, so there is no version of this that refreshes your sister's
Spotify token overnight *and* cannot read it ([ADR-0006](docs/adr/0006-server-can-decrypt.md)).
Tell the people you onboard.

A stored site password is not revocable by you — only by that person changing it at the
site. Prefer OAuth wherever a service offers it.

Accounts and sessions are in memory in v1 ([ADR-0004](docs/adr/0004-in-memory-stores.md)):
a restart loses them. Swap in a durable store before anyone else depends on it.
