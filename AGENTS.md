# AGENTS.md

Working notes for anyone — human or agent — changing this codebase. Read this before your
first edit. It is the single source of truth for how work is done here; `CLAUDE.md` just
points at it.

## What this service is

**keyring** is one HTTP service. It holds accounts (people who log in), profiles (named
credential sets those people own), and connections (a profile's link to one third-party
service). Other services authenticate against it and ask for a *usable* credential at the
moment they need one.

It is not a library, and it is not part of another service. media-tool will call it over
HTTP; that is the only relationship between them.

The HTTP surface is designed to be fronted by an **MCP server** later, so an assistant can
call it as tools. That is why route `operation_id`s and descriptions are treated as
contract rather than decoration — see [Invariants](#invariants).

## Commands

| Command | What it does |
| --- | --- |
| `make install` | Create the venv and install everything. |
| `make check` | **The gate.** Format check, lint, strict types, layering contracts, tests at 100% branch coverage. Run before every commit. |
| `make test` | Tests only. |
| `make fmt` | Format and auto-fix. |
| `make run` | Serve on :8001 with reload. Docs at `/docs`. |
| `make cov` | HTML coverage report in `htmlcov/`. |
| `make smoke` | End-to-end check against a keyring already running on :8099. See `scripts/smoke.py`. |

Always run `make check` rather than a bare `pytest` — piping any of these to `head`/`tail`
in a shell chain masks the exit code, which is how a broken commit slips through.

## The map

```
src/keyring_api/
  core/          config, clock, logging, request context, and the composition root
  domain/        pure types and rules: Account, Session, Grant, Profile, Connection,
                 Permission, Role. Imports nothing internal.
  audit/         the append-only record of privileged actions
  secrets/       SecretStore port + envelope-encrypted file adapter. The only layer that
                 sees plaintext credential material at rest.
  notifications/ EmailSender port, SMTP/file/disabled adapters, the outbox, templates
  accounts/      hashing, tokens, stores, roles, the account service, rate limiting,
                 JWT signing
  profiles/      ProfileStore port + in-memory adapter
  credentials/   the four consumption ports, the three credential kinds, OAuth, TOTP
  admin/         administrative operations over accounts, roles and others' profiles
  api/           FastAPI app, routers, wire schemas, problem+json errors, middleware
```

Dependencies point inward:
`api → admin → credentials → profiles → accounts → notifications → audit → secrets → domain`.
`core` is a shared kernel everything may use, except `domain`.

`admin/` started life inside `accounts/` and the layering contract rejected it — correctly.
An administrative delete has to remove an account's credentials too, and a layer that must
reach sideways is a layer in the wrong place.

## Invariants

These are enforced mechanically. If you want to break one, change the enforcement
deliberately and say why in the commit message — do not work around it.

1. **The domain imports nothing from the rest of the package.** import-linter contract.
2. **Layers point inward.** Also a contract.
3. **`argon2`, `cryptography` and `jwt` are only imported by their adapters.** A third
   contract. It caught a real leak during the build: the API layer had imported `jwt`
   just to catch `InvalidTokenError`, which would have made swapping the JWT library a
   change to HTTP handlers. `TokenSigner.verify` now raises a domain error instead.
4. **Nothing reads the wall clock directly.** Every component that behaves differently
   over time takes a `Clock`. This includes JWT expiry — PyJWT's own `verify_exp` is
   turned off and the check is done against the injected clock, because otherwise a test
   could only ever assert that a token minted now is valid now.
5. **Nothing reveals whether an account, profile or token exists.** Login and reset answer
   identically for a known and an unknown address, and cost the same CPU. Cross-account
   access is **404, never 403**. `InvalidGrantError` covers unknown, expired and
   already-used alike. Adding a distinguishable error here is a security change.
6. **No endpoint returns a stored secret**, except `resolve_form_secrets`, which needs a
   password because a login form does — and therefore requires two credentials. A contract
   test walks every response schema asserting no secret-bearing field exists.
7. **Coverage is 100% branch coverage, and the exclusions are only non-executable lines** —
   `if TYPE_CHECKING:`, bare `...` protocol bodies, `@overload`, the `__main__` guard.
   There is no `# pragma: no cover` in `src/`. If a line is hard to cover, that is usually
   the code telling you it is shaped wrong: two of the awkward ones during the build were
   genuinely dead code and one was a lock held longer than it needed to be.
8. **Route `operation_id`s are public API.** They become MCP tool names. A contract test
   pins the exact set and requires a summary and a real description on every operation.
9. **Secrets never reach a log record.** The logging pipeline redacts by field name before
   rendering, and there is a test proving the processor is actually installed rather than
   merely written. The same rule covers email: message bodies carry live tokens and are
   never logged, by any adapter, on any path — including the failure paths, which are the
   ones most likely to log too much.
10. **No permission returns another account's credential.** There is no
    `credentials:read_any`; `profiles:read_any` is metadata only. Adding one would be a
    change of kind, not degree — see [ADR-0010](docs/adr/0010-rbac.md). A domain test
    asserts no permission name even suggests it, so the boundary survives a refactor.
11. **You cannot grant a permission you do not hold.** Enforced on assigning a role *and*
    on creating or editing one; either alone is bypassed by doing the other first.
12. **Permission is checked before existence** in every administrative method, so a caller
    without the permission cannot use the 403/404 difference to enumerate account ids.
13. **The last owner cannot be demoted or deleted**, and the check happens inside the
    store's lock together with the write — otherwise two concurrent demotions both pass.

## How we work: TDD

Every change follows red → green → refactor, and each commit leaves `make check` passing.

1. Write the test first. It should fail for the reason you expect — check that it does.
2. Write the smallest implementation that passes.
3. Refactor with the test as a safety net.

Notes earned during this build:

- **Name tests after the behaviour.** `test_an_unknown_address_fails_identically_to_a_wrong_password`
  beats `test_login_401`.
- **Write the "why" when it is not obvious.** A comment explaining that the dummy hash
  exists so a login against an unknown address costs the same as a real one is worth more
  than the assertion.
- **Don't assert an object is truthy.** `assert await service.login(...)` always passes.
  Strict mypy's `truthy-bool` catches it; a dozen were caught that way here.
- **Separate the thresholds a test is about from the ones it is not.** The lockout test was
  passing for the wrong reason because the rate limit tripped first at the same number.
- **Fakes are hand-written and must satisfy the real Protocol** (`tests/fakes/`). If a port
  changes, they fail to type-check, which is how you find out.
- **Never sleep in a test.** Inject the clock. Two whole subsystems here — sessions and
  OAuth refresh — are defined by expiry, and none of it needs a real second to test.
- **Recover test inputs the way the real caller does.** The OAuth tests read the state out
  of the authorization URL rather than the store, so a change that stopped putting it there
  fails the tests instead of passing them.

## Recipe: add a permission

The claim RBAC makes is that permissions are a closed set and every check goes through one.

1. Add a value to `Permission` in `domain/rbac.py`, named `resource:verb`.
2. Add it to `owner` — `BUILTIN_ROLES[OWNER]` is `ALL_PERMISSIONS`, so this is automatic,
   and there is a test that fails if it ever stops being.
3. Decide whether `admin` and `auditor` should have it. Default to no.
4. Add a line to `PERMISSION_DESCRIPTIONS` in `api/routers/admin.py`, or `list_permissions`
   will raise — deliberately, so a new permission cannot be undocumented.
5. Use it: `actor.require(Permission.X)` in the service, and
   `dependencies=[Depends(requires(Permission.X))]` on the route. **Both.** The route
   dependency is the one a reader sees; the service check is the one that still holds when
   a handler is called from elsewhere.
6. Check the permission **before** looking the target up.
7. Tests: the empty-actor case, the has-it case, and the before-existence ordering.

Before adding one, ask whether it would let one account read another's credentials. If so,
the answer is no — see invariant 10.

## Recipe: add an endpoint group

1. Create `src/keyring_api/api/routers/<name>.py` with
   `router = APIRouter(prefix="/v1/<plural-noun>", tags=["<name>"])`.
2. Add wire models in `src/keyring_api/api/schemas/<name>.py`. Set
   `model_config = ConfigDict(extra="forbid")` on request bodies so an invented field is
   rejected rather than ignored. Give every field a `description` and every model an
   `examples` entry — a model reads these to decide whether and how to call the tool.
3. On every route set `operation_id` (snake_case `verb_noun`, stable forever), `summary`,
   a real `description`, and `responses` for every failure a caller can provoke.
4. Register it in `ROUTERS` in `api/routers/__init__.py`. That is the only wiring step;
   problem+json, request ids, the account binding and access logging are inherited.
5. Take `CurrentAccountDep` and address every store through that account. Never accept an
   account id as a parameter.
6. Raise domain errors. Map any new one in `_DOMAIN_STATUS` in `api/errors.py` — never
   build an error response in a handler.
7. Tests: an integration test per behaviour, an isolation test per verb, and extend the
   OpenAPI contract test with the new `operation_id`.

## Recipe: add a credential kind

The claim this architecture makes is that kinds grow and consumers do not. Adding one
should touch no consumer.

1. Add a value to `CredentialKind` in `domain/profiles.py`, and decide `can_refresh`.
2. Add a class in `credentials/kinds.py` satisfying **an existing port** —
   `HttpAuth` if it is attached to a request, `FormSecrets` if it is typed into a form.
   If it fits neither, stop and think hard: a third consumer is a much bigger change than
   a fourth kind, and the ports are meant to be closed.
3. Wire it into `CredentialService.resolve_http_auth` / `resolve_form_secrets`.
4. Add an entry endpoint in `api/routers/profiles.py` if the value is entered directly.
5. Tests: port conformance (`checked: HttpAuth = your_credential`), the happy path, and
   every way the stored material can be malformed — those must raise
   `CredentialUnavailableError`, never a `KeyError` escaping into a caller.

## Recipe: add an OAuth provider

A provider is data — no code changes.

1. Add an entry to the JSON file at `KEYRING_OAUTH_PROVIDERS_PATH`. The schema is
   `OAuthProvider` in `credentials/providers.py`.
2. `chmod 0600` the file. The loader refuses anything looser, because the file holds
   client secrets.
3. Register `KEYRING_OAUTH_REDIRECT_URI` with the provider, exactly.
4. Ask for the fewest scopes that do the job. Granted scopes are recorded, not requested
   ones, so you will see what you actually got.

## Environment gotchas

- `asyncio_mode = "auto"`, so `async def test_*` needs no marker.
- `filterwarnings = ["error"]`: a new deprecation warning fails the suite. Fix it rather
  than filtering it.
- Nested settings use a double underscore: `KEYRING_ARGON2__TIME_COST`.
- A `KEYRING_`-prefixed variable that no setting matches is a **startup error**, not a
  warning. A typo in `KEYRING_MASTER_KEY` would otherwise start the service with no vault.
- Argon2 needs 8 KiB of memory per lane; config validates that relationship so raising
  parallelism without raising memory fails at startup rather than at the first login.
- Tests use a deliberately cheap Argon2 cost. Production defaults take ~50ms per call
  **on purpose** — do not "optimise" them.

## Commit conventions

Conventional-commit subject (`feat(scope):`, `fix(scope):`, `chore:`), imperative mood, no
trailing period. The body explains **why** — the tradeoff, the failure mode being
prevented, the thing that surprised you. A reader six months from now has the diff already;
what they lack is your reasoning.

## Definition of done

- [ ] Tests were written first, and failed first.
- [ ] `make check` passes: format, lint, strict types, layering contracts, 100% coverage.
- [ ] New behaviour is covered by a test named after the behaviour.
- [ ] Anything touching accounts, profiles or credentials has an **isolation test** proving
      another account gets a 404.
- [ ] Anything administrative has: a no-permission test, a has-permission test, a
      permission-before-existence test, and — if it grants anything — an escalation test
      written as an attacker.
- [ ] Anything acting on another account writes an audit entry, and the entry contains no
      secret and no email address.
- [ ] Nothing new can appear in a log record or a response that should not — check the
      redaction field list and the response-schema contract test.
- [ ] Public HTTP changes: `operation_id`s stable, descriptions written for a model to
      read, contract test updated.
- [ ] Docs updated — this file for workflow, `docs/` for design, an ADR for a decision that
      future-you would otherwise re-litigate.
