# Changelog

All notable changes to keyring-api are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`clients/python/keyring_client`**, the verifier every service in the family shares.
  It holds the JWKS client, the token verifier, the service-token authenticator, the
  credential client and the test fakes, so that the rules by which a token is believed
  cannot differ between two services. Consuming services install it from this repository
  and delete their own copies. See [docs/integration.md](docs/integration.md) and
  [clients/python/README.md](clients/python/README.md).
- **Per-person session settings.** With `KEYRING_SETTINGS_API_BASE_URL` and
  `KEYRING_SETTINGS_API_TOKEN` configured, login reads `keyring.session_ttl_days`,
  `keyring.session_absolute_ttl_days` and `keyring.max_sessions` from settings-api for
  the account that just authenticated, clamped to this deployment's own values. Unset,
  every session uses the configuration as before. An outage falls back to the
  deployment's values rather than failing a login; a refusal fails the login, because a
  missing grant must not be hidden behind defaults.
- Migration `0003_session_idle_ttl.sql` stamps the idle TTL on each session at creation,
  so changing the setting reshapes new sessions only and never a live one.

### Changed

- **Breaking:** the floor is now **Python 3.12** (CI runs 3.12 and 3.13).
  `.python-version`, `requires-python`, ruff's `target-version`, mypy's `python_version`,
  the Docker base image and the pre-commit interpreter all moved together, and `uv.lock`
  was regenerated. The family-wide reason is in the meta-repo's
  [ADR-0008](https://github.com/tochi-mba/LUCY-assistant/blob/main/docs/adr/0008-python-3-12-floor.md):
  `weftai`, which the assistant hub depends on, requires 3.12 and uses PEP 695 type
  parameters that do not parse on 3.11. Generics here moved to PEP 695 syntax with it.
- CI inherits `FAMILY_GITHUB_TOKEN`; image builds accept a BuildKit `github_token`
  secret so tagged client packages can be fetched from private family repositories.
  `make docker` uses the signed-in GitHub account without saving its token in an image.
- **Breaking:** `GET /healthy` is liveness only -- the process is running, no I/O, and it
  never fails. The account, vault and connection checks moved to a new `GET /ready`
  (`check_readiness`), which answers 503 when any of them is unusable. An orchestrator
  restarts a container whose liveness check fails, so reporting a sealed vault there had it
  restarting a working process for a problem restarting cannot fix. Point container
  healthchecks at `/healthy` and load balancers at `/ready`.
- Each value in `KEYRING_SERVICE_TOKENS` must be at least 32 characters, and no two
  services may share one. Both are startup errors; sharing one would make the audience
  check meaningless.
- The default issuer is `http://127.0.0.1:8001`, matching `.env.example` and every
  consumer's default, rather than `https://keyring.local`.

### Fixed

- `.env.example` no longer sets `KEYRING_SECRET_DIR`, which stopped existing when the
  vault moved to SQLite (ADR-0012). Copying the file to `.env` was a startup error.
- The owner-only file checks on the key material and the OAuth providers file are POSIX
  rules, and are now stated as such: on Windows, where `os.chmod` cannot express them and
  ACLs decide, the check logs that it was skipped instead of refusing to load. The test
  suite runs green natively on Windows as well as in CI.
- A connection whose authorization has started but not completed reports no `scopes`.
  It used to report every scope the provider was asked for, as though the person had
  already granted them.
