# Running keyring

This service holds other people's credentials and is meant to be reachable from the
internet. That combination is why this page is a checklist rather than a description.

> **Do not skip the hardening section.** The service refuses to run without
> authentication — there is no flag for that — but everything below the application
> layer is yours to get right.

## Before it is reachable from the internet

- [ ] **TLS, terminated by a reverse proxy.** Caddy or nginx with Let's Encrypt. The app
      binds `127.0.0.1` by default and should stay there; the proxy is the only thing
      listening publicly. Every token this service issues is a bearer token — over plain
      HTTP, anyone on the path has them.
- [ ] **`--proxy-headers` on the app, and a proxy that sets them.** Rate limits are keyed
      by the connection's address. Without this every request appears to come from the
      proxy and one person exhausts everyone's budget.
- [ ] **`KEYRING_MASTER_KEY` set**, from your deployment's secret handling. Not in the
      repository, not in the image, not in a committed `.env`.
- [ ] **`KEYRING_ADMIN_TOKEN` set**, long and random. This is the break-glass path
      ([ADR-0010](adr/0010-rbac.md)) — it holds every permission. Day-to-day
      administration should be done by an account holding a role, so that actions are
      attributable in the audit log; break-glass exists for when no owner can log in.
- [ ] **`KEYRING_ISSUER` and `KEYRING_OAUTH_REDIRECT_URI` set to the real public URL.**
      The redirect must match what is registered with each provider, exactly.
- [ ] **Rate limiting at the proxy as well as in the app.** The app's limiter protects
      login, reset and invite redemption specifically. The proxy should cap everything
      else, because the app cannot refuse a request it has already parsed.
- [ ] **Backups of `KEYRING_DATABASE_PATH` and the signing key, and separately of the
      master key.** Losing the database loses your family's stored logins. Losing the
      master key makes the backup unreadable. Storing them together makes the backup as
      sensitive as the vault. Take them with `VACUUM INTO`, never `cp` — see
      [The database](#the-database).
- [ ] **A restore you have actually tried.** A backup you have never restored is a belief,
      not a backup. Copy one to a scratch directory, point a keyring at it on a throwaway
      port, and log in.

## Generating the keys

```bash
# Master key: base64 of 32 random bytes.
python -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())'

# Admin token: long and random.
python -c 'import secrets; print(secrets.token_urlsafe(32))'

# One token per service that will call the internal endpoints.
python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

The signing key is generated on first start at `KEYRING_SIGNING_KEY_PATH` and persists
across restarts on purpose — see [ADR-0008](adr/0008-opaque-sessions-signed-service-tokens.md).

## Configuration

Every setting is an environment variable prefixed `KEYRING_`; nested ones use a double
underscore. A prefixed variable that matches no setting is a **startup error**, not a
warning — a typo in `KEYRING_MASTER_KEY` would otherwise start the service with no vault
and nothing in the logs saying so. See `.env.example` for the full list.

The OAuth provider file must be mode 0600; the loader refuses anything looser, because it
holds client secrets.

That check is POSIX-only. Run natively on Windows there is no mode to read -- NTFS keeps no
permission bits, `chmod` only toggles the read-only flag, and every writable file reports
0666 -- so rather than refuse every file, the loader skips the comparison and logs a
`oauth_provider_file_mode_unchecked` warning carrying the file's path each time it loads
it. Who can read the file there is decided by its ACL, which it inherits from its
directory: keep it somewhere only the account running keyring can read, such as under that
account's profile.

## Onboarding somebody

There is no public registration ([ADR-0009](adr/0009-invite-only.md)). The **first account
you create becomes the owner**; every one after it gets `member`, which has no
administrative permissions.

```bash
# 1. Mint an invite.
curl -sX POST https://keyring.example/v1/admin/invites \
  -H "Authorization: Bearer $KEYRING_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"email":"someone@example.com"}'
# -> {"grant_id": "...", "token": "...", "expires_at": "..."}

# 2. Send them the token over whatever channel you already use with them.
# 3. They redeem it, choosing their own password:
curl -sX POST https://keyring.example/v1/auth/invites/redeem \
  -H 'Content-Type: application/json' \
  -d '{"token":"<the invite token>","password":"a long passphrase"}'
```

### Delivering the token

With `KEYRING_EMAIL__BACKEND=smtp` the invite is emailed and the response omits the token,
so it exists in exactly one place. With mail disabled — the default — the token is returned
to you and you deliver it. Forgotten passwords work the same way: the person calls
`request_password_reset`, which always answers identically whether or not the address
exists, and the link is either emailed or handed to you to pass on.

### Mail

Any provider that speaks SMTP works, and the free tiers are ample at this scale: Gmail
with an app password (500/day), Brevo (300/day), Resend or MailerSend (3,000/month).

```bash
KEYRING_EMAIL__BACKEND=smtp
KEYRING_EMAIL__HOST=smtp.example.com
KEYRING_EMAIL__PORT=587            # 587 + STARTTLS, or 465 with USE_IMPLICIT_TLS=true
KEYRING_EMAIL__USERNAME=...
KEYRING_EMAIL__PASSWORD=...
KEYRING_EMAIL__FROM_ADDRESS=keyring@example.com
KEYRING_EMAIL__LINK_BASE_URL=https://keyring.example   # omit to send the bare token
```

Configuring a username and password with TLS turned off is a **startup error**, not a
warning: SMTP AUTH on a plaintext connection sends the password in base64, and a mailbox
that sends password resets is worth more than most of what it protects. There is
deliberately no setting that disables certificate verification.

Deliverability — SPF, DKIM, a from-address that does not land in spam — is yours, and none
of it is in this repository. `KEYRING_EMAIL__BACKEND=file` writes messages to a directory
instead of sending them, which is how to check what would have gone out without putting a
live reset link into the logs.

### Delegating administration

```bash
# Give somebody the ability to help with lockouts, and nothing else.
curl -sX POST https://keyring.example/v1/admin/roles \
  -H "Authorization: Bearer $OWNER_SESSION" -H 'Content-Type: application/json' \
  -d '{"name":"support","description":"Helps people who are locked out",
       "permissions":["accounts:read","accounts:revoke_sessions"]}'

curl -sX PUT https://keyring.example/v1/admin/accounts/$THEIR_ID/roles \
  -H "Authorization: Bearer $OWNER_SESSION" -H 'Content-Type: application/json' \
  -d '{"roles":["member","support"]}'
```

You cannot grant a permission you do not hold yourself, so an `admin` cannot mint an
`owner`. Every action taken on somebody else's account is recorded in
`GET /v1/admin/audit`, which is the reason to administer through a role rather than through
break-glass: break-glass entries name no person.

### What to tell them, in plain words

Have this conversation during onboarding rather than after an incident:

- **You can technically read anything they store.** Unattended token refresh requires the
  server to decrypt without them present ([ADR-0006](adr/0006-server-can-decrypt.md)).
  There is no version of this where it refreshes their token overnight and you cannot read
  it.
- **Prefer connecting with OAuth wherever the service offers it.** It is scoped, and they
  can revoke it at the provider without involving you. A password they give you can only
  be revoked by changing it at the site.
- **Storing a TOTP seed puts their second factor in the same place as their first.** It is
  opt-in and flagged on the connection. Offer the choice; do not default it on.
- **If keyring is breached, their third-party accounts are exposed, not just yours.**

## The database

One SQLite file, at `KEYRING_DATABASE_PATH`, holding everything: accounts, sessions,
invites, profiles, connections, roles, the audit log, and the encrypted credential
material ([ADR-0012](adr/0012-sqlite.md)). It is created mode 0600, and so are its `-wal`
and `-shm` sidecars -- the credential material in them is encrypted, but the password
hashes and session token hashes are not.

The schema is applied at startup from numbered files in `src/keyring_api/storage/migrations/`
and recorded in a `schema_version` table. Starting an up-to-date database applies nothing,
so it is safe on every start.

### Backing it up

**`VACUUM INTO`, never `cp`.** The database runs in WAL mode, so a plain copy of the main
file can miss transactions that are committed but still in the write-ahead log. `VACUUM
INTO` takes a consistent snapshot of a live database without stopping the service:

```bash
sqlite3 /var/lib/keyring/keyring.db "VACUUM INTO '/backup/keyring-$(date +%F).db'"
```

The `sqlite3` CLI is a separate package and is not always installed. The same command
through the Python that is already there:

```bash
python -c "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); \
           c.execute(f\"VACUUM INTO '{sys.argv[2]}'\"); c.close()" \
  /var/lib/keyring/keyring.db /backup/keyring-$(date +%F).db
```

Either way the snapshot arrives mode 0644, because it is a new file this service did not
create. `chmod 600` it. The snapshot is as sensitive as the original.

Keep the master key somewhere else: together they are the vault, apart the backup is
unreadable.

### Restoring it

Stop the service, put the file at `KEYRING_DATABASE_PATH`, make sure the master key and the
signing key are the ones that go with it, and start. Delete any stale `-wal` and `-shm`
beside the old file first; they belong to the database they were written for.

A backup you have never restored is a belief. Copy one to a scratch directory, point a
keyring at it on a throwaway port, and log in.

### Looking inside it

```bash
sqlite3 /var/lib/keyring/keyring.db "SELECT account_id, email, status FROM accounts"
sqlite3 /var/lib/keyring/keyring.db "SELECT at, action, actor_id, detail FROM audit
                                     ORDER BY sequence DESC LIMIT 20"
```

The `secrets` table is four columns of opaque bytes and will tell you nothing without the
master key -- which is the intent. There is no supported way to decrypt a credential
outside the service, and adding one would be adding a way.

## Watching it

`GET /healthy` says only that the process is running: no I/O, and it never fails, so an
orchestrator does not restart a working container during somebody else's outage.

`GET /ready` needs no authentication and reports counts only — never an address, a
profile name, or which service someone has connected. It goes **503** when:

- the vault is sealed (no master key), or
- any stored connection can no longer produce a credential.

That second check is the one that earns its place: an expired grant shows up here, with
the fix, rather than as a job failing mysteriously hours later.

**It is not a readiness probe for other services.** One person's expired grant is enough
to make it 503, so a consumer whose readiness check pointed here would take itself out of
rotation for a problem it does not have. Consumers report their own readiness from the
signing keys they have cached instead; see [integration.md](integration.md#readiness).

Log records are JSON with a `request_id` on every line and an `account_id` on every
authenticated one. Values whose field name looks like a secret are redacted before
rendering — see `core/logging.py`. If you add a field that should never be logged, add its
name there rather than remembering not to log it.

## What is deliberately not here

- **No email.** Reset and invite delivery is manual ([ADR-0009](adr/0009-invite-only.md)).
- **No WAF, no DDoS protection.** Out of proportion for a dozen known users.
- **No cryptographic shredding on delete.** Deleting an account deletes its rows
  ([ADR-0005](adr/0005-envelope-encryption.md)); an old backup remains readable.
- **No revocation of a signed service token before it expires**
  ([ADR-0008](adr/0008-opaque-sessions-signed-service-tokens.md)).
- **No multi-replica anything.** One process, deliberately, and three separate
  things enforce it ([ADR-0013](adr/0013-single-process.md)).

## Legal and terms

Automated login and credential storage are not neutral technical acts. Many services' terms
forbid a third party storing user credentials, and automating logins breaches many sites'
terms outright. Running this for other people makes that your exposure, not theirs. Prefer
an official API and an OAuth grant wherever one exists.
