# Contributing

Read [AGENTS.md](AGENTS.md) first — it is the single source of truth for how work is done
here, including the invariants that are enforced mechanically.

## Getting set up

```bash
make install
cp .env.example .env
export KEYRING_MASTER_KEY="$(python -c 'import base64,os; print(base64.b64encode(os.urandom(32)).decode())')"
export KEYRING_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
make run          # http://127.0.0.1:8001/docs
```

Optionally `pre-commit install` — a fast subset of `make check` on staged files.

## The loop

1. Write the test first. Watch it fail for the reason you expect.
2. Write the smallest implementation that passes.
3. Refactor with the test as a safety net.
4. `make check` before every commit, and `make matrix` before pushing — `check` runs one
   interpreter, and coverage genuinely differs between the versions CI tests. Never pipe
   either to `head` or `tail`: that masks the exit code, which is how a broken commit
   slips through.

## This is a credential vault

Which changes what "done" means for anything touching accounts, permissions or secrets:

- **Add an isolation test.** Another account must get a 404, not a 403.
- **Add an escalation test** for anything that grants. Write it as an attacker: self-target,
  do it in two steps, edit rather than assign.
- **Check the permission before looking the target up.** The other order makes the 403/404
  difference an account-id oracle.
- **Nothing new may reach a log record or a response.** If you add a field that could hold a
  secret, add its name to the redaction list in `core/logging.py` — and add the test that
  proves it.
- **Do not add a permission that returns another account's credential.** See
  [ADR-0010](docs/adr/0010-rbac.md); there is a test asserting none exists.

If a change requires breaking one of the invariants in AGENTS.md, change the enforcement
deliberately and say why in the commit message. Do not work around it.

## Commits

Conventional-commit subject (`feat(scope):`, `fix(scope):`, `chore:`), imperative, no
trailing period. The body explains **why** — the tradeoff, the failure mode being prevented,
the thing that surprised you. A reader six months from now has the diff; what they lack is
your reasoning.

Write an ADR for any decision future-you would otherwise re-litigate. The existing ones in
[docs/adr/](docs/adr/) each say what was decided, what it cost, and what would change our
minds — follow that shape.
