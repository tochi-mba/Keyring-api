# How this is tested

`make check` is the gate: format, lint, strict types over `src` **and** `tests`, the
layering contracts, and the suite at 100% branch coverage. Coverage is the floor, not the
goal — the concentration is deliberate, because most of what can go wrong in this service
goes wrong silently.

## Where the volume is, and why

| Area | What is tested, and the failure it prevents |
| --- | --- |
| **Enumeration** | Login with a known and an unknown address produce byte-identical responses. Reset request answers identically either way. Cross-account access is 404, never 403. Each is the easiest thing to get wrong and the hardest to notice. |
| **Timing** | The dummy-hash path is taken for a missing account — asserted by observing the call, not by measuring a clock. A wall-clock assertion would be measuring the CI runner. |
| **Escalation** | Every guard has a test written *as an attacker*: grant above yourself, create-then-grant, edit a role you already hold, self-target, do it in two steps. |
| **Isolation** | One account reading, writing or deleting another's job, artifact, profile or credential. One test per verb, each named for the property. |
| **Tokens** | Single use, TTL expiry through a fake clock, tampering rejected, hashed at rest, constant-time compare. |
| **Session lifecycle** | Revoke one, revoke all, every session dies on password change and on reset. |
| **Secret handling** | No secret in any response — walked over every response schema in the OpenAPI document, so a field added later is caught here. None in logs, on any path including the failure paths. Files 0600. |
| **Concurrency** | Two simultaneous demotions of the last two owners must leave one. Two callbacks racing one OAuth state: exactly one wins. |
| **Property-based** | Token entropy and uniqueness, encrypt/decrypt round-trip, normalization idempotence. |

## Rules that produced better tests

**Never sleep.** Sessions, invites, resets, lockouts, OAuth state and token refresh are all
defined by expiry, and every one is exercised by moving a `FakeClock`. That extends to JWTs:
PyJWT's own expiry check is turned off and done against the injected clock, because
otherwise a test could only assert that a token minted now is valid now.

**Recover test inputs the way the real caller does.** The OAuth tests read the state out of
the authorization URL rather than the store, so a change that stopped putting it there fails
the tests instead of passing them.

**Assert something that could fail.** `assert await service.login(...)` always passes.
Strict mypy's `truthy-bool` catches these mechanically; a dozen were caught that way here.

**Separate the thresholds a test is not about.** The lockout test was passing for the wrong
reason because the rate limit tripped first at the same number. Test settings now set the
two far apart.

**Fakes satisfy the real `Protocol`.** If a port changes, the fakes fail to type-check,
which is how you find out.

**Check the specification, not your own output.** TOTP is verified against RFC 6238's
published vectors. Testing it against our own output would only prove it is self-consistent.

## What coverage found that review did not

Coverage at 100% is not there for the number. Three genuine defects surfaced as uncovered
lines:

- A `None` check in `/auth/me` that no test could reach, because the dependency had already
  proved the account exists. Dead code, removed.
- A cancel loop in the email outbox that could never run: the drain timeout already cancels
  the gathered tasks, and their done-callbacks empty the pending set first. Dead code,
  removed, with a test pinning the mechanism that makes it unnecessary.
- A lock held across a raise in the rate limiter. Restructured so the verdict is computed
  under the lock and raised outside it.

Each time, the awkward-to-cover line was the code saying it was shaped wrong. There is no
`# pragma: no cover` in `src/`.
