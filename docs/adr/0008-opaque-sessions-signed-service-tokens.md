# ADR-0008: opaque sessions for people, signed tokens between services

**Status:** accepted

## Context

Two different questions, routinely answered with the same mechanism: how does a person
prove who they are to keyring, and how does another service prove who a request is *for*?

## Decision

Two token types.

**People get opaque session tokens.** Random, stored only as a SHA-256 hash, looked up in a
session table on every request.

**Services get short-lived signed tokens** (RS256 JWT, ~15 minutes), verified locally
against a JWKS document keyring publishes at `/.well-known/jwks.json`.

## Why

**Why sessions are opaque.** A JWT cannot be revoked without a blocklist, and a blocklist is
a session table with extra steps and worse ergonomics. Keeping the session in a table is
what makes "log out everywhere" and "revoke every session when the password changes"
actually work rather than approximately work — and both of those are the things a person
reaches for when they think they have been compromised.

**Why service tokens are signed.** An opaque token would mean a network call to keyring on
every single request another service serves. Signed means none.

**Why fifteen minutes.** A signed token cannot be revoked — that is precisely what makes it
verifiable offline. The expiry is therefore the only revocation mechanism there is, and it
bounds how long a logged-out session keeps working somewhere else.

**Why RS256 rather than EdDSA**, which would be smaller and faster: RS256 is supported by
every JWT library on every runtime, and this service exists to be consumed by things not
written yet.

## Consequences worth knowing

- **A logged-out session's service token keeps working until it expires.** That is the
  trade for offline verification, it is bounded by the TTL, and there is a test asserting
  the current behaviour rather than a wish.
- The signing key is persisted, not generated per process. A key that changed on restart
  would invalidate every token in flight and force every consumer to re-fetch the JWKS at
  exactly the moment the service is coming back up.
- The `kid` is derived from the key rather than random, so a consumer caching by `kid` gets
  a hit across restarts.
- Tokens are audience-scoped: one minted for media-tool is rejected everywhere else, which
  matters because a service holds one for the length of a job.

## What would change our minds

Nothing about the split. The MCP OAuth 2.1 authorization spec (revised 2026-07-28) is the
natural replacement for the *person* half when other MCP clients need to connect — it drops
in behind the same `Authenticator` port.
