# ADR-0004: in-memory stores for v1, behind ports

**Status:** accepted

## Context

Accounts, sessions, invites, resets, profiles and OAuth flows all need somewhere to live.
The credentials themselves are on disk (ADR-0005); the records describing them are not.

## Decision

Every store is a `Protocol` with an in-memory adapter. Nothing else knows which adapter is
in use.

## Why

It is the smallest thing that works, and the ports mean the decision is reversible without
touching a caller. The tests are written against the ports rather than the dictionaries, so
a Postgres adapter inherits the suite instead of needing a new one.

## What it costs

This is the weakest part of the service, and it is worth stating plainly:

- **A restart loses every account.** Not just sessions — accounts, invites, profiles.
  The encrypted credential *files* survive on disk, but the records pointing at them do
  not, which means they are unreachable and effectively lost.
- Nothing spans replicas, so there is exactly one process.

That is tolerable for a service being built, and it is **not** tolerable the day somebody
else's login is in it. A restart losing your sister's connections is a support incident you
cannot resolve for her.

## What would change our minds

Nothing — this is a scheduled change, not a standing decision. Postgres, single replica,
before the service is exposed to anyone but its author. The work is one adapter per port
plus a migration, and the ports exist precisely so that is all it is.
