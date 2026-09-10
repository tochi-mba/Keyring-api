# ADR-0012: SQLite, one file, behind the same ports

**Status:** accepted. Supersedes [ADR-0004](0004-in-memory-stores.md).

## Context

ADR-0004 called the in-memory stores "the weakest part of the service" and said the change
was scheduled rather than open. This is that change.

What it was costing: a restart lost every account, invite, session and profile, while the
encrypted credential material survived on disk with nothing left that knew whose it was --
unreachable, and invisible to every delete path that might have collected it.

## Decision

One SQLite database, in WAL mode, through the stdlib `sqlite3` driver. Every store keeps
the port it already had; only the adapter changed. The encrypted credential material moves
into the same file, as rows of opaque bytes.

Not Postgres.

## Why SQLite and not Postgres

This is one process serving about a dozen people with no availability requirement.
Postgres would buy concurrent writers and replication, neither of which is wanted here,
and would cost a second service to run, back up, patch and be woken up by.

The important half of this decision is that it is *reversible*. The ports are unchanged,
the tests are written against the ports, and a Postgres adapter would inherit the suite
rather than need a new one -- which is the same argument ADR-0004 made for in-memory
stores, now cashed in for the first time.

## Why the credential material moved in too

It was already the one durable thing, in its own directory of envelope files. Keeping it
there would have meant two storage systems, two backup procedures and two ways for a
deletion to be half-done. The envelope crypto did not change -- it was lifted into
`secrets/envelope.py` first, unchanged, so the move could be about *where the bytes go*
and nothing else.

## What it costs

- **One process, still.** A single connection, a process-local rate limiter and in-memory
  OAuth state each say so on their own. See [ADR-0013](0013-single-process.md).
- **No concurrent writers.** WAL gives readers concurrency with a writer, and the single
  connection then declines to use it. That is deliberate -- it is what makes a
  check-and-write pair indivisible -- and it is a store-internal decision that a pool
  could change later without any caller noticing.
- **Hand-rolled migrations.** Numbered `.sql` files and a `schema_version` table, no
  Alembic. What a migration tool buys is autogeneration from an ORM and a dozen engines;
  there is no ORM here and there is one engine, so what would be left is "run these files
  in order". Same reasoning that made RFC 6238 hand-written in `credentials/totp.py`.
- **Backups are `VACUUM INTO`, not `cp`.** A plain copy of a live WAL database can miss
  committed transactions. See [docs/operations.md](../operations.md).

## What the ports gained on the way

The migration was not a translation. Four things that were only *approximately* true in
memory became structurally true:

- A role held by somebody cannot be deleted -- `ON DELETE RESTRICT`, rather than a count
  the caller took under a different lock.
- The per-account session cap holds under concurrent logins -- one statement, rather than
  a count-then-drop loop two logins could interleave.
- Adding a connection cannot lose another one -- connections are rows, rather than a field
  inside a profile that got written back wholesale.
- Deleting an account takes everything it owns, in one transaction -- `ON DELETE CASCADE`,
  rather than a hand-ordered sequence with a documented lesser harm if it failed partway.

## What would change our minds

More than one process needing to write: another replica, or a worker outside the API. That
is a Postgres adapter and a different answer to the rate limiter and OAuth state, and the
ports are what make it that rather than a rewrite.
