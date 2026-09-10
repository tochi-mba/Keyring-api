# ADR-0013: one process, and the three things that say so

**Status:** accepted

## Context

The service has always run as a single process. That used to be implied by the in-memory
stores and never stated. [ADR-0012](0012-sqlite.md) makes the *data* durable, which makes
it worth saying out loud what is still true, so that nobody discovers it by starting a
second replica and watching people get logged out at random.

## Decision

keyring runs as exactly one process. Three things enforce it, and each is a deliberate
choice rather than an oversight:

**One database connection.** Every call is submitted to a single worker thread, which is
what makes a transaction indivisible without a lock that cancellation can drop (see
`storage/database.py`). A second process would open a second connection, and the
check-and-write pairs the last-owner rule depends on would be relying on SQLite's own
locking rather than on this.

**A process-local rate limiter.** It keys on `clock.monotonic()`, which has no meaning
across processes. Persisting it is a different design, not a different adapter. A restart
therefore clears per-caller throttles -- acceptable, and worth knowing. Account *lockouts*
are a different mechanism, live on the account row, and are durable.

**In-memory OAuth state.** A single-use CSRF value with a ten-minute TTL. A restart
mid-flow fails the callback with an error that already says what to do. A table for a
value that is meaningless in ten minutes is not worth the schema.

## What it costs

No horizontal scaling, and a restart is a brief outage rather than a rolling one. At this
size that is not a cost anyone will notice.

## What would change our minds

Wanting a second replica, or a background worker outside the API process. Then all three
move: a Postgres adapter behind the same ports, a shared rate limiter, and OAuth state in
a table. Naming them here is most of the work of doing it.
