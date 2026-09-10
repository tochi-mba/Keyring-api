"""How a moment in time becomes a column, and comes back unchanged.

SQLite has no date type, so this is a decision rather than a detail, and there are two
properties to preserve:

**Timezone awareness survives the round trip.** Nothing in this service reads a naive
datetime -- every expiry comparison is against a UTC-aware one -- so a column that
returned a naive datetime would raise at the first comparison, in a code path far from
the store that produced it.

**Lexicographic order matches chronological order.** ``drop_oldest``, grant expiry and
the session sweep all sort on these columns, in SQL, as text. That only works because
the format is fixed width: a stamp whose microseconds were omitted when zero would sort
*after* one that kept them, and the oldest session would sometimes not be the one that
went.

Both are pinned by tests, because both fail silently.
"""

from __future__ import annotations

from datetime import UTC, datetime

__all__ = ["from_column", "from_column_optional", "to_column", "to_column_optional"]


def to_column(value: datetime) -> str:
    """Render a timezone-aware datetime as a sortable, fixed-width UTC stamp.

    Raises:
        ValueError: if the datetime is naive. A naive datetime here means a caller read
            the wall clock directly instead of taking the injected one, which is a bug
            worth failing on rather than guessing a zone for.
    """
    if value.tzinfo is None:
        msg = "refusing to store a naive datetime: it has no unambiguous instant"
        raise ValueError(msg)
    # timespec is explicit because isoformat() drops the fractional part when it is
    # zero, which would break the fixed width the ordering depends on.
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def from_column(raw: str) -> datetime:
    """Parse a stamp written by :func:`to_column` back into a UTC datetime."""
    return datetime.fromisoformat(raw).astimezone(UTC)


def to_column_optional(value: datetime | None) -> str | None:
    """Render a datetime that may be absent."""
    return None if value is None else to_column(value)


def from_column_optional(raw: str | None) -> datetime | None:
    """Parse a stamp that may be absent."""
    return None if raw is None else from_column(raw)
