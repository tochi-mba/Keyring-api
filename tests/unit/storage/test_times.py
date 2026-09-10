"""How a datetime survives a round trip through a TEXT column.

Two properties, both of which fail silently if they break, which is why they are pinned
here rather than left to the stores that depend on them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from keyring_api.storage.times import (
    from_column,
    from_column_optional,
    to_column,
    to_column_optional,
)

# Hypothesis wants naive bounds when it is the one attaching the timezone, so these
# two are naive on purpose rather than by omission.
EARLIEST = datetime(1900, 1, 1)  # noqa: DTZ001
LATEST = datetime(2200, 1, 1)  # noqa: DTZ001


class TestRoundTrip:
    def test_it_preserves_the_instant(self) -> None:
        moment = datetime(2026, 9, 10, 21, 43, 7, 123456, tzinfo=UTC)

        assert from_column(to_column(moment)) == moment

    def test_it_comes_back_timezone_aware(self) -> None:
        restored = from_column(to_column(datetime(2026, 1, 1, tzinfo=UTC)))

        assert restored.tzinfo is not None
        assert restored.utcoffset() == timedelta(0)

    def test_it_normalizes_a_non_utc_offset_to_utc(self) -> None:
        tokyo = datetime(2026, 9, 10, 6, 0, tzinfo=timezone(timedelta(hours=9)))

        assert to_column(tokyo) == "2026-09-09T21:00:00.000000+00:00"

    def test_it_refuses_a_naive_datetime(self) -> None:
        with pytest.raises(ValueError, match="naive datetime"):
            to_column(datetime(2026, 1, 1))  # noqa: DTZ001 -- the point of the test

    @given(
        st.datetimes(
            min_value=EARLIEST,
            max_value=LATEST,
            timezones=st.just(UTC),
        )
    )
    def test_any_aware_datetime_survives(self, moment: datetime) -> None:
        assert from_column(to_column(moment)) == moment


class TestOrdering:
    """Sorting the stored text has to agree with sorting the datetimes.

    ``drop_oldest`` and the expiry sweeps both ORDER BY these columns in SQL, so an
    encoding whose text order disagreed with chronological order would drop the wrong
    session -- occasionally, and only for the moments where the two disagree.
    """

    def test_a_zero_microsecond_stamp_keeps_its_width(self) -> None:
        # isoformat() omits the fractional part when it is zero, which would sort such a
        # stamp after every stamp that kept one. timespec="microseconds" is what stops
        # that, and this is the assertion that would fail if it were dropped.
        assert to_column(datetime(2026, 1, 1, tzinfo=UTC)) == "2026-01-01T00:00:00.000000+00:00"

    def test_every_stamp_is_the_same_width(self) -> None:
        widths = {
            len(to_column(datetime(2026, 1, 1, tzinfo=UTC) + timedelta(microseconds=step)))
            for step in (0, 1, 999_999, 1_000_000, 86_400_000_000)
        }

        assert widths == {32}

    @given(
        st.lists(
            st.datetimes(
                min_value=EARLIEST,
                max_value=LATEST,
                timezones=st.just(UTC),
            ),
            min_size=2,
            max_size=12,
        )
    )
    def test_text_order_matches_chronological_order(self, moments: list[datetime]) -> None:
        assert [to_column(moment) for moment in sorted(moments)] == sorted(
            to_column(moment) for moment in moments
        )


class TestOptional:
    def test_absent_stays_absent(self) -> None:
        assert to_column_optional(None) is None
        assert from_column_optional(None) is None

    def test_present_round_trips(self) -> None:
        moment = datetime(2026, 3, 4, 5, 6, 7, 8, tzinfo=UTC)

        assert from_column_optional(to_column_optional(moment)) == moment
