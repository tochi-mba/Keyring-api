"""Rate limiting on the endpoints a stranger can reach."""

from __future__ import annotations

import contextlib
from datetime import timedelta

import pytest

from keyring_api.accounts.ratelimit import InMemoryRateLimiter, RateLimiter
from keyring_api.domain.errors import RateLimitedError
from tests.fakes.clock import FakeClock

LIMIT = 3
WINDOW = 60.0


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def limiter(clock: FakeClock) -> InMemoryRateLimiter:
    return InMemoryRateLimiter(clock=clock)


def test_it_satisfies_the_port(limiter: InMemoryRateLimiter) -> None:
    checked: RateLimiter = limiter

    assert isinstance(checked, RateLimiter)


async def test_attempts_up_to_the_limit_are_allowed(limiter: InMemoryRateLimiter) -> None:
    for _ in range(LIMIT):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)


async def test_one_attempt_past_the_limit_is_refused(limiter: InMemoryRateLimiter) -> None:
    for _ in range(LIMIT):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    with pytest.raises(RateLimitedError):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)


async def test_the_refusal_says_how_long_to_wait(limiter: InMemoryRateLimiter) -> None:
    # A client that has to guess either gives up on a working service or hammers it.
    for _ in range(LIMIT):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    with pytest.raises(RateLimitedError) as caught:
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    assert 0 < caught.value.retry_after_seconds <= WINDOW


async def test_each_endpoint_has_its_own_budget(limiter: InMemoryRateLimiter) -> None:
    # A shared bucket means one person's forgotten password exhausts everyone's ability
    # to log in -- a denial of service handed out for free.
    for _ in range(LIMIT):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    await limiter.check("reset", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)


async def test_each_caller_has_its_own_budget(limiter: InMemoryRateLimiter) -> None:
    for _ in range(LIMIT):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    await limiter.check("login", "5.6.7.8", limit=LIMIT, window_seconds=WINDOW)


async def test_the_window_slides_rather_than_resetting_on_a_boundary(
    limiter: InMemoryRateLimiter, clock: FakeClock
) -> None:
    # A fixed window lets an attacker spend the whole budget at the end of one window
    # and the whole budget at the start of the next -- twice the limit, back to back.
    for _ in range(LIMIT):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    clock.advance(timedelta(seconds=WINDOW - 1))

    with pytest.raises(RateLimitedError):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)


async def test_the_budget_returns_once_the_window_has_passed(
    limiter: InMemoryRateLimiter, clock: FakeClock
) -> None:
    for _ in range(LIMIT):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    clock.advance(timedelta(seconds=WINDOW))

    await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)


async def test_a_refused_attempt_still_counts_against_the_caller(
    limiter: InMemoryRateLimiter, clock: FakeClock
) -> None:
    # Otherwise an attacker who keeps hammering never adds to their own record, and the
    # window drains while they are still attacking.
    for _ in range(LIMIT + 2):
        with contextlib.suppress(RateLimitedError):
            await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    clock.advance(timedelta(seconds=WINDOW - 1))

    with pytest.raises(RateLimitedError):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)


async def test_a_successful_outcome_can_clear_the_caller_s_record(
    limiter: InMemoryRateLimiter,
) -> None:
    # A person who mistypes their password twice and then gets it right should not be
    # one mistake away from a lockout for the rest of the window.
    for _ in range(LIMIT):
        await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    await limiter.reset("login", "1.2.3.4")

    await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)


async def test_resetting_a_caller_with_no_record_is_not_an_error(
    limiter: InMemoryRateLimiter,
) -> None:
    await limiter.reset("login", "nobody")


async def test_sweeping_forgets_callers_whose_window_has_passed(
    limiter: InMemoryRateLimiter, clock: FakeClock
) -> None:
    # Without a sweep the limiter is an unbounded map keyed by anything an
    # unauthenticated caller can put in it, which is a memory exhaustion bug.
    await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    clock.advance(timedelta(seconds=WINDOW * 2))

    assert await limiter.purge_expired(window_seconds=WINDOW) == 1
    assert await limiter.tracked_callers() == 0


async def test_sweeping_keeps_callers_still_inside_their_window(
    limiter: InMemoryRateLimiter,
) -> None:
    await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    assert await limiter.purge_expired(window_seconds=WINDOW) == 0
    assert await limiter.tracked_callers() == 1


async def test_a_caller_s_history_is_capped(limiter: InMemoryRateLimiter) -> None:
    # The window bounds how long attempts are remembered, not how many. A caller
    # hammering a long window would otherwise grow an unbounded deque -- memory an
    # unauthenticated stranger allocates on the server, one request at a time.
    from keyring_api.accounts.ratelimit import MAX_TIMESTAMPS_PER_CALLER

    for _ in range(MAX_TIMESTAMPS_PER_CALLER + 10):
        with contextlib.suppress(RateLimitedError):
            await limiter.check("login", "1.2.3.4", limit=LIMIT, window_seconds=WINDOW)

    assert len(limiter._attempts[("login", "1.2.3.4")]) == MAX_TIMESTAMPS_PER_CALLER
