"""Request-scoped context: the request id, and who the request is for."""

from __future__ import annotations

import asyncio

from keyring_api.core.context import (
    bind_account_id,
    bind_request_id,
    get_account_id,
    get_request_id,
    new_request_id,
)


def test_a_fresh_request_id_is_unique() -> None:
    assert new_request_id() != new_request_id()


def test_nothing_is_bound_outside_a_request() -> None:
    assert get_request_id() is None
    assert get_account_id() is None


def test_binding_exposes_the_value_for_the_duration_of_the_block() -> None:
    with bind_request_id("abc") as bound:
        assert bound == "abc"
        assert get_request_id() == "abc"

    assert get_request_id() is None


def test_binding_restores_the_previous_value_rather_than_clearing_it() -> None:
    # Nested binds happen when an internal call is made while serving a request; the
    # inner one must not erase the outer request's identity on the way out.
    with bind_request_id("outer"), bind_request_id("inner"):
        assert get_request_id() == "inner"

    assert get_request_id() is None


def test_the_account_id_binds_and_unwinds_the_same_way() -> None:
    with bind_account_id("acct_1"):
        assert get_account_id() == "acct_1"

    assert get_account_id() is None


async def test_concurrent_tasks_never_see_each_other_s_account() -> None:
    # The whole isolation story rests on this: if the account id leaked across tasks,
    # one person's request could be served with another person's identity.
    seen: list[str | None] = []

    async def serve(account_id: str, delay: float) -> None:
        with bind_account_id(account_id):
            await asyncio.sleep(delay)
            seen.append(get_account_id())

    await asyncio.gather(serve("acct_a", 0.01), serve("acct_b", 0.0))

    assert sorted(item or "" for item in seen) == ["acct_a", "acct_b"]
