"""The audit log.

Two things are being tested here, and only one of them is a data structure.

The first is ordinary: entries go in, come back newest first, can be filtered by actor
and counted, and stop accumulating at a cap.

The second is the reason the module exists. An audit log is read by more people than the
vault is and kept for longer than the accounts it describes, so what an entry may *hold*
is a security property in its own right: no secret, no address, opaque ids only. Those
rules live in the shape of :class:`AuditEntry` rather than in a validator, which means a
test walking that shape is what keeps them true through the next refactor.
"""

from __future__ import annotations

import asyncio
import dataclasses
from datetime import timedelta

import pytest

from keyring_api.audit.log import (
    BREAK_GLASS_ACTOR,
    MAX_ENTRIES,
    AuditAction,
    AuditEntry,
    AuditLog,
    InMemoryAuditLog,
)
from keyring_api.domain.accounts import ACCOUNT_ID_PREFIX, new_account_id
from tests.fakes.clock import EPOCH, FakeClock

SECRET_WORDS = ("token", "password", "secret", "credential", "key")
"""Field names that would mean the log had become somewhere to leave a secret."""


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def log(clock: FakeClock) -> InMemoryAuditLog:
    return InMemoryAuditLog(clock=clock)


async def test_it_satisfies_the_port(log: InMemoryAuditLog) -> None:
    checked: AuditLog = log

    assert isinstance(checked, AuditLog)


async def test_recording_returns_the_entry_it_stored(log: InMemoryAuditLog) -> None:
    entry = await log.record(
        AuditAction.ACCOUNT_DISABLED,
        actor_id="acct_actor",
        target_id="acct_target",
        detail="status disabled",
    )

    assert await log.recent() == [entry]


async def test_an_entry_says_who_did_what_to_whom(log: InMemoryAuditLog) -> None:
    entry = await log.record(
        AuditAction.ROLES_ASSIGNED,
        actor_id="acct_actor",
        target_id="acct_target",
        detail="roles auditor",
    )

    assert entry.actor_id == "acct_actor"
    assert entry.target_id == "acct_target"
    assert entry.action == AuditAction.ROLES_ASSIGNED
    assert entry.detail == "roles auditor"


async def test_an_action_on_no_particular_account_records_no_target(
    log: InMemoryAuditLog,
) -> None:
    entry = await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor")

    assert entry.target_id is None
    assert entry.detail == ""


async def test_an_empty_log_reads_back_empty(log: InMemoryAuditLog) -> None:
    assert await log.recent() == []
    assert await log.count() == 0


async def test_entries_read_back_newest_first(log: InMemoryAuditLog) -> None:
    # The question an audit log is asked under pressure is "what just happened", so the
    # answer to it must not be on the far side of a page of history.
    for index in range(3):
        await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor", detail=f"role {index}")

    assert [entry.detail for entry in await log.recent()] == ["role 2", "role 1", "role 0"]


async def test_the_limit_keeps_the_newest_entries(log: InMemoryAuditLog) -> None:
    for index in range(5):
        await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor", detail=f"role {index}")

    assert [entry.detail for entry in await log.recent(limit=2)] == ["role 4", "role 3"]


async def test_reading_without_a_limit_returns_one_page(log: InMemoryAuditLog) -> None:
    for index in range(120):
        await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor", detail=f"role {index}")

    assert len(await log.recent()) == 100


async def test_a_limit_of_zero_returns_nothing(log: InMemoryAuditLog) -> None:
    await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor")

    assert await log.recent(limit=0) == []


async def test_filtering_by_actor_shows_only_that_actor_s_actions(log: InMemoryAuditLog) -> None:
    await log.record(AuditAction.ACCOUNT_DISABLED, actor_id="acct_a", target_id="acct_x")
    await log.record(AuditAction.ACCOUNT_DISABLED, actor_id="acct_b", target_id="acct_y")

    entries = await log.recent(actor_id="acct_a")

    assert [entry.target_id for entry in entries] == ["acct_x"]


async def test_the_limit_applies_to_the_filtered_entries(log: InMemoryAuditLog) -> None:
    # A limit that counted the other actor's entries would answer "the last two things
    # this account did" with an empty list whenever somebody else was busier.
    for index in range(3):
        await log.record(AuditAction.ROLE_UPDATED, actor_id="acct_a", detail=f"a {index}")
        await log.record(AuditAction.ROLE_UPDATED, actor_id="acct_b", detail=f"b {index}")

    entries = await log.recent(limit=2, actor_id="acct_a")

    assert [entry.detail for entry in entries] == ["a 2", "a 1"]


async def test_an_actor_who_did_nothing_has_no_entries(log: InMemoryAuditLog) -> None:
    await log.record(AuditAction.ACCOUNT_DELETED, actor_id="acct_a", target_id="acct_x")

    assert await log.recent(actor_id="acct_b") == []


async def test_counting_reports_how_many_entries_are_held(log: InMemoryAuditLog) -> None:
    for _ in range(4):
        await log.record(AuditAction.ACCOUNT_INVITED, actor_id="acct_actor")

    assert await log.count() == 4


async def test_the_oldest_entries_are_dropped_at_the_cap(clock: FakeClock) -> None:
    # An uncapped audit log is a memory leak with an audit-shaped excuse: entries arrive
    # at whatever rate callers make privileged requests, and nothing ever frees them.
    log = InMemoryAuditLog(clock=clock, max_entries=3)

    for index in range(5):
        await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor", detail=f"role {index}")

    assert await log.count() == 3
    assert [entry.detail for entry in await log.recent()] == ["role 4", "role 3", "role 2"]


async def test_the_default_log_is_capped(log: InMemoryAuditLog) -> None:
    # The bound has to be the default rather than something a caller opts into.
    assert log._entries.maxlen == MAX_ENTRIES


async def test_entry_ids_are_unique(log: InMemoryAuditLog) -> None:
    for _ in range(50):
        await log.record(AuditAction.ACCOUNT_INVITED, actor_id="acct_actor")

    entries = await log.recent(limit=50)

    assert len({entry.entry_id for entry in entries}) == 50


async def test_entry_times_come_from_the_injected_clock(
    log: InMemoryAuditLog, clock: FakeClock
) -> None:
    # Asserting an exact recorded time is only possible because nothing in the module
    # reads the wall clock; a log that called datetime.now() could only be tested for
    # "roughly now", which is not a test of when anything happened.
    clock.advance(timedelta(minutes=5))

    entry = await log.record(AuditAction.ACCOUNT_ENABLED, actor_id="acct_actor")

    assert entry.at == EPOCH + timedelta(minutes=5)


async def test_concurrent_records_all_survive(log: InMemoryAuditLog) -> None:
    # Appends happen under the log's own lock, so a burst of privileged requests cannot
    # lose the one entry somebody later goes looking for.
    await asyncio.gather(
        *(
            log.record(AuditAction.ROLE_UPDATED, actor_id="acct_actor", detail=f"role {index}")
            for index in range(20)
        )
    )

    entries = await log.recent(limit=20)

    assert await log.count() == 20
    assert {entry.detail for entry in entries} == {f"role {index}" for index in range(20)}


def test_no_entry_field_could_hold_a_secret() -> None:
    # The rule "never record a secret" is kept by there being nowhere to put one. A new
    # field named for a token or a credential would make the log a second copy of the
    # vault, in the one file that is exported, shipped to observability and kept longest.
    named_for_a_secret = [
        field.name
        for field in dataclasses.fields(AuditEntry)
        if any(word in field.name for word in SECRET_WORDS)
    ]

    assert named_for_a_secret == []


async def test_an_entry_names_accounts_by_opaque_id_rather_than_address(
    log: InMemoryAuditLog,
) -> None:
    # An audit log outlives the account it describes and is read by more people than the
    # vault is, so an address in one spreads personal data everywhere the log goes.
    actor_id = new_account_id()
    target_id = new_account_id()

    entry = await log.record(
        AuditAction.ACCOUNT_PASSWORD_RESET_ISSUED,
        actor_id=actor_id,
        target_id=target_id,
        detail="password reset issued",
    )

    assert actor_id.startswith(ACCOUNT_ID_PREFIX)
    assert "@" not in repr(entry)


def test_the_break_glass_actor_is_a_constant_no_account_resembles() -> None:
    # Break-glass access is legitimate and should be rare. It is recorded under a name
    # that reads as itself in a list of account ids, so a log full of it is conspicuous.
    assert BREAK_GLASS_ACTOR == "break-glass"
    assert not BREAK_GLASS_ACTOR.startswith(ACCOUNT_ID_PREFIX)
    assert "@" not in BREAK_GLASS_ACTOR


async def test_break_glass_actions_are_filterable_like_any_other_actor(
    log: InMemoryAuditLog,
) -> None:
    await log.record(AuditAction.ACCOUNT_DELETED, actor_id=BREAK_GLASS_ACTOR, target_id="acct_x")
    await log.record(AuditAction.ACCOUNT_DELETED, actor_id="acct_a", target_id="acct_y")

    entries = await log.recent(actor_id=BREAK_GLASS_ACTOR)

    assert [entry.target_id for entry in entries] == ["acct_x"]
