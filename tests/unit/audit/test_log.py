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
import inspect
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from keyring_api.audit.log import (
    BREAK_GLASS_ACTOR,
    MAX_ENTRIES,
    AuditAction,
    AuditEntry,
    AuditLog,
)
from keyring_api.audit.sql_log import SqlAuditLog
from keyring_api.domain.accounts import ACCOUNT_ID_PREFIX, new_account_id
from tests.fakes.clock import EPOCH, FakeClock

if TYPE_CHECKING:
    from keyring_api.storage.database import Database

SECRET_WORDS = ("token", "password", "secret", "credential", "key")
"""Field names that would mean the log had become somewhere to leave a secret."""


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def log(database: Database, clock: FakeClock) -> SqlAuditLog:
    return SqlAuditLog(database=database, clock=clock)


async def test_it_satisfies_the_port(log: SqlAuditLog) -> None:
    checked: AuditLog = log

    assert isinstance(checked, AuditLog)


async def test_recording_returns_the_entry_it_stored(log: SqlAuditLog) -> None:
    entry = await log.record(
        AuditAction.ACCOUNT_DISABLED,
        actor_id="acct_actor",
        target_id="acct_target",
        detail="status disabled",
    )

    assert await log.recent() == [entry]


async def test_an_entry_says_who_did_what_to_whom(log: SqlAuditLog) -> None:
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
    log: SqlAuditLog,
) -> None:
    entry = await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor")

    assert entry.target_id is None
    assert entry.detail == ""


async def test_an_empty_log_reads_back_empty(log: SqlAuditLog) -> None:
    assert await log.recent() == []
    assert await log.count() == 0


async def test_entries_read_back_newest_first(log: SqlAuditLog) -> None:
    # The question an audit log is asked under pressure is "what just happened", so the
    # answer to it must not be on the far side of a page of history.
    for index in range(3):
        await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor", detail=f"role {index}")

    assert [entry.detail for entry in await log.recent()] == ["role 2", "role 1", "role 0"]


async def test_the_limit_keeps_the_newest_entries(log: SqlAuditLog) -> None:
    for index in range(5):
        await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor", detail=f"role {index}")

    assert [entry.detail for entry in await log.recent(limit=2)] == ["role 4", "role 3"]


async def test_reading_without_a_limit_returns_one_page(log: SqlAuditLog) -> None:
    for index in range(120):
        await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor", detail=f"role {index}")

    assert len(await log.recent()) == 100


async def test_a_limit_of_zero_returns_nothing(log: SqlAuditLog) -> None:
    await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor")

    assert await log.recent(limit=0) == []


async def test_filtering_by_actor_shows_only_that_actor_s_actions(log: SqlAuditLog) -> None:
    await log.record(AuditAction.ACCOUNT_DISABLED, actor_id="acct_a", target_id="acct_x")
    await log.record(AuditAction.ACCOUNT_DISABLED, actor_id="acct_b", target_id="acct_y")

    entries = await log.recent(actor_id="acct_a")

    assert [entry.target_id for entry in entries] == ["acct_x"]


async def test_the_limit_applies_to_the_filtered_entries(log: SqlAuditLog) -> None:
    # A limit that counted the other actor's entries would answer "the last two things
    # this account did" with an empty list whenever somebody else was busier.
    for index in range(3):
        await log.record(AuditAction.ROLE_UPDATED, actor_id="acct_a", detail=f"a {index}")
        await log.record(AuditAction.ROLE_UPDATED, actor_id="acct_b", detail=f"b {index}")

    entries = await log.recent(limit=2, actor_id="acct_a")

    assert [entry.detail for entry in entries] == ["a 2", "a 1"]


async def test_an_actor_who_did_nothing_has_no_entries(log: SqlAuditLog) -> None:
    await log.record(AuditAction.ACCOUNT_DELETED, actor_id="acct_a", target_id="acct_x")

    assert await log.recent(actor_id="acct_b") == []


async def test_counting_reports_how_many_entries_are_held(log: SqlAuditLog) -> None:
    for _ in range(4):
        await log.record(AuditAction.ACCOUNT_INVITED, actor_id="acct_actor")

    assert await log.count() == 4


async def test_the_oldest_entries_are_dropped_at_the_cap(
    database: Database, clock: FakeClock
) -> None:
    # An uncapped audit log is a memory leak with an audit-shaped excuse: entries arrive
    # at whatever rate callers make privileged requests, and nothing ever frees them.
    log = SqlAuditLog(database=database, clock=clock, max_entries=3)

    for index in range(5):
        await log.record(AuditAction.ROLE_CREATED, actor_id="acct_actor", detail=f"role {index}")

    assert await log.count() == 3
    assert [entry.detail for entry in await log.recent()] == ["role 4", "role 3", "role 2"]


def test_the_default_log_is_capped() -> None:
    # The bound has to be the default rather than something a caller opts into. Asserted
    # against the signature rather than by writing ten thousand entries, and through the
    # public one rather than by reaching for whatever holds them.
    assert inspect.signature(SqlAuditLog).parameters["max_entries"].default == MAX_ENTRIES


async def test_entry_ids_are_unique(log: SqlAuditLog) -> None:
    for _ in range(50):
        await log.record(AuditAction.ACCOUNT_INVITED, actor_id="acct_actor")

    entries = await log.recent(limit=50)

    assert len({entry.entry_id for entry in entries}) == 50


async def test_entry_times_come_from_the_injected_clock(log: SqlAuditLog, clock: FakeClock) -> None:
    # Asserting an exact recorded time is only possible because nothing in the module
    # reads the wall clock; a log that called datetime.now() could only be tested for
    # "roughly now", which is not a test of when anything happened.
    clock.advance(timedelta(minutes=5))

    entry = await log.record(AuditAction.ACCOUNT_ENABLED, actor_id="acct_actor")

    assert entry.at == EPOCH + timedelta(minutes=5)


async def test_concurrent_records_all_survive(log: SqlAuditLog) -> None:
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
    log: SqlAuditLog,
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
    log: SqlAuditLog,
) -> None:
    await log.record(AuditAction.ACCOUNT_DELETED, actor_id=BREAK_GLASS_ACTOR, target_id="acct_x")
    await log.record(AuditAction.ACCOUNT_DELETED, actor_id="acct_a", target_id="acct_y")

    entries = await log.recent(actor_id=BREAK_GLASS_ACTOR)

    assert [entry.target_id for entry in entries] == ["acct_x"]


class TestSurvivingItsSubjects:
    """The audit table has no foreign keys, and this is why.

    Deleting an account must not delete the record that it was deleted -- which is the
    one entry somebody is most likely to come looking for. The consequence is that an
    entry has to be self-describing, because its referents may already be gone.
    """

    async def test_an_entry_outlives_the_account_it_is_about(
        self, log: SqlAuditLog, database: Database
    ) -> None:
        from keyring_api.accounts.sql_store import SqlAccountStore
        from keyring_api.domain.accounts import Account

        accounts = SqlAccountStore(database=database)
        doomed = Account(
            account_id=new_account_id(),
            email="doomed@example.com",
            password_hash="$argon2id$fake",
            created_at=EPOCH,
            updated_at=EPOCH,
        )
        await accounts.add(doomed)
        await log.record(
            AuditAction.ACCOUNT_DELETED, actor_id=BREAK_GLASS_ACTOR, target_id=doomed.account_id
        )

        await accounts.delete(doomed.account_id)

        entries = await log.recent()
        assert len(entries) == 1
        assert entries[0].target_id == doomed.account_id

    async def test_an_entry_outlives_the_actor_who_made_it(
        self, log: SqlAuditLog, database: Database
    ) -> None:
        from keyring_api.accounts.sql_store import SqlAccountStore
        from keyring_api.domain.accounts import Account

        accounts = SqlAccountStore(database=database)
        actor = Account(
            account_id=new_account_id(),
            email="actor@example.com",
            password_hash="$argon2id$fake",
            created_at=EPOCH,
            updated_at=EPOCH,
        )
        await accounts.add(actor)
        await log.record(AuditAction.ACCOUNT_INVITED, actor_id=actor.account_id)

        await accounts.delete(actor.account_id)

        assert [entry.actor_id for entry in await log.recent()] == [actor.account_id]

    async def test_an_entry_can_name_an_account_that_never_existed(self, log: SqlAuditLog) -> None:
        # Not a constraint violation, because there is no constraint. The log records
        # what was attempted, and an attempt against an id nobody holds is exactly the
        # kind of thing an audit log is read to find.
        await log.record(
            AuditAction.ACCOUNT_DISABLED, actor_id=BREAK_GLASS_ACTOR, target_id="acct_nobody"
        )

        assert await log.count() == 1


class TestDurability:
    async def test_entries_survive_a_restart(self, database: Database, clock: FakeClock) -> None:
        from keyring_api.storage.database import Database as Db
        from keyring_api.storage.migrator import migrate

        path = database.path
        await SqlAuditLog(database=database, clock=clock).record(
            AuditAction.ROLE_CREATED, actor_id=BREAK_GLASS_ACTOR, detail="role 'support'"
        )
        await database.aclose()

        reopened = Db(path)
        migrate(reopened, now=EPOCH)
        try:
            restored = SqlAuditLog(database=reopened, clock=clock)

            assert [entry.detail for entry in await restored.recent()] == ["role 'support'"]
        finally:
            await reopened.aclose()

    async def test_the_order_survives_a_restart(self, database: Database, clock: FakeClock) -> None:
        """Ordering is the sequence column, not the timestamp.

        These three share a timestamp, because the clock does not move between them.
        A restart must not turn "newest first" into an arbitrary permutation.
        """
        from keyring_api.storage.database import Database as Db
        from keyring_api.storage.migrator import migrate

        path = database.path
        log = SqlAuditLog(database=database, clock=clock)
        for index in range(3):
            await log.record(
                AuditAction.ROLE_CREATED, actor_id=BREAK_GLASS_ACTOR, detail=str(index)
            )
        await database.aclose()

        reopened = Db(path)
        migrate(reopened, now=EPOCH)
        try:
            restored = SqlAuditLog(database=reopened, clock=clock)

            assert [entry.detail for entry in await restored.recent()] == ["2", "1", "0"]
        finally:
            await reopened.aclose()
