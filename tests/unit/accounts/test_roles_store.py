"""The role store, and the last-owner guarantee inside the account store.

The CRUD half is ordinary. The half worth reading is the pair of operations that can
leave a deployment with nobody able to administer it -- demoting an owner and deleting an
owner -- both of which check and write as one transaction.

The concurrency tests come in two shapes, and both changed when these stores moved into
SQL. The plain ``gather`` ones submit every call before any of them runs, because the
database serializes on a single worker thread. The reinforced ones occupy that thread
first, so every call is provably queued and unstarted before the first one is allowed to
proceed -- exactly the interleaving in which a check made outside the transaction reads
"there are four owners" four times and every demotion goes ahead.

They no longer reach for a lock to park on. What they assert now is the *outcome* --
exactly one owner survives -- rather than the mechanism, which means they would still
mean something if the single connection were ever replaced by a pool.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from keyring_api.accounts.roles import RoleStore
from keyring_api.accounts.sql_roles import SqlRoleStore
from keyring_api.accounts.sql_store import SqlAccountStore
from keyring_api.domain.accounts import Account, AccountStatus, new_account_id
from keyring_api.domain.errors import (
    AccountNotFoundError,
    InvalidRoleError,
    LastOwnerError,
    RoleExistsError,
    RoleInUseError,
    RoleNotFoundError,
)
from keyring_api.domain.rbac import (
    ADMIN,
    ALL_PERMISSIONS,
    AUDITOR,
    BUILTIN_ROLES,
    MEMBER,
    OWNER,
    Permission,
    Role,
)
from tests.fakes.clock import EPOCH

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

    from keyring_api.storage.database import Database

SCHEDULER_TURNS = 8
"""Passes through the event loop, enough for every queued call to reach the database."""


def make_account(
    email: str = "person@example.com",
    *,
    roles: tuple[str, ...] = (),
    created_at: datetime = EPOCH,
    status: AccountStatus = AccountStatus.ACTIVE,
) -> Account:
    return Account(
        account_id=new_account_id(),
        email=email,
        password_hash="$argon2id$fake",
        created_at=created_at,
        updated_at=created_at,
        status=status,
        roles=roles,
    )


def make_role(name: str, *permissions: Permission) -> Role:
    return Role(name=name, permissions=frozenset(permissions), description=f"the {name} role")


@contextlib.asynccontextmanager
async def database_held(database: Database) -> AsyncIterator[None]:
    """Occupy the database's only worker thread for the duration of the block.

    The successor to parking every call on a store's lock. Everything submitted inside
    the block queues behind this and cannot begin, so a test can line several calls up
    and know that none of them has read anything yet.
    """
    started = threading.Event()
    release = threading.Event()

    def block(_connection: Any) -> None:
        started.set()
        release.wait(timeout=5)

    holding = asyncio.create_task(database.run(block))
    for _ in range(1000):
        if started.is_set():
            break
        await asyncio.sleep(0.001)
    assert started.is_set(), "the database never picked the blocking call up"

    try:
        yield
    finally:
        release.set()
        await holding


async def park_behind_the_database(calls: Sequence[asyncio.Future[Any]]) -> None:
    """Let every call start and queue behind the held database.

    Asserting that none of them finished is what makes the reinforced tests mean
    something: it proves each call really is suspended before it has read anything,
    rather than having run to completion before the next one started.
    """
    for _ in range(SCHEDULER_TURNS):
        await asyncio.sleep(0)

    assert [call.done() for call in calls] == [False] * len(calls)


class TestRoleStore:
    @pytest.fixture
    def store(self, database: Database) -> SqlRoleStore:
        return SqlRoleStore(database=database)

    async def test_it_satisfies_the_port(self, store: SqlRoleStore) -> None:
        checked: RoleStore = store

        assert isinstance(checked, RoleStore)

    @pytest.mark.parametrize("name", [OWNER, ADMIN, AUDITOR, MEMBER])
    async def test_a_fresh_store_already_holds_the_builtin_roles(
        self, store: SqlRoleStore, name: str
    ) -> None:
        # A deployment has to be administrable before anyone has defined a role.
        role = await store.get(name)

        assert role is not None
        assert role.permissions == BUILTIN_ROLES[name]
        assert role.builtin

    async def test_the_builtins_match_the_domain_definition_exactly(
        self, store: SqlRoleStore
    ) -> None:
        """One definition of what ``admin`` means, not two that drift.

        The built-ins are seeded from ``domain.rbac`` rather than written into the
        migration, and this is what says so: adding a permission to a built-in role in
        the domain is enough, with no second edit anywhere.
        """
        stored = {role.name: role.permissions for role in await store.list_all() if role.builtin}

        assert stored == BUILTIN_ROLES

    async def test_an_unknown_role_reads_back_as_absent(self, store: SqlRoleStore) -> None:
        assert await store.get("ghost") is None

    async def test_requiring_a_known_role_returns_the_whole_role(self, store: SqlRoleStore) -> None:
        role = await store.require(AUDITOR)

        assert role.name == AUDITOR
        assert role.permissions == BUILTIN_ROLES[AUDITOR]
        assert role.builtin

    async def test_requiring_an_unknown_role_raises(self, store: SqlRoleStore) -> None:
        with pytest.raises(RoleNotFoundError):
            await store.require("ghost")

    async def test_listing_puts_builtins_first_then_custom_roles_alphabetically(
        self, store: SqlRoleStore
    ) -> None:
        # Built-ins are the vocabulary the custom roles were defined in terms of, so a
        # reader meets them first.
        await store.add(make_role("zebra", Permission.ACCOUNTS_READ))
        await store.add(make_role("aardvark", Permission.ACCOUNTS_READ))

        names = [role.name for role in await store.list_all()]

        assert names == [ADMIN, AUDITOR, MEMBER, OWNER, "aardvark", "zebra"]

    async def test_the_listing_is_a_copy_rather_than_a_way_into_the_store(
        self, store: SqlRoleStore
    ) -> None:
        listed = await store.list_all()
        listed.clear()

        assert len(await store.list_all()) == len(BUILTIN_ROLES)

    async def test_an_added_role_is_stored_as_a_custom_one(self, store: SqlRoleStore) -> None:
        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        stored = await store.get("support")

        assert stored is not None
        assert stored.permissions == frozenset({Permission.ACCOUNTS_READ})
        assert not stored.builtin

    async def test_a_role_round_trips_its_description_and_timestamps(
        self, store: SqlRoleStore
    ) -> None:
        role = Role(
            name="support",
            permissions=frozenset({Permission.ACCOUNTS_READ}),
            description="answers the phone",
            created_at=EPOCH,
            updated_at=EPOCH + timedelta(hours=1),
        )
        await store.add(role)

        assert await store.get("support") == role

    async def test_a_second_role_with_the_same_name_leaves_the_first_one_untouched(
        self, store: SqlRoleStore
    ) -> None:
        # The refusal has to happen before the write, not alongside it: an add that
        # stored the role and then raised would redefine an existing role while
        # reporting failure, and the caller would never look again.
        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        with pytest.raises(RoleExistsError):
            await store.add(make_role("support", Permission.ACCOUNTS_DELETE))

        stored = await store.get("support")
        assert stored is not None
        assert stored.permissions == frozenset({Permission.ACCOUNTS_READ})

    async def test_a_role_named_after_a_builtin_leaves_the_builtin_untouched(
        self, store: SqlRoleStore
    ) -> None:
        # Shadowing "member" with a custom definition would be an escalation that never
        # shows up as a role change on anybody's account: every account already holds
        # it. So the refusal is checked, and so is the built-in still being empty
        # afterwards.
        with pytest.raises(RoleExistsError):
            await store.add(make_role(MEMBER, Permission.ACCOUNTS_DELETE))

        stored = await store.get(MEMBER)
        assert stored is not None
        assert stored.permissions == frozenset()
        assert stored.builtin

    async def test_two_simultaneous_adds_of_one_name_cannot_both_win(
        self, store: SqlRoleStore, database: Database
    ) -> None:
        # Taken with the test above: "the name is taken" is decided inside the same
        # transaction that writes, so a second definition cannot slip past by arriving
        # at the same moment as the first.
        async with database_held(database):
            adds = [
                asyncio.create_task(store.add(make_role("support", Permission.ACCOUNTS_READ))),
                asyncio.create_task(store.add(make_role("support", Permission.ACCOUNTS_DELETE))),
            ]
            await park_behind_the_database(adds)

        outcomes = await asyncio.gather(*adds, return_exceptions=True)

        refused = [outcome for outcome in outcomes if isinstance(outcome, RoleExistsError)]
        assert len(refused) == 1
        stored = await store.get("support")
        assert stored is not None
        winner = Permission.ACCOUNTS_READ if outcomes[0] is None else Permission.ACCOUNTS_DELETE
        assert stored.permissions == frozenset({winner})

    async def test_saving_replaces_the_stored_role(self, store: SqlRoleStore) -> None:
        role = make_role("support", Permission.ACCOUNTS_READ)
        await store.add(role)

        await store.save(
            role.with_permissions(
                frozenset({Permission.AUDIT_READ}), description="narrowed", now=EPOCH
            )
        )

        stored = await store.get("support")
        assert stored is not None
        assert stored.permissions == frozenset({Permission.AUDIT_READ})
        assert stored.description == "narrowed"
        assert not stored.builtin

    async def test_saving_does_not_itself_refuse_a_builtin_name(self, store: SqlRoleStore) -> None:
        # Recorded because it is the one asymmetry in this store: add() and delete()
        # both refuse a built-in, save() does not. Built-in immutability is enforced one
        # layer up, in AdminService.update_role, which checks role.builtin before it
        # gets here -- so this store is only safe while that is the sole caller of
        # save(). A second caller, or an adapter reimplementing this port, has to bring
        # the check with it.
        overwritten = Role(name=MEMBER, permissions=ALL_PERMISSIONS, builtin=True)

        await store.save(overwritten)

        stored = await store.get(MEMBER)
        assert stored is not None
        assert stored.permissions == ALL_PERMISSIONS

    async def test_deleting_a_builtin_role_is_refused(self, store: SqlRoleStore) -> None:
        with pytest.raises(InvalidRoleError):
            await store.delete(MEMBER, held_by=0)

        assert await store.get(MEMBER) is not None

    async def test_deleting_an_unheld_custom_role_removes_it(self, store: SqlRoleStore) -> None:
        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        await store.delete("support", held_by=0)

        assert await store.get("support") is None
        with pytest.raises(RoleNotFoundError):
            await store.require("support")

    async def test_a_deleted_name_can_be_defined_again_from_scratch(
        self, store: SqlRoleStore
    ) -> None:
        # The second definition is a new role, not a resurrection of the old one: the
        # permissions it was deleted with must not come back with the name.
        await store.add(make_role("support", Permission.ACCOUNTS_DELETE))
        await store.delete("support", held_by=0)

        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        stored = await store.get("support")
        assert stored is not None
        assert stored.permissions == frozenset({Permission.ACCOUNTS_READ})

    async def test_deleting_an_unknown_role_raises(self, store: SqlRoleStore) -> None:
        with pytest.raises(RoleNotFoundError):
            await store.delete("ghost", held_by=0)

    async def test_resolving_unions_the_permissions_of_every_named_role(
        self, store: SqlRoleStore
    ) -> None:
        # Additive, not a precedence order: there is no rule anyone has to remember
        # about which of an account's roles wins.
        await store.add(make_role("support", Permission.ACCOUNTS_INVITE))

        resolved = await store.resolve((AUDITOR, "support"))

        assert resolved == BUILTIN_ROLES[AUDITOR] | {Permission.ACCOUNTS_INVITE}

    async def test_resolving_the_same_role_twice_grants_it_once(self, store: SqlRoleStore) -> None:
        assert await store.resolve((AUDITOR, AUDITOR)) == BUILTIN_ROLES[AUDITOR]

    async def test_resolving_no_roles_grants_no_permissions(self, store: SqlRoleStore) -> None:
        assert await store.resolve(()) == frozenset()

    async def test_a_name_with_no_role_behind_it_contributes_nothing(
        self, store: SqlRoleStore
    ) -> None:
        # The safe reading of an inconsistent store is "no permissions", never "all of
        # them" -- and never an exception, which would lock every holder out of a
        # deployment because one role name went missing.
        assert await store.resolve((AUDITOR, "ghost")) == BUILTIN_ROLES[AUDITOR]
        assert await store.resolve(("ghost",)) == frozenset()


class TestDeletingARoleSomebodyHolds:
    """The race the in-memory adapter could not close, and the foreign key does.

    ``delete()`` used to be told how many accounts held the role, and the caller took
    that count outside the store -- so a grant could land in between and the "nobody
    holds it" refusal could be decided on a number that was already out of date. The
    count is now taken inside the transaction that does the delete, and
    ``account_roles.role_name`` is ``ON DELETE RESTRICT`` underneath it.
    """

    @pytest.fixture
    def roles(self, database: Database) -> SqlRoleStore:
        return SqlRoleStore(database=database)

    @pytest.fixture
    def accounts(self, database: Database) -> SqlAccountStore:
        return SqlAccountStore(database=database)

    async def test_deleting_a_role_accounts_still_hold_is_refused(
        self, roles: SqlRoleStore, accounts: SqlAccountStore
    ) -> None:
        # Refused rather than cascaded: silently stripping a permission from everybody
        # who had it is the kind of change nobody notices until somebody cannot work.
        await roles.add(make_role("support", Permission.ACCOUNTS_READ))
        await accounts.add(make_account(roles=("support",)))

        with pytest.raises(RoleInUseError):
            await roles.delete("support", held_by=0)

        assert await roles.get("support") is not None

    async def test_the_refusal_says_how_many_still_hold_it(
        self, roles: SqlRoleStore, accounts: SqlAccountStore
    ) -> None:
        await roles.add(make_role("support", Permission.ACCOUNTS_READ))
        await accounts.add(make_account("a@example.com", roles=("support",)))
        await accounts.add(make_account("b@example.com", roles=("support",)))

        with pytest.raises(RoleInUseError, match="2 account"):
            await roles.delete("support", held_by=99)

    async def test_a_stale_count_from_the_caller_no_longer_decides_it(
        self, roles: SqlRoleStore, accounts: SqlAccountStore
    ) -> None:
        """The count the caller passes is ignored, and this is what that buys.

        Here the caller reads "nobody holds it", the role is granted to somebody, and
        only then does the delete arrive carrying the stale zero. The in-memory adapter
        deleted it and left the holder resolving to no permissions. This one re-reads.
        """
        holder = make_account(roles=(MEMBER,))
        await accounts.add(holder)
        await roles.add(make_role("support", Permission.ACCOUNTS_DELETE))

        held_by = await accounts.count_holding("support")
        await accounts.set_roles(holder.account_id, ("support",), now=EPOCH)

        with pytest.raises(RoleInUseError):
            await roles.delete("support", held_by=held_by)

        assert await roles.resolve(("support",)) == frozenset({Permission.ACCOUNTS_DELETE})

    async def test_granting_a_role_that_no_longer_exists_is_a_domain_error(
        self, accounts: SqlAccountStore
    ) -> None:
        """Not a driver exception surfacing as a 500.

        Callers check the role exists before granting it, so this is only reachable when
        the role is deleted in between -- but "in between" is exactly what a vault has to
        answer cleanly.
        """
        await accounts.add(make_account("owner@example.com", roles=(OWNER,)))
        holder = make_account(roles=(MEMBER,))
        await accounts.add(holder)

        with pytest.raises(RoleNotFoundError):
            await accounts.set_roles(holder.account_id, ("vanished",), now=EPOCH)

        stored = await accounts.get(holder.account_id)
        assert stored is not None
        assert stored.roles == (MEMBER,)

    async def test_adding_an_account_with_a_role_that_does_not_exist_is_refused(
        self, accounts: SqlAccountStore
    ) -> None:
        with pytest.raises(RoleNotFoundError):
            await accounts.add(make_account(roles=("vanished",)))

        assert await accounts.count() == 0

    async def test_a_grant_racing_a_delete_cannot_orphan_the_holder(
        self, roles: SqlRoleStore, accounts: SqlAccountStore, database: Database
    ) -> None:
        """Both orders are safe: either the delete refuses, or the grant does.

        What must never happen is both succeeding, which leaves an account holding a
        role that does not exist and therefore holding no permissions at all.
        """
        holder = make_account(roles=(MEMBER,))
        await accounts.add(holder)
        await roles.add(make_role("support", Permission.ACCOUNTS_DELETE))

        async with database_held(database):
            calls = [
                asyncio.create_task(accounts.set_roles(holder.account_id, ("support",), now=EPOCH)),
                asyncio.create_task(roles.delete("support", held_by=0)),
            ]
            await park_behind_the_database(calls)

        await asyncio.gather(*calls, return_exceptions=True)

        stored = await accounts.get(holder.account_id)
        assert stored is not None
        for name in stored.roles:
            assert await roles.get(name) is not None, f"{name!r} is held but does not exist"


class TestAccountStoreRoles:
    @pytest.fixture
    def store(self, database: Database) -> SqlAccountStore:
        return SqlAccountStore(database=database)

    async def test_setting_roles_replaces_them_and_returns_the_updated_account(
        self, store: SqlAccountStore
    ) -> None:
        account = make_account(roles=(MEMBER,))
        await store.add(account)
        later = EPOCH + timedelta(hours=1)

        updated = await store.set_roles(account.account_id, (AUDITOR,), now=later)

        assert updated.roles == (AUDITOR,)
        assert updated.updated_at == later
        stored = await store.get(account.account_id)
        assert stored is not None
        assert stored.roles == (AUDITOR,)
        assert stored.updated_at == later

    async def test_setting_roles_changes_nothing_else_about_the_account(
        self, store: SqlAccountStore
    ) -> None:
        # A role change is not a rehabilitation: an account an administrator disabled
        # must still be disabled afterwards, or demoting somebody would quietly hand
        # them their login back.
        account = make_account(roles=(ADMIN,), status=AccountStatus.DISABLED)
        await store.add(account)

        updated = await store.set_roles(
            account.account_id, (MEMBER,), now=EPOCH + timedelta(hours=1)
        )

        assert updated.status is AccountStatus.DISABLED
        assert updated.email == account.email
        assert updated.password_hash == account.password_hash
        assert updated.created_at == EPOCH

    async def test_setting_roles_returns_a_new_account_rather_than_editing_the_old_one(
        self, store: SqlAccountStore
    ) -> None:
        # The caller may be holding an account read before the change, and it must not
        # mutate underneath them.
        account = make_account(roles=(MEMBER,))
        await store.add(account)

        updated = await store.set_roles(account.account_id, (AUDITOR,), now=EPOCH)

        assert updated is not account
        assert account.roles == (MEMBER,)

    async def test_setting_roles_on_an_unknown_account_raises(self, store: SqlAccountStore) -> None:
        with pytest.raises(AccountNotFoundError):
            await store.set_roles("acct_nope", (MEMBER,), now=EPOCH)

    async def test_demoting_the_last_owner_is_refused(self, store: SqlAccountStore) -> None:
        # A deployment with no owner cannot appoint one, because appointing an owner
        # requires being one. The only way back in is the break-glass token.
        owner = make_account(roles=(OWNER,))
        await store.add(owner)
        await store.add(make_account("other@example.com", roles=(MEMBER,)))

        with pytest.raises(LastOwnerError):
            await store.set_roles(owner.account_id, (MEMBER,), now=EPOCH)

        stored = await store.get(owner.account_id)
        assert stored is not None
        assert stored.roles == (OWNER,)

    async def test_a_refused_demotion_does_not_touch_the_timestamp_either(
        self, store: SqlAccountStore
    ) -> None:
        """The whole transaction rolls back, not just the role rows."""
        owner = make_account(roles=(OWNER,))
        await store.add(owner)

        with pytest.raises(LastOwnerError):
            await store.set_roles(owner.account_id, (MEMBER,), now=EPOCH + timedelta(days=1))

        stored = await store.get(owner.account_id)
        assert stored is not None
        assert stored.updated_at == EPOCH

    async def test_stripping_every_role_from_the_last_owner_is_refused(
        self, store: SqlAccountStore
    ) -> None:
        # The empty set is the shortest way to write the demotion, and the one a
        # "reset this account" code path reaches for.
        owner = make_account(roles=(OWNER,))
        await store.add(owner)

        with pytest.raises(LastOwnerError):
            await store.set_roles(owner.account_id, (), now=EPOCH)

        assert await store.count_holding(OWNER) == 1

    @pytest.mark.parametrize("lookalike", ["Owner", "OWNER", " owner", "owners", "owner "])
    async def test_a_role_name_that_merely_resembles_owner_does_not_satisfy_the_guard(
        self, store: SqlAccountStore, lookalike: str
    ) -> None:
        # The guard compares role names exactly, and nothing normalizes them on the way
        # in. A near-miss therefore fails closed -- the demotion is refused -- rather
        # than counting as "still an owner" and leaving the deployment with a role
        # nobody has any permissions for.
        owner = make_account(roles=(OWNER,))
        await store.add(owner)

        with pytest.raises(LastOwnerError):
            await store.set_roles(owner.account_id, (lookalike,), now=EPOCH)

        assert await store.count_holding(OWNER) == 1

    async def test_demoting_an_owner_who_is_not_the_last_one_is_allowed(
        self, store: SqlAccountStore
    ) -> None:
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        updated = await store.set_roles(first.account_id, (MEMBER,), now=EPOCH)

        assert updated.roles == (MEMBER,)
        assert await store.count_holding(OWNER) == 1

    async def test_the_other_owner_counts_wherever_owner_sits_among_their_roles(
        self, store: SqlAccountStore
    ) -> None:
        # Roles are a set written as a tuple; there is no first-role-wins rule, and the
        # survivor count has to search all of them rather than look at one slot.
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(AUDITOR, MEMBER, OWNER))
        await store.add(first)
        await store.add(second)

        updated = await store.set_roles(first.account_id, (MEMBER,), now=EPOCH)

        assert updated.roles == (MEMBER,)
        assert await store.count_holding(OWNER) == 1

    async def test_the_last_owner_may_change_roles_while_staying_an_owner(
        self, store: SqlAccountStore
    ) -> None:
        # The guard is about the owner role surviving, not about the account's roles
        # being frozen.
        owner = make_account(roles=(OWNER,))
        await store.add(owner)

        updated = await store.set_roles(owner.account_id, (OWNER, AUDITOR), now=EPOCH)

        assert updated.roles == (OWNER, AUDITOR)
        stored = await store.get(owner.account_id)
        assert stored is not None
        assert stored.roles == (OWNER, AUDITOR)

    async def test_appointing_a_second_owner_first_lets_the_first_one_step_down(
        self, store: SqlAccountStore
    ) -> None:
        # The supported way out. The guard refuses the state, not the intent, so the
        # two-step version of a demotion the store refused in one step is allowed --
        # and that is the difference between a safety rail and a trap.
        owner = make_account("owner@example.com", roles=(OWNER,))
        successor = make_account("successor@example.com", roles=(MEMBER,))
        await store.add(owner)
        await store.add(successor)

        await store.set_roles(successor.account_id, (OWNER,), now=EPOCH)
        updated = await store.set_roles(owner.account_id, (MEMBER,), now=EPOCH)

        assert updated.roles == (MEMBER,)
        assert await store.count_holding(OWNER) == 1

    async def test_deleting_the_other_owner_first_does_not_open_the_way_to_stepping_down(
        self, store: SqlAccountStore
    ) -> None:
        # The two-step version of the attack: thin the owners out one call at a time and
        # hope the guard only ever looks at the arguments of the call in front of it. It
        # re-reads every time, so the second step lands on a deployment with exactly one
        # owner and is refused.
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        assert await store.delete(second.account_id)
        with pytest.raises(LastOwnerError):
            await store.set_roles(first.account_id, (MEMBER,), now=EPOCH)

        assert await store.count_holding(OWNER) == 1

    async def test_deleting_the_last_owner_account_is_refused(self, store: SqlAccountStore) -> None:
        owner = make_account(roles=(OWNER,))
        await store.add(owner)

        with pytest.raises(LastOwnerError):
            await store.delete(owner.account_id)

        assert await store.get(owner.account_id) is not None

    async def test_deleting_an_account_that_is_not_an_owner_is_allowed(
        self, store: SqlAccountStore
    ) -> None:
        owner = make_account("owner@example.com", roles=(OWNER,))
        member = make_account("member@example.com", roles=(MEMBER,))
        await store.add(owner)
        await store.add(member)

        assert await store.delete(member.account_id)
        assert await store.get(member.account_id) is None

    async def test_deleting_one_of_two_owners_is_allowed(self, store: SqlAccountStore) -> None:
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        assert await store.delete(first.account_id)
        assert await store.count_holding(OWNER) == 1

    async def test_deleting_both_owners_one_after_the_other_is_refused_at_the_second(
        self, store: SqlAccountStore
    ) -> None:
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        assert await store.delete(first.account_id)
        with pytest.raises(LastOwnerError):
            await store.delete(second.account_id)

        assert await store.get(second.account_id) is not None

    async def test_two_simultaneous_demotions_cannot_between_them_remove_every_owner(
        self, store: SqlAccountStore
    ) -> None:
        # The whole reason the check and the write are one transaction. Performed by a
        # caller instead, both of these read "there are two owners", both conclude they
        # are safe to proceed, and the deployment ends with none.
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        outcomes = await asyncio.gather(
            store.set_roles(first.account_id, (MEMBER,), now=EPOCH),
            store.set_roles(second.account_id, (MEMBER,), now=EPOCH),
            return_exceptions=True,
        )

        assert await store.count_holding(OWNER) == 1
        refused = [outcome for outcome in outcomes if isinstance(outcome, LastOwnerError)]
        assert len(refused) == 1

    async def test_demotions_that_all_start_before_any_of_them_writes_still_leave_an_owner(
        self, store: SqlAccountStore, database: Database
    ) -> None:
        # The reinforced version, and the one with teeth. The database is occupied
        # first, so all four demotions are queued and unstarted before any of them may
        # read -- exactly the interleaving in which a check made outside the transaction
        # reads "there are four owners" four times and every demotion proceeds.
        owners = [make_account(f"owner{index}@example.com", roles=(OWNER,)) for index in range(4)]
        for owner in owners:
            await store.add(owner)

        async with database_held(database):
            demotions = [
                asyncio.create_task(store.set_roles(owner.account_id, (MEMBER,), now=EPOCH))
                for owner in owners
            ]
            await park_behind_the_database(demotions)

        outcomes = await asyncio.gather(*demotions, return_exceptions=True)

        assert await store.count_holding(OWNER) == 1
        refused = [outcome for outcome in outcomes if isinstance(outcome, LastOwnerError)]
        assert len(refused) == 1

    async def test_a_demotion_and_a_deletion_racing_cannot_between_them_remove_every_owner(
        self, store: SqlAccountStore, database: Database
    ) -> None:
        # Both routes out of the owner role share one guard, so mixing them is not a way
        # around either. Whichever reaches the database first wins; the assertions do
        # not care which, only that exactly one did.
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        async with database_held(database):
            demotion = asyncio.create_task(store.set_roles(first.account_id, (MEMBER,), now=EPOCH))
            deletion = asyncio.create_task(store.delete(second.account_id))
            await park_behind_the_database([demotion, deletion])

        outcomes = await asyncio.gather(demotion, deletion, return_exceptions=True)

        assert await store.count_holding(OWNER) == 1
        refused = [outcome for outcome in outcomes if isinstance(outcome, LastOwnerError)]
        assert len(refused) == 1

    async def test_counting_holders_ignores_accounts_without_that_role(
        self, store: SqlAccountStore
    ) -> None:
        await store.add(make_account("owner@example.com", roles=(OWNER, AUDITOR)))
        await store.add(make_account("auditor@example.com", roles=(AUDITOR,)))
        await store.add(make_account("member@example.com", roles=(MEMBER,)))

        assert await store.count_holding(AUDITOR) == 2
        assert await store.count_holding(OWNER) == 1
        assert await store.count_holding("ghost") == 0

    async def test_an_account_naming_a_role_twice_is_still_one_holder(
        self, store: SqlAccountStore
    ) -> None:
        # The count decides whether a role may be deleted. Counting names rather than
        # accounts would make a role with a duplicated name permanently undeletable.
        await store.add(make_account("owner@example.com", roles=(OWNER,)))
        await store.add(make_account("double@example.com", roles=(AUDITOR, AUDITOR)))

        assert await store.count_holding(AUDITOR) == 1

    async def test_a_disabled_owner_still_counts_as_the_surviving_owner(
        self, store: SqlAccountStore
    ) -> None:
        # Recorded rather than assumed, because it is the one shape in which the lockout
        # this guard exists to prevent is still reachable: disable the other owner, then
        # step down, and every owner that remains is one that cannot log in. The guard
        # counts the role, not who can currently authenticate. A status-aware check
        # belongs in this transaction, and not in a caller.
        disabled = make_account(
            "disabled@example.com", roles=(OWNER,), status=AccountStatus.DISABLED
        )
        active = make_account("active@example.com", roles=(OWNER,))
        await store.add(disabled)
        await store.add(active)

        updated = await store.set_roles(active.account_id, (MEMBER,), now=EPOCH)

        assert updated.roles == (MEMBER,)
        assert await store.count_holding(OWNER) == 1

    async def test_listing_accounts_returns_every_one_oldest_first(
        self, store: SqlAccountStore
    ) -> None:
        middle = make_account("middle@example.com", created_at=EPOCH + timedelta(hours=1))
        oldest = make_account("oldest@example.com", created_at=EPOCH)
        newest = make_account("newest@example.com", created_at=EPOCH + timedelta(hours=2))
        for account in (middle, oldest, newest):
            await store.add(account)

        listed = await store.list_all()

        assert [account.email for account in listed] == [
            "oldest@example.com",
            "middle@example.com",
            "newest@example.com",
        ]

    async def test_listing_carries_each_account_s_roles(self, store: SqlAccountStore) -> None:
        await store.add(make_account("owner@example.com", roles=(OWNER,)))
        await store.add(make_account("plain@example.com"))

        listed = await store.list_all()

        assert {account.email: account.roles for account in listed} == {
            "owner@example.com": (OWNER,),
            "plain@example.com": (),
        }

    async def test_owner_is_the_role_the_guard_is_written_against(self) -> None:
        # The guard names one role. If OWNER ever stopped being the everything-role,
        # the lockout protection would be guarding the wrong thing.
        assert BUILTIN_ROLES[OWNER] == ALL_PERMISSIONS
