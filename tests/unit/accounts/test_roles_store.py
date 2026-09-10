"""The role store, and the last-owner guarantee inside the account store.

The CRUD half is ordinary. The half worth reading is the pair of operations that can
leave a deployment with nobody able to administer it -- demoting an owner and deleting
an owner -- both of which check and write as one step under the store's lock.

The concurrency tests come in two shapes. The plain ``gather`` ones run the calls
back-to-back, which is what an event loop actually does with a lock nobody is holding.
The reinforced ones take the store's lock first, park every call on it, and only then
let go: that forces the interleaving a check performed *outside* the lock would lose to,
where every caller reads the store before any of them writes.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from keyring_api.accounts.roles import InMemoryRoleStore, RoleStore
from keyring_api.accounts.store import InMemoryAccountStore
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
    from collections.abc import Sequence

SCHEDULER_TURNS = 8
"""Passes through the event loop, enough for every parked call to reach the lock."""


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


async def park_on_the_store_lock(calls: Sequence[asyncio.Future[Any]]) -> None:
    """Let every call start and block on the lock the test is currently holding.

    Asserting that none of them finished is what makes the reinforced concurrency tests
    mean something: it proves each call really is suspended mid-operation, rather than
    having run to completion before the next one started.
    """
    for _ in range(SCHEDULER_TURNS):
        await asyncio.sleep(0)

    assert [call.done() for call in calls] == [False] * len(calls)


class TestRoleStore:
    @pytest.fixture
    def store(self) -> InMemoryRoleStore:
        return InMemoryRoleStore()

    async def test_it_satisfies_the_port(self, store: InMemoryRoleStore) -> None:
        checked: RoleStore = store

        assert isinstance(checked, RoleStore)

    @pytest.mark.parametrize("name", [OWNER, ADMIN, AUDITOR, MEMBER])
    async def test_a_fresh_store_already_holds_the_builtin_roles(
        self, store: InMemoryRoleStore, name: str
    ) -> None:
        # A deployment has to be administrable before anyone has defined a role.
        role = await store.get(name)

        assert role is not None
        assert role.permissions == BUILTIN_ROLES[name]
        assert role.builtin

    async def test_an_unknown_role_reads_back_as_absent(self, store: InMemoryRoleStore) -> None:
        assert await store.get("ghost") is None

    async def test_requiring_a_known_role_returns_the_whole_role(
        self, store: InMemoryRoleStore
    ) -> None:
        role = await store.require(AUDITOR)

        assert role.name == AUDITOR
        assert role.permissions == BUILTIN_ROLES[AUDITOR]
        assert role.builtin

    async def test_requiring_an_unknown_role_raises(self, store: InMemoryRoleStore) -> None:
        with pytest.raises(RoleNotFoundError):
            await store.require("ghost")

    async def test_listing_puts_builtins_first_then_custom_roles_alphabetically(
        self, store: InMemoryRoleStore
    ) -> None:
        # Built-ins are the vocabulary the custom roles were defined in terms of, so a
        # reader meets them first.
        await store.add(make_role("zebra", Permission.ACCOUNTS_READ))
        await store.add(make_role("aardvark", Permission.ACCOUNTS_READ))

        names = [role.name for role in await store.list_all()]

        assert names == [ADMIN, AUDITOR, MEMBER, OWNER, "aardvark", "zebra"]

    async def test_the_listing_is_a_copy_rather_than_a_way_into_the_store(
        self, store: InMemoryRoleStore
    ) -> None:
        listed = await store.list_all()
        listed.clear()

        assert len(await store.list_all()) == len(BUILTIN_ROLES)

    async def test_an_added_role_is_stored_as_a_custom_one(self, store: InMemoryRoleStore) -> None:
        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        stored = await store.get("support")

        assert stored is not None
        assert stored.permissions == frozenset({Permission.ACCOUNTS_READ})
        assert not stored.builtin

    async def test_a_second_role_with_the_same_name_leaves_the_first_one_untouched(
        self, store: InMemoryRoleStore
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
        self, store: InMemoryRoleStore
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
        self, store: InMemoryRoleStore
    ) -> None:
        # Taken together with the test above: "the name is taken" is decided under the
        # lock, so a second definition cannot slip past by arriving at the same moment
        # as the first.
        await store._lock.acquire()
        adds = [
            asyncio.create_task(store.add(make_role("support", Permission.ACCOUNTS_READ))),
            asyncio.create_task(store.add(make_role("support", Permission.ACCOUNTS_DELETE))),
        ]
        try:
            await park_on_the_store_lock(adds)
        finally:
            store._lock.release()

        outcomes = await asyncio.gather(*adds, return_exceptions=True)

        refused = [outcome for outcome in outcomes if isinstance(outcome, RoleExistsError)]
        assert len(refused) == 1
        stored = await store.get("support")
        assert stored is not None
        winner = Permission.ACCOUNTS_READ if outcomes[0] is None else Permission.ACCOUNTS_DELETE
        assert stored.permissions == frozenset({winner})

    async def test_saving_replaces_the_stored_role(self, store: InMemoryRoleStore) -> None:
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

    async def test_saving_does_not_itself_refuse_a_builtin_name(
        self, store: InMemoryRoleStore
    ) -> None:
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

    async def test_deleting_a_builtin_role_is_refused(self, store: InMemoryRoleStore) -> None:
        with pytest.raises(InvalidRoleError):
            await store.delete(MEMBER, held_by=0)

        assert await store.get(MEMBER) is not None

    async def test_deleting_a_role_accounts_still_hold_is_refused(
        self, store: InMemoryRoleStore
    ) -> None:
        # Refused rather than cascaded: silently stripping a permission from everybody
        # who had it is the kind of change nobody notices until somebody cannot work.
        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        with pytest.raises(RoleInUseError):
            await store.delete("support", held_by=2)

        assert await store.get("support") is not None

    async def test_deleting_an_unheld_custom_role_removes_it(
        self, store: InMemoryRoleStore
    ) -> None:
        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        await store.delete("support", held_by=0)

        assert await store.get("support") is None
        with pytest.raises(RoleNotFoundError):
            await store.require("support")

    async def test_a_deleted_name_can_be_defined_again_from_scratch(
        self, store: InMemoryRoleStore
    ) -> None:
        # The second definition is a new role, not a resurrection of the old one: the
        # permissions it was deleted with must not come back with the name.
        await store.add(make_role("support", Permission.ACCOUNTS_DELETE))
        await store.delete("support", held_by=0)

        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        stored = await store.get("support")
        assert stored is not None
        assert stored.permissions == frozenset({Permission.ACCOUNTS_READ})

    async def test_deleting_an_unknown_role_raises(self, store: InMemoryRoleStore) -> None:
        with pytest.raises(RoleNotFoundError):
            await store.delete("ghost", held_by=0)

    async def test_resolving_unions_the_permissions_of_every_named_role(
        self, store: InMemoryRoleStore
    ) -> None:
        # Additive, not a precedence order: there is no rule anyone has to remember
        # about which of an account's roles wins.
        await store.add(make_role("support", Permission.ACCOUNTS_INVITE))

        resolved = await store.resolve((AUDITOR, "support"))

        assert resolved == BUILTIN_ROLES[AUDITOR] | {Permission.ACCOUNTS_INVITE}

    async def test_resolving_the_same_role_twice_grants_it_once(
        self, store: InMemoryRoleStore
    ) -> None:
        assert await store.resolve((AUDITOR, AUDITOR)) == BUILTIN_ROLES[AUDITOR]

    async def test_resolving_no_roles_grants_no_permissions(self, store: InMemoryRoleStore) -> None:
        assert await store.resolve(()) == frozenset()

    async def test_a_name_with_no_role_behind_it_contributes_nothing(
        self, store: InMemoryRoleStore
    ) -> None:
        # The safe reading of an inconsistent store is "no permissions", never "all of
        # them" -- and never an exception, which would lock every holder out of a
        # deployment because one role name went missing.
        assert await store.resolve((AUDITOR, "ghost")) == BUILTIN_ROLES[AUDITOR]
        assert await store.resolve(("ghost",)) == frozenset()

    async def test_a_role_deleted_on_a_stale_count_leaves_its_holders_with_nothing(
        self, store: InMemoryRoleStore
    ) -> None:
        # delete() is told how many accounts hold the role, and that count is taken by
        # the caller, outside this store's lock -- so a grant can land in between and
        # the "nobody holds it" refusal can be decided on a number that is already out
        # of date. This store cannot close that window. What makes it survivable is the
        # rule above: the holder is left resolving to no permissions rather than to a
        # role that no longer exists, so the race costs access instead of granting it.
        accounts = InMemoryAccountStore()
        holder = make_account(roles=(MEMBER,))
        await accounts.add(holder)
        await store.add(make_role("support", Permission.ACCOUNTS_DELETE))

        held_by = await accounts.count_holding("support")
        granted = await accounts.set_roles(holder.account_id, ("support",), now=EPOCH)
        await store.delete("support", held_by=held_by)

        assert granted.roles == ("support",)
        assert await store.resolve(granted.roles) == frozenset()


class TestAccountStoreRoles:
    @pytest.fixture
    def store(self) -> InMemoryAccountStore:
        return InMemoryAccountStore()

    async def test_setting_roles_replaces_them_and_returns_the_updated_account(
        self, store: InMemoryAccountStore
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

    async def test_setting_roles_changes_nothing_else_about_the_account(
        self, store: InMemoryAccountStore
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
        self, store: InMemoryAccountStore
    ) -> None:
        # The store hands out shared references, so a request holding an account from
        # before the change must not see it mutate underneath.
        account = make_account(roles=(MEMBER,))
        await store.add(account)

        updated = await store.set_roles(account.account_id, (AUDITOR,), now=EPOCH)

        assert updated is not account
        assert account.roles == (MEMBER,)

    async def test_setting_roles_on_an_unknown_account_raises(
        self, store: InMemoryAccountStore
    ) -> None:
        with pytest.raises(AccountNotFoundError):
            await store.set_roles("acct_nope", (MEMBER,), now=EPOCH)

    async def test_demoting_the_last_owner_is_refused(self, store: InMemoryAccountStore) -> None:
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

    async def test_stripping_every_role_from_the_last_owner_is_refused(
        self, store: InMemoryAccountStore
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
        self, store: InMemoryAccountStore, lookalike: str
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
        self, store: InMemoryAccountStore
    ) -> None:
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        updated = await store.set_roles(first.account_id, (MEMBER,), now=EPOCH)

        assert updated.roles == (MEMBER,)
        assert await store.count_holding(OWNER) == 1

    async def test_the_other_owner_counts_wherever_owner_sits_among_their_roles(
        self, store: InMemoryAccountStore
    ) -> None:
        # Roles are a set written as a tuple; there is no first-role-wins rule, and the
        # survivor count has to search the whole tuple rather than look at one slot.
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(AUDITOR, MEMBER, OWNER))
        await store.add(first)
        await store.add(second)

        updated = await store.set_roles(first.account_id, (MEMBER,), now=EPOCH)

        assert updated.roles == (MEMBER,)
        assert await store.count_holding(OWNER) == 1

    async def test_the_last_owner_may_change_roles_while_staying_an_owner(
        self, store: InMemoryAccountStore
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
        self, store: InMemoryAccountStore
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
        self, store: InMemoryAccountStore
    ) -> None:
        # The two-step version of the attack: thin the owners out one call at a time and
        # hope the guard only ever looks at the arguments of the call in front of it. It
        # re-reads the store every time, so the second step lands on a deployment with
        # exactly one owner and is refused.
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        assert await store.delete(second.account_id)
        with pytest.raises(LastOwnerError):
            await store.set_roles(first.account_id, (MEMBER,), now=EPOCH)

        assert await store.count_holding(OWNER) == 1

    async def test_deleting_the_last_owner_account_is_refused(
        self, store: InMemoryAccountStore
    ) -> None:
        owner = make_account(roles=(OWNER,))
        await store.add(owner)

        with pytest.raises(LastOwnerError):
            await store.delete(owner.account_id)

        assert await store.get(owner.account_id) is not None

    async def test_deleting_an_account_that_is_not_an_owner_is_allowed(
        self, store: InMemoryAccountStore
    ) -> None:
        owner = make_account("owner@example.com", roles=(OWNER,))
        member = make_account("member@example.com", roles=(MEMBER,))
        await store.add(owner)
        await store.add(member)

        assert await store.delete(member.account_id)
        assert await store.get(member.account_id) is None

    async def test_deleting_one_of_two_owners_is_allowed(self, store: InMemoryAccountStore) -> None:
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        assert await store.delete(first.account_id)
        assert await store.count_holding(OWNER) == 1

    async def test_deleting_both_owners_one_after_the_other_is_refused_at_the_second(
        self, store: InMemoryAccountStore
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
        self, store: InMemoryAccountStore
    ) -> None:
        # The whole reason the check and the write are one step inside the store's lock.
        # Performed by a caller instead, both of these read "there are two owners", both
        # conclude they are safe to proceed, and the deployment ends with none.
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
        self, store: InMemoryAccountStore
    ) -> None:
        # The reinforced version of the test above, and the one with teeth. Gathering
        # two calls on an uncontended lock runs them back-to-back, which a check made
        # outside the lock would survive by luck. Here the test holds the lock itself
        # until every demotion is parked on it, so each one begins its work only after
        # all of them have started -- exactly the interleaving in which a caller-side
        # check reads "there are four owners" four times and every demotion proceeds.
        owners = [make_account(f"owner{index}@example.com", roles=(OWNER,)) for index in range(4)]
        for owner in owners:
            await store.add(owner)

        await store._lock.acquire()
        demotions = [
            asyncio.create_task(store.set_roles(owner.account_id, (MEMBER,), now=EPOCH))
            for owner in owners
        ]
        try:
            await park_on_the_store_lock(demotions)
        finally:
            store._lock.release()

        outcomes = await asyncio.gather(*demotions, return_exceptions=True)

        assert await store.count_holding(OWNER) == 1
        refused = [outcome for outcome in outcomes if isinstance(outcome, LastOwnerError)]
        assert len(refused) == 1

    async def test_a_demotion_and_a_deletion_racing_cannot_between_them_remove_every_owner(
        self, store: InMemoryAccountStore
    ) -> None:
        # Both routes out of the owner role share one guard and one lock, so mixing them
        # is not a way around either. Whichever of the two reaches the lock first wins;
        # the assertions do not care which, only that exactly one did.
        first = make_account("first@example.com", roles=(OWNER,))
        second = make_account("second@example.com", roles=(OWNER,))
        await store.add(first)
        await store.add(second)

        await store._lock.acquire()
        demotion = asyncio.create_task(store.set_roles(first.account_id, (MEMBER,), now=EPOCH))
        deletion = asyncio.create_task(store.delete(second.account_id))
        parked: list[asyncio.Future[Any]] = [demotion, deletion]
        try:
            await park_on_the_store_lock(parked)
        finally:
            store._lock.release()

        outcomes = await asyncio.gather(demotion, deletion, return_exceptions=True)

        assert await store.count_holding(OWNER) == 1
        refused = [outcome for outcome in outcomes if isinstance(outcome, LastOwnerError)]
        assert len(refused) == 1

    async def test_counting_holders_ignores_accounts_without_that_role(
        self, store: InMemoryAccountStore
    ) -> None:
        await store.add(make_account("owner@example.com", roles=(OWNER, AUDITOR)))
        await store.add(make_account("auditor@example.com", roles=(AUDITOR,)))
        await store.add(make_account("member@example.com", roles=(MEMBER,)))

        assert await store.count_holding(AUDITOR) == 2
        assert await store.count_holding(OWNER) == 1
        assert await store.count_holding("ghost") == 0

    async def test_an_account_naming_a_role_twice_is_still_one_holder(
        self, store: InMemoryAccountStore
    ) -> None:
        # The count decides whether a role may be deleted. Counting names rather than
        # accounts would make a role with a duplicated name permanently undeletable.
        await store.add(make_account("owner@example.com", roles=(OWNER,)))
        await store.add(make_account("double@example.com", roles=(AUDITOR, AUDITOR)))

        assert await store.count_holding(AUDITOR) == 1

    async def test_a_disabled_owner_still_counts_as_the_surviving_owner(
        self, store: InMemoryAccountStore
    ) -> None:
        # Recorded rather than assumed, because it is the one shape in which the lockout
        # this guard exists to prevent is still reachable: disable the other owner, then
        # step down, and every owner that remains is one that cannot log in. The guard
        # counts the role, not who can currently authenticate. A status-aware check
        # belongs here, under this lock, and not in a caller.
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
        self, store: InMemoryAccountStore
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

    async def test_owner_is_the_role_the_guard_is_written_against(self) -> None:
        # The guard names one role. If OWNER ever stopped being the everything-role,
        # the lockout protection would be guarding the wrong thing.
        assert BUILTIN_ROLES[OWNER] == ALL_PERMISSIONS
