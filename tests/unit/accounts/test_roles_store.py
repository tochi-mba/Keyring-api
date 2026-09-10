"""The role store, and the last-owner guarantee inside the account store.

The CRUD half is ordinary. The half worth reading is the pair of operations that can
leave a deployment with nobody able to administer it -- demoting an owner and deleting
an owner -- both of which check and write as one step under the store's lock.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import pytest

from keyring_api.accounts.roles import InMemoryRoleStore, RoleStore
from keyring_api.accounts.store import InMemoryAccountStore
from keyring_api.domain.accounts import Account, new_account_id
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


def make_account(
    email: str = "person@example.com",
    *,
    roles: tuple[str, ...] = (),
    created_at: datetime = EPOCH,
) -> Account:
    return Account(
        account_id=new_account_id(),
        email=email,
        password_hash="$argon2id$fake",
        created_at=created_at,
        updated_at=created_at,
        roles=roles,
    )


def make_role(name: str, *permissions: Permission) -> Role:
    return Role(name=name, permissions=frozenset(permissions), description=f"the {name} role")


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

    async def test_requiring_a_known_role_returns_it(self, store: InMemoryRoleStore) -> None:
        role = await store.require(AUDITOR)

        assert role.name == AUDITOR

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

    async def test_an_added_role_is_stored_as_a_custom_one(self, store: InMemoryRoleStore) -> None:
        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        stored = await store.get("support")

        assert stored is not None
        assert stored.permissions == frozenset({Permission.ACCOUNTS_READ})
        assert not stored.builtin

    async def test_a_second_role_with_the_same_name_is_refused(
        self, store: InMemoryRoleStore
    ) -> None:
        await store.add(make_role("support", Permission.ACCOUNTS_READ))

        with pytest.raises(RoleExistsError):
            await store.add(make_role("support", Permission.ACCOUNTS_DELETE))

    async def test_a_role_named_after_a_builtin_is_refused(self, store: InMemoryRoleStore) -> None:
        # Shadowing "member" with a custom definition would be an escalation that never
        # shows up as a role change on anybody's account.
        with pytest.raises(RoleExistsError):
            await store.add(make_role(MEMBER, Permission.ACCOUNTS_DELETE))

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

    async def test_the_last_owner_may_change_roles_while_staying_an_owner(
        self, store: InMemoryAccountStore
    ) -> None:
        # The guard is about the owner role surviving, not about the account's roles
        # being frozen.
        owner = make_account(roles=(OWNER,))
        await store.add(owner)

        updated = await store.set_roles(owner.account_id, (OWNER, AUDITOR), now=EPOCH)

        assert updated.roles == (OWNER, AUDITOR)

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

        assert await store.count_holding(OWNER) >= 1
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
