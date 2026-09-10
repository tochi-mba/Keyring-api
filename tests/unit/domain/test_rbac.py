"""Roles and permissions: what a name may be, what a role may hold, and who may grant it.

The escalation guards themselves live in the admin service and are tested there. What is
tested here is the vocabulary those guards are written in -- a closed permission enum, a
subset check, and a set of built-in roles whose contents are a security decision rather
than a default.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from keyring_api.domain.errors import InsufficientPermissionError, InvalidRoleError
from keyring_api.domain.rbac import (
    ADMIN,
    ALL_PERMISSIONS,
    AUDITOR,
    BUILTIN_ROLES,
    DEFAULT_ROLE,
    MAX_ROLE_NAME_LENGTH,
    MEMBER,
    OWNER,
    Permission,
    Role,
    builtin_role,
    check_can_grant,
    normalize_role_name,
    parse_permissions,
    permissions_of,
)
from tests.fakes.clock import EPOCH

LATER = EPOCH + timedelta(minutes=5)

DESTRUCTIVE_PERMISSIONS = frozenset(
    {
        Permission.ACCOUNTS_INVITE,
        Permission.ACCOUNTS_DISABLE,
        Permission.ACCOUNTS_DELETE,
        Permission.ACCOUNTS_REVOKE_SESSIONS,
        Permission.ACCOUNTS_RESET_PASSWORD,
        Permission.ROLES_WRITE,
        Permission.ROLES_ASSIGN,
        Permission.PROFILES_DELETE_ANY,
    }
)
"""Everything that changes somebody else's account or what anyone is allowed to do."""

_NAME_EDGE = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=1)
_NAME_BODY = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789._-", max_size=28)


def make_role(name: str, *permissions: Permission) -> Role:
    return Role(
        name=name,
        permissions=frozenset(permissions),
        description=f"{name} role",
        created_at=EPOCH,
        updated_at=EPOCH,
    )


class TestRoleNames:
    def test_a_name_is_lowercased_so_one_role_is_one_role(self) -> None:
        # "Auditor" and "auditor" as two separate roles is two separate permission sets
        # somebody has to keep in step.
        assert normalize_role_name("Auditor") == "auditor"

    def test_surrounding_whitespace_is_removed(self) -> None:
        assert normalize_role_name("  release-manager  ") == "release-manager"

    @pytest.mark.parametrize("name", ["team-lead", "on.call", "a1", "x_y", "support2"])
    def test_ordinary_names_are_accepted_unchanged(self, name: str) -> None:
        assert normalize_role_name(name) == name

    @pytest.mark.parametrize("name", ["", "   ", "\t\n"])
    def test_a_name_that_is_nothing_but_whitespace_is_refused(self, name: str) -> None:
        with pytest.raises(InvalidRoleError, match="empty"):
            normalize_role_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "..",
            ".",
            "../x",
            "a/b",
            "a\\b",
            "-lead",
            "trail-",
            "with space",
            "_leading",
            "trailing_",
            "owner!",
            "ünïcode",
        ],
    )
    def test_a_name_that_could_not_be_an_identifier_is_refused(self, name: str) -> None:
        # A role name is addressed in a URL path and used as a dict key, so anything that
        # could be read as a path segment or as two different names is refused at the door
        # rather than escaped at each use.
        with pytest.raises(InvalidRoleError, match="lowercase letters"):
            normalize_role_name(name)

    def test_an_over_long_name_is_refused(self) -> None:
        with pytest.raises(InvalidRoleError, match="at most"):
            normalize_role_name("a" * (MAX_ROLE_NAME_LENGTH + 1))

    def test_a_name_exactly_at_the_limit_is_accepted(self) -> None:
        name = "a" * MAX_ROLE_NAME_LENGTH

        assert normalize_role_name(name) == name

    @given(_NAME_EDGE, _NAME_BODY, _NAME_EDGE)
    def test_normalizing_an_already_normal_name_changes_nothing(
        self, head: str, body: str, tail: str
    ) -> None:
        # Stored names are compared against normalized input on every lookup, so a second
        # pass has to be a no-op or a role becomes unreachable by the name it was saved as.
        once = normalize_role_name(f"  {head}{body}{tail}  ".upper())

        assert normalize_role_name(once) == once


class TestParsingPermissions:
    @pytest.mark.parametrize("permission", sorted(Permission))
    def test_every_permission_survives_a_round_trip_through_the_wire(
        self, permission: Permission
    ) -> None:
        assert parse_permissions([permission.value]) == frozenset({permission})

    def test_the_whole_set_parses_at_once(self) -> None:
        assert parse_permissions([permission.value for permission in Permission]) == ALL_PERMISSIONS

    def test_no_permissions_parses_to_no_permissions(self) -> None:
        assert parse_permissions([]) == frozenset()

    def test_a_repeated_value_is_the_same_as_naming_it_once(self) -> None:
        assert parse_permissions(["audit:read", "audit:read"]) == frozenset({Permission.AUDIT_READ})

    def test_an_unknown_value_is_refused_rather_than_dropped(self) -> None:
        # A silently ignored permission is a role that reads correctly in the API response
        # and does nothing, and the discovery happens when somebody cannot do their job.
        with pytest.raises(InvalidRoleError, match="unknown permissions"):
            parse_permissions(["accounts:read", "accounts:impersonate"])

    def test_the_error_names_every_unknown_value_not_just_the_first(self) -> None:
        # One round trip per typo is a caller who submits four times to fix four typos.
        with pytest.raises(InvalidRoleError) as caught:
            parse_permissions(["accounts:read", "accounts:impersonate", "vault:read", "roles:*"])

        message = str(caught.value)
        assert "accounts:impersonate" in message
        assert "vault:read" in message
        assert "roles:*" in message

    @pytest.mark.parametrize("value", ["ACCOUNTS:READ", "Accounts:Read", " accounts:read"])
    def test_a_near_miss_is_not_quietly_corrected(self, value: str) -> None:
        # Permissions are not normalized the way names are: accepting a near miss here
        # would mean the string in the request and the string in the audit trail differ.
        with pytest.raises(InvalidRoleError, match="unknown permissions"):
            parse_permissions([value])

    def test_a_one_pass_iterable_of_known_values_is_not_silently_emptied(self) -> None:
        # The parameter is annotated Iterable[str], so a generator is a legal argument --
        # but the scan for unknown values consumes it, leaving the pass that builds the
        # result with nothing to read. The caller gets a role with no permissions at all:
        # the same "looks right in the response, does nothing" failure this function was
        # written to prevent, arriving through a different door.
        assert parse_permissions(iter(["accounts:read", "audit:read"])) == frozenset(
            {Permission.ACCOUNTS_READ, Permission.AUDIT_READ}
        )


class TestUnioningRoles:
    def test_holding_two_roles_means_holding_both_sets(self) -> None:
        roles = [
            make_role("reader", Permission.ACCOUNTS_READ),
            make_role("assigner", Permission.ROLES_ASSIGN, Permission.ROLES_READ),
        ]

        assert permissions_of(roles) == frozenset(
            {Permission.ACCOUNTS_READ, Permission.ROLES_ASSIGN, Permission.ROLES_READ}
        )

    def test_holding_no_roles_means_holding_nothing(self) -> None:
        # The failure mode worth ruling out is an empty union that reads as "unrestricted".
        assert permissions_of([]) == frozenset()

    def test_a_permission_two_roles_share_is_still_one_permission(self) -> None:
        roles = [
            make_role("first", Permission.AUDIT_READ, Permission.ACCOUNTS_READ),
            make_role("second", Permission.AUDIT_READ),
        ]

        assert permissions_of(roles) == frozenset({Permission.AUDIT_READ, Permission.ACCOUNTS_READ})

    def test_an_empty_role_adds_nothing_to_the_union(self) -> None:
        roles = [make_role("member-like"), make_role("reader", Permission.ACCOUNTS_READ)]

        assert permissions_of(roles) == frozenset({Permission.ACCOUNTS_READ})

    def test_roles_are_additive_rather_than_ranked(self) -> None:
        # Order is not a precedence rule: there is nothing for an operator to remember
        # about which of somebody's roles "wins".
        reader = make_role("reader", Permission.ACCOUNTS_READ)
        writer = make_role("writer", Permission.ROLES_WRITE)

        assert permissions_of([reader, writer]) == permissions_of([writer, reader])


class TestGrantingBoundedByYourOwn:
    def test_granting_a_subset_of_what_you_hold_is_allowed(self) -> None:
        check_can_grant(
            holder=frozenset({Permission.ROLES_ASSIGN, Permission.ACCOUNTS_READ}),
            granted=frozenset({Permission.ACCOUNTS_READ}),
        )

    def test_granting_exactly_what_you_hold_is_allowed(self) -> None:
        # Equality is the boundary case: refusing it would mean nobody could ever appoint
        # a peer, and an owner could not appoint a second owner.
        held = frozenset({Permission.ROLES_ASSIGN, Permission.ACCOUNTS_DELETE})

        check_can_grant(holder=held, granted=held)

    def test_granting_nothing_is_allowed_even_holding_nothing(self) -> None:
        check_can_grant(holder=frozenset(), granted=frozenset())

    def test_granting_a_single_permission_you_lack_is_refused(self) -> None:
        # Without this, "assign roles" is a synonym for "give yourself every permission".
        with pytest.raises(InsufficientPermissionError):
            check_can_grant(
                holder=frozenset({Permission.ROLES_ASSIGN}),
                granted=frozenset({Permission.ROLES_ASSIGN, Permission.ACCOUNTS_DELETE}),
            )

    def test_holding_nothing_grants_nothing(self) -> None:
        with pytest.raises(InsufficientPermissionError):
            check_can_grant(holder=frozenset(), granted=frozenset({Permission.ACCOUNTS_READ}))

    def test_the_refusal_names_the_permissions_that_were_missing(self) -> None:
        # So the caller can see what they would need, and so the message never doubles as
        # a hint about permissions they already have.
        with pytest.raises(InsufficientPermissionError) as caught:
            check_can_grant(
                holder=frozenset({Permission.ROLES_ASSIGN}),
                granted=frozenset(
                    {Permission.ROLES_ASSIGN, Permission.ACCOUNTS_DELETE, Permission.ROLES_WRITE}
                ),
            )

        message = str(caught.value)
        assert "accounts:delete" in message
        assert "roles:write" in message
        assert "roles:assign" not in message


class TestBuiltInRoles:
    def test_owner_holds_every_permission_that_exists(self) -> None:
        # Asserted against ALL_PERMISSIONS rather than a written-out list, so a permission
        # added later that nobody can grant fails here instead of at two in the morning.
        assert BUILTIN_ROLES[OWNER] == ALL_PERMISSIONS

    def test_admin_cannot_mint_new_roles(self) -> None:
        # Minting a permission set is an owner's job. The subset rule would stop an admin
        # creating anything more powerful than themselves anyway; this keeps the blast
        # radius of a compromised admin session smaller than that.
        assert Permission.ROLES_WRITE not in BUILTIN_ROLES[ADMIN]

    def test_admin_holds_everything_else(self) -> None:
        assert BUILTIN_ROLES[ADMIN] == ALL_PERMISSIONS - {Permission.ROLES_WRITE}

    def test_member_holds_nothing(self) -> None:
        assert BUILTIN_ROLES[MEMBER] == frozenset()

    def test_a_new_account_gets_the_role_that_holds_nothing(self) -> None:
        assert DEFAULT_ROLE == MEMBER
        assert BUILTIN_ROLES[DEFAULT_ROLE] == frozenset()

    def test_auditor_is_exactly_the_three_read_permissions(self) -> None:
        assert BUILTIN_ROLES[AUDITOR] == frozenset(
            {Permission.ACCOUNTS_READ, Permission.ROLES_READ, Permission.AUDIT_READ}
        )

    def test_auditor_can_change_nothing(self) -> None:
        # An auditor is handed out on the understanding that it is read-only; the moment
        # that stops being true, the role is being given to the wrong people.
        assert BUILTIN_ROLES[AUDITOR].isdisjoint(DESTRUCTIVE_PERMISSIONS)

    def test_auditor_cannot_see_another_account_profiles(self) -> None:
        assert Permission.PROFILES_READ_ANY not in BUILTIN_ROLES[AUDITOR]

    @pytest.mark.parametrize("name", sorted(BUILTIN_ROLES))
    def test_every_built_in_is_marked_immutable(self, name: str) -> None:
        # The flag is what stops "member" being edited into "owner", which would be the
        # quietest possible escalation: nobody's roles would have changed.
        role = builtin_role(name)

        assert role.builtin
        assert role.name == name
        assert role.permissions == BUILTIN_ROLES[name]

    @pytest.mark.parametrize("name", sorted(BUILTIN_ROLES))
    def test_every_built_in_says_what_it_is_for(self, name: str) -> None:
        # These are the roles an operator picks from without reading the source.
        assert len(builtin_role(name).description) > 0

    def test_no_two_built_ins_hold_the_same_permissions(self) -> None:
        sets = [BUILTIN_ROLES[name] for name in BUILTIN_ROLES]

        assert len(set(sets)) == len(sets)


class TestChangingARole:
    def test_new_permissions_produce_a_new_role_rather_than_editing_the_old_one(self) -> None:
        original = make_role("reviewer", Permission.ACCOUNTS_READ)

        changed = original.with_permissions(
            frozenset({Permission.ACCOUNTS_READ, Permission.AUDIT_READ}),
            description="reads the log too",
            now=LATER,
        )

        assert changed is not original
        assert changed.permissions == frozenset({Permission.ACCOUNTS_READ, Permission.AUDIT_READ})
        assert changed.description == "reads the log too"
        assert changed.updated_at == LATER

    def test_the_original_role_is_untouched(self) -> None:
        original = make_role("reviewer", Permission.ACCOUNTS_READ)

        original.with_permissions(frozenset(ALL_PERMISSIONS), description="everything", now=LATER)

        assert original.permissions == frozenset({Permission.ACCOUNTS_READ})
        assert original.description == "reviewer role"
        assert original.updated_at == EPOCH

    def test_identity_and_creation_time_carry_across(self) -> None:
        original = make_role("reviewer", Permission.ACCOUNTS_READ)

        changed = original.with_permissions(frozenset(), description="", now=LATER)

        assert changed.name == "reviewer"
        assert changed.created_at == EPOCH
        assert changed.builtin is False

    def test_the_permission_set_is_replaced_rather_than_merged(self) -> None:
        # An update that merged would make removing a permission impossible through the
        # only endpoint that edits a role.
        original = make_role("reviewer", Permission.ACCOUNTS_READ, Permission.AUDIT_READ)

        changed = original.with_permissions(
            frozenset({Permission.AUDIT_READ}), description="", now=LATER
        )

        assert changed.permissions == frozenset({Permission.AUDIT_READ})


class TestTheLineThisModuleDoesNotCross:
    def test_no_permission_reads_another_account_credential(self) -> None:
        # This asserts an absence, deliberately. The operator can already decrypt the
        # vault, because they hold the master key -- but that needs shell access, leaves
        # the credential in one place, and cannot be delegated. A permission that produced
        # somebody else's token would be remote, silent, grantable to anyone and usable
        # from a browser. Administration here means managing accounts, not becoming them,
        # and a boundary that lives only in a docstring survives exactly until the first
        # refactor that finds it inconvenient.
        values = [permission.value for permission in Permission]

        assert [value for value in values if "credential" in value] == []
        assert [value for value in values if "secret" in value] == []
        assert [value for value in values if "impersonate" in value] == []
        assert "profiles:read_secret" not in values

    def test_the_permission_that_does_exist_for_other_accounts_is_named_as_metadata(self) -> None:
        # profiles:read_any is safe to hand out precisely because its name is the whole
        # promise: which services somebody has connected, never what the connection holds.
        assert Permission.PROFILES_READ_ANY.value == "profiles:read_any"

    def test_even_the_owner_cannot_hold_a_credential_reading_permission(self) -> None:
        # Owner is the union of everything, so if such a permission were ever added this
        # is the role that would silently acquire it.
        assert [
            permission.value for permission in BUILTIN_ROLES[OWNER] if "credential" in permission
        ] == []
