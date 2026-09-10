"""Account rules: what an address normalizes to, and what a password has to be."""

from __future__ import annotations

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from keyring_api.domain.accounts import (
    MAX_PASSWORD_LENGTH,
    MIN_PASSWORD_LENGTH,
    Account,
    AccountStatus,
    check_password_policy,
    new_account_id,
    normalize_email,
)
from keyring_api.domain.errors import InvalidEmailError, InvalidPasswordError
from tests.fakes.clock import EPOCH


def make_account(**overrides: object) -> Account:
    defaults: dict[str, object] = {
        "account_id": "acct_1",
        "email": "person@example.com",
        "password_hash": "$argon2id$fake",
        "created_at": EPOCH,
        "updated_at": EPOCH,
    }
    return Account(**{**defaults, **overrides})  # type: ignore[arg-type]


class TestEmailNormalization:
    def test_surrounding_whitespace_is_removed(self) -> None:
        assert normalize_email("  person@example.com  ") == "person@example.com"

    def test_the_address_is_lowercased_so_one_person_gets_one_account(self) -> None:
        # Strictly, the local part is case-sensitive per RFC 5321. In practice no
        # provider treats it that way, and honouring the spec here would let the same
        # person hold two accounts and be unable to explain why their login "sometimes"
        # fails.
        assert normalize_email("Person@Example.COM") == "person@example.com"

    @pytest.mark.parametrize(
        "address",
        ["", "   ", "no-at-sign", "@example.com", "person@", "a@b@c.com", "person @x.com"],
    )
    def test_an_unusable_address_is_rejected(self, address: str) -> None:
        with pytest.raises(InvalidEmailError):
            normalize_email(address)

    def test_an_absurdly_long_address_is_rejected(self) -> None:
        # Bounded because it is stored, indexed, and echoed into log records.
        with pytest.raises(InvalidEmailError):
            normalize_email("a" * 300 + "@example.com")

    def test_an_embedded_newline_is_rejected_rather_than_stripped(self) -> None:
        # Stripping would silently accept an address that was assembled from a header
        # injection attempt; rejecting says so.
        with pytest.raises(InvalidEmailError):
            normalize_email("person@example.com\nBcc: someone@else.com")

    @given(st.emails())
    def test_normalization_is_idempotent(self, address: str) -> None:
        once = normalize_email(address)

        assert normalize_email(once) == once


class TestPasswordPolicy:
    def test_a_long_passphrase_is_accepted_without_composition_rules(self) -> None:
        # NIST SP 800-63B: length is what matters, and forced composition rules push
        # people towards Password1! and a sticky note.
        check_password_policy("correct horse battery staple")

    @pytest.mark.parametrize("length", [0, 1, MIN_PASSWORD_LENGTH - 1])
    def test_a_short_password_is_rejected(self, length: int) -> None:
        with pytest.raises(InvalidPasswordError, match="at least"):
            check_password_policy("a" * length)

    def test_the_minimum_length_itself_is_accepted(self) -> None:
        check_password_policy("a" * MIN_PASSWORD_LENGTH)

    def test_an_unbounded_password_is_rejected(self) -> None:
        # Argon2 hashes whatever it is given, so an enormous password is a way to make
        # the server do an enormous amount of work on an unauthenticated endpoint.
        with pytest.raises(InvalidPasswordError, match="at most"):
            check_password_policy("a" * (MAX_PASSWORD_LENGTH + 1))

    def test_length_is_counted_in_characters_not_bytes(self) -> None:
        # Otherwise a passphrase in a non-Latin script silently needs to be far shorter
        # than one in English.
        check_password_policy("🔐" * MIN_PASSWORD_LENGTH)

    def test_a_password_that_is_only_whitespace_is_rejected(self) -> None:
        with pytest.raises(InvalidPasswordError, match="whitespace"):
            check_password_policy(" " * (MIN_PASSWORD_LENGTH + 2))

    def test_internal_whitespace_is_preserved_rather_than_trimmed(self) -> None:
        # A passphrase's spaces are part of it. Trimming would mean the password stored
        # is not the password typed.
        check_password_policy("  a passphrase with spaces  ")


class TestAccountIds:
    def test_ids_are_unique(self) -> None:
        assert new_account_id() != new_account_id()

    def test_an_id_is_opaque_and_carries_no_personal_data(self) -> None:
        # Account ids end up in log records and in token subjects. An email address
        # there would put personal data everywhere the logs go.
        assert "@" not in new_account_id()

    def test_an_id_is_prefixed_so_it_is_recognisable_in_a_log_line(self) -> None:
        assert new_account_id().startswith("acct_")


class TestAccountState:
    def test_a_new_account_is_active(self) -> None:
        assert make_account().status is AccountStatus.ACTIVE

    def test_an_account_is_not_locked_when_it_has_never_been_locked(self) -> None:
        assert not make_account().is_locked(now=EPOCH)

    def test_an_account_is_locked_until_the_lock_expires(self) -> None:
        account = make_account(locked_until=EPOCH + timedelta(minutes=5))

        assert account.is_locked(now=EPOCH)
        assert account.is_locked(now=EPOCH + timedelta(minutes=4, seconds=59))

    def test_the_lock_lifts_exactly_when_it_expires(self) -> None:
        account = make_account(locked_until=EPOCH + timedelta(minutes=5))

        assert not account.is_locked(now=EPOCH + timedelta(minutes=5))

    def test_recording_a_failure_returns_a_new_account_rather_than_mutating(self) -> None:
        # The stores hand out shared references; a mutable account would let one
        # request's failed login alter the object another request is reading.
        account = make_account()

        failed = account.with_failure(now=EPOCH, lockout_threshold=3, lockout_seconds=60)

        assert account.failed_attempts == 0
        assert failed.failed_attempts == 1

    def test_reaching_the_threshold_locks_the_account(self) -> None:
        account = make_account(failed_attempts=2)

        failed = account.with_failure(now=EPOCH, lockout_threshold=3, lockout_seconds=60)

        assert failed.is_locked(now=EPOCH)
        assert failed.locked_until == EPOCH + timedelta(seconds=60)

    def test_a_failure_below_the_threshold_does_not_lock(self) -> None:
        failed = make_account().with_failure(now=EPOCH, lockout_threshold=3, lockout_seconds=60)

        assert not failed.is_locked(now=EPOCH)

    def test_a_successful_login_clears_the_failure_count_and_any_lock(self) -> None:
        account = make_account(failed_attempts=5, locked_until=EPOCH + timedelta(minutes=5))

        assert account.with_success().failed_attempts == 0
        assert account.with_success().locked_until is None
