"""Invites and password resets: single-use, expiring, and hashed at rest."""

from __future__ import annotations

from datetime import timedelta

import pytest

from keyring_api.domain.grants import Grant, GrantPurpose, new_grant_id
from tests.fakes.clock import EPOCH

TTL = timedelta(hours=1)


def make_grant(**overrides: object) -> Grant:
    defaults: dict[str, object] = {
        "grant_id": "grant_1",
        "purpose": GrantPurpose.INVITE,
        "email": "person@example.com",
        "account_id": None,
        "token_hash": "hash",
        "created_at": EPOCH,
        "expires_at": EPOCH + TTL,
    }
    return Grant(**{**defaults, **overrides})  # type: ignore[arg-type]


def test_grant_ids_are_unique_and_recognisable() -> None:
    assert new_grant_id() != new_grant_id()
    assert new_grant_id().startswith("grant_")


class TestRedeemability:
    def test_a_fresh_grant_can_be_redeemed(self) -> None:
        assert make_grant().is_redeemable(now=EPOCH)

    def test_an_expired_grant_cannot(self) -> None:
        assert not make_grant().is_redeemable(now=EPOCH + TTL)

    def test_a_redeemed_grant_cannot_be_redeemed_again(self) -> None:
        # Single use is the point. A reset link that works twice is a reset link that
        # still works after the person has already used it and moved on.
        used = make_grant().redeemed(now=EPOCH)

        assert not used.is_redeemable(now=EPOCH)

    def test_redeeming_records_when_it_happened(self) -> None:
        used = make_grant().redeemed(now=EPOCH)

        assert used.redeemed_at == EPOCH

    def test_redeeming_returns_a_new_grant_rather_than_mutating(self) -> None:
        # Two requests racing to redeem the same token must not both see an unused one;
        # the store decides the winner, and it can only do that if the value is frozen.
        grant = make_grant()

        grant.redeemed(now=EPOCH)

        assert grant.redeemed_at is None

    def test_a_revoked_grant_cannot_be_redeemed(self) -> None:
        # Changing a password invalidates every outstanding reset token, which is what
        # stops an attacker's already-requested link surviving the very action taken to
        # lock them out.
        assert not make_grant().revoked_now().is_redeemable(now=EPOCH)


class TestPurpose:
    def test_a_reset_grant_names_the_account_it_is_for(self) -> None:
        grant = make_grant(purpose=GrantPurpose.PASSWORD_RESET, account_id="acct_1", email=None)

        assert grant.account_id == "acct_1"

    def test_an_invite_grant_names_the_address_it_was_sent_to(self) -> None:
        assert make_grant().email == "person@example.com"

    def test_a_grant_must_identify_someone(self) -> None:
        # A grant with neither an address nor an account cannot be redeemed into
        # anything, and a token that redeems into nothing is a bug waiting to be a hole.
        with pytest.raises(ValueError, match="email or an account"):
            make_grant(email=None, account_id=None)
