"""Password change and reset.

This is the highest-risk code in the project, so the tests are weighted towards the
failures that are silent. A download that breaks tells you. An authentication bug tells
whoever finds it first.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from keyring_api.accounts.service import AccountService
from keyring_api.core.config import Settings
from keyring_api.domain.errors import (
    AuthenticationError,
    InvalidGrantError,
    InvalidPasswordError,
    RateLimitedError,
)
from tests.fakes.clock import FakeClock
from tests.unit.accounts._helpers import CALLER, EMAIL, PASSWORD, onboard
from tests.unit.accounts._helpers import clock as clock  # noqa: PLC0414
from tests.unit.accounts._helpers import service as service  # noqa: PLC0414
from tests.unit.accounts._helpers import settings as settings  # noqa: PLC0414


class TestPasswordChange:
    async def test_changing_a_password_requires_the_current_one(
        self, service: AccountService
    ) -> None:
        # Otherwise a stolen session is an account takeover rather than a session
        # someone can revoke.
        account_id = await onboard(service)

        with pytest.raises(AuthenticationError):
            await service.change_password(
                account_id, current_password="wrong", new_password="a new passphrase"
            )

    async def test_the_new_password_works_and_the_old_one_stops(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)

        await service.change_password(
            account_id, current_password=PASSWORD, new_password="a new passphrase"
        )

        assert (await service.login(email=EMAIL, password="a new passphrase", caller=CALLER)).token
        with pytest.raises(AuthenticationError):
            await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

    async def test_a_weak_new_password_is_refused(self, service: AccountService) -> None:
        account_id = await onboard(service)

        with pytest.raises(InvalidPasswordError):
            await service.change_password(
                account_id, current_password=PASSWORD, new_password="short"
            )

    async def test_every_other_session_is_revoked(self, service: AccountService) -> None:
        # If an attacker's session survived a password change, the action taken to lock
        # them out would have done nothing about the thing they actually hold.
        account_id = await onboard(service)
        attacker = await service.login(email=EMAIL, password=PASSWORD, caller="6.6.6.6")
        current = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        await service.change_password(
            account_id,
            current_password=PASSWORD,
            new_password="a new passphrase",
            keep_session_id=current.session_id,
        )

        with pytest.raises(AuthenticationError):
            await service.resolve_session(attacker.token)

    async def test_the_session_it_was_changed_from_survives(self, service: AccountService) -> None:
        # Signing someone out of the tab they just changed their password in is a
        # confusing way to confirm it worked.
        account_id = await onboard(service)
        current = await service.login(email=EMAIL, password=PASSWORD, caller=CALLER)

        await service.change_password(
            account_id,
            current_password=PASSWORD,
            new_password="a new passphrase",
            keep_session_id=current.session_id,
        )

        assert (await service.resolve_session(current.token)).session_id == current.session_id

    async def test_outstanding_reset_tokens_are_revoked(self, service: AccountService) -> None:
        # An attacker who requested a reset before being locked out otherwise still
        # holds a working link afterwards.
        account_id = await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        await service.change_password(
            account_id, current_password=PASSWORD, new_password="a new passphrase"
        )

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="attacker's choice", caller=CALLER
            )


class TestPasswordReset:
    async def test_requesting_a_reset_for_a_real_account_yields_a_token(
        self, service: AccountService
    ) -> None:
        await onboard(service)

        assert await service.request_password_reset(email=EMAIL, caller=CALLER) is not None

    async def test_requesting_a_reset_for_an_unknown_address_yields_nothing(
        self, service: AccountService
    ) -> None:
        # None, not an error. The API renders the same "if that address exists, we have
        # sent a link" either way, so the caller learns nothing.
        assert (
            await service.request_password_reset(email="nobody@example.com", caller=CALLER) is None
        )

    async def test_an_unusable_address_also_yields_nothing_rather_than_a_validation_error(
        self, service: AccountService
    ) -> None:
        # A distinct error for a malformed address is a smaller oracle than one for a
        # missing account, but it is still one: it tells a caller which shapes this
        # service considers real.
        assert await service.request_password_reset(email="not-an-address", caller=CALLER) is None

    async def test_redeeming_a_reset_sets_the_new_password(self, service: AccountService) -> None:
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        await service.redeem_password_reset(
            token=reset.token, new_password="a new passphrase", caller=CALLER
        )

        assert (
            await service.login(email=EMAIL, password="a new passphrase", caller=CALLER)
        ).account_id

    async def test_a_reset_can_only_be_used_once(self, service: AccountService) -> None:
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None
        await service.redeem_password_reset(
            token=reset.token, new_password="a new passphrase", caller=CALLER
        )

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="another passphrase", caller=CALLER
            )

    async def test_an_expired_reset_cannot_be_used(
        self, service: AccountService, clock: FakeClock, settings: Settings
    ) -> None:
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        clock.advance(timedelta(seconds=settings.reset_ttl_seconds))

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="a new passphrase", caller=CALLER
            )

    async def test_a_reset_revokes_every_session(self, service: AccountService) -> None:
        # Reset is the flow someone runs *because* they think they have been
        # compromised. Leaving the attacker's session alive defeats the entire exercise.
        await onboard(service)
        attacker = await service.login(email=EMAIL, password=PASSWORD, caller="6.6.6.6")
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        await service.redeem_password_reset(
            token=reset.token, new_password="a new passphrase", caller=CALLER
        )

        with pytest.raises(AuthenticationError):
            await service.resolve_session(attacker.token)

    async def test_a_second_reset_request_invalidates_the_first_link(
        self, service: AccountService
    ) -> None:
        # Two live links means the older one is still a password sitting in an inbox
        # after the person has already used the newer one.
        await onboard(service)
        first = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert first is not None

        await service.request_password_reset(email=EMAIL, caller=CALLER)

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=first.token, new_password="a new passphrase", caller=CALLER
            )

    async def test_an_invite_cannot_be_redeemed_as_a_reset(self, service: AccountService) -> None:
        invite = await service.issue_invite(email="new@example.com")

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=invite.token, new_password="a new passphrase", caller=CALLER
            )

    async def test_a_weak_new_password_is_refused_and_the_token_survives(
        self, service: AccountService
    ) -> None:
        await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None

        with pytest.raises(InvalidPasswordError):
            await service.redeem_password_reset(
                token=reset.token, new_password="short", caller=CALLER
            )

        assert (
            await service.redeem_password_reset(
                token=reset.token, new_password="a new passphrase", caller=CALLER
            )
        ).email == EMAIL

    async def test_reset_requests_are_rate_limited(
        self, service: AccountService, settings: Settings
    ) -> None:
        # Unlimited reset requests are unlimited mail sent to someone else's inbox.
        await onboard(service)

        for _ in range(settings.rate_limit.reset_attempts):
            await service.request_password_reset(email=EMAIL, caller=CALLER)

        with pytest.raises(RateLimitedError):
            await service.request_password_reset(email=EMAIL, caller=CALLER)

    async def test_a_reset_for_an_account_that_vanished_mid_flow_fails_cleanly(
        self, service: AccountService
    ) -> None:
        account_id = await onboard(service)
        reset = await service.request_password_reset(email=EMAIL, caller=CALLER)
        assert reset is not None
        await service._accounts.delete(account_id)

        with pytest.raises(InvalidGrantError):
            await service.redeem_password_reset(
                token=reset.token, new_password="a new passphrase", caller=CALLER
            )
