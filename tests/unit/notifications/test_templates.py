"""What the messages say.

Wording is not decoration here. These messages are the only thing standing between a
family member and a phishing mail that looks exactly like them.
"""

from __future__ import annotations

import pytest

from keyring_api.domain.changes import ChangeOrigin, CredentialChange
from keyring_api.notifications.templates import (
    CREDENTIAL_CHANGE_SUBJECT,
    credential_change_message,
    invite_message,
    new_session_message,
    reset_message,
)
from tests.fakes.clock import EPOCH

TOKEN = "the-live-token"
AT = EPOCH


class TestReset:
    def test_it_carries_the_token(self) -> None:
        message = reset_message(
            to_address="person@example.com",
            token=TOKEN,
            expires_in_minutes=60,
            link_base_url="",
        )

        assert TOKEN in message.body

    def test_it_says_how_long_it_lasts(self) -> None:
        message = reset_message(
            to_address="person@example.com", token=TOKEN, expires_in_minutes=60, link_base_url=""
        )

        assert "60 minutes" in message.body

    def test_it_tells_someone_who_did_not_ask_that_they_need_do_nothing(self) -> None:
        # The alternative -- "secure your account" -- is alarming and actionless, and
        # trains people to panic at mail about their passwords.
        message = reset_message(
            to_address="person@example.com", token=TOKEN, expires_in_minutes=60, link_base_url=""
        )

        assert "did not ask" in message.body
        assert "expires unused" in message.body

    def test_it_warns_that_using_it_signs_other_devices_out(self) -> None:
        message = reset_message(
            to_address="person@example.com", token=TOKEN, expires_in_minutes=60, link_base_url=""
        )

        assert "sign" in message.body

    def test_it_names_no_account_detail(self) -> None:
        # A reset mail goes to an address. It must not describe the account behind that
        # address to whoever is reading the mailbox.
        message = reset_message(
            to_address="person@example.com", token=TOKEN, expires_in_minutes=60, link_base_url=""
        )

        assert "acct_" not in message.body
        assert "profile" not in message.body.lower()

    def test_a_link_is_built_when_a_redemption_url_is_configured(self) -> None:
        message = reset_message(
            to_address="person@example.com",
            token=TOKEN,
            expires_in_minutes=60,
            link_base_url="https://keyring.example/",
        )

        assert "https://keyring.example/reset?token=the-live-token" in message.body

    def test_the_token_is_escaped_into_the_url(self) -> None:
        # The generator already produces URL-safe tokens; this is the layer that would
        # suffer if that ever changed, so it does not depend on the promise.
        message = reset_message(
            to_address="person@example.com",
            token="a token/with?specials",
            expires_in_minutes=60,
            link_base_url="https://keyring.example",
        )

        assert "a%20token%2Fwith%3Fspecials" in message.body

    def test_no_link_is_invented_when_there_is_no_ui(self) -> None:
        # Pointing somebody at a page that does not exist is worse than asking them to
        # copy a string.
        message = reset_message(
            to_address="person@example.com", token=TOKEN, expires_in_minutes=60, link_base_url=""
        )

        assert "http" not in message.body


class TestInvite:
    def test_it_says_what_the_service_is(self) -> None:
        # The recipient has never heard of keyring. A message that assumes otherwise is
        # indistinguishable from phishing.
        message = invite_message(
            to_address="person@example.com", token=TOKEN, expires_in_days=7, link_base_url=""
        )

        assert "keyring" in message.body
        assert "invited" in message.body

    def test_it_says_the_invite_is_worth_protecting(self) -> None:
        message = invite_message(
            to_address="person@example.com", token=TOKEN, expires_in_days=7, link_base_url=""
        )

        assert "like a password" in message.body

    def test_it_carries_the_token_and_the_expiry(self) -> None:
        message = invite_message(
            to_address="person@example.com", token=TOKEN, expires_in_days=7, link_base_url=""
        )

        assert TOKEN in message.body
        assert "7 days" in message.body

    def test_it_addresses_the_right_person(self) -> None:
        message = invite_message(
            to_address="person@example.com", token=TOKEN, expires_in_days=7, link_base_url=""
        )

        assert message.to_address == "person@example.com"

    def test_both_messages_are_plain_text(self) -> None:
        # An HTML mail from a credential service is a phishing lesson in the wrong
        # direction: it trains the recipient to click styled buttons in mail about their
        # passwords.
        for message in (
            invite_message(
                to_address="p@example.com", token=TOKEN, expires_in_days=7, link_base_url=""
            ),
            reset_message(
                to_address="p@example.com", token=TOKEN, expires_in_minutes=60, link_base_url=""
            ),
        ):
            assert "<html" not in message.body.lower()
            assert "<a " not in message.body.lower()


class TestNewSession:
    def test_it_says_when_and_to_whom(self) -> None:
        message = new_session_message(to_address="person@example.com", at=AT)

        assert message.to_address == "person@example.com"
        assert "2026-01-01 12:00 UTC" in message.body
        assert "signed in" in message.body

    def test_it_says_what_to_do_if_it_was_not_them(self) -> None:
        """The bug, named: a warning with no remedy, which only alarms.

        The remedy that actually removes an intruder is a password change, because that is
        what ends every other session.
        """
        message = new_session_message(to_address="person@example.com", at=AT)

        assert "Change your keyring password" in message.body
        assert "signs out every other session" in message.body

    def test_it_carries_nothing_to_click_and_nothing_secret(self) -> None:
        """The bug, named: a security notice with a link in it is the shape of phishing.

        And a session id or token in a mailbox is a session somebody else can use.
        """
        message = new_session_message(to_address="person@example.com", at=AT)

        assert "http" not in message.body
        assert "sess_" not in message.body
        assert "acct_" not in message.body
        assert "token" not in message.body.lower()


class TestCredentialChange:
    @pytest.mark.parametrize("change", list(CredentialChange))
    @pytest.mark.parametrize("origin", list(ChangeOrigin))
    def test_every_change_and_origin_has_words(
        self, change: CredentialChange, origin: ChangeOrigin
    ) -> None:
        message = credential_change_message(
            to_address="person@example.com", change=change, origin=origin, at=AT
        )

        assert message.subject == CREDENTIAL_CHANGE_SUBJECT
        assert "2026-01-01 12:00 UTC" in message.body
        assert "<" not in message.body

    def test_removal_and_storage_read_differently(self) -> None:
        stored = credential_change_message(
            to_address="p@example.com",
            change=CredentialChange.STORED,
            origin=ChangeOrigin.PERSON,
            at=AT,
        )
        removed = credential_change_message(
            to_address="p@example.com",
            change=CredentialChange.REMOVED,
            origin=ChangeOrigin.SERVICE,
            at=AT,
        )

        assert "added or replaced" in stored.body
        assert "signed-in session" in stored.body
        assert "removed" in removed.body
        assert "a service acting for you" in removed.body

    def test_it_never_says_which_credential(self) -> None:
        """The bug, named: a notice that tells a mailbox what the account holds.

        Whoever reads the mailbox may not be the account's owner. The message takes no
        service, profile or value at all, so none can leak into it.
        """
        message = credential_change_message(
            to_address="p@example.com",
            change=CredentialChange.STORED,
            origin=ChangeOrigin.PROVIDER,
            at=AT,
        )

        assert "does not say which one" in message.body
        assert "http" not in message.body
        assert "profile" not in message.body.lower()
