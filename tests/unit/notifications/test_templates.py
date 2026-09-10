"""What the messages say.

Wording is not decoration here. These messages are the only thing standing between a
family member and a phishing mail that looks exactly like them.
"""

from __future__ import annotations

from keyring_api.notifications.templates import invite_message, reset_message

TOKEN = "the-live-token"


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
