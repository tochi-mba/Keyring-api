"""What the messages actually say.

Plain text, short, and written on the assumption that the recipient is a person who was
not expecting mail from a service they have never heard of.

Three rules shape the wording:

**Say who it is from and who asked.** A message that just says "click here to reset your
password" is indistinguishable from phishing, and training your family to click those is
a worse outcome than a forgotten password.

**Say what to do if they did not ask.** For a reset, that is "ignore this" -- the token
expires unused, and there is nothing for them to do. Telling them to "secure their
account" would be alarming and useless.

**Never include anything the recipient does not already know.** No account id, no profile
names, no list of connected services. A reset mail goes to an address; it must not
describe the account behind it to whoever is reading that mailbox.

A link is only included when a redemption URL is configured. With no web UI, inventing a
link to a page that does not exist is worse than asking somebody to copy a string.
"""

from __future__ import annotations

from urllib.parse import quote

from keyring_api.notifications.base import EmailMessage

INVITE_SUBJECT = "You have been invited to keyring"
RESET_SUBJECT = "Reset your keyring password"


def invite_message(
    *, to_address: str, token: str, expires_in_days: int, link_base_url: str
) -> EmailMessage:
    """The message carrying an invite token."""
    action = _action(link_base_url, path="invite", token=token, fallback="Your invite code is:")
    body = f"""\
Someone with access to a keyring server has invited you to create an account on it.
keyring stores the logins and API keys your services use on your behalf.

{action}

This invite works once and expires in {expires_in_days} days. Anyone who has it can
create the account, so treat it like a password until you have used it.

If you were not expecting this, ignore it -- the invite expires on its own and no
account is created.
"""
    return EmailMessage(to_address=to_address, subject=INVITE_SUBJECT, body=body)


def reset_message(
    *, to_address: str, token: str, expires_in_minutes: int, link_base_url: str
) -> EmailMessage:
    """The message carrying a password-reset token."""
    action = _action(link_base_url, path="reset", token=token, fallback="Your reset code is:")
    body = f"""\
Someone asked to reset the keyring password for this address.

{action}

This works once and expires in {expires_in_minutes} minutes. Using it will also sign
this account out everywhere else.

If you did not ask for this, ignore this message. Your password has not changed and the
code above expires unused. Nobody needs to do anything.
"""
    return EmailMessage(to_address=to_address, subject=RESET_SUBJECT, body=body)


def _action(link_base_url: str, *, path: str, token: str, fallback: str) -> str:
    """A link when one can be built, otherwise the bare token.

    The token is percent-encoded with ``safe=""``. The default leaves ``/`` alone, which
    is right for a path segment and wrong for a query value -- a token containing one
    would produce a URL that parses into something else entirely. Tokens are URL-safe
    today, but the layer that builds a URL should not depend on a promise made three
    modules away.
    """
    if not link_base_url:
        return f"{fallback}\n\n    {token}"

    return (
        f"Open this link:\n\n    {link_base_url.rstrip('/')}/{path}?token={quote(token, safe='')}"
    )
