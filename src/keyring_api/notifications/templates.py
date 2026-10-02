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

The two notices -- a new session, a credential change -- carry no link and no token at
all. A security notice with a button in it is the exact shape of the phishing it warns
about, and there is nothing to click: the remedy is a password change, made wherever the
person normally signs in. Nor do they name the service or profile that changed, by the
third rule.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import quote

from keyring_api.domain.changes import ChangeOrigin, CredentialChange
from keyring_api.notifications.base import EmailMessage

if TYPE_CHECKING:
    from datetime import datetime

INVITE_SUBJECT = "You have been invited to keyring"
RESET_SUBJECT = "Reset your keyring password"
NEW_SESSION_SUBJECT = "New sign-in to your keyring account"
CREDENTIAL_CHANGE_SUBJECT = "A stored credential changed in your keyring account"

_CHANGED = {
    CredentialChange.STORED: "added or replaced",
    CredentialChange.REMOVED: "removed",
}

_BY = {
    ChangeOrigin.PERSON: "from a signed-in session on your account",
    ChangeOrigin.SERVICE: "by a service acting for you with a token you gave it",
    ChangeOrigin.PROVIDER: "when an authorization finished at the service's own sign-in page",
    ChangeOrigin.ADMINISTRATOR: "by an administrator of this keyring server",
}

_IF_NOT_YOU = """\
If that was not you, somebody else can use your account. Change your keyring password
now: that signs out every other session, including theirs. If you cannot sign in, ask
whoever runs this keyring server to reset it."""


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


def new_session_message(*, to_address: str, at: datetime) -> EmailMessage:
    """The notice that somebody just signed in to this account.

    When, and nothing else: no session id, no token, no address the sign-in came from --
    behind a proxy that is the proxy's address, and a wrong clue is worse than none.
    """
    body = f"""\
Your keyring account was signed in to at {_moment(at)}.

If that was you, there is nothing to do.

{_IF_NOT_YOU}

You get this because new sign-in notices are on for this account. You can turn them
off in your settings.
"""
    return EmailMessage(to_address=to_address, subject=NEW_SESSION_SUBJECT, body=body)


def credential_change_message(
    *, to_address: str, change: CredentialChange, origin: ChangeOrigin, at: datetime
) -> EmailMessage:
    """The notice that a stored credential was added, replaced or removed.

    Says what kind of change and who asked for it, never which credential: whoever reads
    this mailbox would otherwise learn what the account holds. The person's own list of
    connections answers "which" for somebody who can sign in.
    """
    body = f"""\
A credential stored in your keyring account was {_CHANGED[change]} at {_moment(at)},
{_BY[origin]}.

This message does not say which one. Sign in to keyring to see your connections as they
are now.

If that was you, there is nothing to do.

{_IF_NOT_YOU} Then check your connections.

You get this because credential-change notices are on for this account. You can turn
them off in your settings.
"""
    return EmailMessage(to_address=to_address, subject=CREDENTIAL_CHANGE_SUBJECT, body=body)


def _moment(at: datetime) -> str:
    """A time a person can read, to the minute, in UTC so it means one thing everywhere."""
    return at.strftime("%Y-%m-%d %H:%M UTC")


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
