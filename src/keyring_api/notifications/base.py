"""The email port.

Deliberately tiny. Everything this service ever needs to send is a short plain-text
message to one address, so the port is one method, and every provider worth using --
Gmail, Brevo, Resend, MailerSend, SES -- speaks SMTP. One adapter covers all of them, and
no vendor SDK goes into the process that holds the credentials.

Two properties matter more than they look:

``is_enabled`` exists so the API can decide whether to *return* an invite token or rely
on it arriving by mail. Getting that wrong in the safe direction means the operator
copies a token unnecessarily; getting it wrong the other way means the token is in an
HTTP response *and* an inbox.

``send`` must not raise into a request handler. A broken SMTP configuration must not turn
password reset into a 500 -- and, worse, must not make a request for a real address behave
differently from one for an unknown address. Delivery failures are logged and swallowed
here; the outbox in :mod:`keyring_api.notifications.outbox` keeps them off the request
path entirely.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class EmailMessage:
    """One plain-text message to one recipient.

    Plain text only. An HTML mail from a credential service is a phishing lesson in the
    wrong direction: it trains the recipient to click styled buttons in mail claiming to
    be about their passwords.
    """

    to_address: str
    subject: str
    body: str


@runtime_checkable
class EmailSender(Protocol):
    """Delivers a message, or reports that it cannot."""

    @property
    def is_enabled(self) -> bool:
        """Whether this sender actually delivers anywhere."""
        ...

    async def send(self, message: EmailMessage) -> bool:
        """Attempt delivery. Returns whether it succeeded. Never raises."""
        ...

    async def aclose(self) -> None:
        """Release anything held open."""
        ...
