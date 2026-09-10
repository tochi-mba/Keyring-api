"""Email adapters: disabled, file, and SMTP.

Three, because the three situations are genuinely different:

* **Disabled** is the default. The service must start and be fully usable with no mail
  configuration at all, delivering invite tokens through the operator instead.
* **File** writes messages to a directory. For development, and for the case where you
  want to see exactly what would have gone out. It exists so that "check what the mail
  said" never becomes "log the token", which would put a live reset link in the log
  pipeline.
* **SMTP** is the real one, and it is the only network client here on purpose: every
  provider a small deployment would pick -- Gmail with an app password, Brevo, Resend,
  MailerSend, SES -- speaks it.

The SMTP adapter uses the standard library in a worker thread rather than an async SMTP
dependency. Mail is sent a few times a day at this scale, so the thread is free, and it
is one fewer package in the process that holds the credentials.
"""

from __future__ import annotations

import smtplib
import ssl
from asyncio import to_thread
from email.message import EmailMessage as MimeMessage
from typing import TYPE_CHECKING

from keyring_api.core.config import EmailBackend
from keyring_api.core.logging import get_logger

if TYPE_CHECKING:
    from pathlib import Path

    from keyring_api.core.config import EmailSettings
    from keyring_api.notifications.base import EmailMessage

logger = get_logger(__name__)

OUTBOX_FILE_MODE = 0o600
OUTBOX_DIR_MODE = 0o700
"""A written message contains a live invite or reset link. It is credential-grade."""


class DisabledEmailSender:
    """Sends nothing, and says so.

    Not a failure mode -- the default. With this in place the operator delivers invite
    tokens by hand, which is exactly the flow described in ADR-0009.
    """

    __slots__ = ()

    @property
    def is_enabled(self) -> bool:
        return False

    async def send(self, message: EmailMessage) -> bool:
        # The recipient is logged; the body is not, ever. It contains the token.
        logger.info("email_not_sent", reason="delivery_disabled", to=message.to_address)
        return False

    async def aclose(self) -> None:
        return


class FileEmailSender:
    """Writes each message to a file instead of sending it.

    For development. The alternative people reach for is logging the message, which puts
    a live reset link into the log pipeline and from there into wherever logs are
    shipped -- so this exists to make the lazy option unnecessary.
    """

    def __init__(self, *, directory: Path) -> None:
        self._directory = directory
        self._sequence = 0

    @property
    def is_enabled(self) -> bool:
        return True

    async def send(self, message: EmailMessage) -> bool:
        self._sequence += 1
        path = self._directory / f"{self._sequence:04d}-{_slug(message.to_address)}.eml"

        try:
            self._directory.mkdir(mode=OUTBOX_DIR_MODE, parents=True, exist_ok=True)
            self._directory.chmod(OUTBOX_DIR_MODE)
            path.write_text(_render(message))
            path.chmod(OUTBOX_FILE_MODE)
        except OSError:
            logger.warning("email_write_failed", to=message.to_address)
            return False

        logger.info("email_written", to=message.to_address, path=str(path))
        return True

    async def aclose(self) -> None:
        return


class SmtpEmailSender:
    """Sends over SMTP, using the standard library in a worker thread."""

    def __init__(self, settings: EmailSettings) -> None:
        self._settings = settings

    @property
    def is_enabled(self) -> bool:
        return True

    async def send(self, message: EmailMessage) -> bool:
        """Deliver, and swallow every failure.

        A provider being down must not turn a password reset into a 500 -- and must
        certainly not make a request for a real address behave differently from one for
        an address with no account. The reason goes to the logs, where only the operator
        reads it; the caller sees the same acknowledgement either way.
        """
        try:
            await to_thread(self._send_blocking, message)
        except (OSError, smtplib.SMTPException):
            # Deliberately broad on the SMTP side: providers raise a long tail of
            # subclasses, and every one of them means the same thing here.
            logger.warning("email_send_failed", to=message.to_address, host=self._settings.host)
            return False

        logger.info("email_sent", to=message.to_address)
        return True

    async def aclose(self) -> None:
        return

    def _send_blocking(self, message: EmailMessage) -> None:
        """The blocking half, run off the event loop."""
        mime = MimeMessage()
        # set_content and the header setters quote and encode for us. Building headers by
        # string concatenation is how a newline in an address becomes header injection --
        # normalize_email already rejects those, but this is the layer that would suffer.
        mime["From"] = self._settings.from_header()
        mime["To"] = message.to_address
        mime["Subject"] = message.subject
        # Tells well-behaved autoresponders not to reply, which stops a vacation
        # responder bouncing a live reset link back out to a mailing list.
        mime["Auto-Submitted"] = "auto-generated"
        mime.set_content(message.body)

        context = ssl.create_default_context()
        with self._connect(context) as server:
            if self._settings.use_starttls:
                server.starttls(context=context)
            if self._settings.username and self._settings.password:
                server.login(self._settings.username, self._settings.password.get_secret_value())
            server.send_message(mime)

    def _connect(self, context: ssl.SSLContext) -> smtplib.SMTP:
        """Open the connection, implicit TLS or plain."""
        if self._settings.use_implicit_tls:
            return smtplib.SMTP_SSL(
                self._settings.host,
                self._settings.port,
                timeout=self._settings.timeout_seconds,
                context=context,
            )
        return smtplib.SMTP(
            self._settings.host, self._settings.port, timeout=self._settings.timeout_seconds
        )


def build_sender(
    settings: EmailSettings,
) -> DisabledEmailSender | FileEmailSender | SmtpEmailSender:
    """Choose an adapter from configuration.

    Validated at startup rather than at the first send: a deployment that thinks it has
    mail configured and does not should find out while somebody is watching, not when
    somebody's reset link fails to arrive.
    """
    if settings.backend is EmailBackend.SMTP:
        return SmtpEmailSender(settings)
    if settings.backend is EmailBackend.FILE:
        return FileEmailSender(directory=settings.outbox_dir)
    return DisabledEmailSender()


def _render(message: EmailMessage) -> str:
    """Render a message in the shape a `.eml` file takes."""
    return f"To: {message.to_address}\nSubject: {message.subject}\n\n{message.body}\n"


def _slug(address: str) -> str:
    """A filename-safe fragment of an address."""
    return "".join(character if character.isalnum() else "-" for character in address)[:40]
