"""The email adapters.

The property that matters most is negative: a message body carries a live invite or reset
link, and it must never reach a log record, a response, or anything world-readable.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage as MimeMessage
from typing import TYPE_CHECKING, Any, ClassVar

import pytest
from pydantic import SecretStr

from keyring_api.core.config import EmailBackend, EmailSettings, LogFormat
from keyring_api.core.logging import configure_logging
from keyring_api.notifications.base import EmailMessage, EmailSender
from keyring_api.notifications.senders import (
    DisabledEmailSender,
    FileEmailSender,
    SmtpEmailSender,
    build_sender,
)
from tests.support.filemode import assert_mode

if TYPE_CHECKING:
    from pathlib import Path

MESSAGE = EmailMessage(
    to_address="person@example.com",
    subject="Reset your keyring password",
    body="Your reset code is:\n\n    the-live-token",
)


class TestPortConformance:
    def test_every_adapter_satisfies_the_port(self, tmp_path: Path) -> None:
        # A fake that drifts from the port is a fake that tests something the service
        # does not do -- and these are real adapters, so the same reasoning applies.
        for sender in (
            DisabledEmailSender(),
            FileEmailSender(directory=tmp_path),
            SmtpEmailSender(EmailSettings()),
        ):
            checked: EmailSender = sender

            assert isinstance(checked, EmailSender)

    def test_every_adapter_says_whether_it_delivers(self, tmp_path: Path) -> None:
        """Asserted here rather than left to the isinstance check above.

        Until Python 3.12, `isinstance` against a runtime-checkable Protocol called
        `getattr` for each member, which *executed* the `is_enabled` property and made it
        look covered. 3.12 switched to `getattr_static`, so it does not -- and what that
        exposed was a genuine gap: nothing asserted that the two sending adapters report
        themselves enabled.

        Which matters more than a coverage number. The API reads `is_enabled` to decide
        whether to return an invite token in the HTTP response or rely on it arriving by
        mail. A sender that wrongly reported itself disabled would put a live token in a
        response body *and* an inbox.
        """
        assert FileEmailSender(directory=tmp_path).is_enabled is True
        assert SmtpEmailSender(EmailSettings()).is_enabled is True
        assert DisabledEmailSender().is_enabled is False


class TestDisabled:
    async def test_it_is_the_default(self) -> None:
        # A credential vault that cannot start without an SMTP server is a credential
        # vault nobody can start.
        assert isinstance(build_sender(EmailSettings()), DisabledEmailSender)

    async def test_it_reports_that_it_delivers_nothing(self) -> None:
        # The API reads this to decide whether to return an invite token. Getting it
        # wrong in this direction means the operator copies a token unnecessarily;
        # the other way means the token is in an HTTP response *and* an inbox.
        assert not DisabledEmailSender().is_enabled

    async def test_sending_reports_failure_rather_than_raising(self) -> None:
        assert not await DisabledEmailSender().send(MESSAGE)

    async def test_it_does_not_log_the_body(self, capsys: pytest.CaptureFixture[str]) -> None:
        configure_logging(level="INFO", log_format=LogFormat.JSON)

        await DisabledEmailSender().send(MESSAGE)

        assert "the-live-token" not in capsys.readouterr().out

    async def test_closing_is_a_no_op(self) -> None:
        await DisabledEmailSender().aclose()


class TestFile:
    @pytest.fixture
    def sender(self, tmp_path: Path) -> FileEmailSender:
        return FileEmailSender(directory=tmp_path / "outbox")

    async def test_it_writes_the_message(self, sender: FileEmailSender, tmp_path: Path) -> None:
        assert await sender.send(MESSAGE)

        written = list((tmp_path / "outbox").iterdir())
        assert len(written) == 1
        assert "the-live-token" in written[0].read_text(encoding="utf-8")

    async def test_the_written_file_is_owner_only(
        self, sender: FileEmailSender, tmp_path: Path
    ) -> None:
        # It contains a live reset link. Same posture as a stored credential.
        await sender.send(MESSAGE)

        written = next((tmp_path / "outbox").iterdir())
        assert_mode(written, 0o600)
        assert_mode(tmp_path / "outbox", 0o700)

    async def test_messages_do_not_overwrite_each_other(
        self, sender: FileEmailSender, tmp_path: Path
    ) -> None:
        await sender.send(MESSAGE)
        await sender.send(MESSAGE)

        assert len(list((tmp_path / "outbox").iterdir())) == 2

    async def test_it_never_logs_the_body(
        self, sender: FileEmailSender, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # This adapter exists precisely so nobody reaches for the lazy alternative of
        # logging the message to see what it said.
        configure_logging(level="INFO", log_format=LogFormat.JSON)

        await sender.send(MESSAGE)

        # The whole stream, not one record: a later line is just as public as the first.
        assert "the-live-token" not in capsys.readouterr().out

    async def test_an_unwritable_directory_reports_failure_rather_than_raising(
        self, tmp_path: Path
    ) -> None:
        # A full disk must not turn a password reset into a 500 -- and must not make a
        # request for a real address behave differently from one for an unknown address.
        blocked = tmp_path / "blocked"
        blocked.write_text("this is a file, not a directory")

        assert not await FileEmailSender(directory=blocked / "outbox").send(MESSAGE)


class TestSmtpSelection:
    def test_smtp_is_chosen_when_configured(self) -> None:
        settings = EmailSettings(
            backend=EmailBackend.SMTP, host="smtp.example.com", from_address="k@example.com"
        )

        assert isinstance(build_sender(settings), SmtpEmailSender)

    def test_file_is_chosen_when_configured(self) -> None:
        assert isinstance(build_sender(EmailSettings(backend=EmailBackend.FILE)), FileEmailSender)

    async def test_an_unreachable_server_reports_failure_rather_than_raising(self) -> None:
        # Port 9 is the discard service; nothing is listening in a test container.
        settings = EmailSettings(
            backend=EmailBackend.SMTP,
            host="127.0.0.1",
            port=9,
            from_address="k@example.com",
            use_starttls=False,
            timeout_seconds=0.2,
        )

        assert not await SmtpEmailSender(settings).send(MESSAGE)

    async def test_a_failure_does_not_log_the_body(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The failure path is the one most likely to log too much, because whoever wrote
        # it wanted to know what went wrong.
        configure_logging(level="INFO", log_format=LogFormat.JSON)
        settings = EmailSettings(
            backend=EmailBackend.SMTP,
            host="127.0.0.1",
            port=9,
            from_address="k@example.com",
            use_starttls=False,
            timeout_seconds=0.2,
        )

        await SmtpEmailSender(settings).send(MESSAGE)

        assert "the-live-token" not in capsys.readouterr().out

    async def test_closing_an_smtp_sender_is_a_no_op(self) -> None:
        await SmtpEmailSender(EmailSettings()).aclose()

    def test_the_from_header_carries_a_display_name_when_one_is_set(self) -> None:
        settings = EmailSettings(from_address="k@example.com", from_name="keyring")

        assert settings.from_header() == "keyring <k@example.com>"

    def test_the_from_header_is_the_bare_address_without_one(self) -> None:
        settings = EmailSettings(from_address="k@example.com", from_name="")

        assert settings.from_header() == "k@example.com"

    def test_the_smtp_password_is_never_rendered(self) -> None:
        # Settings get logged at startup and dumped into crash reports. A mailbox that
        # sends password resets is worth more than most of what it protects.
        settings = EmailSettings(password=SecretStr("hunter2"))

        assert "hunter2" not in repr(settings)
        assert "hunter2" not in str(settings.model_dump())


class FakeSmtp:
    """A stand-in for ``smtplib.SMTP`` that records the order of operations.

    Order is the point. STARTTLS must happen *before* login, or the password goes over
    the wire in base64 -- which is not encryption. A test that only checked "did it
    login" would pass on the broken version.
    """

    instances: ClassVar[list[FakeSmtp]] = []

    def __init__(self, host: str, port: int, timeout: float = 0.0, **kwargs: object) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.kwargs = kwargs
        self.calls: list[str] = []
        self.messages: list[MimeMessage] = []
        FakeSmtp.instances.append(self)

    def __enter__(self) -> FakeSmtp:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.calls.append("quit")

    def starttls(self, context: object = None) -> None:
        self.calls.append("starttls")
        self.tls_context = context

    def login(self, username: str, password: str) -> None:
        self.calls.append("login")
        self.username = username
        self.password = password

    def send_message(self, message: MimeMessage) -> None:
        self.calls.append("send")
        self.messages.append(message)


@pytest.fixture
def fake_smtp(monkeypatch: pytest.MonkeyPatch) -> type[FakeSmtp]:
    FakeSmtp.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSmtp)
    return FakeSmtp


def smtp_settings(**overrides: Any) -> EmailSettings:
    defaults: dict[str, Any] = {
        "backend": EmailBackend.SMTP,
        "host": "smtp.example.com",
        "port": 587,
        "from_address": "keyring@example.com",
    }
    return EmailSettings(**{**defaults, **overrides})


class TestSmtpDelivery:
    async def test_it_sends_the_message(self, fake_smtp: type[FakeSmtp]) -> None:
        assert await SmtpEmailSender(smtp_settings()).send(MESSAGE)

        assert fake_smtp.instances[0].calls == ["starttls", "send", "quit"]

    async def test_starttls_happens_before_login(self, fake_smtp: type[FakeSmtp]) -> None:
        # The order is the security property. SMTP AUTH on a plaintext connection sends
        # the password in base64, and a mailbox that sends password resets is worth more
        # than most of what it protects.
        settings = smtp_settings(username="user", password=SecretStr("pw"))

        await SmtpEmailSender(settings).send(MESSAGE)

        calls = fake_smtp.instances[0].calls
        assert calls.index("starttls") < calls.index("login")

    async def test_it_does_not_authenticate_when_no_credentials_are_configured(
        self, fake_smtp: type[FakeSmtp]
    ) -> None:
        # Some relays authenticate by source address. Sending an empty login would fail
        # the connection rather than skip authentication.
        await SmtpEmailSender(smtp_settings()).send(MESSAGE)

        assert "login" not in fake_smtp.instances[0].calls

    async def test_implicit_tls_skips_starttls(self, fake_smtp: type[FakeSmtp]) -> None:
        # Port 465 is TLS from the first byte; issuing STARTTLS on it is an error.
        settings = smtp_settings(port=465, use_starttls=False, use_implicit_tls=True)

        await SmtpEmailSender(settings).send(MESSAGE)

        assert fake_smtp.instances[0].calls == ["send", "quit"]

    async def test_the_configured_host_port_and_timeout_reach_the_connection(
        self, fake_smtp: type[FakeSmtp]
    ) -> None:
        await SmtpEmailSender(smtp_settings(timeout_seconds=3.5)).send(MESSAGE)

        connection = fake_smtp.instances[0]
        assert (connection.host, connection.port, connection.timeout) == (
            "smtp.example.com",
            587,
            3.5,
        )

    async def test_the_headers_are_set_through_the_email_api(
        self, fake_smtp: type[FakeSmtp]
    ) -> None:
        # Built with EmailMessage rather than string concatenation: that is what makes a
        # newline in an address a rejected header rather than an injected one.
        await SmtpEmailSender(smtp_settings()).send(MESSAGE)

        sent = fake_smtp.instances[0].messages[0]
        assert sent["To"] == "person@example.com"
        assert sent["From"] == "keyring <keyring@example.com>"
        assert sent["Subject"] == "Reset your keyring password"

    async def test_it_asks_autoresponders_not_to_reply(self, fake_smtp: type[FakeSmtp]) -> None:
        # Stops a vacation responder bouncing a live reset link back out to whatever
        # address it replies to.
        await SmtpEmailSender(smtp_settings()).send(MESSAGE)

        assert fake_smtp.instances[0].messages[0]["Auto-Submitted"] == "auto-generated"

    async def test_the_body_survives_intact(self, fake_smtp: type[FakeSmtp]) -> None:
        await SmtpEmailSender(smtp_settings()).send(MESSAGE)

        assert "the-live-token" in fake_smtp.instances[0].messages[0].get_content()

    async def test_a_certificate_is_verified(self, fake_smtp: type[FakeSmtp]) -> None:
        # ssl.create_default_context() verifies hostname and chain. There is deliberately
        # no setting that turns this off -- it is the one knob that turns a working
        # configuration into a silently intercepted one.
        await SmtpEmailSender(smtp_settings()).send(MESSAGE)

        context = fake_smtp.instances[0].tls_context
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname

    async def test_an_smtp_error_reports_failure_rather_than_raising(
        self, fake_smtp: type[FakeSmtp], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Providers raise a long tail of SMTPException subclasses, and every one of them
        # means the same thing here: the mail did not go, and the request must not care.
        def refuse(_self: FakeSmtp, _message: MimeMessage) -> None:
            raise smtplib.SMTPRecipientsRefused({})

        monkeypatch.setattr(fake_smtp, "send_message", refuse)

        assert not await SmtpEmailSender(smtp_settings()).send(MESSAGE)


class TestSmtpConfigurationIsValidatedAtStartup:
    def test_credentials_without_tls_are_refused(self) -> None:
        # Not a warning. A deployment that authenticates in the clear should fail to
        # start, while somebody is watching.
        with pytest.raises(ValueError, match="without TLS"):
            smtp_settings(username="user", password=SecretStr("pw"), use_starttls=False)

    def test_both_tls_modes_at_once_is_refused(self) -> None:
        # STARTTLS on an implicit-TLS connection is a protocol error, and the symptom is
        # a connection that hangs rather than one that says why.
        with pytest.raises(ValueError, match="mutually exclusive"):
            smtp_settings(use_starttls=True, use_implicit_tls=True)

    def test_smtp_without_a_host_is_refused(self) -> None:
        with pytest.raises(ValueError, match="host and from_address"):
            smtp_settings(host="")

    def test_smtp_without_a_from_address_is_refused(self) -> None:
        with pytest.raises(ValueError, match="host and from_address"):
            smtp_settings(from_address="")

    def test_an_unauthenticated_relay_without_tls_is_allowed(self) -> None:
        # A local relay on loopback is a real deployment. There is no password to leak,
        # so the rule that refuses credentials in the clear does not apply.
        assert smtp_settings(use_starttls=False).backend is EmailBackend.SMTP

    def test_the_disabled_backend_needs_no_configuration_at_all(self) -> None:
        assert EmailSettings().backend is EmailBackend.DISABLED


async def test_the_file_sender_closes_cleanly(tmp_path: Path) -> None:
    # Nothing to release -- but the port says every sender closes, and a shutdown path
    # that raises on one adapter is a shutdown path that hangs.
    await FileEmailSender(directory=tmp_path).aclose()
