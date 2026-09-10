"""The outbox.

It exists for a security reason rather than a performance one, and that is what these
tests are about: delivery must not happen on the request path, because a real address
taking an SMTP round trip while an unknown one returns immediately would rebuild the
enumeration oracle that the identical response body exists to close.
"""

from __future__ import annotations

import asyncio

import pytest

from keyring_api.notifications.base import EmailMessage
from keyring_api.notifications.outbox import MAX_PENDING, Outbox
from keyring_api.notifications.senders import DisabledEmailSender

MESSAGE = EmailMessage(to_address="person@example.com", subject="s", body="the-live-token")


class SlowSender:
    """A sender that blocks until released, so a test can observe the request path."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.sent: list[EmailMessage] = []
        self.closed = False

    @property
    def is_enabled(self) -> bool:
        return True

    async def send(self, message: EmailMessage) -> bool:
        self.started.set()
        await self.release.wait()
        self.sent.append(message)
        return True

    async def aclose(self) -> None:
        self.closed = True


class FailingSender(SlowSender):
    """Raises rather than swallowing, which is the harsher case the outbox must survive."""

    async def send(self, message: EmailMessage) -> bool:  # noqa: ARG002
        failure = "the provider is down"
        raise RuntimeError(failure)


async def test_enqueue_returns_before_the_send_completes() -> None:
    # The whole point. If this blocked, the response time for a real address would differ
    # from one for an address with no account.
    sender = SlowSender()
    outbox = Outbox(sender)

    assert outbox.enqueue(MESSAGE)
    assert sender.sent == []

    sender.release.set()
    await outbox.drain()
    assert len(sender.sent) == 1


async def test_a_disabled_sender_queues_nothing() -> None:
    assert not Outbox(DisabledEmailSender()).enqueue(MESSAGE)


async def test_it_reports_whether_delivery_goes_anywhere() -> None:
    assert not Outbox(DisabledEmailSender()).is_enabled
    assert Outbox(SlowSender()).is_enabled


async def test_the_queue_is_bounded() -> None:
    # An unbounded set of pending tasks is memory an unauthenticated caller allocates,
    # one reset request at a time. The rate limits bound the rate, not the total.
    sender = SlowSender()
    outbox = Outbox(sender)

    queued = sum(1 for _ in range(MAX_PENDING + 10) if outbox.enqueue(MESSAGE))

    assert queued == MAX_PENDING

    sender.release.set()
    await outbox.drain()


async def test_draining_waits_for_queued_messages() -> None:
    # A queued reset link silently dropped by a restart is a person waiting for mail that
    # will never arrive, with nothing anywhere saying why.
    sender = SlowSender()
    outbox = Outbox(sender)
    outbox.enqueue(MESSAGE)
    await sender.started.wait()
    sender.release.set()

    await outbox.drain()

    assert len(sender.sent) == 1


async def test_draining_gives_up_rather_than_hanging_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A provider that accepts the connection and never answers must not keep the process
    # alive indefinitely.
    monkeypatch.setattr("keyring_api.notifications.outbox.DRAIN_TIMEOUT_SECONDS", 0.05)
    sender = SlowSender()
    outbox = Outbox(sender)
    outbox.enqueue(MESSAGE)
    await sender.started.wait()

    await outbox.drain()

    assert sender.sent == []
    # The timeout's cancellation propagated into the send and its done-callback emptied
    # the pending set. This is why drain() needs no cancel loop of its own -- and the
    # assertion is here so that if the mechanism ever changes, something says so.
    assert outbox._pending == set()


async def test_draining_an_empty_outbox_is_immediate() -> None:
    await Outbox(SlowSender()).drain()


async def test_a_send_that_raises_does_not_escape() -> None:
    # Nothing awaits these tasks except drain(), so an exception here would surface as an
    # unretrieved-task warning at an unrelated moment -- and filterwarnings=error would
    # fail whichever test happened to be running.
    outbox = Outbox(FailingSender())
    outbox.enqueue(MESSAGE)

    await outbox.drain()


async def test_closing_drains_and_releases_the_sender() -> None:
    sender = SlowSender()
    sender.release.set()
    outbox = Outbox(sender)
    outbox.enqueue(MESSAGE)

    await outbox.aclose()

    assert sender.closed
    assert len(sender.sent) == 1
