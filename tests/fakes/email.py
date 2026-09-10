"""Email senders for tests.

Hand-written and satisfying the real ``EmailSender`` protocol, so a change to the port
makes these fail to type-check rather than silently drift.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from keyring_api.notifications.base import EmailMessage


class RecordingSender:
    """Delivers nowhere and remembers everything."""

    def __init__(self) -> None:
        self.sent: list[EmailMessage] = []
        self.closed = False

    @property
    def is_enabled(self) -> bool:
        return True

    async def send(self, message: EmailMessage) -> bool:
        self.sent.append(message)
        return True

    async def aclose(self) -> None:
        self.closed = True


class ExplodingSender:
    """Fails the way a provider outage fails.

    A real sender swallows its own failures, so this one raises instead -- which is the
    harsher case, and proves nothing escapes into the request path even then.
    """

    @property
    def is_enabled(self) -> bool:
        return True

    async def send(self, message: EmailMessage) -> bool:
        outage = "the provider is unreachable"
        raise RuntimeError(outage)

    async def aclose(self) -> None:
        return
