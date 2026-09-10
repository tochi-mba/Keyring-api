"""Dispatching mail without putting it on the request path.

The reason this exists is a security property rather than a performance one.

``request_password_reset`` must answer identically whether or not the address has an
account. The body and status already do. But if a *real* address meant waiting for an
SMTP round trip and an unknown one returned immediately, the response *time* would say
which -- rebuilding the enumeration oracle that the identical body was there to close.
So delivery is handed to a background task and the handler returns at once, whatever the
outcome.

Two consequences are handled here rather than left to chance:

* The queue is bounded. An unbounded set of pending tasks is memory an unauthenticated
  caller allocates, one reset request at a time -- and the request-level rate limits
  bound the rate, not the total.
* Shutdown drains it. A queued reset link silently dropped by a restart is a person
  waiting for mail that will never arrive, with nothing anywhere saying why.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

from keyring_api.core.logging import get_logger

if TYPE_CHECKING:
    from keyring_api.notifications.base import EmailMessage, EmailSender

logger = get_logger(__name__)

MAX_PENDING = 64
"""Messages in flight before new ones are dropped rather than queued."""

DRAIN_TIMEOUT_SECONDS = 10.0


class Outbox:
    """Sends messages in the background, bounded and drainable."""

    def __init__(self, sender: EmailSender) -> None:
        self._sender = sender
        self._pending: set[asyncio.Task[bool]] = set()

    @property
    def is_enabled(self) -> bool:
        """Whether delivery actually goes anywhere.

        The API reads this to decide whether to return an invite token in the response.
        """
        return self._sender.is_enabled

    def enqueue(self, message: EmailMessage) -> bool:
        """Schedule delivery and return immediately.

        The return value says whether it was *queued*, not whether it was delivered --
        no caller ever learns the latter, because a caller that did could tell a real
        address from an unknown one by whether delivery succeeded.
        """
        if not self._sender.is_enabled:
            return False

        if len(self._pending) >= MAX_PENDING:
            # Dropped rather than queued. The alternative is unbounded memory driven by
            # unauthenticated requests; a dropped message is visible here, and the token
            # it carried expires unused.
            logger.warning("email_dropped", reason="outbox_full", to=message.to_address)
            return False

        task = asyncio.create_task(self._sender.send(message), name="email-send")
        # Held in a set until done: asyncio only keeps a weak reference, so a task that
        # nothing holds can be garbage-collected mid-flight.
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)
        return True

    async def drain(self) -> None:
        """Wait for queued messages, then give up rather than hang the shutdown.

        No explicit cancellation afterwards, deliberately. When the timeout fires it
        cancels the task awaiting the gather, that cancellation propagates into the
        gathered sends, and each one's done-callback removes it from the pending set --
        so by the time this returns they are already cancelled and the set is empty. A
        cancel loop here looked like prudence and was unreachable code; the test below
        pins the behaviour that makes it unnecessary.
        """
        if not self._pending:
            return

        logger.info("outbox_draining", pending=len(self._pending))
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(DRAIN_TIMEOUT_SECONDS):
                await asyncio.gather(*self._pending, return_exceptions=True)

    async def aclose(self) -> None:
        """Drain, then release the sender."""
        await self.drain()
        await self._sender.aclose()
