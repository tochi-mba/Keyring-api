"""Fixtures shared by the client library's tests."""

from __future__ import annotations

from typing import Any

import pytest

from keyring_client.testing import FakeClock, FakeKeyring


class RecordingLogger:
    """A :class:`~keyring_client.Logger` that keeps what it was told, for assertions.

    The assertions it exists for are the ones about what must *not* reach a log: a token, a
    URL, an exception's message.
    """

    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    def info(self, event: str, **fields: Any) -> None:
        self.records.append(("info", event, fields))

    def warning(self, event: str, **fields: Any) -> None:
        self.records.append(("warning", event, fields))

    def exception(self, event: str, **fields: Any) -> None:
        self.records.append(("exception", event, fields))

    def events(self) -> list[str]:
        return [event for _, event, _ in self.records]

    def rendered(self) -> str:
        """Everything recorded, as one string to search for things that must be absent."""
        return repr(self.records)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def keyring() -> FakeKeyring:
    return FakeKeyring()


@pytest.fixture
def recorder() -> RecordingLogger:
    return RecordingLogger()
