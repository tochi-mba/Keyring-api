"""Where this library's diagnostics go.

Every service in the family logs with keyword fields, and several of this library's records
exist precisely so an operator can read *why* a token was refused while the caller is told
nothing. So the library does not choose a logging framework. It takes any object with
``info``, ``warning`` and ``exception`` methods that accept an event name and keyword
fields -- which is exactly the shape of a structlog logger -- and falls back to the standard
library, rendering the fields into the message, when it is given none.

The fields are always names, reasons, key ids and exception *type* names. Never a token,
never a URL, never an exception's message: the text an HTTP client raises carries the URL it
was given, and a URL can carry credentials in its userinfo.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol


class Logger(Protocol):
    """The logging shape this library writes to."""

    def info(self, event: str, **fields: Any) -> Any:
        """Record something an operator may want to read."""
        ...

    def warning(self, event: str, **fields: Any) -> Any:
        """Record something that degraded service."""
        ...

    def exception(self, event: str, **fields: Any) -> Any:
        """Record an unexpected failure, with its traceback."""
        ...


class StdlibLogger:
    """A :class:`Logger` over the standard library, for services that pass none."""

    __slots__ = ("_logger",)

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def info(self, event: str, **fields: Any) -> None:
        self._logger.info(render(event, fields))

    def warning(self, event: str, **fields: Any) -> None:
        self._logger.warning(render(event, fields))

    def exception(self, event: str, **fields: Any) -> None:
        self._logger.exception(render(event, fields))


def render(event: str, fields: dict[str, Any]) -> str:
    """``event key=value ...``, with the keys sorted so a record reads the same every time."""
    if not fields:
        return event
    return event + " " + " ".join(f"{key}={fields[key]}" for key in sorted(fields))
