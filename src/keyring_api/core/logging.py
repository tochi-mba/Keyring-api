"""Structured logging, with a redaction pass that runs before anything is rendered.

JSON in deployment so records are queryable, pretty console output locally. Every record
carries the request id and the authenticated account when there is one, which is what
makes a single person's activity traceable across endpoints.

The redaction processor is the part that matters. This service handles passwords, TOTP
seeds, OAuth tokens and API keys, and a log record is not a private place: records are
shipped to aggregators, kept longer than anyone intends, and read by whoever is
debugging. Redaction is applied by field name rather than by asking every call site to
remember, because "remember not to log the token" is a rule that holds until the one
exception handler that logs its whole context.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import structlog

from keyring_api.core.config import LogFormat
from keyring_api.core.context import get_account_id, get_request_id

if TYPE_CHECKING:
    from structlog.typing import EventDict, Processor, WrappedLogger

REDACTED = "[redacted]"
"""What a sensitive value is replaced with. A constant so tests can assert on it."""

MAX_REDACTION_DEPTH = 6
"""How far into nested structures the redactor walks before giving up and dropping."""

_SENSITIVE_SUBSTRINGS = (
    "authorization",
    "cookie",
    "credential",
    "passphrase",
    "password",
    "passwd",
    "private_key",
    "secret",
    "seed",
    "token",
    "api_key",
    "master_key",
    "signing_key",
)
"""Substrings that make a field name sensitive.

Matched as substrings rather than exact names so `refresh_token`, `new_password` and
`client_secret` are all covered without maintaining a list of every compound. The
failure mode of an over-broad rule is a redacted field that did not need it; the
failure mode of a narrow one is a credential in a log file.
"""


def is_sensitive(field: str) -> bool:
    """Whether a field name means the value must not be recorded."""
    lowered = field.lower()
    return any(marker in lowered for marker in _SENSITIVE_SUBSTRINGS)


def redact_secrets(
    _logger: WrappedLogger | None,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Replace every sensitive value in the record, however deeply it is nested."""
    return {key: _redact_value(key, value, depth=0) for key, value in event_dict.items()}


def _redact_value(key: str, value: object, *, depth: int) -> Any:
    """Redact one key/value pair, recursing into containers."""
    if is_sensitive(key):
        # Replaced wholesale rather than masked: the length and type of a secret are
        # themselves information, and `password=None` would reveal that none was sent.
        return REDACTED
    return _redact_container(value, depth=depth)


def _redact_container(value: object, *, depth: int) -> Any:
    """Walk into a dict or list, or return the value untouched."""
    if not isinstance(value, dict | list):
        return value

    if depth >= MAX_REDACTION_DEPTH:
        # Fail closed. A structure this deep is either a bug or an attempt to bury a
        # secret past the walker, and neither deserves to be rendered.
        return REDACTED

    if isinstance(value, dict):
        return {
            str(key): _redact_value(str(key), item, depth=depth + 1) for key, item in value.items()
        }
    return [_redact_container(item, depth=depth + 1) for item in value]


def add_request_id(
    _logger: WrappedLogger | None,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Attach the bound request id, if there is one.

    Absent outside a request rather than present-and-null, so queries can filter on
    existence.
    """
    request_id = get_request_id()
    if request_id is not None:
        event_dict["request_id"] = request_id
    return event_dict


def add_account_id(
    _logger: WrappedLogger | None,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Attach the authenticated account, if the request has one.

    The account id is an opaque identifier, not an email address: it is safe to record,
    and it is what makes "what did this person do" answerable without a log record ever
    naming them.
    """
    account_id = get_account_id()
    if account_id is not None:
        event_dict["account_id"] = account_id
    return event_dict


def configure_logging(*, level: str, log_format: LogFormat) -> None:
    """Configure structlog process-wide. Safe to call again to change the configuration."""
    shared: list[Processor] = [
        structlog.processors.add_log_level,
        add_request_id,
        add_account_id,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        # Last before rendering, so it also covers anything the processors above added.
        redact_secrets,
    ]
    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if log_format is LogFormat.JSON
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=[*shared, structlog.processors.format_exc_info, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[level.upper()]
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )


class _NamedLogger:
    """A logger that resolves against the configuration in force *when it is called*.

    ``structlog.get_logger().bind(logger=name)`` binds eagerly: ``.bind()`` snapshots the
    processor chain in force at that moment. Every module here does
    ``logger = get_logger(__name__)`` at import, which is before
    :func:`configure_logging` has run -- so those loggers would keep structlog's
    defaults, ``KEYRING_LOG_FORMAT=json`` would validate and do nothing for them, and
    the redactor would never run.

    Resolving per call costs a bind on each record, at a volume of a few records per
    request.
    """

    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        self._name = name

    def __getattr__(self, method: str) -> Any:
        return getattr(structlog.get_logger().bind(logger=self._name), method)


def get_logger(name: str) -> Any:
    """Return a logger tagged with ``name``.

    The name is bound into the event dict rather than read off the underlying logger, so
    it survives regardless of which logger factory is configured.

    The return type is deliberately loose: structlog's filtering bound loggers are
    generated at configuration time and have no single static type.
    """
    return _NamedLogger(name)
