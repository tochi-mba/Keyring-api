"""The server entry point.

Thin, but it is the line between "the tests pass" and "the process starts", and it is
the one place a setting is turned into how the server actually binds.
"""

from __future__ import annotations

from typing import Any

import pytest
import uvicorn

from keyring_api.__main__ import main


def test_it_serves_the_app_factory_on_the_configured_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorded: dict[str, Any] = {}

    def capture(target: str, **kwargs: Any) -> None:
        recorded["target"] = target
        recorded.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", capture)
    monkeypatch.setenv("KEYRING_PORT", "9123")
    monkeypatch.setenv("KEYRING_HOST", "127.0.0.1")

    main()

    assert recorded["target"] == "keyring_api.api.app:create_app"
    assert recorded["factory"] is True
    assert recorded["port"] == 9123
    # log_config=None so uvicorn does not install its own handlers over structlog's --
    # otherwise access lines bypass the redaction processor entirely.
    assert recorded["log_config"] is None
