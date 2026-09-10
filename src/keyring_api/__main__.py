"""Server entry point: ``python -m keyring_api`` or the ``keyring-api`` script."""

from __future__ import annotations

import uvicorn

from keyring_api.core.config import load_settings


def main() -> None:
    """Serve the API using the configured host and port."""
    settings = load_settings()
    uvicorn.run(
        "keyring_api.api.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_config=None,
    )


if __name__ == "__main__":
    main()
