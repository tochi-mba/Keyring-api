"""The application factory.

A factory rather than a module-level app: tests build an app per case with their own
settings, and nothing is constructed as a side effect of importing this module.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastapi import FastAPI

from keyring_api.api.errors import register_exception_handlers
from keyring_api.api.middleware import RequestContextMiddleware
from keyring_api.api.routers import ROUTERS
from keyring_api.core.config import Settings, load_settings
from keyring_api.core.container import Container
from keyring_api.core.logging import configure_logging, get_logger
from keyring_api.core.version import service_version

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = get_logger(__name__)

API_DESCRIPTION = """
Accounts, profiles and credentials for every other service you run.

A person logs in once and gets a session token. Their **profiles** are named credential
sets, and each profile's **connections** link it to one third-party service. Other
services ask keyring for a usable credential at the moment they need one, so nothing
else ever stores a secret.

No endpoint returns a stored secret. Reads report status only -- which connections
exist, and whether each one is currently usable.
""".strip()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application.

    Args:
        settings: configuration to use. Loaded from the environment when omitted, which
            is what the server entry point does; tests pass their own.
    """
    settings = settings or load_settings()
    configure_logging(level=settings.log_level, log_format=settings.log_format)

    app = FastAPI(
        title=settings.app_name,
        description=API_DESCRIPTION,
        version=service_version(),
        lifespan=_lifespan,
        # Route summaries and operation ids are the contract an MCP bridge generates
        # tool names and descriptions from, so they are written for a model to read.
        openapi_tags=[
            {"name": "health", "description": "Liveness and dependency checks."},
            {"name": "auth", "description": "Logging in, logging out, and passwords."},
            {"name": "admin", "description": "Operator-only: invites and account status."},
        ],
    )
    app.state.settings = settings

    app.add_middleware(RequestContextMiddleware)
    register_exception_handlers(app)

    for router in ROUTERS:
        app.include_router(router)

    return app


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Build the container on startup and shut it down cleanly on the way out."""
    container = start(app)
    try:
        yield
    finally:
        await stop(container)


def start(app: FastAPI) -> Container:
    """Wire the application's dependencies and begin background retention."""
    container = Container.build(app.state.settings)
    app.state.container = container
    container.start_sweeper()

    logger.info(
        "service_started",
        environment=container.settings.environment,
        vault_sealed=container.settings.master_key_bytes() is None,
    )
    return container


async def stop(container: Container) -> None:
    """Release everything the application holds open.

    Logged before closing rather than after, so a shutdown that hangs still leaves a
    record of having been asked to stop.
    """
    logger.info("service_stopping")
    await container.aclose()
