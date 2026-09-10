"""keyring: accounts, profiles and credentials for every other service you run.

One place holds the identities — a person's login, and the credential sets ("profiles")
they own for third-party services. Everything else authenticates against it and asks for
a usable credential at the moment it needs one, so no other service ever stores a secret.

The public surface is the FastAPI application built by
:func:`keyring_api.api.app.create_app`. Everything else is internal and free to change,
with the exception of the HTTP contract documented in ``docs/api.md`` — route
``operation_id``s are treated as public because they become MCP tool names.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
