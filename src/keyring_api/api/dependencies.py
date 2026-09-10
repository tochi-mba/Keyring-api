"""FastAPI dependency wiring.

The container is built once at startup and parked on the app; these turn it into typed
parameters so handlers never reach into application state themselves.

:data:`CurrentAccountDep` is the important one. It is the single place a request becomes
an account, which is what makes "every ``/v1`` route requires an account" a fact about
the code rather than a convention that holds until someone forgets a decorator.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from keyring_api.admin.service import Actor
from keyring_api.audit.log import BREAK_GLASS_ACTOR
from keyring_api.core.container import Container
from keyring_api.core.context import set_account_id
from keyring_api.domain.accounts import Account
from keyring_api.domain.errors import AuthenticationError
from keyring_api.domain.rbac import ALL_PERMISSIONS, Permission
from keyring_api.domain.sessions import Session

bearer_scheme = HTTPBearer(auto_error=False, description="A session token from `login`.")
"""``auto_error=False`` so a missing header raises our error, in our problem+json shape.

Left to itself, HTTPBearer raises a bare 403 with a plain JSON body -- a different
status and a different shape from every other failure this service produces.
"""

MISSING_CREDENTIALS = "a session token is required"


def get_container(request: Request) -> Container:
    """Return the container assembled during startup."""
    container: Container = request.app.state.container
    return container


ContainerDep = Annotated[Container, Depends(get_container)]


async def get_current_session(
    container: ContainerDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Session:
    """Resolve the session token on the request to a live session.

    The whole session is returned rather than just the account id, so a handler that
    needs to revoke *this* session -- logout, or a password change that keeps the
    calling device signed in -- has the id without re-reading and re-parsing the
    Authorization header itself. Two handlers doing that by hand is two places for the
    parsing to drift apart.

    Binds the account into the request context as a side effect, so every log record
    produced by the rest of the request says who it was for without any handler passing
    it along.

    Raises:
        AuthenticationError: no token, or one that is unknown, expired, or belongs to an
            account that is gone or disabled.
    """
    if credentials is None:
        raise AuthenticationError(MISSING_CREDENTIALS)

    session = await container.account_service.resolve_session(credentials.credentials)
    set_account_id(session.account_id)
    return session


CurrentSessionDep = Annotated[Session, Depends(get_current_session)]


async def get_current_account(container: ContainerDep, session: CurrentSessionDep) -> Account:
    """The account the request is authenticated as.

    Returns the account rather than its id. resolve_session has already established that
    it exists -- an authenticated request whose account is gone is refused there -- so a
    handler that reads it again would have to re-handle a ``None`` that cannot arrive,
    and would be writing a branch no test can reach.

    Raises:
        AuthenticationError: if the account vanished between the two reads.
    """
    account = await container.accounts.get(session.account_id)
    if account is None:
        # Only reachable if a deletion lands between resolve_session and here. Rare, and
        # the right answer is the same one an expired session gets.
        raise AuthenticationError(MISSING_CREDENTIALS)
    return account


CurrentAccountDep = Annotated[Account, Depends(get_current_account)]


async def get_actor(
    container: ContainerDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> Actor:
    """Work out who is asking and what they may do.

    Two kinds of caller, tried in order:

    **The break-glass token**, compared in constant time. It holds every permission and
    exists for the situation roles cannot cover -- no owner can log in, or none exists
    yet. Recorded in the audit log as ``break-glass``, conspicuously, because an audit
    log full of it means somebody is using the recovery path as a convenience.

    **A session**, resolved to its account and then to that account's roles. Resolved on
    every request rather than cached on the session or baked into a token: that is what
    makes revoking a role take effect on the very next request rather than at next login.

    Raises:
        AuthenticationError: no credentials, or ones that are neither.
    """
    if credentials is None:
        raise AuthenticationError(MISSING_CREDENTIALS)

    admin_token = container.settings.admin_token
    if admin_token is not None and hmac.compare_digest(
        credentials.credentials, admin_token.get_secret_value()
    ):
        set_account_id(BREAK_GLASS_ACTOR)
        return Actor(account_id=BREAK_GLASS_ACTOR, permissions=ALL_PERMISSIONS, is_break_glass=True)

    session = await container.account_service.resolve_session(credentials.credentials)
    account = await container.accounts.get(session.account_id)
    if account is None:
        raise AuthenticationError(MISSING_CREDENTIALS)

    set_account_id(account.account_id)
    return await container.actor_for(account.account_id, account.roles)


ActorDep = Annotated[Actor, Depends(get_actor)]


def requires(permission: Permission) -> Callable[[Actor], Actor]:
    """Build a dependency that admits only actors holding ``permission``.

    Used as a route dependency so the requirement is declared next to the route and shows
    up in the OpenAPI document, rather than being an ``if`` somewhere inside a handler
    that a later edit can drop.

    It does not replace the check inside the service. Both exist deliberately: the route
    dependency is the one a reader sees, and the service check is the one that still
    holds when a handler is called from somewhere else.
    """

    def guard(actor: ActorDep) -> Actor:
        actor.require(permission)
        return actor

    return guard
