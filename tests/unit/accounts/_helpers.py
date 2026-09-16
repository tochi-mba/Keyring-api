"""Builders shared by the account-service tests.

The ``settings`` fixture here is deliberately *not* the suite-wide one: lockout and rate
limits are tight enough that a test can trip the defence under study without the other
masking it. Kept in this module rather than a directory ``conftest.py`` so the sibling
store and hashing tests keep the looser suite defaults.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from keyring_api.accounts.hashing import Argon2PasswordHasher
from keyring_api.accounts.ratelimit import InMemoryRateLimiter
from keyring_api.accounts.service import AccountService
from keyring_api.accounts.sql_store import (
    SqlAccountStore,
    SqlGrantStore,
    SqlSessionStore,
)
from keyring_api.core.config import Argon2Settings, RateLimitSettings, Settings
from keyring_api.core.preferences import DeploymentPreferences
from keyring_api.notifications.base import EmailSender
from keyring_api.notifications.outbox import Outbox
from keyring_api.notifications.senders import DisabledEmailSender
from tests.fakes.clock import FakeClock

if TYPE_CHECKING:
    from keyring_api.core.preferences import PreferenceSource
    from keyring_api.storage.database import Database

EMAIL = "person@example.com"
PASSWORD = "correct horse battery staple"
CALLER = "1.2.3.4"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        _env_file=None,  # type: ignore[call-arg]
        argon2=Argon2Settings(time_cost=1, memory_cost_kib=8, parallelism=1),
        # The two guessing defences are deliberately far apart here so a test can
        # exercise either one without the other tripping first and masking it.
        lockout_threshold=4,
        rate_limit=RateLimitSettings(login_attempts=8, reset_attempts=3, invite_attempts=3),
    )


def build_service(
    *,
    database: Database,
    clock: FakeClock,
    settings: Settings,
    sender: EmailSender | None = None,
    preferences: PreferenceSource | None = None,
) -> AccountService:
    """One service wired onto one database.

    All three stores share the database, which is what a deployment does -- and it means
    the foreign keys between accounts, sessions and grants are live in these tests rather
    than something only the integration suite sees.
    """
    return AccountService(
        accounts=SqlAccountStore(database=database),
        sessions=SqlSessionStore(database=database, clock=clock),
        grants=SqlGrantStore(database=database),
        hasher=Argon2PasswordHasher(settings.argon2),
        limiter=InMemoryRateLimiter(clock=clock),
        outbox=Outbox(sender or DisabledEmailSender()),
        clock=clock,
        settings=settings,
        preferences=preferences if preferences is not None else DeploymentPreferences(settings),
    )


@pytest.fixture
def service(database: Database, clock: FakeClock, settings: Settings) -> AccountService:
    return build_service(database=database, clock=clock, settings=settings)


FOUNDER_EMAIL = "founder@example.com"


async def create(service: AccountService, email: str, password: str = PASSWORD) -> str:
    """Invite an address and redeem it. Returns the new account id."""
    invite = await service.issue_invite(email=email)
    account = await service.redeem_invite(token=invite.token, password=password, caller=CALLER)
    return account.account_id


async def onboard(service: AccountService, email: str = EMAIL, password: str = PASSWORD) -> str:
    """Create the account under test, behind a founder account.

    The founder exists because the *first* account a service ever creates becomes the
    owner, and the last-owner guard refuses to delete or demote the only one. These tests
    are about sessions, resets and deletion mechanics rather than about ownership, so the
    account under test is deliberately an ordinary member -- which is also what every
    account except the first actually is.

    Ownership itself is tested in tests/unit/accounts/test_roles_store.py and
    tests/integration/test_admin_accounts.py.
    """
    if await service._accounts.count() == 0:
        await create(service, FOUNDER_EMAIL)

    return await create(service, email, password)
