"""The offline-grant adapter satisfies the port the rest of the package depends on.

The SQL module does not inherit from the Protocol, so without a test that imports the
port the file never runs and a missing method would be a type-checker finding rather
than a gate failure. Isolation and revocation live in the integration suite.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from keyring_api.profiles.delegations import DelegationStore
from keyring_api.profiles.sql_delegations import SqlDelegationStore

if TYPE_CHECKING:
    from keyring_api.storage.database import Database


@pytest.fixture
async def store(database: Database) -> SqlDelegationStore:
    return SqlDelegationStore(database=database)


async def test_it_satisfies_the_port(store: SqlDelegationStore) -> None:
    checked: DelegationStore = store

    assert isinstance(checked, DelegationStore)
