"""The order in which an administrative delete destroys things.

Its own file because it is about a sequence rather than a permission, and because the bug
it pins was a real one: the vault was emptied *before* the last-owner check ran, so a
refused deletion returned 409 having already destroyed the account's credentials. The
caller was told the deletion did not happen.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from keyring_api.admin.service import Actor
from keyring_api.audit.log import AuditAction
from keyring_api.core.container import Container
from keyring_api.domain.errors import LastOwnerError
from keyring_api.domain.rbac import ALL_PERMISSIONS
from tests.fakes.clock import FakeClock

if TYPE_CHECKING:
    from keyring_api.core.config import Settings

PASSWORD = "correct horse battery staple"


@pytest.fixture
def container(settings: Settings) -> Container:
    return Container.build(settings, clock=FakeClock())


@pytest.fixture
def actor() -> Actor:
    return Actor(account_id="acct_admin", permissions=ALL_PERMISSIONS)


async def onboard(container: Container, email: str) -> str:
    """Create an account through the real invite flow. Returns its id."""
    invite = await container.account_service.issue_invite(email=email)
    account = await container.account_service.redeem_invite(
        token=invite.token, password=PASSWORD, caller="1.2.3.4"
    )
    return account.account_id


async def test_a_refused_deletion_destroys_no_credentials(
    container: Container, actor: Actor
) -> None:
    # The account row is deleted first, because that deletion is what carries the atomic
    # last-owner check. The other order empties the vault and only then discovers the
    # deletion is refused -- data loss wearing a refusal's clothes.
    owner_id = await onboard(container, "owner@example.com")
    await container.credential_service.create_profile(owner_id, "personal")
    await container.secrets.put(owner_id, "personal", "tmdb", {"api_key": "still-here"})

    with pytest.raises(LastOwnerError):
        await container.admin_service.delete_account(actor, owner_id)

    assert await container.secrets.get(owner_id, "personal", "tmdb") == {"api_key": "still-here"}


async def test_a_refused_deletion_records_nothing_in_the_audit_log(
    container: Container, actor: Actor
) -> None:
    # An entry saying an account was deleted, for an account that still exists, is worse
    # than no entry: it is a record that disagrees with reality.
    owner_id = await onboard(container, "owner@example.com")

    with pytest.raises(LastOwnerError):
        await container.admin_service.delete_account(actor, owner_id)

    entries = await container.audit.recent()
    assert [entry.action for entry in entries] == []


async def test_a_successful_deletion_removes_the_credentials_too(
    container: Container, actor: Actor
) -> None:
    await onboard(container, "owner@example.com")
    doomed_id = await onboard(container, "doomed@example.com")
    await container.credential_service.create_profile(doomed_id, "personal")
    await container.secrets.put(doomed_id, "personal", "tmdb", {"api_key": "gone"})

    await container.admin_service.delete_account(actor, doomed_id)

    assert await container.secrets.get(doomed_id, "personal", "tmdb") is None
    assert await container.accounts.get(doomed_id) is None


async def test_a_successful_deletion_is_recorded(container: Container, actor: Actor) -> None:
    await onboard(container, "owner@example.com")
    doomed_id = await onboard(container, "doomed@example.com")

    await container.admin_service.delete_account(actor, doomed_id)

    entries = await container.audit.recent()
    assert entries[0].action is AuditAction.ACCOUNT_DELETED
    assert entries[0].target_id == doomed_id


async def test_a_failed_credential_sweep_still_deletes_the_account(
    container: Container, actor: Actor, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The opposite failure, and the lesser harm: if the sweep fails after the account row
    # is gone, encrypted files are left with nothing referencing them. They are
    # unreachable through the API and an operator can remove the directory -- whereas
    # failing the whole delete would leave an account somebody has asked to be rid of.
    # It is logged rather than silent.
    await onboard(container, "owner@example.com")
    doomed_id = await onboard(container, "doomed@example.com")

    async def unwritable(_account_id: str) -> None:
        failure = "read-only file system"
        raise OSError(failure)

    monkeypatch.setattr(container.credential_service, "delete_account_data", unwritable)

    await container.admin_service.delete_account(actor, doomed_id)

    assert await container.accounts.get(doomed_id) is None
