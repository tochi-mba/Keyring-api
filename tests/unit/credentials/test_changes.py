"""Who is asking for a credential change.

The behaviour of the policy itself is established over HTTP, route by route, in
``tests/integration/test_credential_changes.py``. What is left here is what a route test
cannot see: the value object's repr, and two races no single request can stage.
"""

from __future__ import annotations

from typing import Any, cast

from keyring_api.core.config import Settings
from keyring_api.credentials.changes import CredentialChanges, Requester
from keyring_api.domain.changes import ChangeOrigin
from keyring_api.domain.profiles import (
    Connection,
    ConnectionStatus,
    CredentialKind,
    Profile,
)
from keyring_api.notifications.base import EmailMessage
from tests.fakes.clock import EPOCH, FakeClock
from tests.fakes.preferences import ChosenPreferences

PASSWORD = "correct horse battery staple"
ACCOUNT_ID = "acct_person"


class RacingCredentials:
    """A vault whose answers change between one call and the next, as a concurrent request's
    would. Only the methods :class:`CredentialChanges` calls on a removal."""

    def __init__(self, *, removed: bool) -> None:
        self.removed = removed

    async def get_profile(self, account_id: str, name: str) -> Profile:
        connection = Connection(
            service="tmdb",
            kind=CredentialKind.API_KEY,
            status=ConnectionStatus.ACTIVE,
            created_at=EPOCH,
            updated_at=EPOCH,
        )
        return Profile(
            profile_id="prof_1",
            account_id=account_id,
            name=name,
            created_at=EPOCH,
            updated_at=EPOCH,
            connections=(connection,),
        )

    async def delete_profile(self, _account_id: str, _name: str) -> bool:
        return self.removed

    async def revoke_connection(self, _account_id: str, _profile: str, _service: str) -> bool:
        return self.removed


class GoneAccounts:
    """An account store whose account was deleted after the change it is told about."""

    async def get(self, _account_id: str) -> None:
        return None


class RecordingOutbox:
    def __init__(self) -> None:
        self.queued: list[EmailMessage] = []

    def enqueue(self, message: EmailMessage) -> bool:
        self.queued.append(message)
        return True


def changes_over(credentials: RacingCredentials, outbox: RecordingOutbox) -> CredentialChanges:
    """Notices on, re-authentication off, over stand-ins for everything a race reaches."""
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    preferences = ChosenPreferences(settings, notify_on_credential_change=True)
    return CredentialChanges(
        credentials=cast("Any", credentials),
        accounts=cast("Any", GoneAccounts()),
        account_service=cast("Any", None),
        preferences=preferences,
        outbox=cast("Any", outbox),
        clock=FakeClock(),
    )


async def test_a_profile_removed_by_somebody_else_meanwhile_is_not_announced() -> None:
    """The bug, named: a notice for a removal this request did not make.

    The profile held a credential when it was looked up and was gone when it came to be
    deleted -- a second request got there first, and that one announces it.
    """
    outbox = RecordingOutbox()
    changes = changes_over(RacingCredentials(removed=False), outbox)

    removed = await changes.remove_profile(ACCOUNT_ID, "personal", requester=Requester.person(None))

    assert removed is False
    assert outbox.queued == []


async def test_an_account_gone_before_its_notice_has_nobody_to_tell() -> None:
    outbox = RecordingOutbox()
    changes = changes_over(RacingCredentials(removed=True), outbox)

    removed = await changes.remove_connection(
        ACCOUNT_ID, "personal", "tmdb", requester=Requester.person(None)
    )

    assert removed is True
    assert outbox.queued == []


def test_the_password_never_reaches_a_repr() -> None:
    """The bug, named: a re-entered password printed by a log line or a traceback.

    A requester travels through every credential route, and any of them can end up in an
    exception's locals or a debug line. Its repr must say who asked and nothing else.
    """
    requester = Requester.person(PASSWORD)

    assert PASSWORD not in repr(requester)
    assert "person" in repr(requester)


def test_only_a_person_can_carry_a_password() -> None:
    assert Requester.service().password is None
    assert Requester.administrator().password is None
    assert Requester.service().origin is ChangeOrigin.SERVICE
    assert Requester.administrator().origin is ChangeOrigin.ADMINISTRATOR
