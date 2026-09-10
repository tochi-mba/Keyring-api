"""Session lifetime: idle timeout, absolute ceiling, and revocation."""

from __future__ import annotations

from datetime import timedelta

from keyring_api.domain.sessions import Session, new_session_id
from tests.fakes.clock import EPOCH

IDLE = 3_600.0
ABSOLUTE = 86_400.0


def make_session(**overrides: object) -> Session:
    defaults: dict[str, object] = {
        "session_id": "sess_1",
        "account_id": "acct_1",
        "token_hash": "hash",
        "created_at": EPOCH,
        "last_used_at": EPOCH,
        "expires_at": EPOCH + timedelta(seconds=IDLE),
        "absolute_expires_at": EPOCH + timedelta(seconds=ABSOLUTE),
    }
    return Session(**{**defaults, **overrides})  # type: ignore[arg-type]


def test_session_ids_are_unique_and_recognisable() -> None:
    assert new_session_id() != new_session_id()
    assert new_session_id().startswith("sess_")


def test_a_fresh_session_is_valid() -> None:
    assert not make_session().is_expired(now=EPOCH)


def test_a_session_expires_when_it_has_been_idle_too_long() -> None:
    session = make_session()

    assert session.is_expired(now=EPOCH + timedelta(seconds=IDLE))


def test_using_a_session_pushes_the_idle_deadline_out() -> None:
    session = make_session()
    later = EPOCH + timedelta(seconds=IDLE / 2)

    refreshed = session.touched(now=later, idle_ttl_seconds=IDLE, absolute_expires_at=None)

    assert refreshed.expires_at == later + timedelta(seconds=IDLE)
    assert refreshed.last_used_at == later


def test_touching_a_session_never_moves_its_absolute_deadline() -> None:
    # Otherwise a session used once a day never ends, and "log out everywhere" is the
    # only thing that can ever close it.
    session = make_session()

    refreshed = session.touched(
        now=EPOCH + timedelta(seconds=IDLE / 2), idle_ttl_seconds=IDLE, absolute_expires_at=None
    )

    assert refreshed.absolute_expires_at == session.absolute_expires_at


def test_a_session_expires_at_its_absolute_ceiling_however_recently_it_was_used() -> None:
    just_used = make_session(
        last_used_at=EPOCH + timedelta(seconds=ABSOLUTE - 1),
        expires_at=EPOCH + timedelta(seconds=ABSOLUTE - 1 + IDLE),
    )

    assert just_used.is_expired(now=EPOCH + timedelta(seconds=ABSOLUTE))


def test_the_idle_deadline_is_never_pushed_past_the_absolute_one() -> None:
    # A session touched a minute before its ceiling must not come away with another
    # full idle window.
    session = make_session()
    near_the_end = EPOCH + timedelta(seconds=ABSOLUTE - 60)

    refreshed = session.touched(now=near_the_end, idle_ttl_seconds=IDLE, absolute_expires_at=None)

    assert refreshed.expires_at == session.absolute_expires_at


def test_a_session_is_frozen_so_a_concurrent_request_cannot_see_a_half_update() -> None:
    session = make_session()

    session.touched(
        now=EPOCH + timedelta(seconds=1), idle_ttl_seconds=IDLE, absolute_expires_at=None
    )

    assert session.last_used_at == EPOCH
