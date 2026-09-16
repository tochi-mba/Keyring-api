"""Keyring's public keys, and the rules about when the client goes and gets them again.

Most of the properties here are bounds on how often a consuming service talks to keyring,
rather than statements about what a token means: a warm cache does not fetch again; ten
requests arriving together on a cold one make a single fetch between them; an unrecognised
key id may provoke at most one fetch per window; and a fetch that failed is not retried on
every request. Each is counted, which is what :class:`FakeKeyring` counts fetches for.

The rest is the difference between "that token is not ours" (401) and "keyring is down"
(503), and what happens to tokens that were verifiable a minute ago when keyring blips.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Protocol

import httpx
import pytest

from keyring_client import (
    BAD_TOKEN,
    KEYS_STALE,
    KEYS_UNAVAILABLE,
    AuthenticationError,
    JwksClient,
    KeyringUnreachableError,
    jwks_url,
)
from keyring_client.testing import JWKS_URL, ROTATED_KEY, FakeClock, FakeKeyring, thumbprint

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from tests.unit.client.conftest import RecordingLogger

CACHE_SECONDS = 3_600.0
WINDOW_SECONDS = 60.0
GRACE_SECONDS = 600.0
CONCURRENT_REQUESTS = 10
FLOOD = 50
SCHEDULER_TURNS = 8
"""Passes through the event loop, enough for every queued request to reach the lock."""


class MakeJwks(Protocol):
    """Builds a client against the fake keyring, closed when the test ends."""

    def __call__(
        self,
        *,
        cache_seconds: float = ...,
        min_refetch_seconds: float = ...,
        stale_grace_seconds: float = ...,
        transport: httpx.AsyncBaseTransport | None = ...,
        logger: RecordingLogger | None = ...,
    ) -> JwksClient: ...


def serving(status: int, body: bytes) -> httpx.MockTransport:
    """A keyring answering with exactly these bytes: the shapes something *else* produces."""

    def handle(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=body)

    return httpx.MockTransport(handle)


def parked(keyring: FakeKeyring, release: asyncio.Event) -> httpx.MockTransport:
    """The fake keyring, answering nothing until the test lets it.

    Without somewhere to park, the first fetch would finish before the second request had
    begun, and ten requests would prove exactly what one request proves.
    """
    inner = keyring.transport()

    async def handle(request: httpx.Request) -> httpx.Response:
        await release.wait()
        return await inner.handle_async_request(request)

    return httpx.MockTransport(handle)


@pytest.fixture
async def make_jwks(clock: FakeClock, keyring: FakeKeyring) -> AsyncIterator[MakeJwks]:
    made: list[JwksClient] = []

    def make(
        *,
        cache_seconds: float = CACHE_SECONDS,
        min_refetch_seconds: float = WINDOW_SECONDS,
        stale_grace_seconds: float = GRACE_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
        logger: RecordingLogger | None = None,
    ) -> JwksClient:
        client = JwksClient(
            url=JWKS_URL,
            clock=clock,
            cache_seconds=cache_seconds,
            min_refetch_seconds=min_refetch_seconds,
            stale_grace_seconds=stale_grace_seconds,
            transport=transport if transport is not None else keyring.transport(),
            logger=logger,
        )
        made.append(client)
        return client

    yield make

    for client in made:
        await client.aclose()


def test_the_jwks_url_is_the_well_known_path_under_keyrings_base() -> None:
    # A trailing slash on the configured base must not become a double slash, which some
    # reverse proxies treat as a different path.
    assert jwks_url("http://keyring.test/") == "http://keyring.test/.well-known/jwks.json"


class TestCaching:
    async def test_a_second_request_for_the_same_key_does_not_ask_keyring_again(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        client = make_jwks()

        first = await client.key_for(thumbprint())
        second = await client.key_for(thumbprint())

        assert keyring.fetches == 1
        assert first.key_id == second.key_id == thumbprint()

    async def test_the_cache_expires_on_the_injected_clock(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, clock: FakeClock
    ) -> None:
        client = make_jwks(cache_seconds=120.0)
        await client.key_for(thumbprint())

        clock.advance(119.0)
        await client.key_for(thumbprint())
        assert keyring.fetches == 1

        clock.advance(1.0)
        await client.key_for(thumbprint())
        assert keyring.fetches == 2

    async def test_ten_concurrent_cold_requests_make_exactly_one_fetch_between_them(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        release = asyncio.Event()
        client = make_jwks(transport=parked(keyring, release))
        requests = [
            asyncio.create_task(client.key_for(thumbprint())) for _ in range(CONCURRENT_REQUESTS)
        ]
        for _ in range(SCHEDULER_TURNS):
            await asyncio.sleep(0)
        # Proves all ten are really in flight together, rather than having run one after
        # another with nine of them reading a cache the first had already filled.
        assert [request.done() for request in requests] == [False] * CONCURRENT_REQUESTS

        release.set()
        keys = await asyncio.gather(*requests)

        assert keyring.fetches == 1
        assert [key.key_id for key in keys] == [thumbprint()] * CONCURRENT_REQUESTS

    async def test_constructing_the_client_fetches_nothing(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        # Starting up must not require keyring to be up: the services restart together.
        make_jwks()

        assert keyring.fetches == 0


class TestUnknownKeyIds:
    async def test_a_flood_of_invented_key_ids_provokes_at_most_one_fetch_per_window(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        client = make_jwks()
        await client.key_for(thumbprint())

        for _ in range(FLOOD):
            with pytest.raises(AuthenticationError):
                await client.key_for(uuid.uuid4().hex)

        # One fetch to warm the cache, and one the whole flood was allowed between them.
        assert keyring.fetches == 2

    async def test_one_more_fetch_is_allowed_once_the_window_has_passed(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, clock: FakeClock
    ) -> None:
        # A rate, not a ban: an id unknown at half past may be keyring's at half past one.
        client = make_jwks()
        await client.key_for(thumbprint())
        with pytest.raises(AuthenticationError):
            await client.key_for("invented")

        clock.advance(WINDOW_SECONDS)
        with pytest.raises(AuthenticationError):
            await client.key_for("invented-again")

        assert keyring.fetches == 3

    async def test_a_suppressed_refetch_is_the_token_being_wrong_not_keyring_being_down(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        client = make_jwks()
        await client.key_for(thumbprint())
        with pytest.raises(AuthenticationError):
            await client.key_for("invented")

        with pytest.raises(AuthenticationError) as refusal:
            await client.key_for("invented")

        assert type(refusal.value) is AuthenticationError
        assert str(refusal.value) == BAD_TOKEN
        assert keyring.fetches == 2

    async def test_the_window_is_spent_even_when_the_fetch_it_allowed_fails(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        client = make_jwks()
        await client.key_for(thumbprint())
        keyring.error = httpx.ConnectError("connection refused")

        with pytest.raises(KeyringUnreachableError):
            await client.key_for("invented")
        with pytest.raises(AuthenticationError):
            await client.key_for("invented-again")

        assert keyring.fetches == 2

    async def test_a_replacement_key_is_picked_up_through_the_window(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        # A rotation arrives as an id the cached document does not name -- the same shape as
        # an invented one -- so the window that bounds the flood is also how it is picked up.
        client = make_jwks()
        await client.key_for(thumbprint())

        keyring.rotate()
        key = await client.key_for(thumbprint(ROTATED_KEY))

        assert key.key_id == thumbprint(ROTATED_KEY)
        assert keyring.fetches == 2

    async def test_a_fetch_that_worked_and_lacks_the_key_id_is_the_token_being_wrong(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, recorder: RecordingLogger
    ) -> None:
        client = make_jwks(logger=recorder)

        with pytest.raises(AuthenticationError) as refusal:
            await client.key_for("a-key-id-nobody-published")

        assert str(refusal.value) == BAD_TOKEN
        assert keyring.fetches == 1
        assert "jwks_kid_unknown" in recorder.events()


class TestKeyringUnreachable:
    @pytest.mark.parametrize(
        ("status", "body"),
        [
            pytest.param(503, b'{"keys": []}', id="an-error-status"),
            pytest.param(200, b"<html>502 Bad Gateway</html>", id="a-body-that-is-not-json"),
            pytest.param(200, b'"keys"', id="json-that-is-not-an-object"),
            pytest.param(200, b'{"kid": "something"}', id="a-document-with-no-keys-member"),
            pytest.param(200, b'{"keys": {"kid": "x"}}', id="keys-that-are-not-a-list"),
            pytest.param(200, b'{"keys": []}', id="a-keys-list-with-nothing-in-it"),
            pytest.param(200, b'{"keys": [{"kty": "nothing-we-know"}]}', id="no-usable-key"),
            pytest.param(200, b'{"keys": ["not-a-mapping"]}', id="an-entry-that-is-not-a-mapping"),
            pytest.param(
                200,
                b'{"keys": [{"kty": "RSA", "alg": "RS256", "kid": "k", "n": "AQ", "e": "AQAB"}]}',
                id="a-key-whose-numbers-do-not-parse",
            ),
        ],
    )
    async def test_a_document_that_cannot_be_used_is_keyring_being_unreachable(
        self, make_jwks: MakeJwks, status: int, body: bytes
    ) -> None:
        # None of these says anything about the token in hand, so none of them is a 401.
        client = make_jwks(transport=serving(status, body))

        with pytest.raises(KeyringUnreachableError) as failure:
            await client.key_for(thumbprint())

        assert str(failure.value) == KEYS_UNAVAILABLE

    async def test_the_failure_logged_carries_no_url(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, recorder: RecordingLogger
    ) -> None:
        # The text an HTTP client raises carries the URL, and a URL can carry credentials.
        client = make_jwks(logger=recorder)
        keyring.error = httpx.ConnectError(f"failed to connect to {JWKS_URL}")

        with pytest.raises(KeyringUnreachableError):
            await client.key_for(thumbprint())

        assert "jwks_fetch_failed" in recorder.events()
        assert JWKS_URL not in recorder.rendered()


class TestFailedFetches:
    async def test_a_failed_fetch_is_not_retried_within_the_window(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, clock: FakeClock
    ) -> None:
        # A keyring that is already down must not be asked once per inbound request.
        client = make_jwks()
        keyring.error = httpx.ConnectError("connection refused")

        for _ in range(FLOOD):
            with pytest.raises(KeyringUnreachableError):
                await client.key_for(thumbprint())
        assert keyring.fetches == 1

        keyring.error = None
        clock.advance(WINDOW_SECONDS)
        await client.key_for(thumbprint())
        assert keyring.fetches == 2

    async def test_a_successful_fetch_clears_the_failure(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, clock: FakeClock
    ) -> None:
        client = make_jwks(cache_seconds=120.0)
        keyring.error = httpx.ConnectError("connection refused")
        with pytest.raises(KeyringUnreachableError):
            await client.key_for(thumbprint())

        keyring.error = None
        clock.advance(WINDOW_SECONDS)
        await client.key_for(thumbprint())

        # The cache then expires in the ordinary way and is refetched at once, with no
        # leftover failure window standing in the way.
        clock.advance(120.0)
        await client.key_for(thumbprint())
        assert keyring.fetches == 3


class TestStaleKeys:
    async def test_keys_held_from_a_good_fetch_are_served_through_an_outage(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, clock: FakeClock, recorder: RecordingLogger
    ) -> None:
        # Refusing every good token because keyring blipped is strictly worse than verifying
        # against a copy of public keys that change rarely.
        client = make_jwks(logger=recorder)
        await client.key_for(thumbprint())

        clock.advance(CACHE_SECONDS)
        keyring.error = httpx.ConnectError("connection refused")
        key = await client.key_for(thumbprint())

        assert key.key_id == thumbprint()
        assert "jwks_serving_stale_keys" in recorder.events()

    async def test_stale_keys_stop_being_served_once_the_grace_runs_out(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, clock: FakeClock
    ) -> None:
        # Bounded, so a key keyring has withdrawn does not keep working for ever.
        client = make_jwks()
        await client.key_for(thumbprint())

        clock.advance(CACHE_SECONDS + GRACE_SECONDS)
        keyring.error = httpx.ConnectError("connection refused")

        with pytest.raises(KeyringUnreachableError):
            await client.key_for(thumbprint())

    async def test_a_stale_set_without_the_key_id_is_still_keyring_being_unreachable(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, clock: FakeClock
    ) -> None:
        # We could not look, so we cannot say the token is not keyring's.
        client = make_jwks()
        await client.key_for(thumbprint())

        clock.advance(CACHE_SECONDS)
        keyring.error = httpx.ConnectError("connection refused")

        with pytest.raises(KeyringUnreachableError):
            await client.key_for("a-key-id-we-never-saw")


class TestHealth:
    async def test_a_cold_client_fetches_to_answer(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        client = make_jwks()

        assert await client.healthy() == (True, None)
        assert keyring.fetches == 1

    async def test_a_warm_client_answers_without_asking_keyring(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        client = make_jwks()
        await client.key_for(thumbprint())

        assert await client.healthy() == (True, None)
        assert keyring.fetches == 1

    async def test_an_unreachable_keyring_is_reported_rather_than_raised(
        self, make_jwks: MakeJwks, keyring: FakeKeyring
    ) -> None:
        client = make_jwks()
        keyring.error = httpx.ConnectError(f"failed to connect to {JWKS_URL}")

        healthy, reason = await client.healthy()

        assert healthy is False
        assert reason == KEYS_UNAVAILABLE

    async def test_an_outage_with_usable_cached_keys_is_healthy_but_says_so(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, clock: FakeClock
    ) -> None:
        client = make_jwks()
        await client.key_for(thumbprint())
        clock.advance(CACHE_SECONDS)
        keyring.error = httpx.ConnectError("connection refused")

        assert await client.healthy() == (True, KEYS_STALE)

    async def test_an_unexpected_failure_is_reported_and_logged_not_raised(
        self, make_jwks: MakeJwks, keyring: FakeKeyring, recorder: RecordingLogger
    ) -> None:
        # The wide catch is the point of this method: the unexpected exception IS the thing
        # being reported, and a load balancer cannot read a traceback.
        client = make_jwks(logger=recorder)
        keyring.error = RuntimeError("something nobody anticipated")

        assert await client.healthy() == (False, KEYS_UNAVAILABLE)
        assert "jwks_health_check_failed" in recorder.events()


class TestClosing:
    async def test_closing_twice_is_not_an_error(self, make_jwks: MakeJwks) -> None:
        # Shutdown runs on paths that may already have closed it.
        client = make_jwks()
        await client.aclose()

        await client.aclose()
