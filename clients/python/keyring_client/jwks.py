"""Keyring's public keys, cached, and the rules about when to go and get them again.

A token is verified with no help from keyring beyond a document of public keys that anybody
may fetch. That arrangement is keyring's own design (its ADR-0008) and it has two terms worth
knowing: a signed token cannot be revoked before it expires, and nothing tells a consuming
service that an account has gone.

Five things about the fetching, each of which a sibling service learned the hard way:

**Nothing is fetched while starting up.** Constructing a client does no network work. A
service that refuses to start unless keyring is reachable turns one outage into two, at the
moment the services are being restarted together.

**Ten concurrent cold requests make one fetch.** The lock is taken on a miss, and the cache
is asked again inside it, so a restart under load is not a thundering herd aimed at keyring.

**An unknown key id is rate limited.** A key id is read before anything has been verified,
which makes it the one value an unauthenticated caller puts in front of the verifier.
Without a floor between the fetches an unrecognised one may provoke, every inbound request
carrying an invented id is an outbound request to keyring.

**A failed fetch is not retried on every request.** After one fails, the next attempt waits
the same floor, so a keyring that is already down is not asked once per inbound request.

**Keys held from a successful fetch are served through a short outage.** They are public and
change rarely, so verifying against an hour-old copy for a while is strictly better than
refusing every good token because keyring blipped. The grace is bounded, so a key keyring has
withdrawn does not keep working for ever.

And one distinction that decides a status code: a fetch that *worked* and came back without
the key id is :class:`~keyring_client.errors.AuthenticationError` (the token is not keyring's,
a 401); a fetch that failed, or produced something that is not a usable key set, is
:class:`~keyring_client.errors.KeyringUnreachableError` (we cannot tell, a 503).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import httpx
import jwt

from keyring_client._log import StdlibLogger
from keyring_client.errors import BAD_TOKEN, AuthenticationError, KeyringUnreachableError

if TYPE_CHECKING:
    from keyring_client._log import Logger
    from keyring_client.clock import Clock

JWKS_PATH = "/.well-known/jwks.json"
"""Where keyring publishes its public keys. Unauthenticated by necessity."""

KEYS_UNAVAILABLE = "keyring's signing keys could not be fetched"
"""Said when no token can be verified. Fixed text: an exception's message carries a URL."""

KEYS_STALE = "keyring could not be reached; tokens are verified against cached keys"
"""What :meth:`JwksClient.healthy` reports while serving keys through an outage."""

DEFAULT_CACHE_SECONDS = 3_600.0
DEFAULT_MIN_REFETCH_SECONDS = 60.0
DEFAULT_STALE_GRACE_SECONDS = 86_400.0
DEFAULT_TIMEOUT_SECONDS = 5.0


def jwks_url(base_url: str) -> str:
    """The JWKS document's URL for a keyring at ``base_url``."""
    return base_url.rstrip("/") + JWKS_PATH


class JwksClient:
    """Keyring's signing keys, fetched when one is wanted and cached by ``kid``."""

    # Eight keyword-only arguments, each an independent decision a deployment makes, and all
    # but two defaulted. An options object would be built on one line and unpacked on the next.
    def __init__(  # noqa: PLR0913
        self,
        *,
        url: str,
        clock: Clock,
        cache_seconds: float = DEFAULT_CACHE_SECONDS,
        min_refetch_seconds: float = DEFAULT_MIN_REFETCH_SECONDS,
        stale_grace_seconds: float = DEFAULT_STALE_GRACE_SECONDS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
        logger: Logger | None = None,
    ) -> None:
        self._url = url
        self._clock = clock
        self._cache_seconds = cache_seconds
        self._min_refetch_seconds = min_refetch_seconds
        self._stale_grace_seconds = stale_grace_seconds
        # Made once so connections are pooled. Constructing it is not a network call, which
        # is what keeps startup independent of keyring. Redirects are off: a JWKS document
        # served from wherever a redirect points is a key set somebody else chose.
        self._client = httpx.AsyncClient(
            timeout=timeout_seconds, transport=transport, follow_redirects=False
        )
        self._keys: jwt.PyJWKSet | None = None
        self._fetched_at = 0.0
        self._failed_at: float | None = None
        self._provoked_at: float | None = None
        self._lock = asyncio.Lock()
        self._log: Logger = logger if logger is not None else StdlibLogger(__name__)

    async def key_for(self, kid: str) -> Any:
        """The key keyring signed with, for the ``kid`` a token names.

        Typed as ``Any`` rather than :class:`jwt.PyJWK` on purpose: consuming services keep
        PyJWT inside one package with an import contract, and a signature naming a library's
        type is how that library leaks out of the package meant to hold it.

        Raises:
            AuthenticationError: no key by that id -- a fetch just now came back without it,
                or the key set we hold lacks it and we fetched too recently to look again.
            KeyringUnreachableError: the keys could not be fetched and no usable copy is
                held, so whether the token is good is not something we know.
        """
        cached = self._cached(kid)
        if cached is not None:
            return cached

        async with self._lock:
            # Asked again inside the lock: the requests that queued here want the answer the
            # first one fetched, not a fetch of their own.
            cached = self._cached(kid)
            if cached is not None:
                return cached
            if self._fresh_keys() is not None:
                # What we hold is current and lacks this kid, so the only reason to look again
                # is a rotation -- and that is the path a flood of invented ids rides.
                self._claim_refetch_window(kid)
            try:
                fetched = await self._refresh()
            except KeyringUnreachableError:
                stale = self._stale_key(kid)
                if stale is None:
                    raise
                self._log.warning("jwks_serving_stale_keys", kid=kid)
                return stale

        key = _key_in(fetched, kid)
        if key is None:
            self._log.info("jwks_kid_unknown", kid=kid)
            raise AuthenticationError(BAD_TOKEN)
        return key

    async def healthy(self) -> tuple[bool, str | None]:
        """Whether a token could be verified right now, and what is wrong if anything is.

        Reports rather than raises, which is why the ``except`` below is as wide as it is: a
        health check that raised would answer 500 while trying to say what is wrong, and a
        load balancer cannot read a traceback. The wide catch is confined to this method.

        Fetches when nothing fresh is held, because a check that only reported on the cache
        would have nothing to say on a fresh process -- the moment an operator most wants to
        know whether keyring is reachable.
        """
        if self._fresh_keys() is not None:
            return True, None

        async with self._lock:
            try:
                await self._refresh()
            except KeyringUnreachableError:
                return self._stale_health()
            except Exception:
                self._log.exception("jwks_health_check_failed")
                return self._stale_health()
        return True, None

    async def aclose(self) -> None:
        """Release the connection pool. Safe to call twice."""
        await self._client.aclose()

    def _cached(self, kid: str) -> jwt.PyJWK | None:
        held = self._fresh_keys()
        return None if held is None else _key_in(held, kid)

    def _fresh_keys(self) -> jwt.PyJWKSet | None:
        """The key set we hold, or ``None`` if there is none or it has gone stale."""
        if self._keys is None:
            return None
        if self._clock.monotonic() - self._fetched_at >= self._cache_seconds:
            return None
        return self._keys

    def _usable_stale_keys(self) -> jwt.PyJWKSet | None:
        """The key set we hold if it is still inside its outage grace, else ``None``."""
        if self._keys is None:
            return None
        limit = self._cache_seconds + self._stale_grace_seconds
        if self._clock.monotonic() - self._fetched_at >= limit:
            return None
        return self._keys

    def _stale_key(self, kid: str) -> jwt.PyJWK | None:
        held = self._usable_stale_keys()
        return None if held is None else _key_in(held, kid)

    def _stale_health(self) -> tuple[bool, str | None]:
        if self._usable_stale_keys() is not None:
            return True, KEYS_STALE
        return False, KEYS_UNAVAILABLE

    def _claim_refetch_window(self, kid: str) -> None:
        """Take the one fetch a window allows an unknown key id, or refuse it.

        Spent before the fetch rather than after, so a fetch that fails still costs the
        window: an outage is precisely when a flood must not become a flood of requests.

        Raises:
            AuthenticationError: within ``min_refetch_seconds`` of the last such fetch. We
                looked recently and keyring had no key by that name, which is a fact about
                the token rather than an outage.
        """
        provoked_at = self._provoked_at
        now = self._clock.monotonic()
        if provoked_at is not None and now - provoked_at < self._min_refetch_seconds:
            self._log.warning("jwks_refetch_suppressed", kid=kid)
            raise AuthenticationError(BAD_TOKEN)
        self._provoked_at = now

    async def _refresh(self) -> jwt.PyJWKSet:
        """Fetch, unless a fetch failed too recently to be worth trying again.

        Raises:
            KeyringUnreachableError: the fetch failed, now or within the floor.
        """
        failed_at = self._failed_at
        now = self._clock.monotonic()
        if failed_at is not None and now - failed_at < self._min_refetch_seconds:
            raise KeyringUnreachableError(KEYS_UNAVAILABLE)
        try:
            return await self._fetch()
        except KeyringUnreachableError:
            self._failed_at = self._clock.monotonic()
            raise

    async def _fetch(self) -> jwt.PyJWKSet:
        """Fetch the document and replace what we held.

        The age is taken before the request goes out, so the cache expires by when the
        document was asked for; a slow fetch is a document already a little old on arrival.
        """
        at = self._clock.monotonic()
        key_set = self._key_set_of(await self._get())
        self._keys = key_set
        self._fetched_at = at
        self._failed_at = None
        self._log.info("jwks_fetched", key_count=len(key_set.keys))
        return key_set

    async def _get(self) -> object:
        try:
            response = await self._client.get(self._url)
            response.raise_for_status()
            document: object = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # The type only. The text carries the URL, and a URL can carry credentials.
            self._log.warning("jwks_fetch_failed", error=type(exc).__name__)
            raise KeyringUnreachableError(KEYS_UNAVAILABLE) from exc
        return document

    def _key_set_of(self, document: object) -> jwt.PyJWKSet:
        """Turn a fetched document into a key set, refusing anything that is not one.

        Every refusal here is keyring being unreachable rather than the caller being wrong: a
        proxy's error page served with a 200, a document with no ``keys`` array, a set with
        nothing usable in it. None of those says anything about the token in hand.

        :class:`jwt.PyJWKSet` rather than ``RSAAlgorithm.from_jwk`` because a PyJWK binds the
        algorithm named in the JWK to the key, so nothing downstream can be talked into using
        an RSA public key as an HMAC secret.
        """
        keys = document.get("keys") if isinstance(document, dict) else None
        if not isinstance(keys, list):
            self._log.warning("jwks_document_malformed")
            raise KeyringUnreachableError(KEYS_UNAVAILABLE)
        try:
            key_set = jwt.PyJWKSet(keys)
        except (jwt.PyJWTError, AttributeError, ValueError) as exc:
            # The two exception types that are not PyJWT's: PyJWKSet assumes every entry is a
            # mapping, and one that is not fails further down than its own handling reaches.
            self._log.warning("jwks_document_unusable", error=type(exc).__name__)
            raise KeyringUnreachableError(KEYS_UNAVAILABLE) from exc
        return key_set


def _key_in(key_set: jwt.PyJWKSet, kid: str) -> jwt.PyJWK | None:
    """The key with this id, or ``None``. A missing key is an ordinary answer here."""
    try:
        key = key_set[kid]
    except KeyError:
        return None
    return key
