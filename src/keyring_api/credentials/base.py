"""The narrow ports through which credentials are consumed.

This is the idea that keeps the service from growing without bound. **Credential kinds
grow forever; what consumes them does not.** There are only four questions any caller
ever asks of a credential, so those four are the ports, and they are expected never to
change:

===================  ==========================================  ========================
Port                 Answers                                     Used by
===================  ==========================================  ========================
:class:`HttpAuth`    "what do I attach to this request?"         API-backed providers
:class:`FormSecrets` "what do I type into this login form?"      browser login recipes
:class:`BrowserIdentity` "which proxy and fingerprint?"          a browser runtime
:class:`TransportAuth`   "which certificate or key?"             transport-level clients
===================  ==========================================  ========================

Adding a service later means adding a *kind* and mapping it onto one of these. No
consumer changes. Three kinds across two ports are implemented now -- one that refreshes,
one that does not, and one consumed by a login form rather than an HTTP header -- which
is enough to demonstrate the abstraction rather than assume it.

:class:`HttpAuth` is async because answering may require refreshing an expired token. A
synchronous port would have forced every caller to check expiry first and refresh
itself, which is the knowledge this whole service exists to hold in one place.

What is deliberately *not* here is a generic "give me the raw credential" port. Handing
back the material would make every consumer a place a credential can leak from, and a
generic authenticated proxy -- "POST me a URL and I will forward it with your
credentials" -- is a confused deputy: anything that could reach it could use every
stored credential against any host. Consumers name the service they talk to.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class HttpAuth(Protocol):
    """Turns a credential into what an HTTP request needs.

    Async because it may refresh. A caller attaches what it is given and does not know,
    or need to know, whether a network round trip happened to produce it.
    """

    async def headers(self) -> dict[str, str]:
        """Headers to attach. Empty if this credential authenticates another way.

        Raises:
            CredentialUnavailableError: the credential could not be made usable.
        """
        ...

    async def query_params(self) -> dict[str, str]:
        """Query parameters to attach, for the APIs that authenticate that way."""
        ...


@runtime_checkable
class FormSecrets(Protocol):
    """Turns a credential into what a login form needs.

    The consumer is a browser recipe driving somebody else's login page, which is why
    this is a separate port from :class:`HttpAuth` rather than a method on it: the
    values are typed into fields, not attached to a request, and one of them is a
    time-based code that must be generated at the moment of typing.
    """

    async def fields(self) -> dict[str, str]:
        """The values to type: username, password, and a current TOTP code if stored."""
        ...


@runtime_checkable
class BrowserIdentity(Protocol):
    """Which network identity a browser should present.

    Declared, with no adapter yet. Browser *state* -- profile directories, cookies,
    cache -- deliberately does not live in keyring: it is gigabytes of blob owned by the
    service that launches the browser, and it has to be on that machine's local disk.
    What could sensibly live here is the non-secret identity that goes with a credential:
    an egress proxy, and a consistent fingerprint. See ADR-0002.
    """

    async def proxy_url(self) -> str | None:
        """Egress proxy for this identity, or ``None`` to use the default route."""
        ...


@runtime_checkable
class TransportAuth(Protocol):
    """Which certificate or key a transport-level client should present.

    Declared, with no adapter yet, so that mutual TLS and SSH keys have an obvious home
    when they are needed -- rather than being bolted onto :class:`HttpAuth`, where they
    do not fit, by whoever needs them first.
    """

    async def client_certificate(self) -> tuple[str, str] | None:
        """A ``(certificate, private key)`` PEM pair, or ``None``."""
        ...
