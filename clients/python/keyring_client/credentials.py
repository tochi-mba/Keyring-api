"""Keyring's internal surface: what to attach to a request, and what to type into a form.

A consuming service needs a credential for a *particular person*. Keyring refuses to let a
service name that person: the call carries the service's own token and the person's signed
token, and keyring takes the account from the latter. So there is no request this client can
make for a credential it was not handed a token for, and nothing here erodes that.

What comes back is what to attach -- headers, query parameters -- never what is stored. The one
exception is :meth:`CredentialClient.resolve_form_secrets`, which returns a username and
password because a login form needs them. Keyring's own documentation says never to expose
that as an assistant tool, and neither result type renders its values in a ``repr``: the
realistic leak is a secret in a local that a traceback prints.

Each of keyring's answers becomes an error pointing at the person who can fix it:

* **401** -- :class:`~keyring_client.errors.KeyringRejectedError`. Usually the operator: this
  service's own token is wrong.
* **404** -- :class:`~keyring_client.errors.CredentialNotFoundError`. The person: connect the
  service in keyring.
* **503** -- :class:`~keyring_client.errors.CredentialUnavailableError`. The person: reconnect.
  Keyring's detail says why.
* **anything else** -- :class:`~keyring_client.errors.KeyringUnreachableError`. Nobody yet:
  keyring is unwell, and a retry may work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from keyring_client._log import StdlibLogger
from keyring_client.errors import (
    CredentialNotFoundError,
    CredentialUnavailableError,
    KeyringRejectedError,
    KeyringUnreachableError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from keyring_client._log import Logger

USER_TOKEN_HEADER = "X-Keyring-User-Token"  # noqa: S105 -- a header name
"""Where the person's token travels to keyring, separately from the service's own."""

CREDENTIALS_PATH = "/v1/internal/credentials"
FORM_SECRETS_PATH = "/v1/internal/form-secrets"

UNREACHABLE = "keyring could not be reached"
REJECTED = "keyring did not accept the credentials presented"
NOT_FOUND = "keyring has no such connection for this profile"
MALFORMED = "keyring's answer could not be understood"
UNUSABLE = "keyring could not make the stored credential usable"

DEFAULT_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True, slots=True, repr=False)
class ResolvedCredential:
    """What to attach to one outgoing request. Not what is stored."""

    service: str
    headers: Mapping[str, str] = field(default_factory=dict)
    query_params: Mapping[str, str] = field(default_factory=dict)
    expires_at: datetime | None = None

    def __repr__(self) -> str:
        """Count the entries, never show them. An Authorization header is a credential."""
        return (
            f"ResolvedCredential(service={self.service!r}, "
            f"headers=<{len(self.headers)} redacted>, "
            f"query_params=<{len(self.query_params)} redacted>, "
            f"expires_at={self.expires_at!r})"
        )

    @property
    def secrets(self) -> tuple[str, ...]:
        """Every value that must never reach captured output, longest first.

        For a service that injects these into a process and scrubs what the process prints.
        Longest first, so a value that contains another is replaced whole. The token inside a
        ``Bearer <token>`` header is included on its own, because that is what a program
        prints when it echoes its environment.
        """
        values = {*self.headers.values(), *self.query_params.values()}
        values |= {value.split(" ", 1)[1] for value in self.headers.values() if " " in value}
        return tuple(sorted((value for value in values if value), key=len, reverse=True))


@dataclass(frozen=True, slots=True, repr=False)
class FormSecrets:
    """The values to type into a login form. Held for one attempt, written nowhere."""

    service: str
    fields: Mapping[str, str]

    def __repr__(self) -> str:
        """Field names help diagnosis; field values are never printable."""
        return f"FormSecrets(service={self.service!r}, fields=<{','.join(sorted(self.fields))}>)"


class CredentialClient:
    """An HTTP client for keyring's two internal endpoints."""

    def __init__(
        self,
        *,
        base_url: str,
        service_token: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        transport: httpx.AsyncBaseTransport | None = None,
        logger: Logger | None = None,
    ) -> None:
        self._service_token = service_token
        # Redirects are off: this client sends credentials, and a redirect is somebody else's
        # server asking for them.
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_seconds,
            transport=transport,
            follow_redirects=False,
        )
        self._log: Logger = logger if logger is not None else StdlibLogger(__name__)

    async def resolve_credential(
        self, *, user_token: str, profile: str, service: str
    ) -> ResolvedCredential:
        """What to attach to an outgoing request for the token's owner.

        Raises:
            KeyringRejectedError, CredentialNotFoundError, CredentialUnavailableError,
            KeyringUnreachableError: see the module docstring.
        """
        body = await self._get(CREDENTIALS_PATH, profile, service, user_token=user_token)
        headers = _string_map(body.get("headers"))
        query_params = _string_map(body.get("query_params", {}))
        if headers is None or query_params is None:
            self._log.warning("keyring_answer_malformed", service=service)
            raise KeyringUnreachableError(MALFORMED)
        return ResolvedCredential(
            service=service,
            headers=headers,
            query_params=query_params,
            expires_at=_moment(body.get("expires_at")),
        )

    async def resolve_form_secrets(
        self, *, user_token: str, profile: str, service: str
    ) -> FormSecrets:
        """The values to type into a site's login form, for the token's owner.

        The one call in the family that returns credential material. Never store, log or
        return what it gives you.

        Raises:
            As :meth:`resolve_credential`.
        """
        body = await self._get(FORM_SECRETS_PATH, profile, service, user_token=user_token)
        fields = _string_map(body.get("fields"))
        if not fields:
            self._log.warning("keyring_answer_malformed", service=service)
            raise KeyringUnreachableError(MALFORMED)
        return FormSecrets(service=service, fields=fields)

    async def aclose(self) -> None:
        """Release the connection pool."""
        await self._http.aclose()

    async def _get(
        self, base: str, profile: str, service: str, *, user_token: str
    ) -> dict[str, Any]:
        """Call one internal endpoint with both credentials, and classify the answer.

        Both path segments are percent-encoded, so a profile name cannot climb out of the
        path it is placed in, whatever a request header said it was.
        """
        path = f"{base}/{quote(profile, safe='')}/{quote(service, safe='')}"
        try:
            response = await self._http.get(
                path,
                headers={
                    "Authorization": f"Bearer {self._service_token}",
                    USER_TOKEN_HEADER: user_token,
                },
            )
        except httpx.HTTPError as exc:
            self._log.warning("keyring_unreachable", error=type(exc).__name__)
            raise KeyringUnreachableError(UNREACHABLE) from exc

        status = response.status_code
        if status == httpx.codes.UNAUTHORIZED:
            raise KeyringRejectedError(REJECTED)
        if status == httpx.codes.NOT_FOUND:
            raise CredentialNotFoundError(NOT_FOUND)
        if status == httpx.codes.SERVICE_UNAVAILABLE:
            raise CredentialUnavailableError(_detail_of(response))
        if response.is_error:
            self._log.warning("keyring_failed", status=status)
            raise KeyringUnreachableError(UNREACHABLE)

        try:
            body: object = response.json()
        except ValueError as exc:
            raise KeyringUnreachableError(MALFORMED) from exc
        if not isinstance(body, dict):
            raise KeyringUnreachableError(MALFORMED)
        return body


def _string_map(value: object) -> dict[str, str] | None:
    """A mapping of strings to strings, or ``None`` if ``value`` is not one."""
    if not isinstance(value, dict):
        return None
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in value.items()):
        return None
    return dict(value)


def _moment(value: object) -> datetime | None:
    """Keyring's expiry, tolerating its absence, a trailing ``Z`` and a naive timestamp."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _detail_of(response: httpx.Response) -> str:
    """Keyring's own ``detail`` from a problem body, or a fixed message when there is none."""
    try:
        body: object = response.json()
    except ValueError:
        return UNUSABLE
    detail = body.get("detail") if isinstance(body, dict) else None
    return detail if isinstance(detail, str) and detail else UNUSABLE
