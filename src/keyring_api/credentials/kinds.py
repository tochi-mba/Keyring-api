"""The three credential kinds built now, and how each is consumed.

Three kinds across two ports, deliberately: one that refreshes itself
(:class:`OAuth2Credential`), one that never expires (:class:`ApiKeyCredential`), and one
consumed by a login form rather than an HTTP header (:class:`PasswordCredential`). That
combination is what demonstrates the port split in
:mod:`keyring_api.credentials.base` rather than assuming it -- a design that only ever
had to serve one kind would look fine and prove nothing.

Each class wraps a stored secret and knows nothing about where it came from. Refreshing
is delegated to an injected callable rather than performed here, so the kinds stay pure
and the network lives in one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from keyring_api.credentials.totp import totp_code
from keyring_api.domain.errors import CredentialUnavailableError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from keyring_api.secrets.base import Secret

BEARER_HEADER = "Authorization"

DEFAULT_API_KEY_HEADER = "Authorization"
DEFAULT_API_KEY_TEMPLATE = "Bearer {value}"
"""How an API key is attached when the connection does not say otherwise.

Both are configurable per connection because there is no convention: some services want
``X-API-Key``, some want ``Bearer``, some want a query parameter. Encoding a guess into
the type would mean every service that disagrees needs a new kind.
"""


def _apply_template(template: str, value: str) -> str:
    """Substitute the key into the configured header template.

    Wrapped, because ``str.format`` can fail in a way that puts the *value* into the
    exception message: a format spec is itself a replacement field, so a template of
    ``{value:{value}}`` raises ``ValueError: Invalid format specifier '<the api key>'``.
    Unhandled, that escapes to the unhandled-exception path and is written to the log by
    ``logger.exception`` -- where the field-name redactor never sees it, because it is
    inside a message rather than in a field.

    So every failure becomes a credential error whose text mentions neither the template
    nor the value, and the caller gets the documented 503 rather than a 500.

    Raises:
        CredentialUnavailableError: the template cannot be applied.
    """
    formatted: str | None = None
    try:
        formatted = template.format(value=value)
    except (IndexError, KeyError, ValueError):
        # Swallowed here and re-raised *below*, outside the except block, deliberately.
        # `raise ... from None` would clear __cause__ but Python would still attach the
        # original to __context__, where its message -- the string containing the key --
        # remains reachable to anything that walks the chain. Raising outside the handler
        # leaves nothing attached at all.
        formatted = None

    if formatted is None:
        msg = "stored credential has a malformed header template"
        raise CredentialUnavailableError(msg)

    return formatted


def _require(secret: Secret, field: str) -> str:
    """Read a required string field, or fail the way a caller can act on.

    Stored material can be from an older format, a partial write, or a kind that was
    stored wrong. Any of those must produce a credential error rather than a KeyError
    surfacing from inside a provider.
    """
    value = secret.get(field)
    if not isinstance(value, str) or not value:
        msg = f"stored credential is missing {field!r}"
        raise CredentialUnavailableError(msg)
    return value


@dataclass(frozen=True, slots=True)
class ApiKeyCredential:
    """A static token attached to every request.

    Satisfies :class:`~keyring_api.credentials.base.HttpAuth`. Never expires, so its
    async methods never do any work -- which is exactly why the port is async: the
    caller cannot tell this kind from one that just made a network call.
    """

    secret: Secret

    async def headers(self) -> dict[str, str]:
        header = self.secret.get("header", DEFAULT_API_KEY_HEADER)
        template = self.secret.get("template", DEFAULT_API_KEY_TEMPLATE)
        if not isinstance(header, str) or not isinstance(template, str):
            msg = "stored credential has a malformed header configuration"
            raise CredentialUnavailableError(msg)

        if self.secret.get("in_query"):
            return {}
        return {header: _apply_template(template, _require(self.secret, "api_key"))}

    async def query_params(self) -> dict[str, str]:
        if not self.secret.get("in_query"):
            return {}

        name = self.secret.get("query_name", "api_key")
        if not isinstance(name, str):
            msg = "stored credential has a malformed query parameter name"
            raise CredentialUnavailableError(msg)
        return {name: _require(self.secret, "api_key")}


@dataclass(frozen=True, slots=True)
class OAuth2Credential:
    """A user-consented token pair, refreshed with nobody present.

    Satisfies :class:`~keyring_api.credentials.base.HttpAuth`. The refresh is injected
    rather than performed here: this type decides *whether* a refresh is due, and the
    credential service owns the network call and the write-back. Splitting it that way
    means the expiry rule -- the part that is easy to get subtly wrong -- is testable
    with no HTTP at all.
    """

    secret: Secret
    refresh: Callable[[], Awaitable[Secret]]
    """Called when the stored token is at or past its refresh margin."""

    needs_refresh: bool

    async def headers(self) -> dict[str, str]:
        secret = await self.refresh() if self.needs_refresh else self.secret
        token_type = secret.get("token_type", "Bearer")
        if not isinstance(token_type, str):
            msg = "stored credential has a malformed token type"
            raise CredentialUnavailableError(msg)

        return {BEARER_HEADER: f"{token_type} {_require(secret, 'access_token')}"}

    async def query_params(self) -> dict[str, str]:
        """None. OAuth 2.0 bearer tokens go in the header.

        RFC 6750 does define a query-parameter form, and also deprecates it: a token in
        a URL ends up in access logs, proxy logs and Referer headers.
        """
        return {}


@dataclass(frozen=True, slots=True)
class PasswordCredential:
    """A username and password, optionally with a TOTP seed.

    Satisfies :class:`~keyring_api.credentials.base.FormSecrets`, not ``HttpAuth`` --
    which is the point of having two ports. These values are typed into somebody else's
    login form by a browser, and the TOTP code has to be generated at the moment of
    typing rather than when the credential was fetched.
    """

    secret: Secret
    now: Callable[[], float]
    """Reads the current unix time. Injected, so a generated code is testable."""

    async def fields(self) -> dict[str, str]:
        """The values to type into the form."""
        values = {
            "username": _require(self.secret, "username"),
            "password": _require(self.secret, "password"),
        }

        seed = self.secret.get("totp_seed")
        if isinstance(seed, str) and seed:
            values["totp"] = self._code(seed)
        return values

    def _code(self, seed: str) -> str:
        """Generate a current TOTP code, or fail as a credential error.

        A malformed seed is a stored-credential problem, not a programming error, and
        the caller -- a browser recipe halfway through a login -- needs it to arrive as
        the same kind of failure as every other unusable credential.
        """
        try:
            return totp_code(seed, unix_time=self.now())
        except ValueError as exc:
            msg = "stored TOTP seed could not be used"
            raise CredentialUnavailableError(msg) from exc
