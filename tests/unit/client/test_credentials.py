"""Keyring's internal surface, as a consuming service sees it.

Every one of keyring's answers is mapped to the person who can act on it, and the tests are
grouped that way. The happy paths run against :class:`FakeKeyring`, which checks both
credentials the way keyring does; the odd answers -- a proxy's HTML, a 500, a body that is not
an object -- come from hand-written transports, because keyring itself never produces them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import pytest

from keyring_client import (
    CREDENTIALS_PATH,
    USER_TOKEN_HEADER,
    CredentialClient,
    CredentialNotFoundError,
    CredentialUnavailableError,
    FormSecrets,
    KeyringRejectedError,
    KeyringUnreachableError,
    ResolvedCredential,
)
from keyring_client.credentials import MALFORMED, UNUSABLE
from keyring_client.testing import (
    BASE_URL,
    DEFAULT_SERVICE,
    DEFAULT_SERVICE_TOKEN,
    SEALED_DETAIL,
    FakeKeyring,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from tests.unit.client.conftest import RecordingLogger

ACCOUNT = "account-a"
PROFILE = "personal"
TMDB = "tmdb"
EXPIRES = datetime(2026, 1, 1, 13, 0, tzinfo=UTC)


def answering(respond: Callable[[httpx.Request], httpx.Response]) -> httpx.MockTransport:
    return httpx.MockTransport(respond)


@pytest.fixture
async def make_client(
    keyring: FakeKeyring, recorder: RecordingLogger
) -> AsyncIterator[Callable[..., CredentialClient]]:
    made: list[CredentialClient] = []

    def make(
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        service_token: str = DEFAULT_SERVICE_TOKEN,
    ) -> CredentialClient:
        client = CredentialClient(
            base_url=BASE_URL + "/",
            service_token=service_token,
            transport=transport if transport is not None else keyring.transport(),
            logger=recorder,
        )
        made.append(client)
        return client

    yield make

    for client in made:
        await client.aclose()


@pytest.fixture
def token(keyring: FakeKeyring) -> str:
    return keyring.mint(account_id=ACCOUNT, audience=DEFAULT_SERVICE)


class TestWhatComesBack:
    async def test_the_headers_and_query_parameters_to_attach(
        self, make_client: Callable[..., CredentialClient], keyring: FakeKeyring, token: str
    ) -> None:
        keyring.connect(
            account_id=ACCOUNT,
            profile=PROFILE,
            service=TMDB,
            headers={"Authorization": "Bearer the-api-key"},
            query_params={"region": "gb"},
            expires_at=EXPIRES,
        )

        resolved = await make_client().resolve_credential(
            user_token=token, profile=PROFILE, service=TMDB
        )

        assert resolved.service == TMDB
        assert resolved.headers == {"Authorization": "Bearer the-api-key"}
        assert resolved.query_params == {"region": "gb"}
        assert resolved.expires_at == EXPIRES

    async def test_both_credentials_travel_in_their_own_headers(
        self, make_client: Callable[..., CredentialClient], keyring: FakeKeyring, token: str
    ) -> None:
        keyring.connect(account_id=ACCOUNT, profile=PROFILE, service=TMDB, headers={"X": "y"})

        await make_client().resolve_credential(user_token=token, profile=PROFILE, service=TMDB)

        [call] = keyring.internal_calls
        assert call.headers["Authorization"] == f"Bearer {DEFAULT_SERVICE_TOKEN}"
        assert call.headers[USER_TOKEN_HEADER] == token
        assert call.url.path == f"{CREDENTIALS_PATH}/{PROFILE}/{TMDB}"

    async def test_a_profile_name_cannot_climb_out_of_its_path_segment(
        self, make_client: Callable[..., CredentialClient], keyring: FakeKeyring, token: str
    ) -> None:
        with pytest.raises(CredentialNotFoundError):
            await make_client().resolve_credential(
                user_token=token, profile="../../admin", service=TMDB
            )

        [call] = keyring.internal_calls
        assert b"..%2F..%2Fadmin" in call.url.raw_path

    async def test_the_values_to_type_into_a_login_form(
        self, make_client: Callable[..., CredentialClient], keyring: FakeKeyring, token: str
    ) -> None:
        keyring.connect_form(
            account_id=ACCOUNT,
            profile=PROFILE,
            service="site",
            fields={"username": "me", "password": "hunter2"},
        )

        secrets = await make_client().resolve_form_secrets(
            user_token=token, profile=PROFILE, service="site"
        )

        assert secrets.fields == {"username": "me", "password": "hunter2"}


class TestNothingPrintsASecret:
    def test_a_resolved_credential_counts_its_values_and_shows_none(self) -> None:
        resolved = ResolvedCredential(
            service=TMDB, headers={"Authorization": "Bearer the-api-key"}, query_params={"k": "v"}
        )

        rendered = repr(resolved)

        assert "the-api-key" not in rendered
        assert "headers=<1 redacted>" in rendered
        assert "query_params=<1 redacted>" in rendered

    def test_form_secrets_name_their_fields_and_show_no_value(self) -> None:
        rendered = repr(FormSecrets(service="site", fields={"username": "me", "password": "x1"}))

        assert "x1" not in rendered
        assert "password,username" in rendered

    def test_every_value_to_scrub_is_listed_longest_first_with_the_bare_bearer_token(
        self,
    ) -> None:
        # A program that echoes its environment prints the token without the scheme, so the
        # scheme-less token has to be scrubbed too.
        resolved = ResolvedCredential(
            service=TMDB,
            headers={"Authorization": "Bearer the-api-key", "X-Empty": ""},
            query_params={"key": "abc"},
        )

        assert resolved.secrets == ("Bearer the-api-key", "the-api-key", "abc")


class TestTheOperatorsProblem:
    async def test_a_service_token_keyring_does_not_know_is_a_rejection(
        self, make_client: Callable[..., CredentialClient], token: str
    ) -> None:
        with pytest.raises(KeyringRejectedError):
            await make_client(service_token="not-this-one-0123456789abcdefghij").resolve_credential(
                user_token=token, profile=PROFILE, service=TMDB
            )

    async def test_a_user_token_minted_for_another_service_is_a_rejection(
        self, make_client: Callable[..., CredentialClient], keyring: FakeKeyring
    ) -> None:
        # Keyring requires the token's audience to be the calling service; a token handed to
        # one service cannot be replayed through another.
        stolen = keyring.mint(account_id=ACCOUNT, audience="some-other-service")

        with pytest.raises(KeyringRejectedError):
            await make_client().resolve_credential(user_token=stolen, profile=PROFILE, service=TMDB)


class TestThePersonsProblem:
    async def test_no_such_connection_is_not_found(
        self, make_client: Callable[..., CredentialClient], token: str
    ) -> None:
        with pytest.raises(CredentialNotFoundError):
            await make_client().resolve_credential(user_token=token, profile=PROFILE, service=TMDB)

    async def test_another_accounts_connection_is_exactly_as_absent(
        self, make_client: Callable[..., CredentialClient], keyring: FakeKeyring
    ) -> None:
        keyring.connect(account_id=ACCOUNT, profile=PROFILE, service=TMDB, headers={"X": "y"})
        other = keyring.mint(account_id="account-b")

        with pytest.raises(CredentialNotFoundError):
            await make_client().resolve_credential(user_token=other, profile=PROFILE, service=TMDB)

    async def test_an_unusable_credential_carries_keyrings_own_explanation(
        self, make_client: Callable[..., CredentialClient], keyring: FakeKeyring, token: str
    ) -> None:
        keyring.sealed = True

        with pytest.raises(CredentialUnavailableError) as failure:
            await make_client().resolve_credential(user_token=token, profile=PROFILE, service=TMDB)

        assert str(failure.value) == SEALED_DETAIL

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(503, text="<html>sealed</html>"),
            httpx.Response(503, json=["not", "an", "object"]),
            httpx.Response(503, json={"detail": {"nested": "object"}}),
            httpx.Response(503, json={"detail": ""}),
        ],
        ids=["not-json", "not-an-object", "detail-not-a-string", "detail-empty"],
    )
    async def test_an_unusable_credential_without_a_readable_detail_still_says_so(
        self, make_client: Callable[..., CredentialClient], token: str, response: httpx.Response
    ) -> None:
        client = make_client(transport=answering(lambda _: response))

        with pytest.raises(CredentialUnavailableError) as failure:
            await client.resolve_credential(user_token=token, profile=PROFILE, service=TMDB)

        assert str(failure.value) == UNUSABLE


class TestKeyringUnwell:
    async def test_keyring_that_cannot_be_reached_is_unreachable_and_the_url_is_not_logged(
        self, make_client: Callable[..., CredentialClient], token: str, recorder: RecordingLogger
    ) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            message = f"cannot reach {request.url}"
            raise httpx.ConnectError(message)

        with pytest.raises(KeyringUnreachableError):
            await make_client(transport=answering(refuse)).resolve_credential(
                user_token=token, profile=PROFILE, service=TMDB
            )

        assert "keyring_unreachable" in recorder.events()
        assert BASE_URL not in recorder.rendered()

    async def test_a_server_error_is_unreachable(
        self, make_client: Callable[..., CredentialClient], token: str
    ) -> None:
        client = make_client(transport=answering(lambda _: httpx.Response(500, text="boom")))

        with pytest.raises(KeyringUnreachableError):
            await client.resolve_credential(user_token=token, profile=PROFILE, service=TMDB)

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(200, text="<html>proxy page</html>"),
            httpx.Response(200, json=["a", "list"]),
            httpx.Response(200, json={"service": TMDB}),
            httpx.Response(200, json={"headers": "not-a-mapping"}),
            httpx.Response(200, json={"headers": {"Authorization": 7}}),
            httpx.Response(200, json={"headers": {}, "query_params": ["not", "a", "mapping"]}),
        ],
        ids=[
            "not-json",
            "not-an-object",
            "no-headers",
            "headers-not-a-mapping",
            "a-header-that-is-not-a-string",
            "query-params-not-a-mapping",
        ],
    )
    async def test_an_answer_that_is_not_a_credential_is_malformed(
        self, make_client: Callable[..., CredentialClient], token: str, response: httpx.Response
    ) -> None:
        client = make_client(transport=answering(lambda _: response))

        with pytest.raises(KeyringUnreachableError) as failure:
            await client.resolve_credential(user_token=token, profile=PROFILE, service=TMDB)

        assert str(failure.value) in {MALFORMED, "keyring could not be reached"}

    @pytest.mark.parametrize(
        "body",
        [{"service": "site"}, {"fields": {}}, {"fields": {"password": 1}}],
        ids=["no-fields", "empty-fields", "a-field-that-is-not-a-string"],
    )
    async def test_form_secrets_that_are_not_fields_are_malformed(
        self, make_client: Callable[..., CredentialClient], token: str, body: dict[str, object]
    ) -> None:
        client = make_client(transport=answering(lambda _: httpx.Response(200, json=body)))

        with pytest.raises(KeyringUnreachableError) as failure:
            await client.resolve_form_secrets(user_token=token, profile=PROFILE, service="site")

        assert str(failure.value) == MALFORMED


class TestExpiry:
    @pytest.mark.parametrize(
        ("raw", "parsed"),
        [
            (None, None),
            ("", None),
            ("not a timestamp", None),
            ("2026-01-01T13:00:00Z", EXPIRES),
            ("2026-01-01T13:00:00+00:00", EXPIRES),
            ("2026-01-01T13:00:00", EXPIRES),
        ],
        ids=["absent", "empty", "unparseable", "zulu", "offset", "naive-read-as-utc"],
    )
    async def test_keyrings_expiry_is_read_generously(
        self,
        make_client: Callable[..., CredentialClient],
        token: str,
        raw: str | None,
        parsed: datetime | None,
    ) -> None:
        # An expiry that cannot be read is treated as no expiry, not as a failed credential:
        # the headers are still good, and the caller's cache falls back to its own TTL.
        body = {"service": TMDB, "headers": {"X": "y"}, "query_params": {}, "expires_at": raw}
        client = make_client(transport=answering(lambda _: httpx.Response(200, json=body)))

        resolved = await client.resolve_credential(user_token=token, profile=PROFILE, service=TMDB)

        assert resolved.expires_at == parsed

    async def test_an_answer_with_no_query_parameters_member_attaches_none(
        self, make_client: Callable[..., CredentialClient], token: str
    ) -> None:
        body = {"service": TMDB, "headers": {"X": "y"}}
        client = make_client(transport=answering(lambda _: httpx.Response(200, json=body)))

        resolved = await client.resolve_credential(user_token=token, profile=PROFILE, service=TMDB)

        assert resolved.query_params == {}
