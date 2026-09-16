"""The shared fake keyring refuses what keyring refuses.

A fake that accepts what the real thing rejects is how a bug ships: one sibling service was
built against a stand-in that echoed whatever it was given. These tests pin the fake's own
behaviour; ``tests/integration/test_client_contract.py`` pins it against the real app.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import httpx
import jwt
import pytest

from keyring_client import CREDENTIALS_PATH, JWKS_PATH, USER_TOKEN_HEADER, Clock
from keyring_client.testing import (
    BASE_URL,
    DEFAULT_SERVICE,
    DEFAULT_SERVICE_TOKEN,
    EPOCH,
    ROTATED_KEY,
    SIGNING_KEY,
    FakeClock,
    FakeKeyring,
    jwks,
    mint,
    public_pem,
    thumbprint,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

ACCOUNT = "account-a"


@pytest.fixture
async def http(keyring: FakeKeyring) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=keyring.transport(), base_url=BASE_URL) as client:
        yield client


def internal(user_token: str, service_token: str = DEFAULT_SERVICE_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {service_token}", USER_TOKEN_HEADER: user_token}


class TestTheClock:
    def test_it_moves_only_when_told_by_seconds_or_by_a_timedelta(self) -> None:
        clock = FakeClock()
        assert isinstance(clock, Clock)

        clock.advance(30)
        clock.advance(timedelta(minutes=1))

        assert clock.now() == EPOCH + timedelta(seconds=90)
        assert clock.monotonic() == 90.0


class TestTokens:
    def test_a_minted_token_is_one_keyring_would_mint(self) -> None:
        token = mint(account_id=ACCOUNT)

        claims = jwt.decode(
            token,
            public_pem(),
            algorithms=["RS256"],
            audience=DEFAULT_SERVICE,
            options={"verify_exp": False, "verify_iat": False},
        )

        assert claims["sub"] == ACCOUNT
        assert jwt.get_unverified_header(token)["kid"] == thumbprint(SIGNING_KEY)

    def test_the_default_document_publishes_the_signing_key(self) -> None:
        assert [key["kid"] for key in jwks()["keys"]] == [thumbprint()]


class TestServingKeys:
    async def test_it_counts_fetches_and_can_be_made_to_answer_anything(
        self, keyring: FakeKeyring, http: httpx.AsyncClient
    ) -> None:
        keyring.status = 503
        keyring.body = {"keys": []}

        response = await http.get(JWKS_PATH)

        assert response.status_code == 503
        assert response.json() == {"keys": []}
        assert keyring.fetches == 1

    async def test_a_rotation_publishes_only_the_replacement(
        self, keyring: FakeKeyring, http: httpx.AsyncClient
    ) -> None:
        keyring.rotate()

        document = (await http.get(JWKS_PATH)).json()

        assert [key["kid"] for key in document["keys"]] == [thumbprint(ROTATED_KEY)]

    async def test_a_path_keyring_does_not_serve_is_not_found(
        self, http: httpx.AsyncClient
    ) -> None:
        assert (await http.get("/v1/profiles")).status_code == 404


class TestTheInternalSurface:
    async def test_an_error_set_on_the_fake_is_raised_on_internal_calls_too(
        self, keyring: FakeKeyring, http: httpx.AsyncClient
    ) -> None:
        keyring.error = httpx.ConnectError("down")

        with pytest.raises(httpx.ConnectError):
            await http.get(f"{CREDENTIALS_PATH}/personal/tmdb", headers=internal(keyring.mint()))

    async def test_a_path_with_the_wrong_number_of_segments_is_not_found(
        self, keyring: FakeKeyring, http: httpx.AsyncClient
    ) -> None:
        response = await http.get(f"{CREDENTIALS_PATH}/personal", headers=internal(keyring.mint()))

        assert response.status_code == 404

    async def test_no_authorization_header_is_refused(
        self, keyring: FakeKeyring, http: httpx.AsyncClient
    ) -> None:
        response = await http.get(
            f"{CREDENTIALS_PATH}/personal/tmdb", headers={USER_TOKEN_HEADER: keyring.mint()}
        )

        assert response.status_code == 401

    @pytest.mark.parametrize(
        "user_token",
        [
            "",
            "not-a-token",
            mint(kid="unpublished"),
            mint(audience="another-service"),
            mint(issuer="https://another-keyring.test"),
        ],
        ids=["missing", "garbage", "unpublished-key", "wrong-audience", "wrong-issuer"],
    )
    async def test_a_user_token_keyring_would_refuse_is_refused(
        self, http: httpx.AsyncClient, user_token: str
    ) -> None:
        response = await http.get(f"{CREDENTIALS_PATH}/personal/tmdb", headers=internal(user_token))

        assert response.status_code == 401

    async def test_explicit_service_tokens_replace_the_default_service(self) -> None:
        keyring = FakeKeyring(service_tokens={"media-tool": "media-tool-token-0123456789abcdef"})
        async with httpx.AsyncClient(transport=keyring.transport(), base_url=BASE_URL) as http:
            response = await http.get(
                f"{CREDENTIALS_PATH}/personal/tmdb", headers=internal(keyring.mint())
            )

        assert response.status_code == 401
        assert set(keyring.service_tokens) == {"media-tool"}

    async def test_form_secrets_that_were_never_stored_are_not_found(
        self, keyring: FakeKeyring, http: httpx.AsyncClient
    ) -> None:
        response = await http.get(
            "/v1/internal/form-secrets/personal/site", headers=internal(keyring.mint())
        )

        assert response.status_code == 404
