"""The three credential kinds, and the ports they satisfy.

The point of the suite is the *shape*: three kinds across two ports, one of which
refreshes. If a fourth kind ever needs a third port, that is the signal the abstraction
was wrong -- so these tests assert the port conformance explicitly rather than assuming
it from the fact that the code runs.
"""

from __future__ import annotations

import pytest

from keyring_api.credentials.base import FormSecrets, HttpAuth
from keyring_api.credentials.kinds import (
    ApiKeyCredential,
    OAuth2Credential,
    PasswordCredential,
)
from keyring_api.domain.errors import CredentialUnavailableError
from keyring_api.secrets.base import Secret

RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


async def never_refreshes() -> Secret:
    unexpected = "refresh should not have been called"
    raise AssertionError(unexpected)


class TestApiKey:
    def test_it_satisfies_the_http_port(self) -> None:
        checked: HttpAuth = ApiKeyCredential({"api_key": "abc"})

        assert isinstance(checked, HttpAuth)

    async def test_it_attaches_a_bearer_header_by_default(self) -> None:
        credential = ApiKeyCredential({"api_key": "abc"})

        assert await credential.headers() == {"Authorization": "Bearer abc"}

    async def test_the_header_name_and_shape_are_configurable(self) -> None:
        # There is no convention here: some services want X-API-Key, some want Bearer.
        # Encoding a guess into the type would mean a new kind per disagreement.
        credential = ApiKeyCredential(
            {"api_key": "abc", "header": "X-API-Key", "template": "{value}"}
        )

        assert await credential.headers() == {"X-API-Key": "abc"}

    async def test_a_key_that_belongs_in_the_query_string_goes_there_instead(self) -> None:
        credential = ApiKeyCredential({"api_key": "abc", "in_query": True, "query_name": "key"})

        assert await credential.query_params() == {"key": "abc"}
        assert await credential.headers() == {}

    async def test_a_header_credential_contributes_no_query_parameters(self) -> None:
        assert await ApiKeyCredential({"api_key": "abc"}).query_params() == {}

    async def test_the_query_parameter_name_defaults_sensibly(self) -> None:
        credential = ApiKeyCredential({"api_key": "abc", "in_query": True})

        assert await credential.query_params() == {"api_key": "abc"}

    @pytest.mark.parametrize("secret", [{}, {"api_key": ""}, {"api_key": 42}])
    async def test_material_missing_its_key_fails_as_a_credential_error(
        self, secret: Secret
    ) -> None:
        # Rather than a KeyError or a TypeError escaping into a provider, where it would
        # be reported as a bug in the provider.
        with pytest.raises(CredentialUnavailableError, match="api_key"):
            await ApiKeyCredential(secret).headers()

    async def test_a_malformed_header_configuration_fails_cleanly(self) -> None:
        with pytest.raises(CredentialUnavailableError):
            await ApiKeyCredential({"api_key": "abc", "header": 42}).headers()

    async def test_a_malformed_query_name_fails_cleanly(self) -> None:
        with pytest.raises(CredentialUnavailableError):
            await ApiKeyCredential(
                {"api_key": "a", "in_query": True, "query_name": 1}
            ).query_params()


class TestOAuth2:
    def test_it_satisfies_the_http_port(self) -> None:
        checked: HttpAuth = OAuth2Credential(
            {"access_token": "abc"}, refresh=never_refreshes, needs_refresh=False
        )

        assert isinstance(checked, HttpAuth)

    async def test_a_live_token_is_attached_without_refreshing(self) -> None:
        credential = OAuth2Credential(
            {"access_token": "abc"}, refresh=never_refreshes, needs_refresh=False
        )

        assert await credential.headers() == {"Authorization": "Bearer abc"}

    async def test_a_token_inside_its_margin_is_refreshed_first(self) -> None:
        # The caller attaches what it is given and never learns that a network round
        # trip happened -- which is the entire reason the port is async.
        async def refreshed() -> Secret:
            return {"access_token": "fresh"}

        credential = OAuth2Credential(
            {"access_token": "stale"}, refresh=refreshed, needs_refresh=True
        )

        assert await credential.headers() == {"Authorization": "Bearer fresh"}

    async def test_a_non_bearer_token_type_is_honoured(self) -> None:
        credential = OAuth2Credential(
            {"access_token": "abc", "token_type": "DPoP"},
            refresh=never_refreshes,
            needs_refresh=False,
        )

        assert await credential.headers() == {"Authorization": "DPoP abc"}

    async def test_a_refresh_failure_surfaces_to_the_caller(self) -> None:
        async def fails() -> Secret:
            message = "the provider rejected the refresh token"
            raise CredentialUnavailableError(message)

        credential = OAuth2Credential({"access_token": "x"}, refresh=fails, needs_refresh=True)

        with pytest.raises(CredentialUnavailableError):
            await credential.headers()

    async def test_a_refresh_that_returns_nothing_usable_fails_cleanly(self) -> None:
        async def returns_junk() -> Secret:
            return {"error": "invalid_grant"}

        credential = OAuth2Credential(
            {"access_token": "x"}, refresh=returns_junk, needs_refresh=True
        )

        with pytest.raises(CredentialUnavailableError, match="access_token"):
            await credential.headers()

    async def test_the_token_never_goes_in_the_query_string(self) -> None:
        # RFC 6750 defines the form and deprecates it: a token in a URL ends up in
        # access logs, proxy logs, and Referer headers.
        credential = OAuth2Credential(
            {"access_token": "abc"}, refresh=never_refreshes, needs_refresh=False
        )

        assert await credential.query_params() == {}

    async def test_a_malformed_token_type_fails_cleanly(self) -> None:
        credential = OAuth2Credential(
            {"access_token": "abc", "token_type": 7},
            refresh=never_refreshes,
            needs_refresh=False,
        )

        with pytest.raises(CredentialUnavailableError):
            await credential.headers()


class TestPassword:
    def test_it_satisfies_the_form_port_and_not_the_http_one(self) -> None:
        # The distinction is the whole point of having two ports. These values are typed
        # into somebody else's login page, not attached to a request.
        credential = PasswordCredential({"username": "a", "password": "b"}, now=lambda: 0.0)
        checked: FormSecrets = credential

        assert isinstance(checked, FormSecrets)
        assert not isinstance(credential, HttpAuth)

    async def test_it_yields_the_username_and_password(self) -> None:
        credential = PasswordCredential(
            {"username": "person", "password": "hunter2"}, now=lambda: 0.0
        )

        assert await credential.fields() == {"username": "person", "password": "hunter2"}

    async def test_a_stored_seed_produces_a_current_code(self) -> None:
        # Generated at the moment of typing, not when the credential was fetched: by the
        # time a browser has navigated to the login page, a code from thirty seconds ago
        # is already wrong.
        credential = PasswordCredential(
            {"username": "person", "password": "hunter2", "totp_seed": RFC_SEED},
            now=lambda: 59.0,
        )

        assert (await credential.fields())["totp"] == "287082"

    async def test_no_totp_field_appears_when_no_seed_is_stored(self) -> None:
        # An empty string would be typed into the form and rejected by the site, which
        # looks like a wrong password rather than like a missing second factor.
        credential = PasswordCredential({"username": "a", "password": "b"}, now=lambda: 0.0)

        assert "totp" not in await credential.fields()

    async def test_an_empty_seed_is_treated_as_no_seed(self) -> None:
        credential = PasswordCredential(
            {"username": "a", "password": "b", "totp_seed": ""}, now=lambda: 0.0
        )

        assert "totp" not in await credential.fields()

    async def test_a_malformed_seed_fails_as_a_credential_error(self) -> None:
        # A stored-credential problem, not a programming error: the caller is a browser
        # halfway through a login and needs it to arrive like any other unusable
        # credential.
        credential = PasswordCredential(
            {"username": "a", "password": "b", "totp_seed": "not!base32"}, now=lambda: 0.0
        )

        with pytest.raises(CredentialUnavailableError, match="TOTP"):
            await credential.fields()

    @pytest.mark.parametrize("secret", [{"password": "b"}, {"username": "a"}])
    async def test_incomplete_material_fails_cleanly(self, secret: Secret) -> None:
        with pytest.raises(CredentialUnavailableError):
            await PasswordCredential(secret, now=lambda: 0.0).fields()
