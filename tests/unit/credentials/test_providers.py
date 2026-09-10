"""Loading OAuth provider configuration."""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import pytest

from keyring_api.credentials.providers import OAuthProvider, load_providers
from keyring_api.domain.errors import CredentialUnavailableError

if TYPE_CHECKING:
    from pathlib import Path

ENTRY = {
    "service": "spotify",
    "authorize_url": "https://accounts.example.com/authorize",
    "token_url": "https://accounts.example.com/api/token",
    "client_id": "client-abc",
    "client_secret": "secret-abc",
    "scopes": ["user-read-private", "user-library-read"],
}


def write_providers(tmp_path: Path, entries: object, *, mode: int = 0o600) -> Path:
    path = tmp_path / "providers.json"
    path.write_text(json.dumps(entries))
    path.chmod(mode)
    return path


class TestLoading:
    def test_no_configured_file_means_no_providers(self) -> None:
        # A deployment that only stores API keys and passwords should not have to invent
        # a file to say it has no OAuth providers.
        assert load_providers(None) == {}

    def test_providers_are_keyed_by_service(self, tmp_path: Path) -> None:
        providers = load_providers(write_providers(tmp_path, [ENTRY]))

        assert providers["spotify"].client_id == "client-abc"

    def test_a_missing_file_is_an_error_rather_than_an_empty_result(self, tmp_path: Path) -> None:
        # Silently starting with no providers because of a typo'd path would present as
        # "OAuth is broken" with nothing in the logs saying why.
        with pytest.raises(CredentialUnavailableError, match="does not exist"):
            load_providers(tmp_path / "absent.json")

    def test_a_malformed_file_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "providers.json"
        path.write_text("{not json")
        path.chmod(0o600)

        with pytest.raises(CredentialUnavailableError, match="could not be read"):
            load_providers(path)

    def test_an_entry_missing_a_required_field_is_refused(self, tmp_path: Path) -> None:
        path = write_providers(tmp_path, [{"service": "spotify"}])

        with pytest.raises(CredentialUnavailableError):
            load_providers(path)

    def test_an_unknown_field_is_refused_rather_than_ignored(self, tmp_path: Path) -> None:
        # A misspelled "scopes" that was silently dropped would mean requesting no
        # scopes and finding out at the provider.
        path = write_providers(tmp_path, [{**ENTRY, "scopez": ["a"]}])

        with pytest.raises(CredentialUnavailableError):
            load_providers(path)


class TestFilePermissions:
    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
    def test_a_file_readable_by_anyone_else_is_refused(self, tmp_path: Path, mode: int) -> None:
        # This file holds client secrets. Refusing to start is a worse morning than a
        # warning nobody reads; it is a much better one than six months of a
        # group-readable secret.
        path = write_providers(tmp_path, [ENTRY], mode=mode)

        with pytest.raises(CredentialUnavailableError, match="0600"):
            load_providers(path)

    def test_an_owner_only_file_is_accepted(self, tmp_path: Path) -> None:
        path = write_providers(tmp_path, [ENTRY], mode=0o600)

        assert load_providers(path)

    def test_a_stricter_mode_is_also_accepted(self, tmp_path: Path) -> None:
        # 0400 is stricter, not looser. Refusing it would be pedantry that pushes an
        # operator towards loosening the file to satisfy us.
        path = write_providers(tmp_path, [ENTRY], mode=0o400)

        assert load_providers(path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o400


class TestAuthorizationUrl:
    @pytest.fixture
    def provider(self) -> OAuthProvider:
        return OAuthProvider.model_validate(ENTRY)

    def test_it_carries_the_state_the_callback_is_checked_against(
        self, provider: OAuthProvider
    ) -> None:
        url = provider.authorization_url(redirect_uri="https://k/cb", state="the-state")

        assert parse_qs(urlparse(url).query)["state"] == ["the-state"]

    def test_it_requests_an_authorization_code(self, provider: OAuthProvider) -> None:
        url = provider.authorization_url(redirect_uri="https://k/cb", state="s")

        assert parse_qs(urlparse(url).query)["response_type"] == ["code"]

    def test_it_asks_for_offline_access(self, provider: OAuthProvider) -> None:
        # Providers differ on whether they issue a refresh token by default. Asking for
        # offline access is what makes unattended refresh possible at all -- without it,
        # every connection dies an hour after it is made.
        url = provider.authorization_url(redirect_uri="https://k/cb", state="s")

        assert parse_qs(urlparse(url).query)["access_type"] == ["offline"]

    def test_scopes_are_space_separated_as_the_spec_requires(self, provider: OAuthProvider) -> None:
        url = provider.authorization_url(redirect_uri="https://k/cb", state="s")

        assert parse_qs(urlparse(url).query)["scope"] == ["user-read-private user-library-read"]

    def test_a_provider_with_no_scopes_sends_no_scope_parameter(self) -> None:
        # An empty scope parameter means different things to different providers; not
        # sending it means the same thing to all of them.
        provider = OAuthProvider.model_validate({**ENTRY, "scopes": []})

        url = provider.authorization_url(redirect_uri="https://k/cb", state="s")

        assert "scope" not in parse_qs(urlparse(url).query)

    def test_an_audience_is_included_when_the_provider_needs_one(self) -> None:
        provider = OAuthProvider.model_validate({**ENTRY, "audience": "https://api.example"})

        url = provider.authorization_url(redirect_uri="https://k/cb", state="s")

        assert parse_qs(urlparse(url).query)["audience"] == ["https://api.example"]

    def test_the_client_secret_never_appears_in_the_url(self, provider: OAuthProvider) -> None:
        # The URL goes into somebody's browser history, and into the provider's logs.
        # The secret belongs only in the server-to-server token request.
        url = provider.authorization_url(redirect_uri="https://k/cb", state="s")

        assert "secret-abc" not in url

    def test_the_redirect_uri_is_escaped_rather_than_concatenated(
        self, provider: OAuthProvider
    ) -> None:
        url = provider.authorization_url(redirect_uri="https://k/cb?injected=1", state="s")

        assert parse_qs(urlparse(url).query)["redirect_uri"] == ["https://k/cb?injected=1"]
        assert "injected" not in parse_qs(urlparse(url).query)
