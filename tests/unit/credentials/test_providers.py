"""Loading OAuth provider configuration."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import pytest

from keyring_api.core.config import LogFormat
from keyring_api.core.logging import configure_logging
from keyring_api.credentials.providers import OAuthProvider, load_providers
from keyring_api.domain.errors import CredentialUnavailableError
from tests.support.filemode import assert_mode

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


def pin_permission_bits(monkeypatch: pytest.MonkeyPatch, *, present: bool) -> None:
    """Decide for the loader whether this platform has permission bits.

    Pinned rather than detected, so both branches run wherever the suite does: Linux CI
    reaches the Windows branch this way, and a native Windows run reaches the POSIX one.
    """
    monkeypatch.setattr("keyring_api.credentials.providers.has_permission_bits", lambda: present)


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
    def test_a_file_readable_by_anyone_else_is_refused(
        self, tmp_path: Path, mode: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # This file holds client secrets. Refusing to start is a worse morning than a
        # warning nobody reads; it is a much better one than six months of a
        # group-readable secret.
        #
        # Pinned to the POSIX branch, which is the one Linux takes anyway. On Windows the
        # pin is what lets the refusal run at all, and every mode here reads back as 0666
        # there -- still readable by others, so still refused.
        pin_permission_bits(monkeypatch, present=True)
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
        assert_mode(path, 0o400)


class TestWhetherTheModeIsChecked:
    """The platform decision, pinned each way so both branches run on any OS.

    POSIX has a mode to compare. Windows does not -- NTFS keeps no permission bits, and
    every writable file reads 0666 -- so there the comparison is skipped, and said to be.
    """

    def test_where_there_are_permission_bits_a_refusal_comes_with_no_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # The warning means "nothing was checked". Printed where the check did run, it
        # would teach operators to ignore it on the one platform where it is true.
        configure_logging(level="INFO", log_format=LogFormat.JSON)
        pin_permission_bits(monkeypatch, present=True)
        path = write_providers(tmp_path, [ENTRY], mode=0o644)

        with pytest.raises(CredentialUnavailableError, match="0600"):
            load_providers(path)

        assert "oauth_provider_file_mode_unchecked" not in capsys.readouterr().out

    def test_where_there_are_none_a_file_the_mode_check_would_refuse_is_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Otherwise keyring run natively on Windows could load no provider at all, since
        # no file there can read back as 0600.
        pin_permission_bits(monkeypatch, present=False)
        path = write_providers(tmp_path, [ENTRY], mode=0o644)

        assert load_providers(path)["spotify"].client_id == "client-abc"

    def test_where_there_are_none_one_warning_names_the_path_and_nothing_inside_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A check that is quietly skipped looks exactly like one that passed. The path is
        # there so an operator can find the file and look at its ACL; the contents are
        # not, because the contents are client secrets.
        configure_logging(level="INFO", log_format=LogFormat.JSON)
        pin_permission_bits(monkeypatch, present=False)
        path = write_providers(tmp_path, [ENTRY])

        load_providers(path)

        output = capsys.readouterr().out
        records = [json.loads(line) for line in output.splitlines()]
        assert [(record["event"], record["level"], record["path"]) for record in records] == [
            ("oauth_provider_file_mode_unchecked", "warning", str(path))
        ]
        assert "POSIX-only" in records[0]["reason"]
        assert "secret-abc" not in output


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
