"""Token signing and the JWKS document."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import jwt
import pytest

from keyring_api.accounts.signing import ALGORITHM, TokenSigner
from keyring_api.domain.errors import AuthenticationError
from tests.fakes.clock import FakeClock
from tests.support.filemode import assert_mode

if TYPE_CHECKING:
    from pathlib import Path

ISSUER = "https://keyring.test"
AUDIENCE = "downstream-tool"


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def signer(tmp_path: Path, clock: FakeClock) -> TokenSigner:
    return TokenSigner(key_path=tmp_path / "keys" / "signing.pem", issuer=ISSUER, clock=clock)


class TestKeyMaterial:
    def test_a_key_is_created_on_first_start(self, tmp_path: Path, clock: FakeClock) -> None:
        path = tmp_path / "keys" / "signing.pem"

        TokenSigner(key_path=path, issuer=ISSUER, clock=clock)

        assert path.exists()

    def test_the_key_file_is_owner_only(self, tmp_path: Path, clock: FakeClock) -> None:
        # This key is the authority behind every token another service trusts. Anyone
        # who can read it can mint a token for any account.
        path = tmp_path / "keys" / "signing.pem"
        TokenSigner(key_path=path, issuer=ISSUER, clock=clock)

        assert_mode(path, 0o600)
        assert_mode(path.parent, 0o700)

    def test_the_key_survives_a_restart(self, tmp_path: Path, clock: FakeClock) -> None:
        # A key that changed on restart would invalidate every token in flight and force
        # every consuming service to re-fetch the JWKS at exactly the moment this
        # service is coming back up.
        path = tmp_path / "keys" / "signing.pem"
        first = TokenSigner(key_path=path, issuer=ISSUER, clock=clock)

        second = TokenSigner(key_path=path, issuer=ISSUER, clock=clock)

        assert first.jwks() == second.jwks()

    def test_a_file_that_is_not_a_private_key_is_refused(
        self, tmp_path: Path, clock: FakeClock
    ) -> None:
        path = tmp_path / "signing.pem"
        path.write_bytes(b"-----BEGIN NOT A KEY-----\n")

        with pytest.raises(ValueError, match="PEM"):
            TokenSigner(key_path=path, issuer=ISSUER, clock=clock)

    def test_a_public_key_file_is_refused_rather_than_used(
        self, tmp_path: Path, clock: FakeClock
    ) -> None:
        # Pointing the setting at the wrong half of a pair must fail loudly at startup,
        # not produce a service that cannot sign anything and says so per request.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        path = tmp_path / "signing.pem"
        wrong_kind = ed25519.Ed25519PrivateKey.generate()
        path.write_bytes(
            wrong_kind.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        with pytest.raises(TypeError, match="RSA"):
            TokenSigner(key_path=path, issuer=ISSUER, clock=clock)


class TestIssuedTokens:
    def test_a_token_verifies_against_the_published_key(self, signer: TokenSigner) -> None:
        token = signer.issue(account_id="acct_1", audience=AUDIENCE, ttl_seconds=900)

        assert signer.verify(token, audience=AUDIENCE) == "acct_1"

    def test_a_consumer_can_verify_it_with_the_jwks_alone(self, signer: TokenSigner) -> None:
        # The whole point: another service verifies locally, with no call back to
        # keyring on every request it serves. Verified here the way that service will --
        # from the published document, with a real JWT library.
        token = signer.issue(account_id="acct_1", audience=AUDIENCE, ttl_seconds=900)
        key = jwt.PyJWK(signer.jwks()["keys"][0])

        claims = jwt.decode(
            token,
            key,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            options={"verify_exp": False},
        )

        assert claims["sub"] == "acct_1"

    def test_the_subject_is_the_opaque_account_id_not_an_address(self, signer: TokenSigner) -> None:
        # This token is handed to another service, logged there, and possibly cached.
        # None of that should spread somebody's email address around.
        token = signer.issue(account_id="acct_1", audience=AUDIENCE, ttl_seconds=900)

        assert "@" not in jwt.decode(token, options={"verify_signature": False})["sub"]

    def test_the_issuer_is_stamped_so_a_consumer_can_pin_it(self, signer: TokenSigner) -> None:
        token = signer.issue(account_id="acct_1", audience=AUDIENCE, ttl_seconds=900)

        assert jwt.decode(token, options={"verify_signature": False})["iss"] == ISSUER

    def test_the_key_id_is_in_the_header_so_a_consumer_can_cache_by_it(
        self, signer: TokenSigner
    ) -> None:
        token = signer.issue(account_id="acct_1", audience=AUDIENCE, ttl_seconds=900)

        assert jwt.get_unverified_header(token)["kid"] == signer.jwks()["keys"][0]["kid"]

    def test_the_key_id_is_stable_across_restarts(self, tmp_path: Path, clock: FakeClock) -> None:
        # Derived from the key rather than random: a consuming service caches the JWKS
        # by kid, and a fresh id every boot means a cache miss and a re-fetch each time.
        path = tmp_path / "signing.pem"
        first = TokenSigner(key_path=path, issuer=ISSUER, clock=clock).jwks()

        second = TokenSigner(key_path=path, issuer=ISSUER, clock=clock).jwks()

        assert first["keys"][0]["kid"] == second["keys"][0]["kid"]


class TestVerification:
    def test_an_expired_token_is_refused(self, signer: TokenSigner, clock: FakeClock) -> None:
        # A signed token cannot be revoked -- that is what makes it verifiable offline --
        # so the expiry is the only revocation mechanism there is.
        token = signer.issue(account_id="acct_1", audience=AUDIENCE, ttl_seconds=900)

        clock.advance(timedelta(seconds=901))

        with pytest.raises(AuthenticationError):
            signer.verify(token, audience=AUDIENCE)

    def test_a_token_for_a_different_audience_is_refused(self, signer: TokenSigner) -> None:
        # Otherwise a token minted for one service is usable at every other service that
        # trusts this issuer.
        token = signer.issue(account_id="acct_1", audience="downstream-tool", ttl_seconds=900)

        with pytest.raises(AuthenticationError):
            signer.verify(token, audience="some-other-service")

    def test_a_token_from_a_different_issuer_is_refused(
        self, tmp_path: Path, clock: FakeClock, signer: TokenSigner
    ) -> None:
        impostor = TokenSigner(
            key_path=tmp_path / "other.pem", issuer="https://elsewhere", clock=clock
        )
        token = impostor.issue(account_id="acct_1", audience=AUDIENCE, ttl_seconds=900)

        with pytest.raises(AuthenticationError):
            signer.verify(token, audience=AUDIENCE)

    def test_an_unsigned_token_is_refused(self, signer: TokenSigner) -> None:
        # The classic JWT failure: a caller supplies alg "none" and the library, left to
        # its own devices, accepts it. The algorithm is pinned on decode.
        forged = jwt.encode(
            {"sub": "acct_1", "aud": AUDIENCE, "iss": ISSUER}, key="", algorithm="none"
        )

        with pytest.raises(AuthenticationError):
            signer.verify(forged, audience=AUDIENCE)

    def test_a_token_signed_with_the_public_key_as_an_hmac_secret_is_refused(
        self, signer: TokenSigner
    ) -> None:
        # The other classic: downgrade RS256 to HS256 and sign with the public key,
        # which is published. Assembled by hand rather than with jwt.encode, because
        # PyJWT refuses to *produce* one -- and an attacker will not be using PyJWT.
        # Pinning the algorithm on decode is what closes it.
        forged = _forge_hs256(
            {"sub": "acct_1", "aud": AUDIENCE, "iss": ISSUER, "exp": 9999999999, "iat": 0},
            secret=signer._public_pem(),
        )

        with pytest.raises(AuthenticationError):
            signer.verify(forged, audience=AUDIENCE)

    def test_a_tampered_token_is_refused(self, signer: TokenSigner) -> None:
        token = signer.issue(account_id="acct_1", audience=AUDIENCE, ttl_seconds=900)
        header, payload, signature = token.split(".")

        with pytest.raises(AuthenticationError):
            signer.verify(f"{header}.{payload}x.{signature}", audience=AUDIENCE)

    def test_a_token_missing_required_claims_is_refused(self, signer: TokenSigner) -> None:
        incomplete = jwt.encode({"sub": "acct_1"}, signer._private_pem(), algorithm=ALGORITHM)

        with pytest.raises(AuthenticationError):
            signer.verify(incomplete, audience=AUDIENCE)


class TestJwks:
    def test_it_contains_no_private_material(self, signer: TokenSigner) -> None:
        # This document is fetched by anything that needs to verify, so it is served
        # unauthenticated -- and must contain nothing that could sign.
        key = signer.jwks()["keys"][0]

        assert set(key) == {"kty", "use", "alg", "kid", "n", "e"}
        assert "d" not in key

    def test_it_declares_the_algorithm_it_signs_with(self, signer: TokenSigner) -> None:
        assert signer.jwks()["keys"][0]["alg"] == ALGORITHM

    def test_the_encoded_modulus_has_no_base64_padding(self, signer: TokenSigner) -> None:
        # base64url without padding, per RFC 7515. A stray "=" is the kind of thing that
        # works in one JWT library and fails in the next.
        assert "=" not in signer.jwks()["keys"][0]["n"]


def _forge_hs256(claims: dict[str, object], *, secret: bytes) -> str:
    """Hand-assemble an HS256 token, as an attacker would."""
    import base64
    import hmac
    import json

    def segment(payload: dict[str, object]) -> bytes:
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")

    signing_input = segment({"alg": "HS256", "typ": "JWT"}) + b"." + segment(claims)
    signature = hmac.new(secret, signing_input, "sha256").digest()
    return (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()
