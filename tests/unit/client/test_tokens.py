"""Turning a keyring token into an identity, or into one undifferentiated refusal.

Most of what is here is a refusal, grouped by the rule that refuses: the pinned algorithm,
the pinned issuer, the clock, the required claims, the audience policy. The last test ties
them together -- every refusal says the same thing, byte for byte.

Several tokens are assembled by hand rather than minted, because PyJWT declines to *produce*
the tokens an attacker would send. Nothing here uses a mocking library: the keys and
signatures are real, and the only thing wrong with each token is the thing its test names.
"""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from keyring_client import (
    BAD_TOKEN,
    REQUIRED_CLAIMS,
    AudienceFamily,
    AudiencePolicy,
    AuthenticationError,
    ExactAudience,
    JwksClient,
    KeyringUnreachableError,
    TokenVerifier,
)
from keyring_client.testing import (
    EPOCH,
    ISSUER,
    JWKS_URL,
    ROTATED_KEY,
    SIGNING_KEY,
    FakeClock,
    FakeKeyring,
    forge_hs256,
    forge_unsigned,
    mint,
    private_pem,
    thumbprint,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from tests.unit.client.conftest import RecordingLogger

SERVICE = "downstream-tool"
EXACT = ExactAudience(SERVICE)
OTHER_ISSUER = "https://keyring.other.test"
LIFETIME = 900


def encode(segment: dict[str, Any]) -> str:
    packed = json.dumps(segment, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(packed).rstrip(b"=").decode()


def decode(segment: str) -> dict[str, Any]:
    decoded: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    )
    return decoded


def claims(**changes: Any) -> dict[str, Any]:
    minted: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "account-a",
        "aud": SERVICE,
        "iat": int(EPOCH.timestamp()),
        "exp": int(EPOCH.timestamp()) + LIFETIME,
    }
    return {**minted, **changes}


def hand_signed(payload: dict[str, Any], **headers: Any) -> str:
    """A genuine RS256 token, assembled without PyJWT, which refuses some headers."""
    header = encode({"typ": "JWT", "alg": "RS256", **headers})
    body = encode(payload)
    signature = SIGNING_KEY.sign(f"{header}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return ".".join([header, body, base64.urlsafe_b64encode(signature).rstrip(b"=").decode()])


def with_payload(token: str, **changes: Any) -> str:
    header, payload, signature = token.split(".")
    return ".".join([header, encode({**decode(payload), **changes}), signature])


def with_raw_payload(token: str, raw: bytes) -> str:
    header, _, signature = token.split(".")
    return ".".join([header, base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), signature])


def with_header(token: str, **changes: Any) -> str:
    header, payload, signature = token.split(".")
    return ".".join([encode({**decode(header), **changes}), payload, signature])


def with_flipped_signature(token: str) -> str:
    header, payload, signature = token.split(".")
    return ".".join([header, payload, ("B" if signature[0] != "B" else "C") + signature[1:]])


def with_borrowed_signature(token: str, other: str) -> str:
    return ".".join([*token.split(".")[:2], other.split(".")[2]])


def good(**overrides: Any) -> str:
    """A token keyring would mint for this service, with a realistic lifetime."""
    return mint(audience=SERVICE, ttl_seconds=LIFETIME, **overrides)


@pytest.fixture
async def jwks_client(clock: FakeClock, keyring: FakeKeyring) -> AsyncIterator[JwksClient]:
    client = JwksClient(url=JWKS_URL, clock=clock, transport=keyring.transport())
    yield client
    await client.aclose()


@pytest.fixture
def verifier(jwks_client: JwksClient, clock: FakeClock) -> TokenVerifier:
    return TokenVerifier(jwks=jwks_client, issuer=ISSUER, clock=clock)


class TestAudiencePolicies:
    def test_an_exact_audience_accepts_only_its_own_name(self) -> None:
        assert EXACT.accepts(SERVICE)
        assert not EXACT.accepts(f"{SERVICE}.jobs")
        assert not EXACT.accepts("downstream-toolkit")

    def test_a_family_accepts_its_name_and_its_compartments_and_nothing_that_merely_starts_so(
        self,
    ) -> None:
        # The separator is required: `downstream` must not accept `downstream-toolkit`.
        family = AudienceFamily("user")

        assert family.accepts("user")
        assert family.accepts("user.health")
        assert not family.accepts("user-api")
        assert not family.accepts("users")

    @pytest.mark.parametrize(
        ("audience", "compartment"),
        [("user.health", "health"), ("user", None), ("settings.search", None), ("userx", None)],
    )
    def test_a_family_names_the_compartment_an_audience_carries(
        self, audience: str, compartment: str | None
    ) -> None:
        assert AudienceFamily("user").compartment_of(audience) == compartment

    @pytest.mark.parametrize("name", ["", " settings", "settings ", "user.health"])
    def test_a_name_that_could_not_head_an_audience_is_refused_at_construction(
        self, name: str
    ) -> None:
        # A leading space pasted out of YAML matches no audience keyring mints, and would make
        # every request a 401 with nothing in the configuration looking wrong.
        with pytest.raises(ValueError, match="must be non-empty, trimmed"):
            ExactAudience(name)
        with pytest.raises(ValueError, match="must be non-empty, trimmed"):
            AudienceFamily(name)

    def test_both_policies_satisfy_the_protocol(self) -> None:
        assert isinstance(EXACT, AudiencePolicy)
        assert isinstance(AudienceFamily("user"), AudiencePolicy)


class TestAcceptance:
    async def test_the_identity_is_the_verified_subject_and_audience(
        self, verifier: TokenVerifier
    ) -> None:
        verified = await verifier.verify(good(account_id="account-zed"), audience=EXACT)

        assert verified.account_id == "account-zed"
        assert verified.audience == SERVICE

    async def test_a_family_token_carries_its_compartment_through(
        self, verifier: TokenVerifier
    ) -> None:
        verified = await verifier.verify(
            mint(audience="user.health"), audience=AudienceFamily("user")
        )

        assert verified.audience == "user.health"

    async def test_a_token_signed_by_a_replacement_key_verifies_after_a_rotation(
        self, verifier: TokenVerifier, keyring: FakeKeyring
    ) -> None:
        await verifier.verify(good(), audience=EXACT)

        keyring.rotate()
        verified = await verifier.verify(good(key=ROTATED_KEY), audience=EXACT)

        assert verified.account_id == "account-a"
        assert keyring.fetches == 2


class TestAudience:
    async def test_a_token_minted_for_another_service_is_refused(
        self, verifier: TokenVerifier
    ) -> None:
        # PyJWT checks the audience against the one the token claims, so it passes that check;
        # the policy, applied to the verified claim afterwards, is what refuses it.
        with pytest.raises(AuthenticationError):
            await verifier.verify(mint(audience="spotify"), audience=EXACT)

    async def test_an_audience_that_is_a_list_is_refused(self, verifier: TokenVerifier) -> None:
        listed = mint(claims={"aud": [SERVICE, "spotify"]})

        with pytest.raises(AuthenticationError):
            await verifier.verify(listed, audience=EXACT)


class TestIssuer:
    async def test_a_token_from_another_issuer_is_refused(self, verifier: TokenVerifier) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(good(issuer=OTHER_ISSUER), audience=EXACT)


class TestExpiry:
    async def test_a_token_is_accepted_until_the_second_before_it_expires(
        self, verifier: TokenVerifier, clock: FakeClock
    ) -> None:
        clock.advance(LIFETIME - 1)

        verified = await verifier.verify(good(), audience=EXACT)

        assert verified.account_id == "account-a"

    async def test_a_token_stops_working_at_the_very_second_it_expires(
        self, verifier: TokenVerifier, clock: FakeClock
    ) -> None:
        clock.advance(LIFETIME)

        with pytest.raises(AuthenticationError):
            await verifier.verify(good(), audience=EXACT)

    async def test_a_token_issued_ahead_of_the_wall_clock_is_judged_on_the_injected_one(
        self, jwks_client: JwksClient
    ) -> None:
        # Why verify_iat is off as well as verify_exp: PyJWT refuses a future iat by the wall
        # clock, which would refuse every good token in a test pinned to next decade.
        next_decade = EPOCH + timedelta(days=3_650)
        verifier = TokenVerifier(jwks=jwks_client, issuer=ISSUER, clock=FakeClock(next_decade))

        verified = await verifier.verify(good(issued_at=next_decade), audience=EXACT)

        assert verified.account_id == "account-a"

    @pytest.mark.parametrize("expiry", ["soon", True, None], ids=["a-string", "a-boolean", "null"])
    async def test_an_expiry_that_is_not_a_number_is_refused_rather_than_crashing(
        self, verifier: TokenVerifier, expiry: object
    ) -> None:
        # With PyJWT's own expiry check off, nothing else looks at the claim's type -- and a
        # string compared against a timestamp would be a 500 from an unauthenticated caller.
        with pytest.raises(AuthenticationError):
            await verifier.verify(good(claims={"exp": expiry}), audience=EXACT)


class TestAlgorithmConfusion:
    async def test_hs256_signed_with_the_published_public_key_is_refused(
        self, verifier: TokenVerifier
    ) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(forge_hs256(audience=SERVICE), audience=EXACT)

    async def test_a_token_claiming_no_algorithm_is_refused(self, verifier: TokenVerifier) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(forge_unsigned(audience=SERVICE), audience=EXACT)

    def test_the_forgeries_are_otherwise_perfect_tokens(self) -> None:
        # Nothing but the pinned algorithm stands between these and an identity.
        for forged in (forge_hs256(audience=SERVICE), forge_unsigned(audience=SERVICE)):
            unverified = jwt.decode(forged, options={"verify_signature": False})
            assert unverified["aud"] == SERVICE
            assert unverified["iss"] == ISSUER
            assert jwt.get_unverified_header(forged)["kid"] == thumbprint()


class TestTampering:
    async def test_an_edited_subject_is_refused(self, verifier: TokenVerifier) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(with_payload(good(), sub="account-b"), audience=EXACT)

    async def test_a_flipped_signature_is_refused(self, verifier: TokenVerifier) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(with_flipped_signature(good()), audience=EXACT)

    async def test_a_borrowed_signature_is_refused(self, verifier: TokenVerifier) -> None:
        borrowed = with_borrowed_signature(good(), good(account_id="account-b"))

        with pytest.raises(AuthenticationError):
            await verifier.verify(borrowed, audience=EXACT)

    async def test_a_swapped_header_algorithm_is_refused(self, verifier: TokenVerifier) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(with_header(good(), alg="HS256"), audience=EXACT)


class TestClaims:
    @pytest.mark.parametrize("claim", REQUIRED_CLAIMS)
    async def test_a_token_that_omits_a_required_claim_is_refused(
        self, verifier: TokenVerifier, claim: str
    ) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(good(omit=claim), audience=EXACT)

    async def test_an_empty_subject_is_refused(self, verifier: TokenVerifier) -> None:
        # Present, so PyJWT's `require` passes it -- and an empty account id is every row that
        # was ever written without one.
        with pytest.raises(AuthenticationError):
            await verifier.verify(good(account_id=""), audience=EXACT)


class TestKeyIds:
    async def test_a_token_with_no_key_id_is_refused_before_anything_is_fetched(
        self, verifier: TokenVerifier, keyring: FakeKeyring
    ) -> None:
        unkeyed = jwt.encode(claims(), private_pem(), algorithm="RS256")

        with pytest.raises(AuthenticationError):
            await verifier.verify(unkeyed, audience=EXACT)

        assert keyring.fetches == 0

    @pytest.mark.parametrize("kid", [7, ""], ids=["not-a-string", "empty"])
    async def test_a_key_id_that_cannot_name_a_key_is_refused(
        self, verifier: TokenVerifier, kid: object
    ) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(hand_signed(claims(), kid=kid), audience=EXACT)

    async def test_a_key_id_nobody_published_is_refused(self, verifier: TokenVerifier) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(good(kid="a-key-id-nobody-published"), audience=EXACT)


class TestMalformed:
    @pytest.mark.parametrize("token", ["", "not-a-token", "a.b", "a.b.c.d", "..."])
    async def test_something_that_is_not_a_token_is_refused_rather_than_crashing(
        self, verifier: TokenVerifier, token: str
    ) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(token, audience=EXACT)

    async def test_a_readable_header_over_an_unreadable_payload_is_refused(
        self, verifier: TokenVerifier
    ) -> None:
        with pytest.raises(AuthenticationError):
            await verifier.verify(with_raw_payload(good(), b"this is not json"), audience=EXACT)


class TestKeyringDown:
    async def test_keyring_being_unreachable_is_not_turned_into_a_refusal(
        self, verifier: TokenVerifier, keyring: FakeKeyring
    ) -> None:
        # Telling somebody to log in again because keyring blipped is advice that does not help.
        keyring.error = RuntimeError("never reached")
        keyring.status = 503

        keyring.error = None
        with pytest.raises(KeyringUnreachableError):
            await verifier.verify(good(), audience=EXACT)


class TestLogging:
    async def test_the_reason_is_logged_and_the_token_is_not(
        self, jwks_client: JwksClient, clock: FakeClock, recorder: RecordingLogger
    ) -> None:
        verifier = TokenVerifier(jwks=jwks_client, issuer=ISSUER, clock=clock, logger=recorder)
        token = good(issuer=OTHER_ISSUER)

        with pytest.raises(AuthenticationError):
            await verifier.verify(token, audience=EXACT)

        [(_, event, fields)] = [
            record for record in recorder.records if record[1] == "token_rejected"
        ]
        assert event == "token_rejected"
        assert fields["reason"] == "decode"
        assert token not in recorder.rendered()


class TestOneRefusalForEverything:
    async def test_every_way_a_token_can_be_refused_says_exactly_the_same_thing(
        self, verifier: TokenVerifier, clock: FakeClock
    ) -> None:
        refusals = {
            "another service's audience": mint(audience="spotify"),
            "another issuer": good(issuer=OTHER_ISSUER),
            "hs256 with the public key": forge_hs256(audience=SERVICE),
            "no algorithm": forge_unsigned(audience=SERVICE),
            "an edited payload": with_payload(good(), sub="account-b"),
            "a flipped signature": with_flipped_signature(good()),
            "a swapped header": with_header(good(), alg="HS256"),
            "no key id": jwt.encode(claims(), private_pem(), algorithm="RS256"),
            "a key id that is not a string": hand_signed(claims(), kid=7),
            "a key id nobody published": good(kid="nobody"),
            "an audience that is a list": mint(claims={"aud": [SERVICE]}),
            "a string expiry": good(claims={"exp": "soon"}),
            "an empty subject": good(account_id=""),
            "a payload that is not json": with_raw_payload(good(), b"nope"),
            "not a token": "not-a-token",
            **{f"no {claim}": good(omit=claim) for claim in REQUIRED_CLAIMS},
        }

        messages: set[str] = set()
        for token in refusals.values():
            with pytest.raises(AuthenticationError) as refusal:
                await verifier.verify(token, audience=EXACT)
            messages.add(str(refusal.value))

        clock.advance(LIFETIME)
        with pytest.raises(AuthenticationError) as expired:
            await verifier.verify(good(), audience=EXACT)
        messages.add(str(expired.value))

        assert messages == {BAD_TOKEN}
