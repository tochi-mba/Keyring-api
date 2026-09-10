"""Token generation and comparison.

Everything a caller ever presents to this service -- a session token, an invite, a reset
link, an OAuth state -- comes from here. The properties are entropy, that the token is
never stored, and that comparing one takes the same time whatever the answer is.
"""

from __future__ import annotations

import hashlib

from hypothesis import given, settings
from hypothesis import strategies as st

from keyring_api.accounts.tokens import (
    MIN_TOKEN_ENTROPY_BYTES,
    hash_token,
    new_token,
    tokens_match,
)


class TestGeneration:
    def test_two_tokens_are_never_the_same(self) -> None:
        assert new_token() != new_token()

    def test_a_token_carries_at_least_the_declared_entropy(self) -> None:
        # url-safe base64 packs 6 bits per character. Asserting on the encoded length
        # rather than the parameter means a change to the encoding cannot silently
        # weaken every token in the service.
        assert len(new_token()) >= MIN_TOKEN_ENTROPY_BYTES * 8 / 6

    def test_a_token_is_url_safe_because_it_travels_in_a_reset_link(self) -> None:
        assert all(character.isalnum() or character in "-_" for character in new_token())

    @settings(max_examples=200)
    @given(st.integers(min_value=1, max_value=200))
    def test_generated_tokens_do_not_collide(self, count: int) -> None:
        assert len({new_token() for _ in range(count)}) == count


class TestHashing:
    def test_a_token_hash_is_deterministic_so_a_presented_token_can_be_found(self) -> None:
        token = new_token()

        assert hash_token(token) == hash_token(token)

    def test_different_tokens_hash_differently(self) -> None:
        assert hash_token("a") != hash_token("b")

    def test_the_hash_is_sha256_rather_than_a_password_hash(self) -> None:
        # Deliberate. A token is 256 bits of uniform randomness, so there is no
        # dictionary to attack and a slow hash buys nothing -- while costing a
        # deliberately expensive computation on every single authenticated request.
        # Passwords are the opposite case and use Argon2.
        assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest()

    def test_hashing_accepts_any_unicode_a_caller_might_send(self) -> None:
        # A token this service issued is ASCII, but a token a caller *presents* is
        # whatever they typed, and it must not raise before it can be rejected.
        assert hash_token("🔐")


class TestComparison:
    def test_a_token_matches_its_own_hash(self) -> None:
        token = new_token()

        assert tokens_match(token, hash_token(token))

    def test_a_wrong_token_does_not_match(self) -> None:
        assert not tokens_match(new_token(), hash_token(new_token()))

    def test_comparison_survives_a_hash_of_the_wrong_shape(self) -> None:
        # Stored data can be corrupt or truncated; that must be a failed match, not a
        # crash on an unauthenticated endpoint.
        assert not tokens_match("anything", "")
