"""TOTP code generation, checked against RFC 6238's published vectors."""

from __future__ import annotations

import pytest

from keyring_api.credentials.totp import totp_code

RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
"""RFC 6238's SHA-1 test key ("12345678901234567890") in base32."""


@pytest.mark.parametrize(
    ("unix_time", "expected"),
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
    ],
)
def test_it_matches_the_published_test_vectors(unix_time: int, expected: str) -> None:
    # From RFC 6238 appendix B. Checking against the specification rather than against
    # our own output is the only way to know this is a TOTP implementation rather than a
    # deterministic number generator that happens to be self-consistent.
    assert totp_code(RFC_SEED, unix_time=unix_time) == expected


def test_the_code_changes_when_the_period_rolls_over() -> None:
    assert totp_code(RFC_SEED, unix_time=29) != totp_code(RFC_SEED, unix_time=30)


def test_the_code_is_stable_within_one_period() -> None:
    assert totp_code(RFC_SEED, unix_time=30) == totp_code(RFC_SEED, unix_time=59)


def test_a_seed_written_out_with_spaces_still_works() -> None:
    # Which is how every authenticator app displays it, and therefore how people paste
    # it. Rejecting it would be technically correct and useless.
    spaced = " ".join(RFC_SEED[index : index + 4] for index in range(0, len(RFC_SEED), 4))

    assert totp_code(spaced, unix_time=59) == "287082"


def test_a_lowercase_seed_still_works() -> None:
    assert totp_code(RFC_SEED.lower(), unix_time=59) == "287082"


def test_an_unpadded_seed_still_works() -> None:
    # Authenticator UIs routinely omit the base32 padding.
    assert totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".rstrip("="), unix_time=59) == "287082"


def test_a_seed_that_is_not_base32_is_refused() -> None:
    with pytest.raises(ValueError, match="base32"):
        totp_code("not!base32", unix_time=59)


def test_the_code_is_zero_padded_to_the_full_width() -> None:
    # A truncated code is silently rejected by the site, which looks like a wrong
    # password rather than like a bug here.
    assert len(totp_code(RFC_SEED, unix_time=1234567890)) == 6
