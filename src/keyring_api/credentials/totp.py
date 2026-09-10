"""Time-based one-time passwords (RFC 6238).

Implemented rather than pulled in, because it is fifteen lines of HMAC that the standard
library already provides -- and because the alternative was another dependency in the
process that holds the credentials, which is the process where a dependency is worth the
most to an attacker.

A TOTP seed is stored only when the person opts in. Keeping it beside the password
collapses their second factor into the same place as their first: whoever reads one
reads both, and the second factor stops being a second anything. The API flags it
distinctly for that reason.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct

DEFAULT_DIGITS = 6
DEFAULT_PERIOD_SECONDS = 30


def totp_code(
    seed: str,
    *,
    unix_time: float,
    digits: int = DEFAULT_DIGITS,
    period_seconds: int = DEFAULT_PERIOD_SECONDS,
) -> str:
    """Return the code valid at ``unix_time``.

    Args:
        seed: the shared secret, base32 as every authenticator app presents it. Spaces
            and case are tolerated because that is how people copy them out of a UI.

    Raises:
        ValueError: if the seed is not decodable base32.
    """
    key = _decode_seed(seed)
    counter = int(unix_time // period_seconds)

    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()

    # Dynamic truncation, RFC 4226 section 5.4: the low nibble of the last byte selects
    # which four bytes of the digest become the code.
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFF_FFFF

    return str(truncated % 10**digits).zfill(digits)


def _decode_seed(seed: str) -> bytes:
    """Decode a base32 seed as it is actually written down."""
    cleaned = seed.replace(" ", "").replace("-", "").upper()
    # Base32 wants a multiple of 8 characters; authenticator UIs routinely omit the
    # padding, so it is restored rather than treated as an error.
    padded = cleaned + "=" * (-len(cleaned) % 8)

    try:
        return base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError) as exc:
        msg = "TOTP seed is not valid base32"
        raise ValueError(msg) from exc
