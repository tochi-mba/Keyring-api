"""Password hashing.

Argon2id via argon2-cffi. None of the cryptography is written here -- the one decision
this module makes is to hand the library the parameters from configuration, and to
expose the two operations the login path needs that a naive wrapper leaves out:
detecting a hash produced under older parameters, and burning the same CPU on a login
against an address that has no account.

That second one is the reason this is a class rather than two functions. The dummy hash
has to be built with the *same* cost as a real one, and computing it once at
construction keeps it that way without a comment asking the next person to remember.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from argon2 import PasswordHasher as Argon2Hasher
from argon2.exceptions import Argon2Error, InvalidHashError

if TYPE_CHECKING:
    from keyring_api.core.config import Argon2Settings

DUMMY_PASSWORD = "keyring-dummy-password-for-constant-time-login"  # noqa: S105
"""Hashed at startup so a login against an unknown address has something to verify.

Not a secret and never accepted as one: :meth:`verify_dummy` returns ``False``
unconditionally, whatever it is given.
"""


@runtime_checkable
class PasswordHasher(Protocol):
    """Turns a password into stored material, and checks one against it."""

    def hash(self, password: str) -> str:
        """Return the stored form of ``password``."""
        ...

    def verify(self, stored_hash: str, password: str) -> bool:
        """Whether ``password`` produced ``stored_hash``. Never raises on bad input."""
        ...

    def verify_dummy(self, password: str) -> bool:
        """Do a verification's worth of work and return ``False``."""
        ...

    def needs_rehash(self, stored_hash: str) -> bool:
        """Whether ``stored_hash`` was produced under weaker parameters than are configured."""
        ...


class Argon2PasswordHasher:
    """The real hasher."""

    def __init__(self, settings: Argon2Settings) -> None:
        self._hasher = Argon2Hasher(
            time_cost=settings.time_cost,
            memory_cost=settings.memory_cost_kib,
            parallelism=settings.parallelism,
            hash_len=settings.hash_length,
            salt_len=settings.salt_length,
        )
        self.dummy_hash = self._hasher.hash(DUMMY_PASSWORD)
        """Built with the configured cost, so the dummy path is as slow as the real one."""

    def hash(self, password: str) -> str:
        """Return the stored form of ``password``.

        Failures here propagate. A verification failure means "wrong password"; a
        *hashing* failure means the service cannot store the password it has just
        accepted, and swallowing that would lose it silently.
        """
        return self._hasher.hash(password)

    def verify(self, stored_hash: str, password: str) -> bool:
        """Whether ``password`` produced ``stored_hash``.

        Every failure -- wrong password, malformed hash, empty stored value -- is
        ``False``. A corrupt row must be a failed login, not a 500 on an
        unauthenticated endpoint, and not an exception whose text names stored material.
        """
        try:
            return self._hasher.verify(stored_hash, password)
        except (Argon2Error, InvalidHashError):
            # Two bases, not one: argon2-cffi raises VerifyMismatchError (an
            # Argon2Error) for a wrong password and InvalidHashError (a ValueError) for
            # material it cannot parse. Catching only the first turns a corrupt row into
            # a 500 on the login endpoint.
            return False

    def verify_dummy(self, password: str) -> bool:
        """Spend a verification's worth of CPU and report failure.

        Called on the path where the address has no account. Without it, a login against
        an unknown address returns as fast as the lookup, and the response time tells an
        attacker which addresses are real -- the enumeration oracle that the identical
        error message was supposed to close.
        """
        self.verify(self.dummy_hash, password)
        return False

    def needs_rehash(self, stored_hash: str) -> bool:
        """Whether this hash predates the current cost settings.

        ``False`` for material that cannot be parsed: rehashing needs the plaintext,
        which only exists during a successful login, and an unparseable hash will never
        produce one.
        """
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return False
