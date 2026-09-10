"""Password hashing.

Argon2id, via argon2-cffi. The library is doing the cryptography; what is tested here is
that this service asks it for the right thing, and that the dummy-verify path -- the one
that keeps a login against an unknown account as slow as one against a real account --
actually exists and is exercised.
"""

from __future__ import annotations

import pytest
from argon2.exceptions import HashingError

from keyring_api.accounts.hashing import Argon2PasswordHasher, PasswordHasher
from keyring_api.core.config import Argon2Settings

CHEAP = Argon2Settings(time_cost=1, memory_cost_kib=8, parallelism=1)
"""Test-only cost. The production defaults take ~50ms per call by design."""


@pytest.fixture
def hasher() -> Argon2PasswordHasher:
    return Argon2PasswordHasher(CHEAP)


class TestPort:
    def test_the_adapter_satisfies_the_port(self, hasher: Argon2PasswordHasher) -> None:
        checked: PasswordHasher = hasher

        assert isinstance(checked, PasswordHasher)


class TestHashing:
    def test_a_password_verifies_against_its_own_hash(self, hasher: Argon2PasswordHasher) -> None:
        stored = hasher.hash("correct horse battery staple")

        assert hasher.verify(stored, "correct horse battery staple")

    def test_a_wrong_password_does_not_verify(self, hasher: Argon2PasswordHasher) -> None:
        stored = hasher.hash("correct horse battery staple")

        assert not hasher.verify(stored, "Correct horse battery staple")

    def test_the_same_password_hashes_differently_every_time(
        self, hasher: Argon2PasswordHasher
    ) -> None:
        # A per-hash salt is what stops one cracked password revealing every account
        # that shares it, and what stops a rainbow table being useful at all.
        assert hasher.hash("same") != hasher.hash("same")

    def test_the_hash_identifies_itself_as_argon2id(self, hasher: Argon2PasswordHasher) -> None:
        # argon2i and argon2d each give up one of the two resistances; id is the variant
        # RFC 9106 recommends when you do not have a specific reason to choose otherwise.
        assert hasher.hash("password").startswith("$argon2id$")

    def test_the_configured_cost_reaches_the_hash(self) -> None:
        # Otherwise raising the cost in a deployment silently changes nothing.
        stored = Argon2PasswordHasher(
            Argon2Settings(time_cost=2, memory_cost_kib=16, parallelism=1)
        ).hash("x")

        assert "t=2" in stored
        assert "m=16" in stored

    def test_a_unicode_password_round_trips(self, hasher: Argon2PasswordHasher) -> None:
        assert hasher.verify(hasher.hash("пароль🔐"), "пароль🔐")

    def test_stored_material_that_is_not_a_hash_fails_rather_than_raises(
        self, hasher: Argon2PasswordHasher
    ) -> None:
        # A corrupt row must be a failed login, not a 500 on an unauthenticated
        # endpoint -- and certainly not an exception whose text names the stored value.
        assert not hasher.verify("not a hash", "password")

    def test_an_empty_stored_hash_fails_rather_than_raises(
        self, hasher: Argon2PasswordHasher
    ) -> None:
        assert not hasher.verify("", "password")


class TestRehashing:
    def test_a_hash_at_the_current_cost_does_not_need_rehashing(
        self, hasher: Argon2PasswordHasher
    ) -> None:
        assert not hasher.needs_rehash(hasher.hash("password"))

    def test_a_hash_at_a_lower_cost_is_flagged_for_upgrade(self) -> None:
        # Costs get raised over the life of a deployment. Without this, everyone who
        # never changes their password stays on the parameters they signed up under.
        old = Argon2PasswordHasher(
            Argon2Settings(time_cost=1, memory_cost_kib=8, parallelism=1)
        ).hash("password")

        assert Argon2PasswordHasher(
            Argon2Settings(time_cost=4, memory_cost_kib=64, parallelism=1)
        ).needs_rehash(old)

    def test_unreadable_material_is_not_reported_as_needing_a_rehash(
        self, hasher: Argon2PasswordHasher
    ) -> None:
        # Rehashing requires the plaintext, which is only available during a successful
        # login -- and a hash that cannot be parsed will never produce one. Saying "yes"
        # here would send the caller down a path that cannot work.
        assert not hasher.needs_rehash("not a hash")


class TestDummyVerification:
    def test_it_returns_false_so_it_can_never_be_mistaken_for_a_success(
        self, hasher: Argon2PasswordHasher
    ) -> None:
        # It is called on the path where there is no account. If a refactor ever made a
        # caller use its return value, the answer has to be "no".
        assert not hasher.verify_dummy("anything")

    def test_it_does_the_same_work_as_a_real_verification(
        self, hasher: Argon2PasswordHasher
    ) -> None:
        # The point is the cost, not the answer: a login against an unknown address must
        # take as long as one against a real one, or the response time is an oracle for
        # which addresses have accounts.
        assert hasher.dummy_hash.startswith("$argon2id$")

    def test_the_dummy_hash_uses_the_configured_cost(self) -> None:
        # A cheap dummy against an expensive real hash would restore the timing
        # difference it exists to remove.
        assert "t=2" in Argon2PasswordHasher(Argon2Settings(time_cost=2)).dummy_hash

    def test_a_hashing_failure_surfaces_rather_than_being_swallowed(
        self, monkeypatch: pytest.MonkeyPatch, hasher: Argon2PasswordHasher
    ) -> None:
        # verify() converts *verification* failures into False. A failure to *produce* a
        # hash is different: it means the service cannot store the password it just
        # accepted, and pretending otherwise would lose it silently.
        def explode(_self: object, _password: str) -> str:
            raise HashingError

        monkeypatch.setattr(type(hasher._hasher), "hash", explode)

        with pytest.raises(HashingError):
            hasher.hash("password")
