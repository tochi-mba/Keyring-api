"""File modes, asserted as exactly as the platform running the suite can express them."""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def assert_mode(path: Path, expected: int) -> None:
    """Assert that ``path`` has the permission bits ``expected``.

    On POSIX, which is where CI runs, this is exact: ``stat.S_IMODE`` of the file against
    ``expected``, so a file that should be 0600 and is 0640 fails.

    On Windows it is weaker, on purpose, and compares the owner's bits alone. NTFS has no
    POSIX permission bits. ``os.chmod`` there can only set or clear the read-only flag,
    which it takes from the owner-write bit, and ``os.stat`` reports the owner's bits
    copied to group and other -- so a file asked to be 0600 reads back 0666, and a
    directory reads 0777, whatever the code under test did. Who may open a file on Windows
    is decided by its ACL, which it inherits from the directory it is created in; the
    suite's temporary directories are under the user's profile by default, and that is
    private to the user already. Nothing under test sets an ACL, so nothing here asserts
    one. What is left to compare is what Windows does record: the owner's access, which
    still tells a file left writable from one made read-only.

    The code under test runs the same on both. Only the reading of its result differs.
    """
    actual = stat.S_IMODE(path.stat().st_mode)
    # Explicit messages, because pytest rewrites asserts in test modules and not here.
    if os.name == "posix":
        assert actual == expected, f"{path} is mode {actual:04o}, expected {expected:04o}"
    else:
        owner, expected_owner = actual & stat.S_IRWXU, expected & stat.S_IRWXU
        assert owner == expected_owner, (
            f"{path} has owner bits {owner:04o}, expected {expected_owner:04o}"
        )
