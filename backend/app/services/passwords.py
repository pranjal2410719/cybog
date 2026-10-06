"""
Password hashing for Cybog backend authentication (T1: UID + password).

Uses Argon2id via ``argon2-cffi`` (already installed; declared in
``pyproject.toml``). Hashes are stored in ``DBUser.password_hash`` and
never logged, returned, or embedded in tokens.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a plaintext password with Argon2id. Raises on empty input."""
    if not password:
        raise ValueError("password must not be empty")
    return _ph.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """
    Return True iff ``password`` matches ``password_hash``.

    ``None`` (or malformed) stored hashes never verify — users without a
    password set cannot log in.
    """
    if not password or not password_hash:
        return False
    try:
        return _ph.verify(password_hash, password)
    except (InvalidHash, VerifyMismatchError):
        return False
