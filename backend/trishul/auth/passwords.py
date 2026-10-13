# SPDX-License-Identifier: Apache-2.0
"""argon2id password hashing. Passwords are never logged, echoed or stored."""

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256  # bounds the work an unauthenticated caller can request

_HASHER = PasswordHasher(type=Type.ID)
_DUMMY: list[str] = []


def hash_password(password: str) -> str:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    return _HASHER.hash(password)


def verify_password(pw_hash: str, password: str) -> bool:
    """False on any mismatch or malformed hash (fail closed)."""
    try:
        return bool(_HASHER.verify(pw_hash, password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def burn_verify(password: str) -> None:
    """Spend one argon2 verification so an unknown user costs the same as a wrong password."""
    if not _DUMMY:
        _DUMMY.append(_HASHER.hash("not-a-real-password"))
    verify_password(_DUMMY[0], password)
