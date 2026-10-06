"""Password hashing (Argon2id) and password policy."""

from __future__ import annotations

import asyncio

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from perseus_common.errors import UnprocessableError

MIN_LENGTH = 12
MAX_LENGTH = 128  # bounds hashing cost; prevents long-password DoS

# OWASP-recommended Argon2id parameters (64 MiB, 3 iterations).
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

# Pre-computed hash used to equalise timing when the user does not exist.
DUMMY_HASH = _hasher.hash("perseus-timing-equaliser-not-a-real-password")

_COMMON_PASSWORDS = frozenset(
    {
        "password1234",
        "password12345",
        "password123!",
        "123456789012",
        "qwertyuiop12",
        "iloveyou1234",
        "letmein12345",
        "welcome12345",
        "administrator",
        "passw0rd1234",
        "changeme1234",
        "qwerty123456",
        "1q2w3e4r5t6y",
        "abc123456789",
        "trustno1trustno1",
        "football1234",
        "baseball1234",
        "superman1234",
        "monkey123456",
        "sunshine1234",
    }
)


async def hash_password(password: str) -> str:
    # Argon2 is deliberately expensive; keep it off the event loop.
    return await asyncio.to_thread(_hasher.hash, password)


async def verify_password(password_hash: str, password: str) -> tuple[bool, bool]:
    """Return ``(matches, needs_rehash)``."""

    def _verify() -> tuple[bool, bool]:
        try:
            _hasher.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False, False
        return True, _hasher.check_needs_rehash(password_hash)

    return await asyncio.to_thread(_verify)


def validate_password_strength(password: str, email: str) -> None:
    if len(password) < MIN_LENGTH:
        raise UnprocessableError(
            f"Password must be at least {MIN_LENGTH} characters.", code="weak_password"
        )
    if len(password) > MAX_LENGTH:
        raise UnprocessableError(
            f"Password must be at most {MAX_LENGTH} characters.", code="weak_password"
        )
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS:
        raise UnprocessableError("Password is too common.", code="weak_password")
    if len(set(password)) < 6:
        raise UnprocessableError("Password is not complex enough.", code="weak_password")
    local_part = email.split("@", 1)[0].lower()
    if len(local_part) >= 4 and local_part in lowered:
        raise UnprocessableError("Password must not contain your email.", code="weak_password")
