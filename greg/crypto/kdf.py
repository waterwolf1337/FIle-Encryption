from __future__ import annotations

from argon2.low_level import Type, hash_secret_raw

from .constants import KEY_LENGTH, Argon2Parameters


def derive_key(
    password: str | bytes,
    salt: bytes,
    parameters: Argon2Parameters,
) -> bytearray:
    """Derive an AES-256 key with Argon2id; callers must wipe the result."""
    parameters.validate()
    password_bytes = password.encode("utf-8") if isinstance(password, str) else password
    if not password_bytes:
        raise ValueError("password must not be empty")
    return bytearray(
        hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=parameters.time_cost,
            memory_cost=parameters.memory_cost_kib,
            parallelism=parameters.parallelism,
            hash_len=KEY_LENGTH,
            type=Type.ID,
            version=19,
        )
    )


def wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0

