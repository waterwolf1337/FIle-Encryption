from __future__ import annotations

from dataclasses import dataclass

MAGIC = b"GREG"
FORMAT_VERSION = 1
KDF_ARGON2ID = 1
CIPHER_AES_256_GCM = 1
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12


@dataclass(frozen=True, slots=True)
class Argon2Parameters:
    """Argon2id cost parameters stored in every public Greg header."""

    time_cost: int = 3
    memory_cost_kib: int = 65_536
    parallelism: int = 4

    def validate(self) -> None:
        # Upper bounds prevent a malicious header from forcing unreasonable work.
        if not 1 <= self.time_cost <= 20:
            raise ValueError("unsupported Argon2 time cost")
        if not 8 * self.parallelism <= self.memory_cost_kib <= 4_194_304:
            raise ValueError("unsupported Argon2 memory cost")
        if not 1 <= self.parallelism <= 64:
            raise ValueError("unsupported Argon2 parallelism")

