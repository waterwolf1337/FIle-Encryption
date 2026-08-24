from __future__ import annotations

import struct
from dataclasses import dataclass

from greg.crypto.constants import (
    CIPHER_AES_256_GCM,
    FORMAT_VERSION,
    KDF_ARGON2ID,
    MAGIC,
    NONCE_LENGTH,
    SALT_LENGTH,
    Argon2Parameters,
)

HEADER_STRUCT = struct.Struct(">4sBBBBIIIHHQ")
MAX_CIPHERTEXT_LENGTH = 1 << 40  # Defensive parser limit: 1 TiB.


@dataclass(frozen=True, slots=True)
class GregHeader:
    parameters: Argon2Parameters
    salt_length: int
    nonce_length: int
    ciphertext_length: int
    version: int = FORMAT_VERSION
    kdf_id: int = KDF_ARGON2ID
    cipher_id: int = CIPHER_AES_256_GCM

    def pack(self) -> bytes:
        return HEADER_STRUCT.pack(
            MAGIC,
            self.version,
            self.kdf_id,
            self.cipher_id,
            0,
            self.parameters.time_cost,
            self.parameters.memory_cost_kib,
            self.parameters.parallelism,
            self.salt_length,
            self.nonce_length,
            self.ciphertext_length,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "GregHeader":
        if len(data) != HEADER_STRUCT.size:
            raise ValueError("truncated Greg header")
        (
            magic,
            version,
            kdf_id,
            cipher_id,
            flags,
            time_cost,
            memory_cost,
            parallelism,
            salt_length,
            nonce_length,
            ciphertext_length,
        ) = HEADER_STRUCT.unpack(data)
        if magic != MAGIC:
            raise ValueError("not a Greg encrypted file")
        if version != FORMAT_VERSION:
            raise RuntimeError(f"unsupported Greg format version: {version}")
        if kdf_id != KDF_ARGON2ID or cipher_id != CIPHER_AES_256_GCM or flags != 0:
            raise ValueError("unsupported Greg cryptographic algorithms or flags")
        parameters = Argon2Parameters(time_cost, memory_cost, parallelism)
        parameters.validate()
        if salt_length != SALT_LENGTH or nonce_length != NONCE_LENGTH:
            raise ValueError("unsupported salt or nonce length")
        if not 16 <= ciphertext_length <= MAX_CIPHERTEXT_LENGTH:
            raise ValueError("invalid ciphertext length")
        return cls(
            parameters=parameters,
            salt_length=salt_length,
            nonce_length=nonce_length,
            ciphertext_length=ciphertext_length,
            version=version,
            kdf_id=kdf_id,
            cipher_id=cipher_id,
        )

