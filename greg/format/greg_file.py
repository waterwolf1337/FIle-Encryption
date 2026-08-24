from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from greg.crypto.constants import NONCE_LENGTH, SALT_LENGTH, Argon2Parameters
from greg.crypto.kdf import derive_key, wipe

from .header import HEADER_STRUCT, GregHeader
from .payload import GregPayload


class GregFormatError(ValueError):
    """The input is not a valid supported Greg container."""


class UnsupportedVersionError(GregFormatError):
    """The container uses a version this application cannot read."""


class AuthenticationError(GregFormatError):
    """The password is wrong or authenticated file data was altered."""


@dataclass(slots=True)
class UnlockedGreg:
    payload: GregPayload
    parameters: Argon2Parameters
    salt: bytes
    _key: bytearray
    _closed: bool = False

    def encrypt(self, payload: GregPayload | None = None) -> bytes:
        if self._closed:
            raise RuntimeError("unlocked Greg key has already been cleared")
        return _encrypt_with_key(
            payload or self.payload, self._key, self.salt, self.parameters
        )

    def close(self) -> None:
        if not self._closed:
            wipe(self._key)
            self._closed = True

    def __enter__(self) -> "UnlockedGreg":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def encrypt_new(
    payload: GregPayload,
    password: str | bytes,
    parameters: Argon2Parameters = Argon2Parameters(),
) -> bytes:
    salt = os.urandom(SALT_LENGTH)
    key = derive_key(password, salt, parameters)
    try:
        return _encrypt_with_key(payload, key, salt, parameters)
    finally:
        wipe(key)


def unlock(container: bytes, password: str | bytes) -> UnlockedGreg:
    header, header_bytes, salt, nonce, ciphertext = _parse_container(container)
    key = derive_key(password, salt, header.parameters)
    try:
        plaintext = AESGCM(bytes(key)).decrypt(
            nonce, ciphertext, header_bytes + salt + nonce
        )
        payload = GregPayload.deserialize(plaintext)
    except InvalidTag as error:
        wipe(key)
        raise AuthenticationError(
            "wrong password or corrupted Greg file"
        ) from error
    except Exception:
        wipe(key)
        raise
    return UnlockedGreg(payload, header.parameters, salt, key)


def inspect_header(container: bytes) -> GregHeader:
    return _parse_container(container)[0]


def _encrypt_with_key(
    payload: GregPayload,
    key: bytes | bytearray,
    salt: bytes,
    parameters: Argon2Parameters,
) -> bytes:
    nonce = os.urandom(NONCE_LENGTH)
    plaintext = payload.serialize()
    # AES-GCM appends a 16-byte authentication tag.
    header = GregHeader(parameters, len(salt), len(nonce), len(plaintext) + 16)
    header_bytes = header.pack()
    ciphertext = AESGCM(bytes(key)).encrypt(
        nonce, plaintext, header_bytes + salt + nonce
    )
    return header_bytes + salt + nonce + ciphertext


def _parse_container(
    container: bytes,
) -> tuple[GregHeader, bytes, bytes, bytes, bytes]:
    if len(container) < HEADER_STRUCT.size:
        raise GregFormatError("truncated Greg file")
    header_bytes = container[: HEADER_STRUCT.size]
    try:
        header = GregHeader.unpack(header_bytes)
    except RuntimeError as error:
        raise UnsupportedVersionError(str(error)) from error
    except ValueError as error:
        raise GregFormatError(str(error)) from error
    salt_start = HEADER_STRUCT.size
    nonce_start = salt_start + header.salt_length
    ciphertext_start = nonce_start + header.nonce_length
    expected_size = ciphertext_start + header.ciphertext_length
    if len(container) != expected_size:
        raise GregFormatError("Greg file length does not match its header")
    return (
        header,
        header_bytes,
        container[salt_start:nonce_start],
        container[nonce_start:ciphertext_start],
        container[ciphertext_start:],
    )

