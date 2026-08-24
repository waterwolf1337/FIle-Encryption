from __future__ import annotations

import struct

import pytest

from greg.format.greg_file import (
    AuthenticationError,
    GregFormatError,
    UnsupportedVersionError,
    encrypt_new,
    inspect_header,
    unlock,
    _parse_container,
)
from greg.format.payload import GregPayload


def test_crypto_round_trip_and_original_metadata(fast_parameters):
    original = GregPayload("test.xlsx", b"xlsx-bytes", {"purpose": "test"})
    container = encrypt_new(original, "correct horse", fast_parameters)

    assert container[:4] == b"GREG"
    assert b"test.xlsx" not in container
    with unlock(container, "correct horse") as opened:
        assert opened.payload == original


def test_wrong_password_fails_authentication(fast_parameters):
    container = encrypt_new(GregPayload("notes.txt", b"secret"), "right", fast_parameters)

    with pytest.raises(AuthenticationError):
        unlock(container, "wrong")


def test_corrupted_ciphertext_fails_authentication(fast_parameters):
    container = bytearray(
        encrypt_new(GregPayload("notes.txt", b"secret"), "right", fast_parameters)
    )
    container[-1] ^= 0x01

    with pytest.raises(AuthenticationError):
        unlock(bytes(container), "right")


def test_two_encryptions_of_same_content_differ(fast_parameters):
    payload = GregPayload("same.pdf", b"identical")

    first = encrypt_new(payload, "password", fast_parameters)
    second = encrypt_new(payload, "password", fast_parameters)

    assert first != second
    assert _parse_container(first)[2] != _parse_container(second)[2]
    assert _parse_container(first)[3] != _parse_container(second)[3]


def test_save_reuses_salt_but_always_changes_nonce(fast_parameters):
    original = encrypt_new(GregPayload("a.bin", b"one"), "password", fast_parameters)
    with unlock(original, "password") as opened:
        first_save = opened.encrypt(GregPayload("a.bin", b"two"))
        second_save = opened.encrypt(GregPayload("a.bin", b"two"))

    assert first_save != second_save


def test_inspect_header_rejects_unsupported_version(fast_parameters):
    container = bytearray(
        encrypt_new(GregPayload("a.bin", b"data"), "password", fast_parameters)
    )
    container[4] = 99

    with pytest.raises(UnsupportedVersionError, match="version: 99"):
        inspect_header(bytes(container))


def test_trailing_or_truncated_bytes_are_rejected(fast_parameters):
    container = encrypt_new(GregPayload("a.bin", b"data"), "password", fast_parameters)

    with pytest.raises(GregFormatError):
        inspect_header(container + b"extra")
    with pytest.raises(GregFormatError):
        inspect_header(container[:-1])


def test_authenticated_header_cannot_be_modified(fast_parameters):
    container = bytearray(
        encrypt_new(GregPayload("a.bin", b"data"), "password", fast_parameters)
    )
    # time_cost is the first uint32 after the 8-byte identifier prefix.
    struct.pack_into(">I", container, 8, 2)

    with pytest.raises(AuthenticationError):
        unlock(bytes(container), "password")


@pytest.mark.parametrize("filename", ["", "..", "../escape.txt", "a/b", "a\\b"])
def test_unsafe_original_filename_is_rejected(filename, fast_parameters):
    with pytest.raises(ValueError, match="unsafe"):
        encrypt_new(GregPayload(filename, b"data"), "password", fast_parameters)
