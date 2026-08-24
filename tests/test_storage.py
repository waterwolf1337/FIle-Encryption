from __future__ import annotations

import os

import pytest

from greg.storage import atomic_write


def test_atomic_write_replaces_file_and_restricts_permissions(tmp_path):
    destination = tmp_path / "document.greg"
    atomic_write(destination, b"ciphertext")

    assert destination.read_bytes() == b"ciphertext"
    assert destination.stat().st_mode & 0o777 == 0o600


def test_atomic_write_failure_preserves_previous_file(tmp_path):
    destination = tmp_path / "document.greg"
    destination.write_bytes(b"valid old container")

    def fail(_temporary):
        raise OSError("simulated staging failure")

    with pytest.raises(OSError, match="simulated"):
        atomic_write(destination, b"new container", before_replace=fail)

    assert destination.read_bytes() == b"valid old container"
    assert not list(tmp_path.glob("*.tmp"))


def test_atomic_write_does_not_change_existing_file_before_replace(tmp_path):
    destination = tmp_path / "document.greg"
    destination.write_bytes(b"old")

    def inspect_staged(temporary):
        assert temporary.read_bytes() == b"new"
        assert destination.read_bytes() == b"old"
        assert temporary.stat().st_mode & 0o777 == 0o600

    atomic_write(destination, b"new", before_replace=inspect_staged)
    assert destination.read_bytes() == b"new"

