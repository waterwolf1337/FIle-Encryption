from __future__ import annotations

import os

import pytest

from greg.storage import atomic_write
from greg.storage import _fsync_directory


def test_atomic_write_replaces_file_and_restricts_permissions(tmp_path):
    destination = tmp_path / "document.greg"
    atomic_write(destination, b"ciphertext")

    assert destination.read_bytes() == b"ciphertext"
    if os.name != "nt":
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
        if os.name != "nt":
            assert temporary.stat().st_mode & 0o777 == 0o600

    atomic_write(destination, b"new", before_replace=inspect_staged)
    assert destination.read_bytes() == b"new"


def test_windows_skips_unsupported_directory_fsync(tmp_path, monkeypatch):
    monkeypatch.setattr("greg.storage.sys.platform", "win32")
    monkeypatch.setattr(
        "greg.storage.os.open",
        lambda *_args: pytest.fail("Windows must not try to os.open a directory"),
    )

    _fsync_directory(tmp_path)
