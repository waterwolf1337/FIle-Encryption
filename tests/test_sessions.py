from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from greg.format.greg_file import encrypt_new, unlock
from greg.format.payload import GregPayload
from greg.sessions import registry
from greg.sessions.cleanup import cleanup_owned_directory, find_stale_directories
from greg.sessions.session import GregSession, PlaintextCleanupError
from greg.storage import atomic_write


def make_greg(path: Path, fast_parameters, data: bytes = b"original") -> bytes:
    container = encrypt_new(
        GregPayload("test.xlsx", data), "password", fast_parameters
    )
    atomic_write(path, container)
    return container


def test_save_cycle_restores_modification_and_cleans_plaintext(tmp_path, fast_parameters):
    path = tmp_path / "test.greg"
    make_greg(path, fast_parameters)
    session = GregSession.open(path, "password")
    directory = session.directory

    assert session.plaintext_path.name == "test.xlsx"
    assert session.plaintext_path.read_bytes() == b"original"
    assert directory.stat().st_mode & 0o777 == 0o700
    assert session.plaintext_path.stat().st_mode & 0o777 == 0o600
    session.plaintext_path.write_bytes(b"modified")
    session.save_and_lock(settle_timeout=0)

    assert not directory.exists()
    with unlock(path.read_bytes(), "password") as reopened:
        assert reopened.payload.filename == "test.xlsx"
        assert reopened.payload.data == b"modified"


def test_cancel_leaves_container_unchanged(tmp_path, fast_parameters):
    path = tmp_path / "test.greg"
    original = make_greg(path, fast_parameters)
    session = GregSession.open(path, "password")
    directory = session.directory
    session.plaintext_path.write_bytes(b"discard me")

    session.cancel()

    assert path.read_bytes() == original
    assert not directory.exists()
    with unlock(path.read_bytes(), "password") as reopened:
        assert reopened.payload.data == b"original"


def test_save_failure_keeps_old_container_and_plaintext_session(
    tmp_path, fast_parameters, monkeypatch
):
    path = tmp_path / "test.greg"
    original = make_greg(path, fast_parameters)
    session = GregSession.open(path, "password")
    session.plaintext_path.write_bytes(b"modified")

    def fail(*_args, **_kwargs):
        raise OSError("simulated write failure")

    monkeypatch.setattr("greg.sessions.session.atomic_write", fail)
    with pytest.raises(OSError, match="simulated"):
        session.save_and_lock(settle_timeout=0)

    assert path.read_bytes() == original
    assert session.plaintext_path.read_bytes() == b"modified"
    session.cancel()


def test_cleanup_failure_is_distinguished_from_encryption_failure(
    tmp_path, fast_parameters, monkeypatch
):
    path = tmp_path / "test.greg"
    original = make_greg(path, fast_parameters)
    session = GregSession.open(path, "password")
    session.plaintext_path.write_bytes(b"saved despite cleanup trouble")
    real_cleanup = cleanup_owned_directory

    def fail_cleanup(*_args, **_kwargs):
        raise OSError("simulated cleanup failure")

    monkeypatch.setattr("greg.sessions.session.cleanup_owned_directory", fail_cleanup)
    with pytest.raises(PlaintextCleanupError, match="was updated"):
        session.save_and_lock(settle_timeout=0)

    assert path.read_bytes() != original
    with unlock(path.read_bytes(), "password") as reopened:
        assert reopened.payload.data == b"saved despite cleanup trouble"
    real_cleanup(session.directory, session.session_id)
    session._ended = True


def test_registry_contains_no_document_secrets(tmp_path, fast_parameters):
    path = tmp_path / "sensitive-name.greg"
    make_greg(path, fast_parameters, b"TOP SECRET CONTENT")
    session = GregSession.open(path, "password")

    registry_text = registry.registry_path().read_text(encoding="utf-8")
    assert "password" not in registry_text
    assert "TOP SECRET" not in registry_text
    assert "test.xlsx" not in registry_text
    assert "sensitive-name" not in registry_text
    session.cancel()


def test_stale_session_is_discovered_and_verified(tmp_path, fast_parameters, monkeypatch):
    path = tmp_path / "test.greg"
    make_greg(path, fast_parameters)
    session = GregSession.open(path, "password")
    monkeypatch.setattr(registry, "_process_is_alive", lambda _pid: False)

    assert session.directory in find_stale_directories()
    cleanup_owned_directory(session.directory, session.session_id)
    session._unlocked.close()
    session._ended = True
    assert not session.directory.exists()


def test_cleanup_refuses_unrelated_directory(tmp_path):
    unrelated = tmp_path / "greg-session-fake"
    unrelated.mkdir()
    (unrelated / "important.txt").write_text("keep")

    with pytest.raises(ValueError, match="refusing"):
        cleanup_owned_directory(unrelated)

    assert (unrelated / "important.txt").exists()


def test_marker_contains_only_ownership_data(tmp_path, fast_parameters):
    path = tmp_path / "test.greg"
    make_greg(path, fast_parameters)
    session = GregSession.open(path, "password")

    marker = json.loads(registry.marker_path(session.directory, session.session_id).read_text())
    assert set(marker) == {"application", "session_id"}
    session.cancel()
