from __future__ import annotations

import os
import tempfile
import time
import uuid
from pathlib import Path

from greg.format.greg_file import UnlockedGreg, unlock
from greg.format.payload import GregPayload
from greg.storage import atomic_write

from .cleanup import cleanup_owned_directory
from .registry import MARKER_PREFIX, SESSION_PREFIX, add_record, new_record, write_marker


class GregSession:
    """An unlocked plaintext copy and its in-memory encryption context."""

    def __init__(
        self,
        greg_path: Path,
        directory: Path,
        plaintext_path: Path,
        session_id: str,
        unlocked: UnlockedGreg,
    ) -> None:
        self.greg_path = greg_path
        self.directory = directory
        self.plaintext_path = plaintext_path
        self.session_id = session_id
        self._unlocked = unlocked
        self._ended = False

    @classmethod
    def open(cls, greg_path: Path, password: str | bytes) -> "GregSession":
        greg_path = greg_path.resolve(strict=True)
        unlocked = unlock(greg_path.read_bytes(), password)
        directory: Path | None = None
        session_id = uuid.uuid4().hex
        while unlocked.payload.filename == f"{MARKER_PREFIX}{session_id}":
            session_id = uuid.uuid4().hex
        try:
            directory = Path(tempfile.mkdtemp(prefix=SESSION_PREFIX))
            os.chmod(directory, 0o700)
            write_marker(directory, session_id)
            plaintext_path = directory / unlocked.payload.filename
            descriptor = os.open(
                plaintext_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(unlocked.payload.data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(plaintext_path, 0o600)
            add_record(new_record(session_id, directory))
            return cls(greg_path, directory, plaintext_path, session_id, unlocked)
        except Exception:
            unlocked.close()
            if directory is not None:
                try:
                    cleanup_owned_directory(directory, session_id)
                except (OSError, ValueError):
                    pass
            raise

    def save_and_lock(self, *, settle_timeout: float = 2.0) -> None:
        self._ensure_active()
        wait_for_file_to_settle(self.plaintext_path, settle_timeout)
        updated = self.plaintext_path.read_bytes()
        payload = GregPayload(
            self._unlocked.payload.filename,
            updated,
            self._unlocked.payload.metadata,
        )
        ciphertext = self._unlocked.encrypt(payload)
        # Cleanup only occurs after a fully staged and atomically replaced container.
        atomic_write(self.greg_path, ciphertext)
        try:
            self._finish()
        except Exception as error:
            raise PlaintextCleanupError(
                "The .greg file was updated, but Greg could not remove its temporary "
                f"plaintext directory: {self.directory}"
            ) from error

    def cancel(self) -> None:
        self._ensure_active()
        self._finish()

    def _finish(self) -> None:
        self._unlocked.close()
        cleanup_owned_directory(self.directory, self.session_id)
        self._ended = True

    def _ensure_active(self) -> None:
        if self._ended:
            raise RuntimeError("Greg session has already ended")


def wait_for_file_to_settle(path: Path, timeout: float, interval: float = 0.2) -> None:
    """Wait for two identical observations; this cannot detect editor RAM changes."""
    deadline = time.monotonic() + max(timeout, 0)
    previous: tuple[int, int] | None = None
    stable_observations = 0
    while True:
        stat = path.stat()
        observation = (stat.st_size, stat.st_mtime_ns)
        if observation == previous:
            stable_observations += 1
            if stable_observations >= 2:
                return
        else:
            previous = observation
            stable_observations = 0
        if time.monotonic() >= deadline:
            return
        time.sleep(min(interval, max(deadline - time.monotonic(), 0)))


class PlaintextCleanupError(OSError):
    """Ciphertext was saved successfully, but plaintext cleanup did not complete."""
