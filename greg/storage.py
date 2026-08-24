from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Callable


def atomic_write(
    destination: Path,
    data: bytes,
    *,
    before_replace: Callable[[Path], None] | None = None,
) -> None:
    """Durably stage ciphertext beside destination, then atomically replace it."""
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        temporary = Path(name)
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if before_replace is not None:
            before_replace(temporary)
        os.replace(temporary, destination)
        temporary = None
        _fsync_directory(destination.parent)
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _fsync_directory(directory: Path) -> None:
    # Windows cannot open directories through os.open. os.replace still provides
    # same-volume atomic replacement there; only the extra directory durability
    # flush is unavailable through Python's standard library.
    if sys.platform == "win32":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
