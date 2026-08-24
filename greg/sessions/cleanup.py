from __future__ import annotations

import shutil
from pathlib import Path

from .registry import (
    is_owned_session_directory,
    orphan_directories,
    read_records,
    remove_record,
    stale_records,
)


def find_stale_directories() -> list[Path]:
    paths = {Path(record.directory) for record in stale_records()}
    paths.update(orphan_directories())
    return sorted(paths, key=str)


def cleanup_owned_directory(path: Path, session_id: str | None = None) -> None:
    """Remove only a verified, marker-bearing Greg temporary directory."""
    if not is_owned_session_directory(path, session_id):
        raise ValueError(f"refusing to remove unverified directory: {path}")
    shutil.rmtree(path)
    if session_id is not None:
        remove_record(session_id)
    else:
        for record in read_records():
            if Path(record.directory) == path:
                remove_record(record.session_id)


def cleanup_stale_directories(paths: list[Path] | None = None) -> list[Path]:
    removed: list[Path] = []
    for path in paths if paths is not None else find_stale_directories():
        cleanup_owned_directory(path)
        removed.append(path)
    return removed

