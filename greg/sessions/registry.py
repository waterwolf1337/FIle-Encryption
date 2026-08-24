from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

APP_MARKER = "greg-encrypted-files-v1"
MARKER_PREFIX = ".greg-owner-"
SESSION_PREFIX = "greg-session-"


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: str
    directory: str
    pid: int
    created_at: float


def registry_path(platform_name: str | None = None) -> Path:
    if (platform_name or os.name) == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
        return base / "Greg" / "sessions.json"
    state_home = Path(
        os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")
    )
    return state_home / "greg" / "sessions.json"


def add_record(record: SessionRecord) -> None:
    records = read_records()
    records = [item for item in records if item.session_id != record.session_id]
    records.append(record)
    _write_records(records)


def remove_record(session_id: str) -> None:
    _write_records(
        [item for item in read_records() if item.session_id != session_id]
    )


def read_records() -> list[SessionRecord]:
    path = registry_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("application") != APP_MARKER or not isinstance(raw["sessions"], list):
            return []
        return [
            SessionRecord(
                session_id=item["session_id"],
                directory=item["directory"],
                pid=int(item["pid"]),
                created_at=float(item["created_at"]),
            )
            for item in raw["sessions"]
            if isinstance(item, dict)
        ]
    except (FileNotFoundError, OSError, ValueError, KeyError, TypeError):
        return []


def write_marker(directory: Path, session_id: str) -> None:
    marker = marker_path(directory, session_id)
    marker.write_text(
        json.dumps({"application": APP_MARKER, "session_id": session_id}),
        encoding="utf-8",
    )
    os.chmod(marker, 0o600)


def marker_matches(directory: Path, session_id: str | None = None) -> bool:
    candidates = (
        [marker_path(directory, session_id)]
        if session_id is not None
        else list(directory.glob(f"{MARKER_PREFIX}*"))
    )
    for candidate in candidates:
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
            marker_session_id = raw.get("session_id")
            if (
                raw.get("application") == APP_MARKER
                and isinstance(marker_session_id, str)
                and candidate.name == f"{MARKER_PREFIX}{marker_session_id}"
                and (session_id is None or marker_session_id == session_id)
            ):
                return True
        except (FileNotFoundError, OSError, ValueError, TypeError):
            continue
    return False


def marker_path(directory: Path, session_id: str) -> Path:
    return directory / f"{MARKER_PREFIX}{session_id}"


def discover_owned_directories() -> list[Path]:
    candidates = {Path(record.directory) for record in read_records()}
    temporary_root = Path(tempfile.gettempdir())
    candidates.update(temporary_root.glob(f"{SESSION_PREFIX}*"))
    return sorted(
        (path for path in candidates if is_owned_session_directory(path)),
        key=str,
    )


def stale_records() -> list[SessionRecord]:
    return [
        record
        for record in read_records()
        if not _process_is_alive(record.pid)
        and is_owned_session_directory(Path(record.directory), record.session_id)
    ]


def orphan_directories() -> list[Path]:
    registered = {Path(record.directory).resolve() for record in read_records()}
    return [
        path
        for path in discover_owned_directories()
        if path.resolve() not in registered
    ]


def is_owned_session_directory(path: Path, session_id: str | None = None) -> bool:
    try:
        resolved = path.resolve(strict=True)
        root = Path(tempfile.gettempdir()).resolve(strict=True)
        return (
            resolved.parent == root
            and resolved.name.startswith(SESSION_PREFIX)
            and resolved.is_dir()
            and marker_matches(resolved, session_id)
        )
    except (FileNotFoundError, OSError):
        return False


def new_record(session_id: str, directory: Path) -> SessionRecord:
    return SessionRecord(session_id, str(directory), os.getpid(), time.time())


def _write_records(records: list[SessionRecord]) -> None:
    path = registry_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    payload = json.dumps(
        {"application": APP_MARKER, "sessions": [asdict(item) for item in records]},
        separators=(",", ":"),
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".sessions-", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _process_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
