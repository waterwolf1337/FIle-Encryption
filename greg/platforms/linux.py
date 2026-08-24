from __future__ import annotations

import os
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

from .launcher import Launcher


class LinuxLauncher(Launcher):
    def launch(self, path: Path) -> None:
        executable = shutil.which("xdg-open")
        if executable is None:
            raise RuntimeError("xdg-open is required to open external files")
        subprocess.Popen(
            [executable, str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )


def install_file_association(
    python_executable: Path | None = None,
) -> tuple[Path, Path]:
    """Install Greg's desktop and MIME declarations for the current Linux user."""
    data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    applications = data_home / "applications"
    mime_packages = data_home / "mime" / "packages"
    applications.mkdir(parents=True, exist_ok=True)
    mime_packages.mkdir(parents=True, exist_ok=True)
    desktop_target = applications / "greg.desktop"
    mime_target = mime_packages / "greg.xml"
    resources = files("greg.resources")
    desktop_text = resources.joinpath("greg.desktop").read_text(encoding="utf-8")
    python_path = (python_executable or Path(sys.executable)).resolve()
    escaped_python = str(python_path).replace("\\", "\\\\").replace('"', '\\"')
    desktop_text = desktop_text.replace(
        "Exec=greg %f", f'Exec="{escaped_python}" -m greg %f'
    )
    desktop_target.write_text(desktop_text, encoding="utf-8")
    mime_target.write_bytes(resources.joinpath("greg.xml").read_bytes())
    subprocess.run(
        ["update-mime-database", str(data_home / "mime")], check=True
    )
    subprocess.run(
        ["update-desktop-database", str(applications)], check=False
    )
    return desktop_target, mime_target
