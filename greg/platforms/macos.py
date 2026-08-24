from __future__ import annotations

import subprocess
from pathlib import Path

from .launcher import Launcher


class MacOSLauncher(Launcher):
    def launch(self, path: Path) -> None:
        subprocess.Popen(
            ["open", str(path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

