from __future__ import annotations

import os
from pathlib import Path

from .launcher import Launcher


class WindowsLauncher(Launcher):
    def launch(self, path: Path) -> None:
        os.startfile(path)  # type: ignore[attr-defined]

