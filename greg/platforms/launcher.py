from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from pathlib import Path


class Launcher(ABC):
    @abstractmethod
    def launch(self, path: Path) -> None:
        """Ask the operating system to open path without assuming process lifetime."""


def default_launcher() -> Launcher:
    if sys.platform.startswith("linux"):
        from .linux import LinuxLauncher

        return LinuxLauncher()
    if sys.platform == "win32":
        from .windows import WindowsLauncher

        return WindowsLauncher()
    if sys.platform == "darwin":
        from .macos import MacOSLauncher

        return MacOSLauncher()
    raise RuntimeError(f"unsupported operating system: {sys.platform}")

