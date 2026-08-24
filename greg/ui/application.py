from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from .main_window import MainWindow


def run_gui(path: Path | None = None) -> int:
    application = QApplication.instance() or QApplication(sys.argv[:1])
    application.setApplicationName("Greg")
    application.setOrganizationName("Greg")
    window = MainWindow()
    window.show()
    window.offer_stale_cleanup()
    if path is not None:
        window.open_greg_file(path)
    return application.exec()

