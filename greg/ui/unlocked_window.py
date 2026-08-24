from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget

from greg.sessions.session import GregSession, PlaintextCleanupError


class UnlockedWindow(QWidget):
    def __init__(self, session: GregSession, parent: QWidget | None = None):
        super().__init__(parent, Qt.WindowType.Window)
        self.session = session
        self._ended = False
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setWindowTitle(f"{session.plaintext_path.name} — Greg")
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        heading = QLabel(f"<b>{session.plaintext_path.name} is currently unlocked</b>")
        heading.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(heading)
        explanation = QLabel(
            "The temporary file is open in your default application. "
            "Save and close it there before locking."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        self._save = QPushButton("Save and Lock")
        self._cancel = QPushButton("Cancel Changes")
        self._save.clicked.connect(self._save_and_lock)
        self._cancel.clicked.connect(self._cancel_changes)
        layout.addWidget(self._save)
        layout.addWidget(self._cancel)

    def _save_and_lock(self) -> None:
        answer = QMessageBox.question(
            self,
            "Save and Lock",
            "Have you saved and closed the document in the external application?\n\n"
            "Greg will now read the temporary file and replace the encrypted file.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._set_busy(True)
        try:
            self.session.save_and_lock()
        except PlaintextCleanupError as error:
            QMessageBox.critical(
                self,
                "Encrypted, but cleanup failed",
                f"{error}\n\nClose the external application and remove that directory "
                "manually, or let Greg offer recovery at its next startup.",
            )
            self._set_busy(False)
            return
        except Exception as error:
            QMessageBox.critical(
                self,
                "Could not lock file",
                "The original .greg file remains intact and the unlocked session is "
                f"still available.\n\n{error}",
            )
            self._set_busy(False)
            return
        self._ended = True
        QMessageBox.information(self, "Locked", "Changes were encrypted successfully.")
        self.close()

    def _cancel_changes(self) -> None:
        answer = QMessageBox.warning(
            self,
            "Discard changes?",
            "Any changes made to the temporary document will be discarded.",
            QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Discard:
            return
        try:
            self.session.cancel()
        except Exception as error:
            QMessageBox.critical(self, "Cleanup failed", str(error))
            return
        self._ended = True
        self.close()

    def _set_busy(self, busy: bool) -> None:
        self._save.setDisabled(busy)
        self._cancel.setDisabled(busy)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt API
        if self._ended:
            event.accept()
            return
        answer = QMessageBox.warning(
            self,
            "Unlocked document",
            "Closing this window will discard changes and remove Greg's temporary "
            "plaintext. Continue?",
            QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Discard:
            event.ignore()
            return
        try:
            self.session.cancel()
        except Exception as error:
            QMessageBox.critical(self, "Cleanup failed", str(error))
            event.ignore()
            return
        self._ended = True
        event.accept()
