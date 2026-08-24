from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from greg.format.greg_file import AuthenticationError, GregFormatError, encrypt_new
from greg.format.payload import GregPayload
from greg.platforms import default_launcher
from greg.sessions.cleanup import cleanup_stale_directories, find_stale_directories
from greg.sessions.session import GregSession
from greg.storage import atomic_write

from .password_dialog import PasswordDialog
from .unlocked_window import UnlockedWindow


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Greg Encrypted Files")
        self.setMinimumWidth(420)
        self._sessions: set[UnlockedWindow] = set()
        central = QWidget()
        layout = QVBoxLayout(central)
        description = QLabel(
            "Encrypt any file as a .greg wrapper, or unlock one in its normal "
            "desktop application."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        encrypt_button = QPushButton("Encrypt File…")
        open_button = QPushButton("Open .greg…")
        encrypt_button.clicked.connect(self.encrypt_file)
        open_button.clicked.connect(self.choose_greg_file)
        layout.addWidget(encrypt_button)
        layout.addWidget(open_button)
        self.setCentralWidget(central)

    def offer_stale_cleanup(self) -> None:
        stale = find_stale_directories()
        if not stale:
            return
        answer = QMessageBox.warning(
            self,
            "Leftover unlocked files",
            f"Greg found {len(stale)} abandoned temporary session(s), which may "
            "contain plaintext. Remove them now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer == QMessageBox.StandardButton.Yes:
            try:
                cleanup_stale_directories(stale)
            except Exception as error:
                QMessageBox.critical(self, "Cleanup failed", str(error))

    def encrypt_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Select a file to encrypt")
        if not filename:
            return
        source = Path(filename)
        output, _ = QFileDialog.getSaveFileName(
            self,
            "Save encrypted file",
            str(source.with_suffix(".greg")),
            "Greg files (*.greg)",
        )
        if not output:
            return
        destination = Path(output)
        if destination.suffix.lower() != ".greg":
            destination = destination.with_suffix(".greg")
        if source.resolve() == destination.resolve():
            QMessageBox.warning(
                self, "Invalid destination", "The source file cannot be overwritten."
            )
            return
        password = PasswordDialog(f"Encrypt {source.name}", self, confirm=True)
        if password.exec() != PasswordDialog.DialogCode.Accepted:
            return
        try:
            container = encrypt_new(
                GregPayload(filename=source.name, data=source.read_bytes()),
                password.password,
            )
            atomic_write(destination, container)
        except Exception as error:
            QMessageBox.critical(self, "Encryption failed", str(error))
            return
        QMessageBox.information(
            self,
            "File encrypted",
            f"Created {destination}. The original file was not deleted.",
        )

    def choose_greg_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(
            self, "Open encrypted file", filter="Greg files (*.greg)"
        )
        if filename:
            self.open_greg_file(Path(filename))

    def open_greg_file(self, path: Path) -> None:
        password = PasswordDialog(f"Unlock {path.name}", self)
        if password.exec() != PasswordDialog.DialogCode.Accepted:
            return
        session: GregSession | None = None
        try:
            session = GregSession.open(path, password.password)
            default_launcher().launch(session.plaintext_path)
        except AuthenticationError:
            QMessageBox.critical(
                self,
                "Could not unlock",
                "The password is wrong or the encrypted file is corrupted.",
            )
            return
        except (GregFormatError, OSError, ValueError, RuntimeError) as error:
            if session is not None:
                try:
                    session.cancel()
                except Exception:
                    pass
            QMessageBox.critical(self, "Could not open file", str(error))
            return
        window = UnlockedWindow(session)
        self._sessions.add(window)
        window.destroyed.connect(lambda: self._sessions.discard(window))
        window.show()

