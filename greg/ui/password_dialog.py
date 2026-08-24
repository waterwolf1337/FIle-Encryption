from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)


class PasswordDialog(QDialog):
    def __init__(self, title: str, parent: QWidget | None = None, *, confirm: bool = False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self._password = QLineEdit()
        self._password.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirmation: QLineEdit | None = None

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(title))
        form = QFormLayout()
        form.addRow("Password:", self._password)
        if confirm:
            self._confirmation = QLineEdit()
            self._confirmation.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Confirm password:", self._confirmation)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Ok
        )
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self._password.setFocus()

    @property
    def password(self) -> str:
        return self._password.text()

    def _validate(self) -> None:
        if not self._password.text():
            QMessageBox.warning(self, "Password required", "Enter a password.")
            return
        if self._confirmation is not None and self._password.text() != self._confirmation.text():
            QMessageBox.warning(self, "Passwords differ", "The two passwords do not match.")
            return
        self.accept()

