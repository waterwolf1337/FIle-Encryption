from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from types import ModuleType

from .launcher import Launcher

PROG_ID = "Greg.EncryptedFile"
EXTENSION_KEY = r"Software\Classes\.greg"
PROG_ID_KEY = rf"Software\Classes\{PROG_ID}"


class WindowsLauncher(Launcher):
    def launch(self, path: Path) -> None:
        os.startfile(str(path), "open")  # type: ignore[attr-defined]


def install_file_association(
    python_executable: Path | None = None,
    *,
    registry_module: ModuleType | None = None,
    notify_shell: bool = True,
) -> str:
    """Register .greg for the current Windows user without administrator rights."""
    winreg = registry_module or _winreg()
    command = _open_command(python_executable or Path(sys.executable))
    _set_registry_value(winreg, EXTENSION_KEY, None, PROG_ID)
    _set_registry_value(
        winreg, EXTENSION_KEY, "Content Type", "application/x-greg-encrypted"
    )
    _set_registry_value(winreg, PROG_ID_KEY, None, "Greg encrypted file")
    _set_registry_value(
        winreg,
        rf"{PROG_ID_KEY}\DefaultIcon",
        None,
        r"%SystemRoot%\System32\shell32.dll,-47",
    )
    _set_registry_value(
        winreg, rf"{PROG_ID_KEY}\shell\open\command", None, command
    )
    if notify_shell:
        _notify_association_changed()
    return command


def uninstall_file_association(
    *,
    registry_module: ModuleType | None = None,
    notify_shell: bool = True,
) -> None:
    """Remove only Greg-owned per-user file-association registry keys."""
    winreg = registry_module or _winreg()
    try:
        extension_key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, EXTENSION_KEY, 0, winreg.KEY_READ
        )
        with extension_key:
            owner, _kind = winreg.QueryValueEx(extension_key, None)
    except FileNotFoundError:
        owner = None
    if owner == PROG_ID:
        _delete_registry_tree(winreg, EXTENSION_KEY)
    _delete_registry_tree(winreg, PROG_ID_KEY)
    if notify_shell:
        _notify_association_changed()


def _open_command(python_executable: Path) -> str:
    executable = python_executable.resolve()
    pythonw = executable.with_name("pythonw.exe")
    if executable.name.lower() == "python.exe" and pythonw.exists():
        executable = pythonw
    escaped = str(executable).replace('"', '\\"')
    return f'"{escaped}" -m greg "%1"'


def _set_registry_value(
    winreg: ModuleType, key_path: str, name: str | None, value: str
) -> None:
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def _delete_registry_tree(winreg: ModuleType, key_path: str) -> None:
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            key_path,
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        ) as key:
            children: list[str] = []
            index = 0
            while True:
                try:
                    children.append(winreg.EnumKey(key, index))
                    index += 1
                except OSError:
                    break
        for child in children:
            _delete_registry_tree(winreg, rf"{key_path}\{child}")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
    except FileNotFoundError:
        return


def _notify_association_changed() -> None:
    # SHCNE_ASSOCCHANGED and SHCNF_IDLIST tell Explorer to refresh associations.
    ctypes.windll.shell32.SHChangeNotify(0x08000000, 0x0000, None, None)


def _winreg() -> ModuleType:
    if sys.platform != "win32":
        raise RuntimeError("Windows file association is only available on Windows")
    import winreg

    return winreg
