from __future__ import annotations

from pathlib import Path

import pytest

from greg.platforms.windows import (
    EXTENSION_KEY,
    PROG_ID,
    PROG_ID_KEY,
    WindowsLauncher,
    install_file_association,
    uninstall_file_association,
)
from greg.sessions.registry import registry_path
from greg.sessions.session import validate_restorable_filename


class FakeKey:
    def __init__(self, registry, path):
        self.registry = registry
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None


class FakeWinreg:
    HKEY_CURRENT_USER = object()
    KEY_SET_VALUE = 1
    KEY_READ = 2
    KEY_WRITE = 4
    REG_SZ = 1

    def __init__(self):
        self.values = {}

    def CreateKeyEx(self, _root, path, _reserved, _access):
        parent = path.rpartition("\\")[0]
        while parent.startswith(PROG_ID_KEY):
            self.values.setdefault(parent, {})
            parent = parent.rpartition("\\")[0]
        self.values.setdefault(path, {})
        return FakeKey(self, path)

    def SetValueEx(self, key, name, _reserved, _kind, value):
        self.values[key.path][name] = value

    def OpenKey(self, _root, path, _reserved, _access):
        if path not in self.values:
            raise FileNotFoundError(path)
        return FakeKey(self, path)

    def QueryValueEx(self, key, name):
        return self.values[key.path][name], self.REG_SZ

    def EnumKey(self, key, index):
        prefix = key.path + "\\"
        children = sorted(
            {
                path[len(prefix) :].split("\\", 1)[0]
                for path in self.values
                if path.startswith(prefix)
            }
        )
        if index >= len(children):
            raise OSError("no more keys")
        return children[index]

    def DeleteKey(self, _root, path):
        if any(item.startswith(path + "\\") for item in self.values):
            raise OSError("key has children")
        if path not in self.values:
            raise FileNotFoundError(path)
        del self.values[path]


def test_windows_launcher_uses_default_open_verb(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "greg.platforms.windows.os.startfile",
        lambda path, verb: calls.append((path, verb)),
        raising=False,
    )

    WindowsLauncher().launch(Path(r"C:\Documents\report.xlsx"))

    assert calls == [(r"C:\Documents\report.xlsx", "open")]


def test_windows_association_is_current_user_and_removable(tmp_path):
    python = tmp_path / "python.exe"
    pythonw = tmp_path / "pythonw.exe"
    python.write_bytes(b"")
    pythonw.write_bytes(b"")
    registry = FakeWinreg()

    command = install_file_association(
        python, registry_module=registry, notify_shell=False
    )

    assert registry.values[EXTENSION_KEY][None] == PROG_ID
    assert registry.values[EXTENSION_KEY]["Content Type"] == (
        "application/x-greg-encrypted"
    )
    assert registry.values[PROG_ID_KEY][None] == "Greg encrypted file"
    assert command == f'"{pythonw.resolve()}" -m greg "%1"'
    assert registry.values[rf"{PROG_ID_KEY}\shell\open\command"][None] == command

    uninstall_file_association(registry_module=registry, notify_shell=False)
    assert not registry.values


def test_uninstall_preserves_extension_owned_by_another_application():
    registry = FakeWinreg()
    registry.values[EXTENSION_KEY] = {None: "Another.Application"}
    registry.values[PROG_ID_KEY] = {None: "Greg encrypted file"}

    uninstall_file_association(registry_module=registry, notify_shell=False)

    assert registry.values[EXTENSION_KEY][None] == "Another.Application"
    assert PROG_ID_KEY not in registry.values


def test_windows_state_registry_uses_local_app_data(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    assert registry_path("nt") == tmp_path / "Local" / "Greg" / "sessions.json"


@pytest.mark.parametrize(
    "filename",
    [
        "CON",
        "nul.txt",
        "CON .txt",
        "CLOCK$.log",
        "report?.txt",
        "bad:name.xlsx",
        "trailing.",
        "a" * 256,
    ],
)
def test_windows_rejects_names_it_cannot_restore(filename):
    with pytest.raises(ValueError):
        validate_restorable_filename(filename, "win32")


@pytest.mark.parametrize("filename", ["report.xlsx", "archive.tar.gz", ".notes"])
def test_windows_accepts_normal_filenames(filename):
    validate_restorable_filename(filename, "win32")
