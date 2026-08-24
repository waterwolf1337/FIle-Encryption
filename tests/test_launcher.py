from __future__ import annotations

from pathlib import Path

from greg.platforms.linux import LinuxLauncher


def test_linux_launcher_uses_xdg_open_without_waiting(monkeypatch):
    calls = []
    monkeypatch.setattr("greg.platforms.linux.shutil.which", lambda name: "/usr/bin/xdg-open")
    monkeypatch.setattr(
        "greg.platforms.linux.subprocess.Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    LinuxLauncher().launch(Path("/tmp/file with spaces.xlsx"))

    assert calls[0][0][0] == ["/usr/bin/xdg-open", "/tmp/file with spaces.xlsx"]
    assert calls[0][1]["start_new_session"] is True

