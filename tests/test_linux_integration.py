from __future__ import annotations

import xml.etree.ElementTree as ET

from greg.platforms.linux import install_file_association


def test_linux_file_association_resources_install_per_user(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "share"))
    calls = []
    monkeypatch.setattr(
        "greg.platforms.linux.subprocess.run",
        lambda command, **options: calls.append((command, options)),
    )

    desktop, mime = install_file_association(tmp_path / "venv" / "python")

    desktop_text = desktop.read_text(encoding="utf-8")
    assert f'Exec="{tmp_path / "venv" / "python"}" -m greg %f' in desktop_text
    assert "MimeType=application/x-greg-encrypted;" in desktop_text
    root = ET.parse(mime).getroot()
    namespace = {"m": "http://www.freedesktop.org/standards/shared-mime-info"}
    mime_type = root.find("m:mime-type", namespace)
    assert mime_type is not None
    assert mime_type.attrib["type"] == "application/x-greg-encrypted"
    assert mime_type.find("m:glob", namespace).attrib["pattern"] == "*.greg"
    assert calls[0][0][0] == "update-mime-database"
