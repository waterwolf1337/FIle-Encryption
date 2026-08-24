from __future__ import annotations

import json

from greg.crypto.constants import Argon2Parameters
from greg.format.greg_file import encrypt_new, unlock
from greg.format.payload import GregPayload
from greg.main import main


def test_top_level_help_does_not_launch_gui(capsys):
    assert main(["--help"]) == 0
    assert "greg encrypt FILE" in capsys.readouterr().out


def test_inspect_reports_public_parameters_only(tmp_path, capsys, fast_parameters):
    path = tmp_path / "secret.greg"
    path.write_bytes(encrypt_new(GregPayload("hidden.txt", b"secret"), "pw", fast_parameters))

    assert main(["inspect", str(path)]) == 0
    output = capsys.readouterr().out
    parsed = json.loads(output)
    assert parsed["version"] == 1
    assert parsed["kdf"] == "Argon2id"
    assert parsed["cipher"] == "AES-256-GCM"
    assert "hidden.txt" not in output
    assert "secret" not in output


def test_cli_encrypt_preserves_source_and_creates_round_trip(
    tmp_path, monkeypatch, fast_parameters
):
    source = tmp_path / "finances.xlsx"
    source.write_bytes(b"spreadsheet")
    answers = iter(["password", "password"])
    monkeypatch.setattr("greg.main.getpass.getpass", lambda _prompt: next(answers))
    monkeypatch.setattr(
        "greg.main.encrypt_new",
        lambda payload, password: encrypt_new(payload, password, fast_parameters),
    )

    assert main(["encrypt", str(source)]) == 0
    destination = tmp_path / "finances.greg"
    assert source.read_bytes() == b"spreadsheet"
    with unlock(destination.read_bytes(), "password") as opened:
        assert opened.payload.filename == "finances.xlsx"
        assert opened.payload.data == b"spreadsheet"
