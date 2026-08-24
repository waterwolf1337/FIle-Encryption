from __future__ import annotations

import pytest

from greg.crypto.constants import Argon2Parameters


@pytest.fixture
def fast_parameters() -> Argon2Parameters:
    return Argon2Parameters(time_cost=1, memory_cost_kib=8_192, parallelism=1)


@pytest.fixture(autouse=True)
def isolated_state_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

