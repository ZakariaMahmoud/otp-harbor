from __future__ import annotations

import base64
import os

import pytest

from app.config import ConfigurationError, Settings


def test_missing_bad_and_overpermissive_master_keys(tmp_path):
    with pytest.raises(ConfigurationError):
        Settings("sqlite:///:memory:", tmp_path / "missing").load_master_key()
    wrong = tmp_path / "wrong"
    wrong.write_text("not-base64!")
    wrong.chmod(0o400)
    with pytest.raises(ConfigurationError):
        Settings("sqlite:///:memory:", wrong).load_master_key()
    broad = tmp_path / "broad"
    broad.write_bytes(base64.b64encode(os.urandom(32)))
    broad.chmod(0o444)
    with pytest.raises(ConfigurationError):
        Settings("sqlite:///:memory:", broad).load_master_key()
