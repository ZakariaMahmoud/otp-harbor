from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import create_api_key
from app.config import Settings
from app.database import Base
from app.main import create_app
from app.models import ApiClient


@pytest.fixture
def test_context(tmp_path: Path):
    key = os.urandom(32)
    key_file = tmp_path / "master.key"
    key_file.write_bytes(base64.b64encode(key))
    key_file.chmod(0o400)
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'vault.db'}",
        master_key_file=key_file,
        otp_rate_limit=2,
        auth_failure_rate_limit=2,
        rate_window_seconds=60,
    )
    app = create_app(settings)
    Base.metadata.create_all(app.state.engine)
    generated = create_api_key()
    with app.state.session_factory() as session:
        admin = ApiClient(name="test admin", key_id=generated.key_id, key_hash=generated.verifier, role="admin")
        session.add(admin)
        session.commit()
        admin_id = admin.id
    with TestClient(app) as client:
        yield app, client, generated.plaintext, admin_id, key


@pytest.fixture
def enrolled(test_context):
    app, client, admin_key, admin_id, master_key = test_context
    secret = "JBSWY3DPEHPK3PXP"  # pragma: allowlist secret -- RFC-style synthetic fixture
    uri = f"otpauth://totp/Example:alice%40example.com?secret={secret}&issuer=Example"
    response = client.post("/api/v1/admin/credentials", json={"uri": uri},
                           headers={"Authorization": f"Bearer {admin_key}"})
    assert response.status_code == 201, response.text
    return test_context, response.json(), secret
