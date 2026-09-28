from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.models import ApiClient, Credential


def auth(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def create_otp_client(client, admin_key: str, name: str = "consumer", expires_at=None):
    payload = {"name": name, "role": "otp"}
    if expires_at is not None:
        payload["expires_at"] = expires_at.isoformat()
    response = client.post("/api/v1/admin/clients", json=payload, headers=auth(admin_key))
    assert response.status_code == 201, response.text
    return response.json()


def test_enrollment_stores_only_ciphertext_and_never_returns_secret(enrolled):
    (app, client, admin_key, _admin_id, _key), credential, secret = enrolled
    with app.state.session_factory() as session:
        row = session.get(Credential, credential["id"])
        assert secret.encode() not in row.encrypted_secret
        assert row.encrypted_secret != secret.encode()
    listed = client.get("/api/v1/admin/credentials", headers=auth(admin_key))
    assert listed.status_code == 200
    assert secret not in listed.text
    assert "encrypted_secret" not in listed.text
    assert "nonce" not in listed.text


def test_auth_authorization_revocation_and_isolation(enrolled):
    (_app, client, admin_key, _admin_id, _key), credential, _secret = enrolled
    allowed = create_otp_client(client, admin_key, "allowed")
    isolated = create_otp_client(client, admin_key, "isolated")

    hidden = client.get(f"/api/v1/otp/{credential['id']}", headers=auth(isolated["api_key"]))
    missing = client.get("/api/v1/otp/00000000-0000-0000-0000-000000000000", headers=auth(isolated["api_key"]))
    assert (hidden.status_code, hidden.json()) == (missing.status_code, missing.json())
    assert hidden.status_code == 404

    grant = client.put(f"/api/v1/admin/clients/{allowed['id']}/permissions/{credential['id']}",
                       headers=auth(admin_key))
    assert grant.status_code == 204
    otp = client.get(f"/api/v1/otp/{credential['id']}", headers=auth(allowed["api_key"]))
    assert otp.status_code == 200
    assert otp.json()["code"].isdigit() and len(otp.json()["code"]) == 6
    assert 1 <= otp.json()["expires_in"] <= 30
    assert client.post(f"/api/v1/admin/clients/{allowed['id']}/revoke", headers=auth(admin_key)).status_code == 204
    assert client.get(f"/api/v1/otp/{credential['id']}", headers=auth(allowed["api_key"])).status_code == 401


def test_expired_key_and_ordinary_client_cannot_admin(enrolled):
    (_app, client, admin_key, _admin_id, _key), _credential, _secret = enrolled
    expired = create_otp_client(client, admin_key, expires_at=datetime.now(UTC) + timedelta(seconds=2))
    ordinary = client.get("/api/v1/admin/credentials", headers=auth(expired["api_key"]))
    assert ordinary.status_code == 403
    app = _app
    with app.state.session_factory() as session:
        row = session.get(ApiClient, expired["id"])
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    assert client.get("/api/v1/admin/credentials", headers=auth(expired["api_key"])).status_code == 401


def test_rate_limits_auth_failures_and_otp(enrolled):
    (_app, client, admin_key, _admin_id, _key), credential, _secret = enrolled
    otp_client = create_otp_client(client, admin_key)
    client.put(f"/api/v1/admin/clients/{otp_client['id']}/permissions/{credential['id']}", headers=auth(admin_key))
    for _ in range(2):
        assert client.get(f"/api/v1/otp/{credential['id']}", headers=auth(otp_client["api_key"])).status_code == 200
    assert client.get(f"/api/v1/otp/{credential['id']}", headers=auth(otp_client["api_key"])).status_code == 429
    assert client.get("/api/v1/admin/credentials", headers=auth("bad-key-1")).status_code == 401
    assert client.get("/api/v1/admin/credentials", headers=auth("bad-key-2")).status_code == 401
    assert client.get("/api/v1/admin/credentials", headers=auth("bad-key-3")).status_code == 429


def test_secret_key_and_otp_absent_from_logs(enrolled, caplog):
    (_app, client, admin_key, _admin_id, _key), credential, secret = enrolled
    otp_client = create_otp_client(client, admin_key)
    client.put(f"/api/v1/admin/clients/{otp_client['id']}/permissions/{credential['id']}", headers=auth(admin_key))
    response = client.get(f"/api/v1/otp/{credential['id']}", headers=auth(otp_client["api_key"]))
    logs = caplog.text
    assert response.status_code == 200
    assert secret not in logs
    assert admin_key not in logs
    assert otp_client["api_key"] not in logs
    assert response.json()["code"] not in logs


def test_invalid_upload_generic_errors_and_health(test_context):
    _app, client, admin_key, _admin_id, _key = test_context
    response = client.post("/api/v1/admin/credentials", content=b"not an image",
                           headers={**auth(admin_key), "content-type": "image/png"})
    assert response.status_code == 400
    assert response.json() == {"detail": "invalid enrollment input"}
    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ok"}


def test_delete_cascades_permissions(enrolled):
    (app, client, admin_key, _admin_id, _key), credential, _secret = enrolled
    otp_client = create_otp_client(client, admin_key)
    client.put(f"/api/v1/admin/clients/{otp_client['id']}/permissions/{credential['id']}", headers=auth(admin_key))
    assert client.delete(f"/api/v1/admin/credentials/{credential['id']}", headers=auth(admin_key)).status_code == 204
    assert client.get(f"/api/v1/otp/{credential['id']}", headers=auth(otp_client["api_key"])).status_code == 404

