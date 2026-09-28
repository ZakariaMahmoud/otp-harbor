from __future__ import annotations

import re

from app.auth import create_api_key
from app.models import ApiClient, CredentialPermission


def login(client, api_key: str):
    page = client.get("/ui/login")
    assert page.status_code == 200
    nonce = re.search(r'name="login_token" value="([^"]+)"', page.text).group(1)
    return client.post("/ui/login", data={"login_token": nonce, "api_key": api_key}, follow_redirects=False)


def csrf_from(text: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', text).group(1)


def test_admin_ui_login_csrf_and_uri_enrollment(test_context):
    _app, client, admin_key, _admin_id, _key = test_context
    anonymous = client.get("/ui/", follow_redirects=False)
    assert anonymous.status_code == 303
    assert "connect-src 'self'" in anonymous.headers["content-security-policy"]
    response = login(client, admin_key)
    assert response.status_code == 303
    dashboard = client.get("/ui/")
    assert "Vault administration" in dashboard.text
    csrf = csrf_from(dashboard.text)
    uri = "otpauth://totp/Example:web-user?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    rejected = client.post("/ui/admin/credentials/uri", data={"csrf": "wrong", "uri": uri})
    assert rejected.status_code == 403
    enrolled = client.post("/ui/admin/credentials/uri", data={"csrf": csrf, "uri": uri}, follow_redirects=False)
    assert enrolled.status_code == 303
    assert "web-user" in client.get("/ui/").text


def test_ui_client_isolation_and_otp(enrolled):
    (app, client, admin_key, _admin_id, _key), credential, _secret = enrolled
    assert login(client, admin_key).status_code == 303
    dashboard = client.get("/ui/")
    csrf = csrf_from(dashboard.text)
    created = client.post("/ui/admin/clients", data={"csrf": csrf, "name": "browser client", "role": "otp"})
    api_key = re.search(r'<div class="secret">([^<]+)</div>', created.text).group(1)
    with app.state.session_factory() as session:
        target = session.query(ApiClient).filter_by(name="browser client").one()
        target_id = target.id
    dashboard = client.get("/ui/")
    csrf = csrf_from(dashboard.text)
    assert client.post("/ui/admin/permissions", data={"csrf": csrf, "client_id": target_id,
                                                       "credential_id": credential["id"]},
                       follow_redirects=False).status_code == 303
    logout_csrf = csrf_from(client.get("/ui/").text)
    assert client.post("/ui/logout", data={"csrf": logout_csrf}, follow_redirects=False).status_code == 303
    assert login(client, api_key).status_code == 303
    client_dashboard = client.get("/ui/")
    assert credential["issuer"] in client_dashboard.text
    csrf = csrf_from(client_dashboard.text)
    otp = client.post(f"/ui/otp/{credential['id']}", data={"csrf": csrf})
    assert otp.status_code == 200
    assert re.search(r'<div class="otp">\d{6}</div>', otp.text)
    assert 'id="otp-refresh"' in otp.text
    assert re.search(r'data-expires="(?:[1-9]|[12]\d|30)"', otp.text)
    assert '<script src="/ui/static/app.js" defer></script>' in otp.text


def test_login_nonce_is_single_use(test_context):
    _app, client, admin_key, _admin_id, _key = test_context
    page = client.get("/ui/login")
    nonce = re.search(r'name="login_token" value="([^"]+)"', page.text).group(1)
    assert client.post("/ui/login", data={"login_token": nonce, "api_key": admin_key}, follow_redirects=False).status_code == 303
    assert client.post("/ui/login", data={"login_token": nonce, "api_key": admin_key}, follow_redirects=False).status_code == 403
