from __future__ import annotations

import html
import json
import uuid
from datetime import UTC, datetime
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from app.api import _read_limited_body, _uri_from_request, audit, credential_aad, db, source_address
from app.auth import authenticate, create_api_key
from app.crypto import DecryptionError, decrypt_secret, encrypt_secret
from app.models import ApiClient, Credential, CredentialPermission
from app.totp import EnrollmentError, TotpConfig, generate_totp, parse_otpauth_uri
from app.ui_sessions import WebSession


router = APIRouter(prefix="/ui", include_in_schema=False)
SESSION_COOKIE = "tv_session"
LOGIN_COOKIE = "tv_login"


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def page(title: str, content: str, *, client: ApiClient | None = None, csrf: str | None = None) -> HTMLResponse:
    nav = ""
    if client and csrf:
        nav = f'''<nav><a href="/ui/">TotpVault</a><span>{esc(client.name)} · {esc(client.role)}</span>
        <form method="post" action="/ui/logout"><input type="hidden" name="csrf" value="{esc(csrf)}"><button>Sign out</button></form></nav>'''
    document = f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)} · TotpVault</title>
    <link rel="stylesheet" href="/ui/static/app.css"></head><body>{nav}<main><h1>{esc(title)}</h1>{content}</main></body></html>'''
    return HTMLResponse(document)


async def form_data(request: Request, limit: int = 16_384) -> dict[str, str]:
    try:
        raw = await _read_limited_body(request, limit)
        parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
    except (EnrollmentError, UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="invalid form") from None
    if any(len(values) != 1 for values in parsed.values()):
        raise HTTPException(status_code=400, detail="invalid form")
    return {key: values[0] for key, values in parsed.items()}


def set_cookie(response: Response, name: str, value: str, request: Request, max_age: int) -> None:
    response.set_cookie(name, value, max_age=max_age, httponly=True, secure=request.app.state.settings.ui_secure_cookie,
                        samesite="strict", path="/ui")


def current_identity(request: Request, session: Session) -> tuple[ApiClient, WebSession, str]:
    token = request.cookies.get(SESSION_COOKIE)
    web_session = request.app.state.ui_sessions.get(token)
    if web_session is None:
        raise HTTPException(status_code=303, headers={"Location": "/ui/login"})
    client = session.get(ApiClient, web_session.client_id)
    now = datetime.now(UTC)
    expires = client.expires_at if client else None
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if client is None or client.revoked_at is not None or (expires is not None and expires <= now):
        request.app.state.ui_sessions.revoke(token)
        raise HTTPException(status_code=303, headers={"Location": "/ui/login"})
    return client, web_session, token or ""


def csrf_or_403(request: Request, web_session: WebSession, submitted: str | None) -> None:
    if not request.app.state.ui_sessions.valid_csrf(web_session, submitted):
        raise HTTPException(status_code=403, detail="request rejected")


@router.get("/static/app.css")
def stylesheet() -> Response:
    css = """*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:#17212b;font:16px system-ui,sans-serif}nav{display:flex;gap:1rem;align-items:center;padding:.8rem max(1rem,calc((100% - 980px)/2));background:#132238;color:white}nav a{color:white;font-weight:700;text-decoration:none}nav span{margin-left:auto}nav form{margin:0}main{max-width:980px;margin:2rem auto;padding:0 1rem}h1,h2{line-height:1.2}.card{background:white;border:1px solid #dce2e8;border-radius:10px;padding:1.2rem;margin:1rem 0;box-shadow:0 2px 8px #17212b0d}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}label{display:block;font-weight:650;margin:.8rem 0 .3rem}input,select,button,textarea{font:inherit}input,select,textarea{width:100%;padding:.65rem;border:1px solid #9aa9b5;border-radius:6px}button,.button{display:inline-block;background:#1261a0;color:white;border:0;border-radius:6px;padding:.62rem .9rem;text-decoration:none;cursor:pointer}.danger{background:#a12622}.muted{color:#586875;font-size:.9rem}.secret{font:700 1rem ui-monospace,monospace;overflow-wrap:anywhere;background:#eef3f7;padding:1rem;border-radius:6px}.otp{font:800 2.5rem ui-monospace,monospace;letter-spacing:.18em}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #dce2e8;padding:.65rem .4rem}form.inline{display:inline}#message{min-height:1.4rem}.error{color:#9b1c1c}@media(max-width:650px){table{display:block;overflow:auto}nav span{display:none}}"""
    return Response(css, media_type="text/css")


@router.get("/static/app.js")
def javascript() -> Response:
    script = """'use strict';const form=document.getElementById('qr-form');if(form){form.addEventListener('submit',async(e)=>{e.preventDefault();const file=document.getElementById('qr-file').files[0];const msg=document.getElementById('message');if(!file){msg.textContent='Choose a PNG or JPEG image.';return}if(!['image/png','image/jpeg'].includes(file.type)){msg.textContent='Only PNG or JPEG images are accepted.';return}msg.textContent='Importing…';try{const response=await fetch('/ui/admin/credentials/qr',{method:'POST',headers:{'Content-Type':file.type,'X-CSRF-Token':form.dataset.csrf},body:file,credentials:'same-origin'});if(!response.ok){throw new Error('The QR code could not be imported.')}location.href='/ui/'}catch(error){msg.textContent=error.message;msg.className='error'}})}const otpForm=document.getElementById('otp-refresh');if(otpForm){const countdown=document.getElementById('otp-countdown');let remaining=Number(otpForm.dataset.expires);const tick=()=>{countdown.textContent=String(Math.max(remaining,0));if(remaining<=0){otpForm.requestSubmit();return}remaining-=1;setTimeout(tick,1000)};tick()}"""
    return Response(script, media_type="application/javascript")


@router.get("/login")
def login_page(request: Request) -> Response:
    nonce = request.app.state.ui_sessions.issue_login_nonce()
    response = page("Sign in", f'''<div class="card"><p>Use an administrator key to manage the vault or an OTP-client key to view assigned codes.</p>
    <form method="post" action="/ui/login"><input type="hidden" name="login_token" value="{esc(nonce)}">
    <label for="api_key">API key</label><input id="api_key" name="api_key" type="password" required autocomplete="current-password" maxlength="128">
    <p><button type="submit">Sign in</button></p></form></div>''')
    set_cookie(response, LOGIN_COOKIE, nonce, request, 300)
    return response


@router.post("/login")
async def login(request: Request, session: Session = Depends(db)) -> Response:
    values = await form_data(request)
    if not request.app.state.ui_sessions.consume_login_nonce(request.cookies.get(LOGIN_COOKIE), values.get("login_token", "")):
        raise HTTPException(status_code=403, detail="request rejected")
    address = source_address(request)
    if not request.app.state.limiter.allow(f"ui-login:{address}", request.app.state.settings.auth_failure_rate_limit,
                                           request.app.state.settings.rate_window_seconds):
        raise HTTPException(status_code=429, detail="request rejected")
    client = authenticate(session, values.get("api_key", ""))
    if client is None:
        audit(session, request, "ui_login", "rejected")
        return page("Sign in failed", '<div class="card"><p>Authentication failed.</p><a class="button" href="/ui/login">Try again</a></div>')
    token, _web_session = request.app.state.ui_sessions.create(client.id)
    audit(session, request, "ui_login", "success", actor=client.id)
    response = RedirectResponse("/ui/", status_code=303)
    set_cookie(response, SESSION_COOKIE, token, request, request.app.state.settings.ui_session_minutes * 60)
    response.delete_cookie(LOGIN_COOKIE, path="/ui")
    return response


@router.post("/logout")
async def logout(request: Request, session: Session = Depends(db)) -> Response:
    client, web_session, token = current_identity(request, session)
    values = await form_data(request)
    csrf_or_403(request, web_session, values.get("csrf"))
    request.app.state.ui_sessions.revoke(token)
    audit(session, request, "ui_logout", "success", actor=client.id)
    response = RedirectResponse("/ui/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/ui")
    return response


@router.get("/")
def dashboard(request: Request, session: Session = Depends(db)) -> Response:
    client, web_session, _token = current_identity(request, session)
    if client.role == "admin":
        credentials = list(session.scalars(select(Credential).order_by(Credential.issuer, Credential.account_name)))
        clients = list(session.scalars(select(ApiClient).order_by(ApiClient.name)))
        credential_rows = "".join(f'''<tr><td>{esc(item.issuer)}</td><td>{esc(item.account_name)}</td><td>{esc(item.algorithm)} / {item.digits} / {item.period}s</td>
        <td><form class="inline" method="post" action="/ui/admin/credentials/{item.id}/delete"><input type="hidden" name="csrf" value="{esc(web_session.csrf_token)}"><button class="danger">Delete</button></form></td></tr>''' for item in credentials) or '<tr><td colspan="4">No credentials enrolled.</td></tr>'
        client_rows = "".join(f'''<tr><td>{esc(item.name)}</td><td>{esc(item.role)}</td><td>{'revoked' if item.revoked_at else 'active'}</td><td>{esc(item.id)}</td>
        <td>{'' if item.id == client.id or item.revoked_at else f'<form class="inline" method="post" action="/ui/admin/clients/{item.id}/revoke"><input type="hidden" name="csrf" value="{esc(web_session.csrf_token)}"><button class="danger">Revoke</button></form>'}</td></tr>''' for item in clients)
        otp_clients = [item for item in clients if item.role == "otp" and item.revoked_at is None]
        options_clients = "".join(f'<option value="{item.id}">{esc(item.name)}</option>' for item in otp_clients)
        options_credentials = "".join(f'<option value="{item.id}">{esc(item.issuer)} — {esc(item.account_name)}</option>' for item in credentials)
        content = f'''<div class="grid"><section class="card"><h2>Import QR code</h2><form id="qr-form" data-csrf="{esc(web_session.csrf_token)}"><label for="qr-file">PNG or JPEG</label><input id="qr-file" type="file" accept="image/png,image/jpeg" required><p><button>Import QR</button></p><p id="message" class="muted"></p></form><script src="/ui/static/app.js" defer></script></section>
        <section class="card"><h2>Import URI</h2><form method="post" action="/ui/admin/credentials/uri"><input type="hidden" name="csrf" value="{esc(web_session.csrf_token)}"><label for="uri">otpauth URI</label><input id="uri" name="uri" type="password" required autocomplete="off" maxlength="4096"><p><button>Import URI</button></p></form></section></div>
        <section class="card"><h2>Credentials</h2><table><thead><tr><th>Issuer</th><th>Account</th><th>Configuration</th><th></th></tr></thead><tbody>{credential_rows}</tbody></table></section>
        <div class="grid"><section class="card"><h2>Create API client</h2><form method="post" action="/ui/admin/clients"><input type="hidden" name="csrf" value="{esc(web_session.csrf_token)}"><label for="name">Name</label><input id="name" name="name" maxlength="128" required><label for="role">Role</label><select id="role" name="role"><option value="otp">OTP client</option><option value="admin">Administrator</option></select><p><button>Create client</button></p></form></section>
        <section class="card"><h2>Grant access</h2><form method="post" action="/ui/admin/permissions"><input type="hidden" name="csrf" value="{esc(web_session.csrf_token)}"><label>OTP client</label><select name="client_id" required>{options_clients}</select><label>Credential</label><select name="credential_id" required>{options_credentials}</select><p><button>Grant permission</button></p></form></section></div>
        <section class="card"><h2>API clients</h2><table><thead><tr><th>Name</th><th>Role</th><th>Status</th><th>ID</th><th></th></tr></thead><tbody>{client_rows}</tbody></table></section>'''
        return page("Vault administration", content, client=client, csrf=web_session.csrf_token)
    credentials = list(session.scalars(select(Credential).join(CredentialPermission).where(
        CredentialPermission.client_id == client.id).order_by(Credential.issuer, Credential.account_name)))
    cards = "".join(f'''<article class="card"><h2>{esc(item.issuer)}</h2><p>{esc(item.account_name)}</p><form method="post" action="/ui/otp/{item.id}"><input type="hidden" name="csrf" value="{esc(web_session.csrf_token)}"><button>Generate code</button></form></article>''' for item in credentials) or '<div class="card"><p>No credentials are assigned to this client.</p></div>'
    return page("My OTP credentials", f'<div class="grid">{cards}</div>', client=client, csrf=web_session.csrf_token)


def require_admin_ui(request: Request, session: Session) -> tuple[ApiClient, WebSession]:
    client, web_session, _token = current_identity(request, session)
    if client.role != "admin":
        raise HTTPException(status_code=403, detail="request rejected")
    return client, web_session


def enroll_config(request: Request, session: Session, admin: ApiClient, config: TotpConfig) -> Credential:
    item = Credential(id=str(uuid.uuid4()), issuer=config.issuer, account_name=config.account_name,
                      encrypted_secret=b"", nonce=b"", algorithm=config.algorithm,
                      digits=config.digits, period=config.period)
    item.encrypted_secret, item.nonce = encrypt_secret(request.app.state.master_key, config.secret, credential_aad(item))
    session.add(item)
    session.commit()
    audit(session, request, "credential_created", "success", actor=admin.id, credential=item.id)
    return item


@router.post("/admin/credentials/uri")
async def enroll_uri(request: Request, session: Session = Depends(db)) -> Response:
    admin, web_session = require_admin_ui(request, session)
    values = await form_data(request, 8_192)
    csrf_or_403(request, web_session, values.get("csrf"))
    try:
        config = parse_otpauth_uri(values.get("uri", ""))
    except EnrollmentError:
        audit(session, request, "credential_created", "rejected", actor=admin.id)
        return page("Import failed", '<div class="card"><p>The TOTP URI is invalid.</p><a class="button" href="/ui/">Return</a></div>', client=admin, csrf=web_session.csrf_token)
    enroll_config(request, session, admin, config)
    return RedirectResponse("/ui/", status_code=303)


@router.post("/admin/credentials/qr")
async def enroll_qr(request: Request, session: Session = Depends(db)) -> Response:
    admin, web_session = require_admin_ui(request, session)
    csrf_or_403(request, web_session, request.headers.get("x-csrf-token"))
    try:
        body = await _read_limited_body(request, request.app.state.settings.max_qr_bytes)
        config = parse_otpauth_uri(_uri_from_request(request, body))
    except EnrollmentError:
        audit(session, request, "credential_created", "rejected", actor=admin.id)
        raise HTTPException(status_code=400, detail="invalid enrollment input") from None
    enroll_config(request, session, admin, config)
    return Response(status_code=204)


@router.post("/admin/credentials/{credential_id}/delete")
async def ui_delete_credential(credential_id: str, request: Request, session: Session = Depends(db)) -> Response:
    admin, web_session = require_admin_ui(request, session)
    values = await form_data(request)
    csrf_or_403(request, web_session, values.get("csrf"))
    item = session.get(Credential, credential_id)
    if item is None:
        raise HTTPException(status_code=404, detail="resource unavailable")
    session.delete(item)
    session.commit()
    audit(session, request, "credential_deleted", "success", actor=admin.id, credential=credential_id)
    return RedirectResponse("/ui/", status_code=303)


@router.post("/admin/clients")
async def ui_create_client(request: Request, session: Session = Depends(db)) -> Response:
    admin, web_session = require_admin_ui(request, session)
    values = await form_data(request)
    csrf_or_403(request, web_session, values.get("csrf"))
    name, role = values.get("name", "").strip(), values.get("role", "")
    if not name or len(name) > 128 or role not in {"admin", "otp"}:
        raise HTTPException(status_code=400, detail="invalid form")
    generated = create_api_key()
    client = ApiClient(name=name, key_id=generated.key_id, key_hash=generated.verifier, role=role)
    session.add(client)
    session.commit()
    audit(session, request, "api_client_created", "success", actor=admin.id,
          metadata={"created_client_id": client.id, "role": role})
    content = f'''<div class="card"><p>Store this key now. It cannot be recovered later.</p><div class="secret">{esc(generated.plaintext)}</div><p><a class="button" href="/ui/">Return to administration</a></p></div>'''
    return page("API client created", content, client=admin, csrf=web_session.csrf_token)


@router.post("/admin/permissions")
async def ui_grant_permission(request: Request, session: Session = Depends(db)) -> Response:
    admin, web_session = require_admin_ui(request, session)
    values = await form_data(request)
    csrf_or_403(request, web_session, values.get("csrf"))
    client_id, credential_id = values.get("client_id", ""), values.get("credential_id", "")
    target, credential = session.get(ApiClient, client_id), session.get(Credential, credential_id)
    if target is None or target.role != "otp" or target.revoked_at is not None or credential is None:
        raise HTTPException(status_code=404, detail="resource unavailable")
    if session.get(CredentialPermission, (client_id, credential_id)) is None:
        session.add(CredentialPermission(client_id=client_id, credential_id=credential_id))
        session.commit()
    audit(session, request, "permission_granted", "success", actor=admin.id, credential=credential_id,
          metadata={"target_client_id": client_id})
    return RedirectResponse("/ui/", status_code=303)


@router.post("/admin/clients/{client_id}/revoke")
async def ui_revoke_client(client_id: str, request: Request, session: Session = Depends(db)) -> Response:
    admin, web_session = require_admin_ui(request, session)
    values = await form_data(request)
    csrf_or_403(request, web_session, values.get("csrf"))
    target = session.get(ApiClient, client_id)
    if target is None:
        raise HTTPException(status_code=404, detail="resource unavailable")
    if target.id == admin.id:
        raise HTTPException(status_code=409, detail="cannot revoke the active administrator")
    target.revoked_at = datetime.now(UTC)
    session.commit()
    audit(session, request, "api_client_revoked", "success", actor=admin.id,
          metadata={"revoked_client_id": target.id})
    return RedirectResponse("/ui/", status_code=303)


@router.post("/otp/{credential_id}")
async def ui_otp(credential_id: str, request: Request, session: Session = Depends(db)) -> Response:
    client, web_session, _token = current_identity(request, session)
    values = await form_data(request)
    csrf_or_403(request, web_session, values.get("csrf"))
    if client.role != "otp" or not request.app.state.limiter.allow(
            f"otp:{client.id}", request.app.state.settings.otp_rate_limit,
            request.app.state.settings.rate_window_seconds):
        raise HTTPException(status_code=429, detail="request rejected")
    item = session.scalar(select(Credential).join(CredentialPermission).where(and_(
        Credential.id == credential_id, CredentialPermission.client_id == client.id)))
    if item is None:
        raise HTTPException(status_code=404, detail="resource unavailable")
    try:
        secret = decrypt_secret(request.app.state.master_key, item.encrypted_secret, item.nonce, credential_aad(item))
        code, expires = generate_totp(TotpConfig(item.issuer, item.account_name, secret, item.algorithm,
                                                  item.digits, item.period))
    except DecryptionError:
        raise HTTPException(status_code=503, detail="service unavailable") from None
    audit(session, request, "otp_request", "success", actor=client.id, credential=item.id)
    content = f'''<div class="card"><h2>{esc(item.issuer)}</h2><p>{esc(item.account_name)}</p><div class="otp">{esc(code)}</div>
    <p>Automatically refreshes in <strong id="otp-countdown">{expires}</strong> seconds.</p>
    <form id="otp-refresh" method="post" action="/ui/otp/{item.id}" data-expires="{expires}"><input type="hidden" name="csrf" value="{esc(web_session.csrf_token)}"><noscript><button>Refresh code</button></noscript></form>
    <p><a class="button" href="/ui/">Back</a></p><script src="/ui/static/app.js" defer></script></div>'''
    return page("Current OTP", content, client=client, csrf=web_session.csrf_token)
