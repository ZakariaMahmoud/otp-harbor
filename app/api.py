from __future__ import annotations

import io
import json
import logging
import uuid
from datetime import UTC, datetime

import zxingcpp
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from PIL import Image, UnidentifiedImageError
from sqlalchemy import and_, desc, select
from sqlalchemy.orm import Session

from app.auth import authenticate, create_api_key, parse_key_id
from app.crypto import DecryptionError, associated_data, decrypt_secret, encrypt_secret
from app.models import ApiClient, AuditEvent, Credential, CredentialPermission
from app.schemas import AuditOut, ClientCreate, ClientCreated, ClientOut, CredentialOut, OtpOut
from app.totp import EnrollmentError, TotpConfig, generate_totp, parse_otpauth_uri

logger = logging.getLogger("totpvault.audit")
router = APIRouter(prefix="/api/v1")


def db(request: Request):
    with request.app.state.session_factory() as session:
        yield session


def source_address(request: Request) -> str:
    return request.client.host[:64] if request.client else "unknown"


def audit(session: Session, request: Request, event: str, outcome: str, *, actor: str | None = None,
          credential: str | None = None, metadata: dict | None = None) -> None:
    safe_metadata = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)
    session.add(AuditEvent(event_type=event, outcome=outcome, actor_client_id=actor,
                           credential_id=credential, request_id=getattr(request.state, "request_id", None),
                           source_address=source_address(request), metadata_json=safe_metadata))
    session.commit()
    logger.info("audit event=%s outcome=%s actor=%s credential=%s request_id=%s", event, outcome,
                actor or "-", credential or "-", getattr(request.state, "request_id", "-"))


def bearer(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, sep, value = header.partition(" ")
    if not sep or scheme.lower() != "bearer" or not value or len(value) > 128:
        return None
    return value


def require_client(request: Request, session: Session = Depends(db)) -> ApiClient:
    token = bearer(request)
    key_id = parse_key_id(token) if token else None
    limiter = request.app.state.limiter
    address = source_address(request)
    client = authenticate(session, token or "")
    if client is None:
        if not limiter.allow(f"auth:{address}", request.app.state.settings.auth_failure_rate_limit,
                             request.app.state.settings.rate_window_seconds):
            raise HTTPException(status_code=429, detail="request rejected")
        audit(session, request, "authentication_rejected", "rejected", metadata={"key_id": key_id} if key_id else {})
        raise HTTPException(status_code=401, detail="request rejected", headers={"WWW-Authenticate": "Bearer"})
    return client


def require_admin(client: ApiClient = Depends(require_client)) -> ApiClient:
    if client.role != "admin":
        raise HTTPException(status_code=403, detail="request rejected")
    return client


def credential_aad(item: Credential) -> bytes:
    return associated_data(credential_id=item.id, issuer=item.issuer, account_name=item.account_name,
                           algorithm=item.algorithm, digits=item.digits, period=item.period)


@router.get("/otp/{credential_id}", response_model=OtpOut)
def current_otp(credential_id: str, request: Request, session: Session = Depends(db),
                client: ApiClient = Depends(require_client)) -> OtpOut:
    if not request.app.state.limiter.allow(f"otp:{client.id}", request.app.state.settings.otp_rate_limit,
                                           request.app.state.settings.rate_window_seconds):
        audit(session, request, "otp_request", "rate_limited", actor=client.id)
        raise HTTPException(status_code=429, detail="request rejected")
    item = session.scalar(select(Credential).join(CredentialPermission).where(and_(
        Credential.id == credential_id, CredentialPermission.client_id == client.id)))
    if item is None:
        audit(session, request, "otp_request", "rejected", actor=client.id)
        raise HTTPException(status_code=404, detail="resource unavailable")
    try:
        secret = decrypt_secret(request.app.state.master_key, item.encrypted_secret, item.nonce, credential_aad(item))
        code, expires = generate_totp(TotpConfig(item.issuer, item.account_name, secret, item.algorithm,
                                                  item.digits, item.period))
    except DecryptionError:
        audit(session, request, "otp_request", "error", actor=client.id, credential=item.id)
        raise HTTPException(status_code=503, detail="service unavailable") from None
    audit(session, request, "otp_request", "success", actor=client.id, credential=item.id)
    return OtpOut(code=code, expires_in=expires)


def _uri_from_request(request: Request, body: bytes) -> str:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type == "application/json":
        try:
            value = json.loads(body)
            if set(value) != {"uri"} or not isinstance(value["uri"], str):
                raise ValueError
            return value["uri"]
        except (json.JSONDecodeError, TypeError, ValueError):
            raise EnrollmentError("invalid enrollment input") from None
    if content_type not in {"image/png", "image/jpeg"}:
        raise EnrollmentError("invalid enrollment input")
    try:
        image = Image.open(io.BytesIO(body))
        if image.width * image.height > 16_000_000 or image.width > 4096 or image.height > 4096:
            raise EnrollmentError("invalid enrollment input")
        image.load()
        results = zxingcpp.read_barcodes(image)
        if len(results) != 1 or results[0].format != zxingcpp.BarcodeFormat.QRCode:
            raise EnrollmentError("invalid enrollment input")
        return results[0].text
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, ValueError):
        raise EnrollmentError("invalid enrollment input") from None


async def _read_limited_body(request: Request, limit: int) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise EnrollmentError("invalid enrollment input")
        body.extend(chunk)
    return bytes(body)


@router.post("/admin/credentials", response_model=CredentialOut, status_code=201)
async def create_credential(request: Request, session: Session = Depends(db),
                            admin: ApiClient = Depends(require_admin)) -> Credential:
    try:
        body = await _read_limited_body(request, request.app.state.settings.max_qr_bytes)
    except EnrollmentError:
        raise HTTPException(status_code=400, detail="invalid enrollment input") from None
    if not body:
        raise HTTPException(status_code=400, detail="invalid enrollment input")
    try:
        config = parse_otpauth_uri(_uri_from_request(request, body))
    except EnrollmentError:
        audit(session, request, "credential_created", "rejected", actor=admin.id)
        raise HTTPException(status_code=400, detail="invalid enrollment input") from None
    item = Credential(id=str(uuid.uuid4()), issuer=config.issuer, account_name=config.account_name,
                      encrypted_secret=b"", nonce=b"", algorithm=config.algorithm,
                      digits=config.digits, period=config.period)
    item.encrypted_secret, item.nonce = encrypt_secret(request.app.state.master_key, config.secret, credential_aad(item))
    session.add(item)
    session.commit()
    audit(session, request, "credential_created", "success", actor=admin.id, credential=item.id)
    return item


@router.get("/admin/credentials", response_model=list[CredentialOut])
def list_credentials(session: Session = Depends(db), _admin: ApiClient = Depends(require_admin)) -> list[Credential]:
    return list(session.scalars(select(Credential).order_by(Credential.created_at)))


@router.delete("/admin/credentials/{credential_id}", status_code=204)
def delete_credential(credential_id: str, request: Request, session: Session = Depends(db),
                      admin: ApiClient = Depends(require_admin)) -> Response:
    item = session.get(Credential, credential_id)
    if item is None:
        raise HTTPException(status_code=404, detail="resource unavailable")
    session.delete(item)
    session.commit()
    audit(session, request, "credential_deleted", "success", actor=admin.id, credential=credential_id)
    return Response(status_code=204)


@router.post("/admin/clients", response_model=ClientCreated, status_code=201)
def create_client(payload: ClientCreate, request: Request, session: Session = Depends(db),
                  admin: ApiClient = Depends(require_admin)) -> ClientCreated:
    expires = payload.expires_at
    if expires is not None:
        if expires.tzinfo is None:
            raise HTTPException(status_code=422, detail="expires_at must include a timezone")
        if expires.astimezone(UTC) <= datetime.now(UTC):
            raise HTTPException(status_code=422, detail="expires_at must be in the future")
    generated = create_api_key()
    client = ApiClient(name=payload.name.strip(), key_id=generated.key_id, key_hash=generated.verifier,
                       role=payload.role, expires_at=expires)
    session.add(client)
    session.commit()
    audit(session, request, "api_client_created", "success", actor=admin.id,
          metadata={"created_client_id": client.id, "role": client.role})
    return ClientCreated(id=client.id, name=client.name, role=client.role,
                         expires_at=client.expires_at, api_key=generated.plaintext)


@router.get("/admin/clients", response_model=list[ClientOut])
def list_clients(session: Session = Depends(db), _admin: ApiClient = Depends(require_admin)) -> list[ApiClient]:
    return list(session.scalars(select(ApiClient).order_by(ApiClient.created_at)))


@router.post("/admin/clients/{client_id}/revoke", status_code=204)
def revoke_client(client_id: str, request: Request, session: Session = Depends(db),
                  admin: ApiClient = Depends(require_admin)) -> Response:
    client = session.get(ApiClient, client_id)
    if client is None:
        raise HTTPException(status_code=404, detail="resource unavailable")
    if client.id == admin.id:
        raise HTTPException(status_code=409, detail="cannot revoke the active administrator")
    client.revoked_at = datetime.now(UTC)
    session.commit()
    audit(session, request, "api_client_revoked", "success", actor=admin.id,
          metadata={"revoked_client_id": client.id})
    return Response(status_code=204)


@router.put("/admin/clients/{client_id}/permissions/{credential_id}", status_code=204)
def grant_permission(client_id: str, credential_id: str, request: Request, session: Session = Depends(db),
                     admin: ApiClient = Depends(require_admin)) -> Response:
    client, credential = session.get(ApiClient, client_id), session.get(Credential, credential_id)
    if client is None or credential is None or client.role != "otp":
        raise HTTPException(status_code=404, detail="resource unavailable")
    if session.get(CredentialPermission, (client_id, credential_id)) is None:
        session.add(CredentialPermission(client_id=client_id, credential_id=credential_id))
        session.commit()
    audit(session, request, "permission_granted", "success", actor=admin.id, credential=credential_id,
          metadata={"target_client_id": client_id})
    return Response(status_code=204)


@router.delete("/admin/clients/{client_id}/permissions/{credential_id}", status_code=204)
def revoke_permission(client_id: str, credential_id: str, request: Request, session: Session = Depends(db),
                      admin: ApiClient = Depends(require_admin)) -> Response:
    permission = session.get(CredentialPermission, (client_id, credential_id))
    if permission is not None:
        session.delete(permission)
        session.commit()
    audit(session, request, "permission_revoked", "success", actor=admin.id, credential=credential_id,
          metadata={"target_client_id": client_id})
    return Response(status_code=204)


@router.get("/admin/audit-events", response_model=list[AuditOut])
def list_audit_events(limit: int = 100, session: Session = Depends(db),
                      _admin: ApiClient = Depends(require_admin)) -> list[AuditEvent]:
    limit = max(1, min(limit, 500))
    return list(session.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(limit)))
