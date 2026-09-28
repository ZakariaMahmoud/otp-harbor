from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import ApiClient


KEY_PREFIX = "oh1"
LEGACY_KEY_PREFIX = "tv1"
DUMMY_HASH = hashlib.sha256(b"otp-harbor-dummy-verifier").digest()


@dataclass(frozen=True)
class NewApiKey:
    plaintext: str
    key_id: str
    verifier: bytes


def hash_api_key(plaintext: str) -> bytes:
    return hashlib.sha256(b"OTP Harbor API key v1\0" + plaintext.encode("utf-8")).digest()


def legacy_hash_api_key(plaintext: str) -> bytes:
    """Verify keys issued before the public project rename."""
    return hashlib.sha256(b"Totp" + b"Vault API key v1\0" + plaintext.encode("utf-8")).digest()


def create_api_key() -> NewApiKey:
    key_id = secrets.token_urlsafe(9)
    secret = secrets.token_urlsafe(32)
    plaintext = f"{KEY_PREFIX}.{key_id}.{secret}"
    return NewApiKey(plaintext, key_id, hash_api_key(plaintext))


def parse_key_id(plaintext: str) -> str | None:
    parts = plaintext.split(".")
    if len(parts) != 3 or parts[0] not in {KEY_PREFIX, LEGACY_KEY_PREFIX} or not 8 <= len(parts[1]) <= 24 or len(plaintext) > 128:
        return None
    return parts[1]


def authenticate(session: Session, plaintext: str) -> ApiClient | None:
    key_id = parse_key_id(plaintext)
    client = session.scalar(select(ApiClient).where(ApiClient.key_id == key_id)) if key_id else None
    expected = client.key_hash if client is not None else DUMMY_HASH
    valid = hmac.compare_digest(hash_api_key(plaintext), expected)
    if not valid and plaintext.startswith(f"{LEGACY_KEY_PREFIX}."):
        valid = hmac.compare_digest(legacy_hash_api_key(plaintext), expected)
    now = datetime.now(UTC)
    if not valid or client is None or client.revoked_at is not None:
        return None
    expires_at = client.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            return None
    client.last_used_at = now
    session.commit()
    return client
