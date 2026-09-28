from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DecryptionError(RuntimeError):
    pass


def associated_data(*, credential_id: str, issuer: str, account_name: str, algorithm: str, digits: int, period: int) -> bytes:
    return json.dumps(
        [1, credential_id, issuer, account_name, algorithm, digits, period],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def encrypt_secret(key: bytes, secret: str, aad: bytes) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = os.urandom(12)
    return AESGCM(key).encrypt(nonce, secret.encode("ascii"), aad), nonce


def decrypt_secret(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes) -> str:
    try:
        cleartext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        return cleartext.decode("ascii")
    except (InvalidTag, UnicodeDecodeError, ValueError) as exc:
        raise DecryptionError("credential decryption failed") from exc

