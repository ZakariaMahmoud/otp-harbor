from __future__ import annotations

import os

import pytest

from app.crypto import DecryptionError, decrypt_secret, encrypt_secret
from app.totp import EnrollmentError, generate_totp, parse_otpauth_uri


def test_authenticated_encryption_rejects_wrong_key_and_corruption():
    key, aad = os.urandom(32), b"bound metadata"
    ciphertext, nonce = encrypt_secret(key, "JBSWY3DPEHPK3PXP", aad)
    assert decrypt_secret(key, ciphertext, nonce, aad) == "JBSWY3DPEHPK3PXP"
    with pytest.raises(DecryptionError):
        decrypt_secret(os.urandom(32), ciphertext, nonce, aad)
    with pytest.raises(DecryptionError):
        decrypt_secret(key, bytes([ciphertext[0] ^ 1]) + ciphertext[1:], nonce, aad)
    with pytest.raises(DecryptionError):
        decrypt_secret(key, ciphertext, nonce, b"other metadata")


def test_rfc6238_sha1_vector():
    config = parse_otpauth_uri(
        "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test&digits=8&period=30"
    )
    code, expires = generate_totp(config, at_time=59)
    assert code == "94287082"
    assert expires == 1


@pytest.mark.parametrize("uri", [
    "https://example.com/qr",
    "otpauth://hotp/Test:a?secret=JBSWY3DPEHPK3PXP&issuer=Test",
    "otpauth://totp/Test:a?secret=NOT*BASE32&issuer=Test",
    "otpauth://totp/Test:a?secret=JBSWY3DPEHPK3PXP&issuer=Other",
    "otpauth://totp/Test:a?secret=JBSWY3DPEHPK3PXP&issuer=Test&digits=7",
    "otpauth://totp/Test:a?secret=JBSWY3DPEHPK3PXP&issuer=Test&period=5",
    "otpauth://totp/Test:a?secret=JBSWY3DPEHPK3PXP&issuer=Test&image=https://evil.invalid/a",
    "otpauth://totp/Test:a?secret=JBSWY3DPEHPK3PXP&secret=JBSWY3DPEHPK3PXP&issuer=Test",
])
def test_rejects_malformed_enrollment(uri):
    with pytest.raises(EnrollmentError):
        parse_otpauth_uri(uri)

