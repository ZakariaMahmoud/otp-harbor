from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

import pyotp


class EnrollmentError(ValueError):
    pass


@dataclass(frozen=True)
class TotpConfig:
    issuer: str
    account_name: str
    secret: str
    algorithm: str
    digits: int
    period: int


def parse_otpauth_uri(uri: str) -> TotpConfig:
    if len(uri) > 4096:
        raise EnrollmentError("invalid TOTP configuration")
    parsed = urlsplit(uri)
    if parsed.scheme != "otpauth" or parsed.netloc.lower() != "totp" or parsed.fragment:
        raise EnrollmentError("invalid TOTP configuration")
    label = unquote(parsed.path.lstrip("/"))
    if not label or len(label) > 385 or any(ord(c) < 32 for c in label):
        raise EnrollmentError("invalid TOTP configuration")
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    allowed = {"secret", "issuer", "algorithm", "digits", "period"}
    if set(query) - allowed or any(len(values) != 1 for values in query.values()):
        raise EnrollmentError("invalid TOTP configuration")
    issuer_from_label, sep, account = label.partition(":")
    query_issuer = query.get("issuer", [""])[0].strip()
    issuer = issuer_from_label.strip() if sep else query_issuer
    account_name = account.strip() if sep else label.strip()
    if sep and query_issuer and issuer != query_issuer:
        raise EnrollmentError("invalid TOTP configuration")
    if not issuer or not account_name or len(issuer) > 128 or len(account_name) > 256:
        raise EnrollmentError("invalid TOTP configuration")
    algorithm = query.get("algorithm", ["SHA1"])[0].upper()
    if algorithm not in {"SHA1", "SHA256", "SHA512"}:
        raise EnrollmentError("invalid TOTP configuration")
    try:
        digits = int(query.get("digits", ["6"])[0])
        period = int(query.get("period", ["30"])[0])
    except ValueError as exc:
        raise EnrollmentError("invalid TOTP configuration") from exc
    if digits not in {6, 8} or not 15 <= period <= 120:
        raise EnrollmentError("invalid TOTP configuration")
    secret = query.get("secret", [""])[0].replace(" ", "").upper().rstrip("=")
    if not 16 <= len(secret) <= 256 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for c in secret):
        raise EnrollmentError("invalid TOTP configuration")
    try:
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        decoded = base64.b32decode(padded, casefold=False)
    except (binascii.Error, ValueError) as exc:
        raise EnrollmentError("invalid TOTP configuration") from exc
    if len(decoded) < 10:
        raise EnrollmentError("invalid TOTP configuration")
    return TotpConfig(issuer, account_name, secret, algorithm, digits, period)


def generate_totp(config: TotpConfig, at_time: float | None = None) -> tuple[str, int]:
    digests = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
    totp = pyotp.TOTP(config.secret, digits=config.digits, interval=config.period, digest=digests[config.algorithm])
    import time
    now = time.time() if at_time is None else at_time
    code = totp.at(now)
    expires_in = config.period - (int(now) % config.period)
    return code, expires_in
