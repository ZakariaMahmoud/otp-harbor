from __future__ import annotations

import base64
import binascii
import os
import stat
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class Settings:
    database_url: str
    master_key_file: Path
    max_qr_bytes: int = 2 * 1024 * 1024
    otp_rate_limit: int = 30
    auth_failure_rate_limit: int = 20
    rate_window_seconds: int = 60
    trust_proxy_headers: bool = False
    ui_session_minutes: int = 30
    ui_secure_cookie: bool = False
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost", "[::1]", "testserver")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            database_url=os.getenv("TOTPVault_DATABASE_URL", "sqlite:////data/vault.db"),
            master_key_file=Path(os.getenv("TOTPVault_MASTER_KEY_FILE", "/run/secrets/totpvault_master_key")),
            max_qr_bytes=int(os.getenv("TOTPVault_MAX_QR_BYTES", str(2 * 1024 * 1024))),
            otp_rate_limit=int(os.getenv("TOTPVault_OTP_RATE_LIMIT", "30")),
            auth_failure_rate_limit=int(os.getenv("TOTPVault_AUTH_FAILURE_RATE_LIMIT", "20")),
            rate_window_seconds=int(os.getenv("TOTPVault_RATE_WINDOW_SECONDS", "60")),
            trust_proxy_headers=os.getenv("TOTPVault_TRUST_PROXY_HEADERS", "false").lower() == "true",
            ui_session_minutes=int(os.getenv("TOTPVault_UI_SESSION_MINUTES", "30")),
            ui_secure_cookie=os.getenv("TOTPVault_UI_SECURE_COOKIE", "false").lower() == "true",
            allowed_hosts=tuple(host.strip() for host in os.getenv(
                "TOTPVault_ALLOWED_HOSTS", "127.0.0.1,localhost,[::1],testserver"
            ).split(",") if host.strip()),
        )

    def load_master_key(self) -> bytes:
        try:
            info = self.master_key_file.stat()
            if stat.S_ISREG(info.st_mode) and info.st_mode & 0o077:
                raise ConfigurationError("master key file permissions are too broad")
            raw = self.master_key_file.read_bytes().strip()
        except ConfigurationError:
            raise
        except OSError as exc:
            raise ConfigurationError("master key is unavailable") from exc
        try:
            key = base64.b64decode(raw, validate=True)
        except binascii.Error as exc:
            raise ConfigurationError("master key file is not valid base64") from exc
        if len(key) != 32:
            raise ConfigurationError("master key must decode to exactly 32 bytes")
        return key
