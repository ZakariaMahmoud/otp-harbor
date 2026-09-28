from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass


@dataclass
class WebSession:
    client_id: str
    csrf_token: str
    expires_at: float


class SessionStore:
    """Bounded, process-local sessions; restarting the service signs everyone out."""

    def __init__(self, ttl_seconds: int, max_sessions: int = 5_000) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self._sessions: dict[bytes, WebSession] = {}
        self._login_nonces: dict[bytes, float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _digest(token: str) -> bytes:
        return hashlib.sha256(token.encode("utf-8")).digest()

    def create(self, client_id: str) -> tuple[str, WebSession]:
        token = secrets.token_urlsafe(32)
        session = WebSession(client_id, secrets.token_urlsafe(32), time.monotonic() + self.ttl_seconds)
        with self._lock:
            self._prune()
            if len(self._sessions) >= self.max_sessions:
                oldest = min(self._sessions, key=lambda key: self._sessions[key].expires_at)
                self._sessions.pop(oldest, None)
            self._sessions[self._digest(token)] = session
        return token, session

    def get(self, token: str | None) -> WebSession | None:
        if not token or len(token) > 128:
            return None
        key = self._digest(token)
        with self._lock:
            session = self._sessions.get(key)
            if session is None or session.expires_at <= time.monotonic():
                self._sessions.pop(key, None)
                return None
            session.expires_at = time.monotonic() + self.ttl_seconds
            return session

    def revoke(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(self._digest(token), None)

    def issue_login_nonce(self) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._login_nonces[self._digest(token)] = time.monotonic() + 300
        return token

    def consume_login_nonce(self, cookie: str | None, submitted: str) -> bool:
        if not cookie or not submitted or len(cookie) > 128 or len(submitted) > 128:
            return False
        cookie_digest = self._digest(cookie)
        with self._lock:
            expiry = self._login_nonces.pop(cookie_digest, None)
        return expiry is not None and expiry > time.monotonic() and hmac.compare_digest(cookie, submitted)

    def valid_csrf(self, session: WebSession, submitted: str | None) -> bool:
        return bool(submitted) and hmac.compare_digest(session.csrf_token, submitted)

    def _prune(self) -> None:
        now = time.monotonic()
        self._sessions = {key: value for key, value in self._sessions.items() if value.expires_at > now}
        self._login_nonces = {key: value for key, value in self._login_nonces.items() if value > now}
