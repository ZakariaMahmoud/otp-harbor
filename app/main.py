from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api import router
from app.config import Settings
from app.database import build_engine, session_factory
from app.rate_limit import SlidingWindowLimiter
from app.ui import router as ui_router
from app.ui_sessions import SessionStore


def configure_logging() -> None:
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.master_key = settings.load_master_key()
        with app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        yield
        app.state.master_key = b""
        app.state.engine.dispose()

    app = FastAPI(title="TotpVault", version="1.0.0", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.state.settings = settings
    app.state.engine = build_engine(settings.database_url)
    app.state.session_factory = session_factory(app.state.engine)
    app.state.limiter = SlidingWindowLimiter()
    app.state.ui_sessions = SessionStore(settings.ui_session_minutes * 60)
    app.include_router(router)
    app.include_router(ui_router)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        try:
            response = await call_next(request)
        except Exception:
            # Do not render exception messages: third-party errors can echo hostile input.
            logging.getLogger("totpvault").error("unhandled request error request_id=%s", request.state.request_id)
            return JSONResponse({"detail": "internal server error"}, status_code=500)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.get("/health/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready", include_in_schema=False)
    def ready() -> dict[str, str]:
        try:
            with app.state.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return {"status": "ok"}
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)

    return app


configure_logging()
app = create_app()
