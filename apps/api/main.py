"""FastAPI application factory and route registration (implementation_plan §5)."""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routes import admin, audit, auth, balances, documents, mandates, proposals, rails, redteam, registry


def create_app() -> FastAPI:
    app = FastAPI(title="Mandate (simulated)", version="0.2.0")

    @app.middleware("http")
    async def security_headers(request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # Same-origin on Vercel needs no CORS entry, but local dev and preview deploys do. Extra origins are
    # supplied via CORS_ORIGINS (comma-separated) so a hosted demo can be reached from its own domain.
    extra = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", *extra],
        allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
    )

    for module in (auth, mandates, documents, proposals, rails, balances, audit, redteam, admin, registry):
        app.include_router(module.router, prefix="/api/v1")

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "banner": "Simulated - no real money moves"}

    return app


app = create_app()
