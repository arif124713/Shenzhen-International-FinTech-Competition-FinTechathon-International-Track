"""Demo admin routes. Mutating routes here are disabled unless DEMO_MODE=1 (implementation_plan §5, §10.2).

`POST /admin/reset` returns the process to its seeded state so the deterministic demo and the e2e
suite start from the same place every time. It never touches real data: the whole system is simulated.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..services.runtime import reset_runtime
from ..settings import settings

router = APIRouter(tags=["admin"])


@router.post("/admin/reset")
def reset() -> dict:
    if not settings.demo_mode:
        # Refuse rather than silently mutate state outside demo mode.
        raise HTTPException(status_code=403, detail={"code": "DEMO_MODE_REQUIRED"})
    reset_runtime()
    return {"status": "reset", "simulated": True}
