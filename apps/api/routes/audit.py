"""Audit log view + chain verification + signed checkpoint (US-09, E2E-08, implementation_plan §4.8)."""
from __future__ import annotations

from fastapi import APIRouter

from ..services.runtime import get_runtime

router = APIRouter(tags=["audit"])


@router.get("/audit")
def list_audit() -> dict:
    rt = get_runtime()
    return {"entries": rt.audit.entries}


@router.get("/audit/verify")
def verify_audit() -> dict:
    rt = get_runtime()
    valid, bad_seq = rt.audit.verify()
    return {"valid": valid, "first_bad_seq": bad_seq, "entries": len(rt.audit.entries)}


@router.post("/audit/checkpoint")
def checkpoint() -> dict:
    rt = get_runtime()
    cp = rt.audit.checkpoint(rt.keys["audit"]["private_b64"], "demo_audit_k1")
    return cp
