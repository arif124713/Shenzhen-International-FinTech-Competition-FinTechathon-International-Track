"""Mandate routes: compile (not active) -> confirm (sign + activate) -> read (implementation_plan §5)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..agents.compiler import compile_rules
from ..services.explain import explain
from ..services.mandates import active_signed, sign_and_activate
from ..services.runtime import get_runtime

router = APIRouter(tags=["mandates"])


class CompileBody(BaseModel):
    text: str
    lang: str = "en"


class ConfirmBody(BaseModel):
    body: dict
    back_translation: str = ""


@router.post("/mandates/compile")
def compile_mandate(body: CompileBody) -> dict:
    rt = get_runtime()
    result = compile_rules(body.text, body.lang, rt.compiler_client.complete)
    return {"status": result.status, "candidate": result.body, "back_translation": result.back_translation,
            "refusal_reason": result.refusal_reason, "clarification": result.clarification,
            "test_cases": result.test_cases or []}


@router.post("/mandates/confirm")
def confirm_mandate(body: ConfirmBody) -> dict:
    rt = get_runtime()
    try:
        signed = sign_and_activate(rt, body.body, back_translation=body.back_translation)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail={"code": "MANDATE_INVALID", "message": str(exc)}) from exc
    return {"mandate_id": signed.body["mandate_id"], "version": signed.body["version"],
            "signature": signed.signature, "rules": signed.body["rules"],
            "back_translation": body.back_translation}


@router.get("/mandates/active")
def get_active() -> dict:
    rt = get_runtime()
    signed = active_signed(rt)
    if signed is None:
        return {"active": False}
    plain = [explain(rule["type"], "en") for rule in signed.body["rules"]]
    return {"active": True, "mandate_id": signed.body["mandate_id"], "version": signed.body["version"],
            "rules": signed.body["rules"], "signature": signed.signature, "plain_language": plain,
            "created_at": signed.body.get("created_at")}


@router.delete("/mandates/active")
def delete_active() -> dict:
    """Remove the active mandate. Authority comes from the signed mandate, so with none active every proposal
    defaults to DENY (default-deny). Every state change is audited (CLAUDE.md invariant 8)."""
    rt = get_runtime()
    signed = active_signed(rt)
    if signed is None:
        return {"status": "none", "active": False}
    version = signed.body["version"]
    rt.clear_active_mandate()
    rt.audit.append("rafi", "MANDATE_DELETED", {"mandate_id": signed.body["mandate_id"], "version": version})
    return {"status": "deleted", "active": False, "deleted_version": version}
