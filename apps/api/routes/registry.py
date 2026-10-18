"""Registry routes: read verified payees, add one (team-enrolled), revoke one (implementation_plan §4.7).

Adding an entry signs it with the demo registry key. A signature proves the record was not altered; it does
NOT prove the institution is genuine — the UI shows the provenance fields and says so plainly. Every change is
audited. In the prototype the registry lives in a signed JSON file under data/registry/.
"""
from __future__ import annotations

import re
from datetime import timedelta

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from ..services.registry import Registry, add_entry, revoke_entry
from ..services.runtime import get_runtime
from ..settings import settings

router = APIRouter(tags=["registry"])


@router.get("/registry")
def list_registry() -> dict:
    rt = get_runtime()
    return {"registry_version": rt.registry.version,
            "entries": rt.registry.list_entries(),
            "trust_note": "A signature shows the record hasn't been changed. It doesn't prove the institution "
                          "is genuine."}


class AddEntryBody(BaseModel):
    legal_name: str
    account_identifier: str
    bank_identifier: str
    entity_id: str | None = None
    source_url: str | None = None

    @field_validator("legal_name", "bank_identifier")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("required")
        return v


def _slug(name: str) -> str:
    return "reg_" + re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")[:40]


@router.post("/registry")
def add_registry_entry(body: AddEntryBody) -> dict:
    """Add a team-enrolled, signed verified payee. The account is canonicalized (spaces/hyphens removed,
    upper-cased) exactly as the reader sanitizer does, so genuine grouped IBANs still match (S1 note 6)."""
    rt = get_runtime()
    account = re.sub(r"[\s-]", "", body.account_identifier).upper()
    bank = re.sub(r"[\s-]", "", body.bank_identifier).upper()
    # Use the runtime's injectable clock (the same one the engine reads) so an entry added now is valid as
    # seen by the engine immediately — a wall clock could be ahead of a simulated clock and look not-yet-valid.
    now = rt.clock()
    entry_body = {
        "entity_id": body.entity_id or _slug(body.legal_name),
        "legal_name": body.legal_name.strip()[:120],
        "account_identifier": account,
        "bank_identifier": bank,
        "provenance": {
            "method": "demo: added in-app by the user (not independently verified)",
            "source_url": (body.source_url or "").strip(),
            "retrieved_on": now.date().isoformat(),
            "second_check": "none",
        },
        "enrolled_by": "user",
        "valid_from": now.isoformat(),
        "valid_to": (now + timedelta(days=365)).isoformat(),
        "revoked_at": None,
        "registry_version": rt.registry.version,
        "signer_key_id": "demo_registry_k1",
    }
    try:
        added = add_entry(settings.registry_dir / "registry.json", rt.keys, entry_body)
    except ValueError as exc:
        code = "REGISTRY_ENTITY_EXISTS" if "ENTITY_EXISTS" in str(exc) else "REGISTRY_ENTRY_INVALID"
        raise HTTPException(status_code=409 if code == "REGISTRY_ENTITY_EXISTS" else 422,
                            detail={"code": code, "message": str(exc)}) from exc
    rt.registry = Registry.load(settings.registry_dir / "registry.json")  # reload so a payment can match now
    rt.audit.append("rafi", "REGISTRY_ENTRY_ADDED", {"entity_id": added["entity_id"]})
    return {"status": "added", "entry": added}


@router.post("/registry/{entity_id}/revoke")
def revoke_registry_entry(entity_id: str) -> dict:
    rt = get_runtime()
    try:
        revoked = revoke_entry(settings.registry_dir / "registry.json", rt.keys, entity_id, rt.clock())
    except KeyError:
        raise HTTPException(status_code=404, detail={"code": "REGISTRY_ENTRY_NOT_FOUND"}) from None
    rt.registry = Registry.load(settings.registry_dir / "registry.json")
    rt.audit.append("rafi", "REGISTRY_ENTRY_REVOKED", {"entity_id": entity_id})
    return {"status": "revoked", "entry": revoked}
