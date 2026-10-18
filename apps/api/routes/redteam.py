"""Red-team report endpoint: serves measured numbers from eval/reports/latest.json (US-09, E2E-10).

Numbers are NEVER hard-coded here; if the report is missing we say so rather than invent values.
"""
from __future__ import annotations

import json

from fastapi import APIRouter

from ..settings import settings

router = APIRouter(tags=["redteam"])


@router.get("/eval/report")
def report() -> dict:
    path = settings.reports_dir / "latest.json"
    if not path.exists():
        return {"available": False, "message": "No report yet. Run `make eval` to generate one."}
    return {"available": True, "report": json.loads(path.read_text(encoding="utf-8"))}
