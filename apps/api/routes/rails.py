"""Rail quoting (US-06): ranked compliant rails with savings vs a simulated default (implementation_plan §4.5)."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from ..services.router import route
from ..services.runtime import get_runtime

router = APIRouter(tags=["rails"])


class QuoteBody(BaseModel):
    source: str = "BDT"
    dest: str = "USD"
    amount_minor: int
    urgency: str = "normal"
    deadline_hours: int | None = None


@router.post("/rails/quote")
def quote(body: QuoteBody) -> dict:
    rt = get_runtime()
    result = route(rt.ratecards, rt.default_rail_id, source=body.source, dest=body.dest,
                   amount_minor=body.amount_minor, urgency=body.urgency, deadline_hours=body.deadline_hours)
    return {
        "corridor": result.corridor,
        "amount_minor": result.amount_minor,
        "chosen_rail_id": result.chosen.rail_id if result.chosen else None,
        "savings_minor": result.savings_minor,
        "default_cost_minor": result.default_cost_minor,
        "ranked": [q.__dict__ for q in result.ranked],
        "excluded": [q.__dict__ for q in result.excluded],
        "note": "Simulated rate cards; savings vs a simulated default bank wire, not live market data.",
    }
