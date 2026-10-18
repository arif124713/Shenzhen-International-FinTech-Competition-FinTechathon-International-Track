"""Balances (D1) and the demo clock control used to advance cooling-off holds."""
from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from ..services.runtime import get_runtime

router = APIRouter(tags=["balances"])

ACCOUNT_CURRENCY = {"acc_rafi_bdt": "BDT", "acc_rafi_usd": "USD", "acc_rafi_gbp": "GBP", "acc_rafi_eur": "EUR"}


@router.get("/balances")
def balances() -> dict:
    rt = get_runtime()
    rows = [{"account_id": a, "currency": ACCOUNT_CURRENCY.get(a, "?"), "balance_minor": bal}
            for a, bal in rt.ledger.balances().items()]
    return {"balances": rows, "simulated": True}


class AdvanceBody(BaseModel):
    hours: float


@router.post("/clock/advance")
def advance_clock(body: AdvanceBody) -> dict:
    """Simulated clock: advance time so a cooling-off hold can be re-evaluated without waiting."""
    rt = get_runtime()
    now = rt.clock.advance(body.hours)
    return {"now": now.isoformat()}
