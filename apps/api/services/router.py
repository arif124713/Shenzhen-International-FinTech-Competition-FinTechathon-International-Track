"""Routing: rank simulated rails by total cost for a corridor (implementation_plan §4.5, testing.md U-ROUTE).

All money math in integer minor units; percentages/rates in Decimal over a set context. Nothing here
touches the policy engine or the ledger. Rate cards are SIMULATED and carry source/assumptions.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal, getcontext
from pathlib import Path

getcontext().prec = 28


@dataclass(frozen=True)
class RateCard:
    rail_id: str
    label: str
    supports: tuple[str, ...]  # corridors "BDT>USD"
    fixed_fee_minor: int
    pct_fee: str  # e.g. "0.004"
    fx_rate: str | None  # offered rate for cross-currency, None if same-currency
    eta_hours: int
    intermediary_fee_minor: int
    receiving_bank_fee_minor: int
    source_url: str
    source_date: str
    assumptions: str
    limitations: str


@dataclass
class RailQuote:
    rail_id: str
    label: str
    total_cost_minor: int
    sender_total_cost_minor: int
    recipient_net_minor: int
    eta_hours: int
    included: bool = True
    excluded_reason: str | None = None


@dataclass
class RouteResult:
    corridor: str
    amount_minor: int
    currency: str
    ranked: list[RailQuote]
    chosen: RailQuote | None
    default_cost_minor: int
    savings_minor: int
    excluded: list[RailQuote] = field(default_factory=list)


class RateCardError(ValueError):
    pass


def load_ratecards(path: Path) -> tuple[list[RateCard], str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    cards: list[RateCard] = []
    for c in data["rails"]:
        for req in ("source_url", "source_date", "assumptions", "limitations"):
            if not c.get(req):
                raise RateCardError(f"rate card {c.get('rail_id')} missing {req}")
        cards.append(RateCard(
            rail_id=c["rail_id"], label=c["label"], supports=tuple(c["supports"]),
            fixed_fee_minor=c["fixed_fee_minor"], pct_fee=c["pct_fee"], fx_rate=c.get("fx_rate"),
            eta_hours=c["eta_hours"], intermediary_fee_minor=c["intermediary_fee_minor"],
            receiving_bank_fee_minor=c["receiving_bank_fee_minor"], source_url=c["source_url"],
            source_date=c["source_date"], assumptions=c["assumptions"], limitations=c["limitations"],
        ))
    return cards, data["default_rail_id"]


def _round_minor(value: Decimal) -> int:
    return int(value.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))


def quote_rail(card: RateCard, *, corridor: str, amount_minor: int, have_currency: str) -> RailQuote:
    amount = Decimal(amount_minor)
    pct = Decimal(card.pct_fee)
    fee = Decimal(card.fixed_fee_minor) + amount * pct + Decimal(card.intermediary_fee_minor) + Decimal(card.receiving_bank_fee_minor)
    total = _round_minor(fee)
    sender_total = amount_minor + total
    if card.fx_rate is not None and have_currency != corridor.split(">")[1]:
        # recipient receives amount converted at the offered rate minus the receiving-bank fee
        converted = _round_minor(amount * Decimal(card.fx_rate)) - card.receiving_bank_fee_minor
    else:
        converted = amount_minor - card.receiving_bank_fee_minor
    return RailQuote(rail_id=card.rail_id, label=card.label, total_cost_minor=total,
                     sender_total_cost_minor=sender_total, recipient_net_minor=max(converted, 0),
                     eta_hours=card.eta_hours)


def route(cards: list[RateCard], default_rail_id: str, *, source: str, dest: str, amount_minor: int,
          urgency: str = "normal", deadline_hours: int | None = None) -> RouteResult:
    corridor = f"{source}>{dest}"
    included: list[RailQuote] = []
    excluded: list[RailQuote] = []
    for card in cards:
        if corridor not in card.supports:
            q = RailQuote(card.rail_id, card.label, 0, 0, 0, card.eta_hours, included=False,
                          excluded_reason="CORRIDOR_NOT_SUPPORTED")
            excluded.append(q)
            continue
        q = quote_rail(card, corridor=corridor, amount_minor=amount_minor, have_currency=source)
        if deadline_hours is not None and q.eta_hours > deadline_hours:
            q.included = False
            q.excluded_reason = "DEADLINE_INFEASIBLE"
            excluded.append(q)
            continue
        included.append(q)

    if not included:
        return RouteResult(corridor, amount_minor, dest, [], None, 0, 0, excluded)

    if urgency == "urgent":
        ranked = sorted(included, key=lambda q: (q.eta_hours, q.total_cost_minor, q.rail_id))
    else:
        ranked = sorted(included, key=lambda q: (q.total_cost_minor, q.eta_hours, q.rail_id))
    chosen = ranked[0]
    default = next((q for q in included if q.rail_id == default_rail_id), ranked[-1])
    savings = max(default.total_cost_minor - chosen.total_cost_minor, 0)
    return RouteResult(corridor, amount_minor, dest, ranked, chosen, default.total_cost_minor, savings, excluded)
