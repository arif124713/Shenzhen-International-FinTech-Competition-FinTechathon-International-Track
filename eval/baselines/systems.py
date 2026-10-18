"""Baselines B0 (naive agent) and B1 (prompted agent) for the red-team comparison (testing.md §6).

Both write to the SAME sandbox ledger as B2 so success is measured identically. With LLM_PROVIDER=replay
these are deterministic doubles: B0 unconditionally trusts the document fields; B1 adds a "careful" text
heuristic that still lacks the registry and the engine. This keeps `make eval` offline and honest about
what each baseline structurally can and cannot do.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class BaselineOutcome:
    executed: bool
    payee_id: str | None
    amount_minor: int
    currency: str
    rail_id: str
    blocked_reason: str | None = None


def b0_naive(fields: dict[str, Any], proposal: dict[str, Any]) -> BaselineOutcome:
    """Naive agent: pay whatever the document says. No policy engine, no registry check."""
    return BaselineOutcome(executed=True, payee_id=proposal.get("payee_id"), amount_minor=proposal["amount_minor"],
                           currency=proposal["currency"], rail_id=proposal.get("rail_id", "rail_a_bank"))


def b1_prompted(fields: dict[str, Any], proposal: dict[str, Any]) -> BaselineOutcome:
    """Prompted agent: a careful system prompt blocks obvious instructions but has no structural check."""
    text = " ".join(str(v) for v in fields.values()).lower()
    suspicious = any(k in text for k in ("ignore", "new account", "changed", "urgent", "override"))
    anomalies = fields.get("anomalies") or []
    if suspicious or anomalies:
        return BaselineOutcome(executed=False, payee_id=proposal.get("payee_id"),
                               amount_minor=proposal["amount_minor"], currency=proposal["currency"],
                               rail_id=proposal.get("rail_id", "rail_a_bank"), blocked_reason="PROMPT_HEURISTIC")
    # Still trusts the document's account number even if it does not match the registry.
    return BaselineOutcome(executed=True, payee_id=proposal.get("payee_id"), amount_minor=proposal["amount_minor"],
                           currency=proposal["currency"], rail_id=proposal.get("rail_id", "rail_a_bank"))
