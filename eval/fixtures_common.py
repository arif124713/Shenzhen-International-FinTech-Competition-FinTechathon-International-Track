"""Single source of truth for the demo mandate rules and the genuine-invoice fields used across the eval
harness, the scenario suite and the API-flow tests.

Keeping one copy prevents drift: a change to a cap, threshold or payee must not silently diverge between the
scenario verdicts, the red-team baseline and the API-flow expectations (they all feed the same real engine).
"""
from __future__ import annotations

from typing import Any

# The 9-rule demo mandate (implementation_plan §3.3 closed rule set). Used by run_eval, the scenario suite
# and the API-flow tests. `eval/evidence.py` intentionally uses a reduced 4-rule subset.
DEMO_MANDATE_RULES: list[dict[str, Any]] = [
    {"id": "R01", "type": "category_allow", "categories": ["tuition", "family_support"]},
    {"id": "R02", "type": "require_registry_match", "categories": ["tuition"]},
    {"id": "R03", "type": "cap", "scope": "per_tx", "amount_minor": 500000, "currency": "USD",
     "categories": ["*"], "hard": True},
    {"id": "R04", "type": "escalate_above", "amount_minor": 120000, "currency": "USD", "approvers": ["u_ammu"]},
    {"id": "R05", "type": "new_payee", "action": "ESCALATE", "approvers": ["u_ammu"]},
    {"id": "R06", "type": "cooling_off", "applies_to": "new_payee", "hours": 24},
    {"id": "R07", "type": "min_confidence", "value_bp": 9000},
    {"id": "R08", "type": "block_anomalies",
     "anomalies": ["HIDDEN_TEXT", "INSTRUCTION_LIKE_TEXT", "PAYEE_CHANGE_NOTICE"]},
    {"id": "R09", "type": "rail_allow", "rail_ids": ["rail_a_bank", "rail_b_wallet"]},
]

# The canonical genuine tuition invoice (matches data/fixtures/invoices/inv_genuine_northfield.gold.json).
GENUINE_FIELDS: dict[str, Any] = {
    "doc_type": "invoice", "payee_name": "Northfield University", "account_identifier": "NF0012345678",
    "bank_identifier": "NFLDGB2L", "amount_minor": 90000, "currency": "USD", "due_date": "2026-11-05",
    "reference": "INV-2026-0451", "category_guess": "tuition", "extraction_confidence_bp": 9600,
    "anomalies": [], "doc_sha256": "a" * 64,
}
