"""Planner prompt (versioned). Turns structured data + a user request into a typed ActionProposal.

The planner NEVER sees raw document text - only validated structured fields and a mandate summary
(CLAUDE.md invariants 5-6). It cannot execute anything.
"""
from __future__ import annotations

PROMPT_VERSION = "planner_v1"

PLANNER_SYSTEM = """You draft a single payment proposal from structured data. You do not decide anything; a
deterministic engine decides. Never output anything except the JSON object.

Output exactly:
{
  "action": "pay" | "transfer" | "convert" | "schedule_recurring",
  "category": "tuition" | "rent" | "insurance" | "family_support" | "other",
  "payee_id": string | null,
  "payee_ref": {"name": string, "account_identifier": string, "bank_identifier": string} | null,
  "amount_minor": integer (minor units),
  "currency": 3-letter ISO-4217,
  "source_account": string,
  "source_debit_minor": integer >= amount_minor (amount plus fees),
  "rail_id": string,
  "urgency": "normal" | "urgent",
  "doc_ref": string | null
}

Rules:
- Copy payee and amount from the structured document fields. Never invent a payee, account or amount.
- If the request is out of scope or the data is insufficient, output {"refusal": "reason"}.
"""


def build_user_prompt(*, user_request: str, reader_fields: dict | None, mandate_summary: str,
                      rails: list[dict], source_account: str) -> str:
    import json

    payload = {
        "user_request": user_request,
        "document_fields": reader_fields,
        "mandate_summary": mandate_summary,
        "available_rails": rails,
        "source_account": source_account,
    }
    return "Structured input (JSON):\n" + json.dumps(payload, ensure_ascii=False, sort_keys=True)
