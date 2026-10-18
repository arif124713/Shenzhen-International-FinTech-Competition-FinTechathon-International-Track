"""Planner: structured data + user request -> typed ActionProposal (implementation_plan §1.1).

Untrusted component. It receives only validated structured fields (never raw document text) and emits a
schema-validated ActionProposal. It has no access to the ledger, registry-write or executor.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from typing import Any

from policy_engine import ActionProposal
from pydantic import ValidationError

from ..llm import LLMResponse
from .prompt import PLANNER_SYSTEM, PROMPT_VERSION, build_user_prompt

Complete = Callable[..., LLMResponse]


class PlanError(ValueError):
    pass


def _parse_json(text: str) -> dict[str, Any]:
    text = text.strip().strip("`")
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise PlanError("no JSON object in planner output")
    return json.loads(text[start : end + 1])


def plan(*, user_request: str, reader_fields: dict | None, mandate_summary: str, rails: list[dict],
         source_account: str, complete: Complete, known_payees: list[dict] | None = None) -> ActionProposal | None:
    """Returns a validated ActionProposal, or None if the planner refuses (out of scope / insufficient data).

    The planner (not the LLM) resolves ``payee_id``: the LLM cannot know registry entity ids, so after the
    model proposes a payee_ref the planner looks the payee up in the read-only registry by its identifiers and
    sets ``payee_id`` to the matched entity. The engine then independently re-checks that the referenced entry
    matches and is valid — the planner never invents an id (implementation_plan §1.1).
    """
    resp = complete(system=PLANNER_SYSTEM,
                    user=build_user_prompt(user_request=user_request, reader_fields=reader_fields,
                                           mandate_summary=mandate_summary, rails=rails,
                                           source_account=source_account),
                    prompt_version=PROMPT_VERSION)
    raw = _parse_json(resp.text)
    if "refusal" in raw:
        return None
    ref = raw.get("payee_ref")
    payee_id = raw.get("payee_id")
    resolved = _resolve_payee_id(ref, known_payees or [])
    if resolved is not None:
        payee_id = resolved
    payload = {
        "proposal_id": raw.get("proposal_id", f"p_{uuid.uuid4().hex[:12]}"),
        "action": raw.get("action", "pay"),
        "category": raw.get("category", "other"),
        "payee_id": payee_id,
        "payee_ref": ref,
        "amount_minor": raw.get("amount_minor", 0),
        "currency": raw.get("currency", "USD"),
        "source_account": raw.get("source_account", source_account),
        "source_debit_minor": raw.get("source_debit_minor", raw.get("amount_minor", 0)),
        "rail_id": raw.get("rail_id", ""),
        "urgency": raw.get("urgency", "normal"),
        "doc_ref": raw.get("doc_ref"),
        "created_by": "planner",
    }
    try:
        return ActionProposal.model_validate(payload)
    except ValidationError as exc:
        raise PlanError(str(exc)) from exc


def _resolve_payee_id(ref: dict | None, known_payees: list[dict]) -> str | None:
    """Look up a document payee in the read-only registry by its identifiers; return the entity id or None.

    Uses the same NFKC normalization + confusable handling as the engine (S1 notes §6), so a genuine grouped
    IBAN still matches. Returns None when nothing matches, so the engine treats it as a new/unknown payee.
    """
    if not ref:
        return None
    from policy_engine.decide import norm  # same NFKC normalization the engine uses

    for entry in known_payees:
        if hasattr(entry, "body"):
            body = entry.body
        elif isinstance(entry, dict):
            body = entry.get("body", entry)
        else:
            body = entry
        if (norm(ref.get("name", "")) == norm(body.get("legal_name", ""))
                and norm(ref.get("account_identifier", "")) == norm(body.get("account_identifier", ""))
                and norm(ref.get("bank_identifier", "")) == norm(body.get("bank_identifier", ""))):
            return body.get("entity_id")
    return None


def mandate_summary(body: dict[str, Any]) -> str:
    """Compact plain-text summary handed to the planner (never the full document)."""
    parts: list[str] = []
    for r in body.get("rules", []):
        parts.append(r.get("type", "?"))
    return "rules: " + ", ".join(parts)
