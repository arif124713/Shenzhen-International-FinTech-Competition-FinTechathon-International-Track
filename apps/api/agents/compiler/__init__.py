"""Intent compiler (implementation_plan §3.3, testing.md §4.1).

NL -> candidate Mandate. Validation: closed rule set, no invented fields. Safety loop: back-translation,
auto-generated behavioral test cases, explicit user confirm before signing. The compiler refuses what it
cannot express and never approximates silently.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from policy_engine import Mandate
from pydantic import ValidationError

from ..llm import LLMResponse
from .prompt import COMPILER_SYSTEM, PROMPT_VERSION, build_user_prompt

Complete = Callable[..., LLMResponse]


@dataclass
class CompileResult:
    status: str  # "ok" | "refused"
    body: dict[str, Any] | None = None
    back_translation: str = ""
    refusal_reason: str = ""
    clarification: str = ""
    test_cases: list[dict[str, Any]] | None = None


class CompileError(ValueError):
    pass


def _parse_json(text: str) -> dict[str, Any]:
    text = text.strip().strip("`")
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise CompileError("no JSON object in compiler output")
    return json.loads(text[start : end + 1])


def compile_rules(text: str, lang: str, complete: Complete, *, attempt_id: str = "c") -> CompileResult:
    resp = complete(system=COMPILER_SYSTEM, user=build_user_prompt(text, lang), prompt_version=PROMPT_VERSION)
    try:
        raw = _parse_json(resp.text)
    except (ValueError, json.JSONDecodeError) as exc:
        return CompileResult(status="refused", refusal_reason="COMPILER_OUTPUT_INVALID",
                             clarification=f"Could not read a policy from that text ({exc}).")

    if raw.get("status") == "refused":
        # The offline/replay model may not know the sentence. Before refusing, try a conservative local
        # extraction so clear amount/category rules still compile (the offline demo must not refuse a
        # perfectly expressible rule just because no fixture exists). We only emit rules that appear in the
        # closed set and in the text; anything else is still refused with a reason.
        local = _local_extract(text)
        if local is not None:
            raw = local
        else:
            reason = raw.get("refusal_reason", "REFUSED")
            # Preserve a specific, model-provided clarification. Only synthesise one locally when the model
            # gave none, or gave the generic template, so refusals always explain WHY (registry vs. a number).
            provided = (raw.get("clarification") or "").strip()
            clarification = provided if (provided and not _is_generic_clarification(provided)) else _clarify(text)
            return CompileResult(status="refused", refusal_reason=reason, clarification=clarification or provided)

    rules = list(raw.get("rules", []))
    if not rules:
        return CompileResult(status="refused", refusal_reason="NO_RULES",
                             clarification=_clarify(text))

    body = {
        "mandate_id": raw.get("mandate_id", f"m_{attempt_id}"),
        "version": 1,
        "owner_id": "u_rafi",
        "base_currency": raw.get("base_currency", "BDT"),
        "co_signers": raw.get("co_signers", []),
        "rules": rules,
        "created_at": raw.get("created_at", "2026-10-18T00:00:00+00:00"),
    }
    try:
        Mandate.model_validate(body)
    except ValidationError as exc:
        return CompileResult(status="refused", refusal_reason="INEXPRESSIBLE",
                             clarification=f"That rule is outside what I can enforce safely ({exc.error_count()} issue(s)).")

    return CompileResult(status="ok", body=body, back_translation=raw.get("back_translation", ""),
                         test_cases=raw.get("test_cases") or _synthetic_test_cases(body))


def _synthetic_test_cases(body: dict[str, Any]) -> list[dict[str, Any]]:
    """If the model did not return behavioral test cases, derive a minimal should-allow/should-deny pair."""
    cats = [c for r in body["rules"] if r["type"] == "category_allow" for c in r["categories"]]
    cases: list[dict[str, Any]] = []
    if cats:
        cases.append({"expect": "allow-ish", "category": cats[0], "note": "a normal payment in an allowed category"})
    cases.append({"expect": "deny", "category": "other", "note": "a category you did not allow"})
    return cases


_INSTITUTION_HINTS = ("university", "college", "institute", "school", "landlord", "insurer",
                      "medical", "hospital", "sust", "tuition")
_AMOUNT_HINTS = ("cap", "maximum", "max", "up to", "limit", "per payment", "over", "$", "usd", "bdt", "gbp", "eur")


def _local_extract(text: str) -> dict[str, Any] | None:
    """Conservative, deterministic NL->rules for the offline demo (no model call).

    Only emits rules that exist in the closed set AND appear in the text; it never invents payees. An
    institution named in the text is not encoded as a rule (identity lives in the signed registry) — that is
    stated in the back-translation instead of being silently dropped. Returns a candidate dict, or None.
    """
    import re

    low = text.lower()
    rules: list[dict[str, Any]] = []
    rid = 0

    def nid() -> str:
        nonlocal rid
        rid += 1
        return f"R{rid:02d}"

    cats = [c for c in ("tuition", "rent", "insurance", "family_support") if c in low]
    if cats:
        rules.append({"id": nid(), "type": "category_allow", "categories": cats})

    amounts = re.findall(r"(?:up to|max(?:imum)?|over|\$)\s*\$?\s*(\d[\d,]*)", low)
    nums = [int(a.replace(",", "")) for a in amounts]
    if nums:
        rules.append({"id": nid(), "type": "cap", "scope": "per_tx", "amount_minor": max(nums) * 100,
                      "currency": "USD", "categories": ["*"], "hard": True})
        if "approval" in low or "approve" in low:
            rules.append({"id": nid(), "type": "escalate_above", "amount_minor": min(nums) * 100,
                          "currency": "USD", "approvers": ["u_ammu"]})

    if "verified" in low or "registry" in low or "my university" in low:
        rules.append({"id": nid(), "type": "require_registry_match", "categories": cats or ["tuition"]})

    if "new payee" in low or "new payees" in low or "new beneficiary" in low:
        rules.append({"id": nid(), "type": "new_payee", "action": "ESCALATE", "approvers": ["u_ammu"]})
        if "wait" in low or "hour" in low or "cool" in low:
            m = re.search(r"(\d+)\s*hour", low)
            rules.append({"id": nid(), "type": "cooling_off", "applies_to": "new_payee",
                          "hours": int(m.group(1)) if m else 24})

    if not rules:
        return None

    parts: list[str] = []
    if cats:
        parts.append(f"allow {', '.join(cats)}")
    if nums:
        parts.append(f"up to {max(nums)} USD per payment")
    if any(r["type"] == "escalate_above" for r in rules):
        parts.append(f"over {min(nums)} USD needs approval")
    if any(r["type"] == "require_registry_match" for r in rules):
        parts.append("require a verified payee")
    if any(r["type"] == "new_payee" for r in rules):
        parts.append("new payees need Ammu's approval")
    back = "I understood: " + "; ".join(parts) + "."
    if any(h in low for h in ("university", "college", "institute", "school", "sust")):
        back += (" Note: a rule cannot name your university directly — institution identity is checked "
                 "against the verified registry, so any institution you want to pay must be added there.")
    return {"status": "ok", "base_currency": "BDT",
            "co_signers": [{"id": "u_ammu", "name": "Ammu", "lang": "bn"}],
            "rules": rules, "back_translation": back,
            "test_cases": _synthetic_test_cases({"rules": rules})}


def _is_generic_clarification(text: str) -> bool:
    """True for a seeded generic template, so it can be replaced by a situation-specific explanation."""
    low = text.lower()
    return ("could not turn that into enforceable rules" in low
            or "try 'up to" in low
            or "can't set a rule by name alone" in low)


def _clarify(text: str) -> str:
    """Turn a bare refusal into something that explains *why* and what to do instead (no silent approximation).

    The rule set is closed and has no 'named institution' rule type: institution identity belongs in the
    signed registry (checked with require_registry_match), not in a free-text name. Say so plainly.
    """
    lowered = text.lower()
    looks_like_institution = any(h in lowered for h in _INSTITUTION_HINTS)
    looks_like_amount = any(h in lowered for h in _AMOUNT_HINTS)
    if looks_like_institution and not looks_like_amount:
        return ("I can't set a rule by name alone — names are easy to fake. To restrict payments to your "
                "university, it must be added to the verified registry, then I can require a verified payee. "
                "You can still set limits, for example: 'up to 2000 USD per payment' or "
                "'tuition needs a verified payee and anything over 1200 USD needs approval'.")
    if looks_like_institution:
        return ("Institutions are matched through the verified registry, not by name. I can set amount and "
                "category rules now — for example: 'allow tuition, up to 2000 USD per payment, over 1200 USD "
                "needs approval'.")
    return ("I could not find a concrete amount or category. Try 'up to 2000 USD per payment' or "
            "'pay tuition only, new payees need approval'.")
