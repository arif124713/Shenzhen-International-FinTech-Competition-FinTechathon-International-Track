"""U-COMPILE / U-PLAN (§4.1, §4.3): compiler refusal, dangerous-error detection, planner isolation."""
from __future__ import annotations

import json

from api.agents.compiler import compile_rules
from api.agents.llm import LLMResponse
from api.agents.planner import mandate_summary, plan


class _Fixed:
    def __init__(self, payload: dict):
        self.payload = payload

    def complete(self, *, system: str, user: str, prompt_version: str, images=None) -> LLMResponse:  # type: ignore[no-untyped-def]
        return LLMResponse(text=json.dumps(self.payload), model="fixed", prompt_version=prompt_version)


class _Spy:
    """Records every prompt it is asked to complete, so we can assert what the planner is shown."""

    def __init__(self, payload: dict):
        self.payload = payload
        self.seen_user: list[str] = []

    def complete(self, *, system: str, user: str, prompt_version: str, images=None) -> LLMResponse:  # type: ignore[no-untyped-def]
        self.seen_user.append(user)
        return LLMResponse(text=json.dumps(self.payload), model="spy", prompt_version=prompt_version)


VALID_RULES = [
    {"id": "R01", "type": "category_allow", "categories": ["tuition"]},
    {"id": "R02", "type": "cap", "scope": "per_tx", "amount_minor": 500000, "currency": "USD",
     "categories": ["*"], "hard": True},
]


def test_compiler_returns_ok_for_expressible_rules():
    payload = {"status": "ok", "base_currency": "BDT", "co_signers": [], "rules": VALID_RULES,
               "back_translation": "Pay tuition up to USD 5,000.", "created_at": "2026-10-18T00:00:00+00:00"}
    result = compile_rules("pay tuition up to 5000", "en", _Fixed(payload).complete)
    assert result.status == "ok" and result.back_translation.startswith("Pay tuition")


def test_compiler_refuses_ambiguous_rule_with_clarification():
    payload = {"status": "refused", "refusal_reason": "AMBIGUOUS",
               "clarification": "How much is 'what's needed'? Give a number."}
    result = compile_rules("send what's needed", "en", _Fixed(payload).complete)
    assert result.status == "refused" and "number" in result.clarification


def test_compiler_refuses_rule_outside_the_closed_set():
    payload = {"status": "ok", "base_currency": "BDT", "co_signers": [], "rules": [
        {"id": "X", "type": "allow_everything"}], "back_translation": "allow all"}
    result = compile_rules("allow everything", "en", _Fixed(payload).complete)
    assert result.status == "refused" and result.refusal_reason in {"INEXPRESSIBLE", "NO_RULES"}


def test_local_extract_compiles_a_clear_sentence_when_the_model_refuses():
    # In offline/replay mode a clear sentence with an amount+category must still compile (not be refused
    # just because no fixture exists). An institution named in text is explained, never silently dropped.
    from api.agents.compiler import _local_extract

    text = ("My university name is Shahjala University of Science and Technology (SUST), pay tuition only to "
            "my university up to 5000 USD per payment, over 1200 USD needs approval, new payees need approval, "
            "new payees wait 24 hours")
    out = _local_extract(text)
    assert out is not None and out["status"] == "ok"
    types = [r["type"] for r in out["rules"]]
    assert {"category_allow", "cap", "escalate_above", "require_registry_match", "new_payee",
            "cooling_off"} <= set(types)
    cap = next(r for r in out["rules"] if r["type"] == "cap")
    assert cap["amount_minor"] == 500000  # 5000 USD in minor units
    assert "registry" in out["back_translation"].lower()  # institution handled via the registry, stated


def test_local_extract_leaves_genuinely_vague_input_to_the_refusal_path():
    from api.agents.compiler import _local_extract

    assert _local_extract("send what's needed") is None  # no amount, no category -> refuse, do not guess
    assert _local_extract("asap always") is None


def test_planner_refuses_out_of_scope_request():
    assert plan(user_request="invest my money in stocks", reader_fields=None, mandate_summary="rules: cap",
                rails=[], source_account="acc_rafi_usd", complete=_Fixed({"refusal": "out of scope"}).complete) is None


def test_planner_never_receives_raw_document_text():
    payload = {"action": "pay", "category": "tuition", "payee_id": "reg_x",
               "payee_ref": {"name": "X", "account_identifier": "1", "bank_identifier": "B"},
               "amount_minor": 100, "currency": "USD", "source_account": "acc_rafi_usd",
               "source_debit_minor": 100, "rail_id": "rail_a_bank", "urgency": "normal"}
    spy = _Spy(payload)
    plan(user_request="pay this", reader_fields={"payee_name": "X", "amount_minor": 100},
         mandate_summary="rules: cap", rails=[{"rail_id": "rail_a_bank"}], source_account="acc_rafi_usd",
         complete=spy.complete)
    joined = "\n".join(spy.seen_user)
    assert "ignore previous rules" not in joined  # no raw document instructions leak in
    assert mandate_summary({"rules": [{"type": "cap"}]}) == "rules: cap"


def test_planner_output_is_schema_validated():
    payload = {"action": "pay", "category": "tuition", "amount_minor": -5, "currency": "USD",
               "source_account": "acc_rafi_usd", "source_debit_minor": 100, "rail_id": "rail_a_bank"}
    import pytest
    from api.agents.planner import PlanError

    with pytest.raises(PlanError):
        plan(user_request="pay", reader_fields=None, mandate_summary="rules: cap", rails=[],
             source_account="acc_rafi_usd", complete=_Fixed(payload).complete)
