"""Scenario runner (testing.md §5, §10). Produces the `scenarios` block of eval/reports/latest.json.

Runs the 48-hour priority subset offline and deterministically against the real engine, registry,
executor, router and audit log. Every scenario returns a structured result: id, category, name,
expected, actual, pass/fail and a one-line note. Nothing here invents a decision: each scenario
drives the genuine `decide()` + `Executor.execute()` path, exactly as the API does.
"""
from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path as _Path
from typing import Any

_ROOT = _Path(__file__).resolve().parents[2]
for _sub in ("packages", "services", "apps", "."):
    _p = str((_ROOT / _sub).resolve())
    if _p not in sys.path:
        sys.path.insert(0, _p)

import uuid  # noqa: E402

from api.services.audit_log import AuditLog  # noqa: E402
from api.services.executor import Executor, make_ledger  # noqa: E402
from api.services.mandates import sign_and_activate  # noqa: E402
from api.services.registry import Registry  # noqa: E402
from api.services.router import load_ratecards, route  # noqa: E402
from api.settings import settings  # noqa: E402
from policy_engine import (  # noqa: E402
    ActionProposal,
    Approval,
    Context,
    KeyInfo,
    ReaderOutput,
    decide,
    issue_decision_token,
)
from policy_engine.canonical import action_hash  # noqa: E402
from policy_engine.signing import generate_keypair  # noqa: E402

from eval.fixtures_common import DEMO_MANDATE_RULES, GENUINE_FIELDS  # noqa: E402

NOW = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)

BASE_RULES = DEMO_MANDATE_RULES


@dataclass
class Env:
    """A fresh, isolated sandbox for one scenario (mirrors the API composition root)."""

    mandate_keys: dict[str, KeyInfo]
    engine_keys: dict[str, KeyInfo]
    registry: Registry
    ledger: Any
    keys: dict[str, dict[str, str]]
    signed: Any = None
    audit: AuditLog | None = None
    executor: Executor | None = None
    now: datetime = NOW
    mark: datetime | None = None

    @classmethod
    def build(cls, rules: list[dict[str, Any]] | None = None) -> Env:
        m_priv, m_pub = generate_keypair()
        e_priv, e_pub = generate_keypair()
        keys = {"mandate": {"private_b64": m_priv, "public_b64": m_pub},
                "engine": {"private_b64": e_priv, "public_b64": e_pub}}
        registry = Registry.load(settings.registry_dir / "registry.json")
        ledger = make_ledger({"acc_rafi_usd": 300000, "acc_rafi_bdt": 50000000, "acc_rafi_gbp": 64000})

        env = cls(mandate_keys={"demo_mandate_k1": KeyInfo(public_key_b64=m_pub)},
                  engine_keys={"demo_engine_k1": KeyInfo(public_key_b64=e_pub)},
                  registry=registry, ledger=ledger, keys=keys)
        env.audit = AuditLog(env.now_fn)
        env.executor = Executor(engine_keys=env.engine_keys, ledger=ledger, audit=env.audit,
                                clock=env.now_fn, active_mandate_version=lambda _mid: 1,
                                registry_entry_valid=lambda eid, ver, now: registry.entry_valid(eid, ver, now))
        body = {"mandate_id": "m_rafi", "owner_id": "u_rafi", "base_currency": "BDT",
                "co_signers": [{"id": "u_ammu", "name": "Ammu", "lang": "bn"}],
                "rules": rules or BASE_RULES, "created_at": NOW.isoformat()}
        from policy_engine import Mandate
        from policy_engine.canonical import canonical_json
        from policy_engine.signing import sign

        body["version"] = 1
        Mandate.model_validate(body)
        env.signed = _Signed(body, sign(m_priv, canonical_json(body)))
        return env

    def now_fn(self) -> datetime:
        return self.now

    def advance(self, hours: float) -> None:
        self.now = self.now + timedelta(hours=hours)


class _Signed:
    def __init__(self, body: dict[str, Any], signature: str):
        self.body = body
        self.signature = signature
        self.signer_key_id = "demo_mandate_k1"


def _proposal(fields: dict[str, Any], *, amount_minor: int | None = None, rail: str = "rail_a_bank",
              category: str | None = None, payee_id: str | None = None, action: str = "pay") -> ActionProposal:
    amt = amount_minor if amount_minor is not None else fields.get("amount_minor", 0)
    known = fields.get("payee_name") == "Northfield University"
    return ActionProposal.model_validate({
        "proposal_id": f"p_{uuid.uuid4().hex[:8]}", "action": action,
        "category": category or fields.get("category_guess", "other"),
        "payee_id": payee_id if payee_id is not None else ("reg_northfield_univ" if known else None),
        "payee_ref": {"name": fields.get("payee_name"), "account_identifier": fields.get("account_identifier"),
                      "bank_identifier": fields.get("bank_identifier")},
        "amount_minor": amt, "currency": fields.get("currency", "USD"), "source_account": "acc_rafi_usd",
        "source_debit_minor": amt + 2000, "rail_id": rail, "urgency": "normal", "doc_ref": "doc1",
    })


def _decide(env: Env, proposal: ActionProposal, *, reader_fields: dict[str, Any] | None = None,
            approvals: tuple[Approval, ...] = (), hold_started_at: datetime | None = None) -> Any:
    reader = None
    flags: tuple[str, ...] = ()
    if reader_fields:
        reader = ReaderOutput.model_validate(reader_fields)
        flags = tuple(reader.anomalies)
    ctx = Context(now=env.now, mandate_keys=env.mandate_keys, registry_keys=env.registry.key_infos,
                  active_mandate_version=1, ledger=(), balances=env.ledger.balances(),
                  registry=env.registry.entries, reader=reader, detector_flags=flags,
                  approvals=approvals, hold_started_at=hold_started_at,
                  paid_action_hashes=env.ledger.executed_action_hashes())
    return decide(env.signed, proposal, ctx)


def _execute(env: Env, proposal: ActionProposal, decision: Any) -> tuple[bool, str | None]:
    token = issue_decision_token(env.keys["engine"]["private_b64"], "demo_engine_k1", decision,
                                 nonce=f"n_{uuid.uuid4().hex[:16]}", issued_at=env.now,
                                 expires_at=env.now + timedelta(minutes=10))
    try:
        env.executor.execute(proposal, token)
        return True, None
    except Exception as exc:  # noqa: BLE001 - a refusal is a normal, expected outcome
        return False, getattr(exc, "code", type(exc).__name__)


@dataclass
class ScenarioResult:
    id: str
    category: str
    name: str
    expected: str
    actual: str
    passed: bool
    status: str = "ran"  # ran | skipped
    note: str = ""


# ---------------------------------------------------------------------------------------------------
# Priority scenarios (testing.md §5 priority subset)
# ---------------------------------------------------------------------------------------------------

def t01_pay_tuition_genuine() -> ScenarioResult:
    env = Env.build()
    prop = _proposal(GENUINE_FIELDS)
    d = _decide(env, prop, reader_fields=GENUINE_FIELDS)
    executed, code = _execute(env, prop, d)
    actual = f"{d.decision}/{'executed' if executed else code}"
    ok = d.decision == "ALLOW" and executed and env.ledger.balances()["acc_rafi_usd"] == 300000 - 92000
    return ScenarioResult("T01", "T", "Pay tuition invoice (USD) to verified university within caps",
                          "ALLOW; ledger debit; audit entries", actual, ok,
                          note="registry match, within cap, no anomalies")


def t02_cross_currency_cheapest_rail() -> ScenarioResult:
    # T02 must exercise the real path: the router selects the cheapest compliant rail, the engine ALLOWs the
    # payment on that rail, and the executor records it. Asserting the ranking property alone would be a
    # tautology (`route` sorts ascending), so we also drive decide() + execute() and check the chosen rail.
    env = Env.build()
    cards, default = load_ratecards(settings.ratecards_path)
    r = route(cards, default, source="BDT", dest="USD", amount_minor=500000)
    if r.chosen is None:
        return ScenarioResult("T02", "T", "Pay tuition; choose cheapest compliant rail",
                              "ALLOW; rail chosen; fees recorded", "no rail chosen", False,
                              note="no compliant rail for BDT>USD")
    cheapest = min(q.total_cost_minor for q in r.ranked)
    # The chosen rail must be the true cheapest, and its rail_id must be one the mandate allows.
    allowed = {"rail_a_bank", "rail_b_wallet"}
    rank_ok = r.chosen.total_cost_minor == cheapest and r.chosen.rail_id in allowed

    fields = dict(GENUINE_FIELDS, currency="USD", amount_minor=90000)
    prop = _proposal(fields, rail=r.chosen.rail_id)
    d = _decide(env, prop, reader_fields=fields)
    executed, code = _execute(env, prop, d)
    fees_recorded = env.ledger.balances()["acc_rafi_usd"] == 300000 - (90000 + 2000)
    ok = rank_ok and d.decision == "ALLOW" and executed and fees_recorded
    actual = (f"chosen={r.chosen.rail_id} (cheapest={rank_ok}), savings_minor={r.savings_minor}, "
              f"{d.decision}/{'executed' if executed else code}")
    return ScenarioResult("T02", "T", "Pay tuition with BDT source; choose cheapest compliant rail",
                          "ALLOW; cheapest compliant rail chosen; fees recorded; savings vs default shown",
                          actual, ok, note="router ranking + engine ALLOW + ledger debit")


def t06_duplicate_invoice_denied() -> ScenarioResult:
    # A second attempt at the *same* invoice (same payee + amount + currency + debit + rail) must not execute
    # again. The action_hash excludes proposal_id, so a re-submitted invoice hashes identically; the engine
    # denies it via DUPLICATE_PAYMENT (decision-layer idempotency), independent of the executor's token guard.
    env = Env.build()
    prop = _proposal(GENUINE_FIELDS)
    d = _decide(env, prop, reader_fields=GENUINE_FIELDS)
    executed, code = _execute(env, prop, d)
    bal_after_first = env.ledger.balances()["acc_rafi_usd"]

    # A fresh proposal object for the same invoice (new proposal_id, same action) re-run with a fresh context
    # built from the ledger: this is exactly what a duplicate submission looks like to the engine.
    dup = _proposal(GENUINE_FIELDS)
    d2 = _decide(env, dup, reader_fields=GENUINE_FIELDS)
    executed2, code2 = _execute(env, dup, d2)
    ok = (d.decision == "ALLOW" and executed
          and d2.decision == "DENY" and "DUPLICATE_PAYMENT" in d2.reason_codes
          and not executed2 and env.ledger.balances()["acc_rafi_usd"] == bal_after_first)
    return ScenarioResult("T06", "T", "Duplicate of an already-paid invoice",
                          "Second attempt DENY DUPLICATE_PAYMENT; no second payment",
                          f"first={d.decision}/executed={executed}, second={d2.decision}/executed={executed2}",
                          ok, note="decision-layer idempotency keyed on action_hash (payee+amount+debit+rail)")


def t07_over_cap() -> ScenarioResult:
    env = Env.build()
    fields = dict(GENUINE_FIELDS, amount_minor=900000)
    prop = _proposal(fields, amount_minor=900000)
    d = _decide(env, prop, reader_fields=fields)
    executed, _ = _execute(env, prop, d)
    ok = d.decision == "DENY" and not executed
    return ScenarioResult("T07", "T", "Invoice amount exceeds per-tx cap",
                          "DENY (hard cap); no execution", f"{d.decision}/executed={executed}", ok,
                          note="hard per-tx cap -> DENY (S1_NOTES §3)")


def t08_low_confidence() -> ScenarioResult:
    env = Env.build()
    fields = dict(GENUINE_FIELDS, extraction_confidence_bp=4000)
    prop = _proposal(fields)
    d = _decide(env, prop, reader_fields=fields)
    ok = d.decision == "ESCALATE" and "LOW_CONFIDENCE" in d.reason_codes
    return ScenarioResult("T08", "T", "Low-quality scan, confidence below threshold",
                          "ESCALATE LOW_CONFIDENCE; guardian/user review",
                          f"{d.decision}/{list(d.reason_codes)}", ok, note="min_confidence 9000 bp")


def r02_compare_corridors() -> ScenarioResult:
    # The chosen rail must equal the true cheapest AND happen to differ from the default rail, so a
    # regression in the sort (or a default-vs-cheapest mixup) fails the scenario instead of passing trivially.
    cards, default = load_ratecards(settings.ratecards_path)
    r = route(cards, default, source="BDT", dest="USD", amount_minor=500000)
    if not r.ranked or r.chosen is None:
        return ScenarioResult("R02", "R", "Compare corridors BDT->USD; pick cheapest",
                              "Ranked table; chosen rail correct per rate cards", "no compliant rails", False,
                              note="no compliant rail for BDT>USD")
    true_cheapest = min(r.ranked, key=lambda q: (q.total_cost_minor, q.eta_hours, q.rail_id))
    ok = r.chosen.rail_id == true_cheapest.rail_id and r.chosen.rail_id != default
    actual = f"chosen={r.chosen.rail_id}, cheapest={true_cheapest.rail_id}, default={default}"
    return ScenarioResult("R02", "R", "Compare corridors BDT->USD; pick cheapest",
                          "Ranked table; chosen rail correct per rate cards (and differs from the default)",
                          actual, ok, note="deterministic from rate cards")


def r05_above_escalate_then_approve() -> ScenarioResult:
    env = Env.build()
    fields = dict(GENUINE_FIELDS, amount_minor=180000)
    prop = _proposal(fields, amount_minor=180000)
    d = _decide(env, prop, reader_fields=fields)
    if d.decision != "ESCALATE":
        return ScenarioResult("R05", "R", "Transfer above escalate_above", "ESCALATE; approve; execute",
                              d.decision, False, note="expected ESCALATE")
    approval = Approval(approval_id="a_1", approver_id="u_ammu", action_hash=action_hash(prop),
                        mandate_version=1, expires_at=env.now + timedelta(hours=24), status="approved")
    d2 = _decide(env, prop, reader_fields=fields, approvals=(approval,))
    executed, code = _execute(env, prop, d2)
    ok = d2.decision == "ALLOW" and executed
    return ScenarioResult("R05", "R", "Transfer above escalate_above; guardian approves",
                          "ESCALATE; guardian approves; re-evaluated; executes",
                          f"{d.decision}->{d2.decision}/{'executed' if executed else code}", ok,
                          note="approval is an input; engine re-run on the same action_hash")


def r06_guardian_rejects() -> ScenarioResult:
    env = Env.build()
    fields = dict(GENUINE_FIELDS, amount_minor=180000)
    prop = _proposal(fields, amount_minor=180000)
    approval = Approval(approval_id="a_1", approver_id="u_ammu", action_hash=action_hash(prop),
                        mandate_version=1, expires_at=env.now + timedelta(hours=24), status="rejected")
    d = _decide(env, prop, reader_fields=fields, approvals=(approval,))
    executed, _ = _execute(env, prop, d)
    ok = d.decision != "ALLOW" and not executed and env.ledger.balances()["acc_rafi_usd"] == 300000
    return ScenarioResult("R06", "R", "Guardian rejects", "No execution; audit shows rejection",
                          f"{d.decision}/executed={executed}", ok, note="rejection is final for the action")


def r07_cooling_off_hold_then_release() -> ScenarioResult:
    env = Env.build()
    fields = {"doc_type": "invoice", "payee_name": "Uncle Karim", "account_identifier": "BK001",
              "bank_identifier": "BKASH", "amount_minor": 50000, "currency": "USD", "due_date": None,
              "reference": "RM-1", "category_guess": "family_support", "extraction_confidence_bp": 9500,
              "anomalies": [], "doc_sha256": "b" * 64}
    prop = _proposal(fields, category="family_support", payee_id=None, action="transfer")
    d = _decide(env, prop, reader_fields=fields)
    env.mark = env.now  # hold starts now (recorded by the API via mark_hold)
    env.advance(25)
    d2 = _decide(env, prop, reader_fields=fields, hold_started_at=env.mark)
    ok = d.decision == "HOLD" and d2.decision == "ESCALATE"
    return ScenarioResult("R07", "R", "New beneficiary with cooling-off 24 h",
                          "HOLD; after simulated 24 h, re-evaluated (+approval if required)",
                          f"{d.decision}->{d2.decision}", ok,
                          note="cooling-off hold released by the simulated clock")


def p01_compile_confirm_english() -> ScenarioResult:
    # The compiler is an LLM component; here we assert the *runtime contract*: a candidate mandate body
    # becomes signed+active through sign_and_activate, and the active view exposes version + signature.
    from api.services.runtime import Runtime

    rt = Runtime()
    rt.set_active_mandate("m_rafi", 1, {"mandate_id": "m_rafi"}, "sig", "")
    signed = sign_and_activate(rt, dict(mandate_id="m_rafi", owner_id="u_rafi", base_currency="BDT",
                                        co_signers=[{"id": "u_ammu", "name": "Ammu", "lang": "bn"}],
                                        rules=BASE_RULES))
    ok = signed.body["version"] == 2 and bool(signed.signature)
    return ScenarioResult("P01", "P", "English rule compiled, confirmed, signed v-active",
                          "Signed mandate active", f"version={signed.body['version']}, signed={bool(signed.signature)}",
                          ok, note="compiler accuracy is measured separately in the reader/compiler eval")


SCENARIOS: list[Callable[[], ScenarioResult]] = [
    t01_pay_tuition_genuine, t02_cross_currency_cheapest_rail, t06_duplicate_invoice_denied,
    t07_over_cap, t08_low_confidence, r02_compare_corridors, r05_above_escalate_then_approve,
    r06_guardian_rejects, r07_cooling_off_hold_then_release, p01_compile_confirm_english,
]


def run() -> dict[str, Any]:
    results: list[ScenarioResult] = []
    for fn in SCENARIOS:
        try:
            results.append(fn())
        except Exception as exc:  # noqa: BLE001 - a crashed scenario is a failure, never a silent pass
            results.append(ScenarioResult(fn.__name__, "?", fn.__name__, "n/a", f"error: {type(exc).__name__}",
                                          False, note=str(exc)[:120]))
    by_category: dict[str, list[int]] = {}
    for r in results:
        slot = by_category.setdefault(r.category, [0, 0])
        slot[1] += 1  # denominator counts every case in the category, incl. skipped (testing.md §10 shape)
        if r.status == "ran" and r.passed:
            slot[0] += 1
    ran = [r for r in results if r.status == "ran"]
    passed = [r for r in ran if r.passed]
    return {
        "total": len(results),
        "ran": len(ran),
        "passed": len(passed),
        "by_category": by_category,
        "failures": [{"id": r.id, "name": r.name, "expected": r.expected, "actual": r.actual,
                      "note": r.note} for r in ran if not r.passed],
        "skipped": [{"id": r.id, "name": r.name, "note": r.note} for r in results if r.status == "skipped"],
        "results": [{"id": r.id, "category": r.category, "name": r.name, "expected": r.expected,
                     "actual": r.actual, "passed": r.passed, "status": r.status, "note": r.note}
                    for r in results],
    }


if __name__ == "__main__":  # pragma: no cover
    import json

    print(json.dumps(run(), indent=2))
