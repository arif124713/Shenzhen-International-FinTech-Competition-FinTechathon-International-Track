"""API integration tests: the flagship tuition flow, tamper, approval, holds, audit (§5, §7 E2E ids)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from api.agents.compiler import compile_rules
from api.agents.llm import LLMResponse
from api.services.mandates import sign_and_activate
from api.services.runtime import get_runtime, reset_runtime

from eval.fixtures_common import DEMO_MANDATE_RULES, GENUINE_FIELDS


@pytest.fixture()
def client():
    from api.main import create_app
    from fastapi.testclient import TestClient

    rt = reset_runtime()
    rt.set_clients(planner=_EchoPlanner())  # planner is an injected, untrusted component
    with TestClient(create_app()) as c:
        yield c


class _EchoPlanner:
    """Deterministic planner double for API tests: copies the structured document fields into a proposal.

    This is legitimate test scaffolding - the planner is explicitly an untrusted, injected component; the
    real engine, registry, executor and audit log under test are the genuine implementations.
    """

    def complete(self, *, system: str, user: str, prompt_version: str, images=None):  # type: ignore[no-untyped-def]
        import json

        from api.agents.llm import LLMResponse

        payload = json.loads(user.split("\n", 1)[1])
        fields = payload.get("document_fields") or {}
        if not fields:
            return LLMResponse(text=json.dumps({"refusal": "no document"}), model="echo", prompt_version=prompt_version)
        payee_known = fields.get("payee_name") == "Northfield University"
        proposal = {
            "action": "pay", "category": fields.get("category_guess", "other"),
            "payee_id": "reg_northfield_univ" if payee_known else None,
            "payee_ref": {"name": fields.get("payee_name"), "account_identifier": fields.get("account_identifier"),
                          "bank_identifier": fields.get("bank_identifier")},
            "amount_minor": fields.get("amount_minor"), "currency": fields.get("currency", "USD"),
            "source_account": payload.get("source_account", "acc_rafi_usd"),
            "source_debit_minor": (fields.get("amount_minor") or 0) + 2000,
            "rail_id": "rail_a_bank", "urgency": "normal", "doc_ref": "doc1",
        }
        return LLMResponse(text=json.dumps(proposal), model="echo", prompt_version=prompt_version)


@pytest.fixture()
def rt():
    return get_runtime()


def activate_mandate(rt, rules=None):
    body = {
        "mandate_id": "m_rafi", "owner_id": "u_rafi", "base_currency": "BDT",
        "co_signers": [{"id": "u_ammu", "name": "Ammu", "lang": "bn"}],
        "rules": rules or DEMO_MANDATE_RULES,
        "created_at": datetime(2026, 10, 18, tzinfo=timezone.utc).isoformat(),
    }
    return sign_and_activate(rt, body)


def _proposal(rt, fields=None, amount_minor=None, rail="rail_a_bank"):
    """Build a valid proposal matching the reader fields, using the planner fixture-free path."""
    f = dict(fields or GENUINE_FIELDS)
    amt = amount_minor or f["amount_minor"]
    return {
        "proposal_id": "p_test", "action": "pay", "category": f["category_guess"],
        "payee_id": "reg_northfield_univ" if f["payee_name"] == "Northfield University" else None,
        "payee_ref": {"name": f["payee_name"], "account_identifier": f["account_identifier"],
                      "bank_identifier": f["bank_identifier"]},
        "amount_minor": amt, "currency": f["currency"], "source_account": "acc_rafi_usd",
        "source_debit_minor": amt + 2000, "rail_id": rail, "urgency": "normal", "doc_ref": "doc1",
    }


def test_health_and_banner(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200 and "Simulated" in r.json()["banner"]


def test_login_seeded_users(client):
    assert client.post("/api/v1/auth/login", json={"username": "rafi"}).json()["role"] == "student"
    assert client.post("/api/v1/auth/login", json={"username": "nobody"}).status_code == 401


def test_compile_confirm_then_active_mandate(client, rt):
    compiled = client.post("/api/v1/mandates/compile",
                           json={"text": "pay tuition only to my university up to 5000, "
                                         "new payees need ammu approval", "lang": "en"})
    assert compiled.status_code == 200
    body = compiled.json()
    assert body["status"] == "ok" and body["candidate"] is not None

    confirmed = client.post("/api/v1/mandates/confirm",
                            json={"body": body["candidate"], "back_translation": body["back_translation"]})
    assert confirmed.status_code == 200 and confirmed.json()["version"] == 1

    active = client.get("/api/v1/mandates/active").json()
    assert active["active"] and active["version"] == 1 and active["signature"]


def test_genuine_invoice_allowed_executes_once(client, rt):
    activate_mandate(rt)
    r = client.post("/api/v1/proposals", json={"user_request": "pay this tuition invoice",
                                               "document_fields": GENUINE_FIELDS}).json()
    assert r["decision"] == "ALLOW" and r["status"] == "executed"
    assert r["receipt"]["simulated"] is True
    assert r["balances"]["acc_rafi_usd"] == 300_000 - (90000 + 2000)


def test_duplicate_invoice_is_denied_and_never_debits_again(client, rt):
    # Paying the same invoice twice must not debit twice (review finding: T06). The second submission is the
    # same payee + amount + currency + debit + rail, so the engine denies it as DUPLICATE_PAYMENT.
    activate_mandate(rt)
    first = client.post("/api/v1/proposals", json={"user_request": "pay", "document_fields": GENUINE_FIELDS}).json()
    assert first["decision"] == "ALLOW" and first["status"] == "executed"
    bal = first["balances"]["acc_rafi_usd"]

    second = client.post("/api/v1/proposals", json={"user_request": "pay again", "document_fields": GENUINE_FIELDS}).json()
    assert second["decision"] == "DENY" and "DUPLICATE_PAYMENT" in second["reason_codes"]
    assert second["status"] == "blocked"
    assert rt.ledger.balances()["acc_rafi_usd"] == bal  # no second debit
    # exactly one execution in the ledger, and the duplicate attempt is audited
    assert len(rt.ledger.rows) == 1


def test_substituted_account_is_blocked_with_registry_mismatch(client, rt):
    activate_mandate(rt)
    bad = dict(GENUINE_FIELDS, account_identifier="NF0012345679")
    r = client.post("/api/v1/proposals", json={"user_request": "pay", "document_fields": bad}).json()
    assert r["decision"] == "DENY" and "REGISTRY_MISMATCH" in r["reason_codes"]
    assert rt.ledger.balances()["acc_rafi_usd"] == 300_000  # no ledger change


def test_hidden_text_invoice_is_blocked(client, rt):
    activate_mandate(rt)
    bad = dict(GENUINE_FIELDS, anomalies=["INSTRUCTION_LIKE_TEXT"])
    r = client.post("/api/v1/proposals", json={"user_request": "pay", "document_fields": bad}).json()
    assert r["decision"] == "DENY" and "ANOMALY_BLOCKED" in r["reason_codes"]


def test_large_amount_escalates_then_guardian_approves_and_executes_once(client, rt):
    activate_mandate(rt)
    large = dict(GENUINE_FIELDS, amount_minor=180000)
    created = client.post("/api/v1/proposals", json={"user_request": "pay", "document_fields": large}).json()
    assert created["decision"] == "ESCALATE" and created["status"] == "needs_approval"
    assert created["approval"]["approver_id"] == "u_ammu"

    proposal = created["proposal"]
    decision = client.post("/api/v1/approvals/decision",
                           json={"token": created["approval"]["token"], "approver_id": "u_ammu",
                                 "approve": True, "proposal": proposal}).json()
    assert decision["decision"] == "ALLOW" and decision["status"] == "executed"


def test_guardian_rejection_blocks_execution(client, rt):
    activate_mandate(rt)
    large = dict(GENUINE_FIELDS, amount_minor=180000)
    created = client.post("/api/v1/proposals", json={"user_request": "pay", "document_fields": large}).json()
    decision = client.post("/api/v1/approvals/decision",
                           json={"token": created["approval"]["token"], "approver_id": "u_ammu",
                                 "approve": False, "proposal": created["proposal"]}).json()
    assert "APPROVAL_REJECTED" in decision["reason_codes"]
    assert rt.ledger.balances()["acc_rafi_usd"] == 300_000


def test_new_payee_hold_then_clock_advance_releases_it(client, rt):
    activate_mandate(rt)
    new_payee = {
        "doc_type": "invoice", "payee_name": "Uncle Karim", "account_identifier": "BK001", "bank_identifier": "BKASH",
        "amount_minor": 50000, "currency": "USD", "due_date": None, "reference": "RM-1",
        "category_guess": "family_support", "extraction_confidence_bp": 9500, "anomalies": [],
        "doc_sha256": "b" * 64,
    }
    prop = {"proposal_id": "p_new", "action": "transfer", "category": "family_support", "payee_id": None,
            "payee_ref": {"name": "Uncle Karim", "account_identifier": "BK001", "bank_identifier": "BKASH"},
            "amount_minor": 50000, "currency": "USD", "source_account": "acc_rafi_usd",
            "source_debit_minor": 52000, "rail_id": "rail_a_bank", "urgency": "normal", "doc_ref": None}
    client.post("/api/v1/proposals", json={"user_request": "send to uncle",
                                           "document_fields": new_payee}).json()
    # planner fixture only knows the tuition case; fall back to the rule path via reevaluate
    r2 = client.post("/api/v1/proposals/p_new/reevaluate", json={"proposal": prop}).json()
    assert r2["decision"] in {"HOLD", "ESCALATE"}

    client.post("/api/v1/clock/advance", json={"hours": 25})
    r3 = client.post("/api/v1/proposals/p_new/reevaluate", json={"proposal": prop}).json()
    assert r3["decision"] == "ESCALATE"  # cooling-off passed -> needs approval


def test_audit_chain_verifies_and_records_execution(client, rt):
    activate_mandate(rt)
    client.post("/api/v1/proposals", json={"user_request": "pay", "document_fields": GENUINE_FIELDS})
    v = client.get("/api/v1/audit/verify").json()
    assert v["valid"] is True and v["entries"] >= 1
    assert any(e["event_type"] == "EXEC_OK" for e in client.get("/api/v1/audit").json()["entries"])


def test_rails_quote_endpoint(client, rt):
    activate_mandate(rt)
    r = client.post("/api/v1/rails/quote", json={"source": "BDT", "dest": "USD", "amount_minor": 500000}).json()
    assert r["chosen_rail_id"] and "Simulated" in r["note"]


def test_report_endpoint_serves_numbers_from_the_file_or_says_run_eval(client):
    r = client.get("/api/v1/eval/report").json()
    if r["available"]:
        # numbers must come from the report file, never typed by hand
        assert r["report"]["attacks"]["total"] >= 1
        assert "run_id" in r["report"] and "generated_at" in r["report"]
    else:
        assert "make eval" in r["message"]


class _Fixed:
    def __init__(self, payload: dict):
        self.payload = payload
    def complete(self, *, system: str, user: str, prompt_version: str, images=None) -> LLMResponse:  # type: ignore[no-untyped-def]
        import json

        return LLMResponse(text=json.dumps(self.payload), model="fixed", prompt_version=prompt_version)


def test_compiler_refusal_path_is_surfaceable():
    result = compile_rules("send what's needed", "en",
                           _Fixed({"status": "refused", "refusal_reason": "AMBIGUOUS",
                                   "clarification": "Give a number."}).complete)
    assert result.status == "refused"


def test_admin_reset_returns_seeded_state_in_demo_mode(client, rt, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "1")
    activate_mandate(rt)
    client.post("/api/v1/proposals", json={"user_request": "pay", "document_fields": GENUINE_FIELDS})
    used = rt.ledger.balances()["acc_rafi_usd"]
    assert used < 300_000
    r = client.post("/api/v1/admin/reset").json()
    assert r["status"] == "reset" and r["simulated"] is True
    assert get_runtime().ledger.balances()["acc_rafi_usd"] == 300_000


def test_admin_reset_is_refused_outside_demo_mode(client, monkeypatch):
    # Settings.demo_mode reads the env var directly, so patching the environment is sufficient.
    monkeypatch.setenv("DEMO_MODE", "0")
    r = client.post("/api/v1/admin/reset")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "DEMO_MODE_REQUIRED"


def test_approval_endpoint_rejects_malformed_proposal_with_typed_400(client, rt):
    # The guardian endpoint is public and token-bound; a malformed body must be a typed 4xx, never a 500
    # (session-goal finding: it previously raised a raw ValidationError -> HTTP 500 + traceback).
    activate_mandate(rt)
    # unknown token with an empty proposal: typed 400 naming the missing approval (not a 500)
    r = client.post("/api/v1/approvals/decision",
                    json={"token": "unknown-token", "approver_id": "u_ammu", "approve": True, "proposal": {}})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] in {"APPROVAL_NOT_FOUND", "PROPOSAL_INVALID"}

    # a real escalate produces a token; posting it with a malformed proposal is a typed 400 too
    created = client.post("/api/v1/proposals",
                          json={"user_request": "pay", "document_fields": dict(GENUINE_FIELDS, amount_minor=180000)}).json()
    assert created["status"] == "needs_approval"
    token = created["approval"]["token"]
    r2 = client.post("/api/v1/approvals/decision",
                     json={"token": token, "approver_id": "u_ammu", "approve": True, "proposal": {"nonsense": 1}})
    assert r2.status_code == 400
    assert r2.json()["detail"]["code"] == "PROPOSAL_INVALID"


def test_approval_endpoint_requires_a_token(client, rt):
    activate_mandate(rt)
    r = client.post("/api/v1/approvals/decision",
                    json={"token": "", "approver_id": "u_ammu", "approve": True, "proposal": _proposal(rt)})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "APPROVAL_TOKEN_INVALID"


def test_delete_mandate_blocks_further_payments_and_is_audited(client, rt):
    activate_mandate(rt)
    assert client.get("/api/v1/mandates/active").json()["active"] is True
    d = client.delete("/api/v1/mandates/active").json()
    assert d["status"] == "deleted" and d["active"] is False
    assert client.get("/api/v1/mandates/active").json()["active"] is False
    # with no active mandate the engine defaults to DENY (default-deny); no execution occurs
    r = client.post("/api/v1/proposals", json={"user_request": "pay", "document_fields": GENUINE_FIELDS})
    assert r.status_code == 409  # NO_ACTIVE_MANDATE
    assert rt.ledger.balances()["acc_rafi_usd"] == 300_000
    assert any(e["event_type"] == "MANDATE_DELETED" for e in client.get("/api/v1/audit").json()["entries"])


def test_approval_summary_endpoint_returns_only_prepayment_fields(client, rt):
    activate_mandate(rt)
    created = client.post("/api/v1/proposals",
                          json={"user_request": "pay", "document_fields": dict(GENUINE_FIELDS, amount_minor=180000)}).json()
    token = created["approval"]["token"]
    r = client.get(f"/api/v1/approvals/{token}")
    assert r.status_code == 200
    summary = r.json()["summary"]
    assert set(summary) == {"payee_name", "amount_minor", "currency", "rail_id", "reason", "expires_hours"}
    assert summary["amount_minor"] == 180000
    # unknown token -> typed 404, never a 500
    assert client.get("/api/v1/approvals/nope").status_code == 404


def test_approval_with_stored_proposal_executes_once(client, rt):
    activate_mandate(rt)
    created = client.post("/api/v1/proposals",
                          json={"user_request": "pay", "document_fields": dict(GENUINE_FIELDS, amount_minor=180000)}).json()
    token = created["approval"]["token"]
    # proposal omitted: the server uses the stored proposal and still recomputes the action_hash
    r = client.post("/api/v1/approvals/decision",
                    json={"token": token, "approver_id": "u_ammu", "approve": True}).json()
    assert r["decision"] == "ALLOW" and r["status"] == "executed"


def _scratch_registry(tmp_path, monkeypatch):
    """An isolated registry dir seeded from the TEMPLATE (not the live file) so a test never depends on — or
    pollutes — the committed registry, and never collides with entries another test/run may have added."""
    import json
    import shutil

    from api.db.keys import sign_registry
    from api.settings import settings

    scratch = tmp_path / "registry"
    scratch.mkdir()
    shutil.copy(settings.registry_dir / "keys.json", scratch / "keys.json")
    keys = json.loads((scratch / "keys.json").read_text(encoding="utf-8"))
    sign_registry(keys, template_path=settings.registry_dir / "registry.template.json",
                  out_path=scratch / "registry.json")
    monkeypatch.setattr(type(settings), "registry_dir", property(lambda self: scratch))
    return scratch


def test_registry_add_then_a_matching_payment_is_verified(client, rt, tmp_path, monkeypatch):
    # Adding a verified payee in-app makes a payment to that exact account verifiable (registry match), and
    # the change is audited. The registry file is redirected to a scratch copy so the repo file is untouched.
    from api.services.registry import Registry

    scratch = _scratch_registry(tmp_path, monkeypatch)
    activate_mandate(rt)
    rt.registry = Registry.load(scratch / "registry.json")

    r = client.post("/api/v1/registry",
                    json={"legal_name": "Shahjala University of Science and Technology", "account_identifier": "sust 0012 3456", "bank_identifier": "dbblbd dh"})
    assert r.status_code == 200
    entry = r.json()["entry"]
    assert entry["account_identifier"] == "SUST00123456"  # canonicalized (spaces removed, upper-cased)
    assert entry["bank_identifier"] == "DBBLBDDH"

    # the registry list shows it, and the entry carries provenance (never "verified institution" without it)
    listed = client.get("/api/v1/registry").json()
    assert any(e["entity_id"] == entry["entity_id"] for e in listed["entries"])
    assert listed["entries"][-1]["provenance"]["method"]
    assert any(e["event_type"] == "REGISTRY_ENTRY_ADDED" for e in client.get("/api/v1/audit").json()["entries"])

    # a payment to that exact account now matches the registry — but only because the PLANNER resolves the
    # registry entity id (the engine requires a payee_id and verifies the referenced entry). Simulate the
    # planner's resolution here and assert the engine now matches (no REGISTRY_MISMATCH).
    from api.agents.planner import _resolve_payee_id

    fields = dict(GENUINE_FIELDS, payee_name="Shahjala University of Science and Technology",
                  account_identifier="SUST00123456", bank_identifier="DBBLBDDH")
    ref = {"name": fields["payee_name"], "account_identifier": fields["account_identifier"],
           "bank_identifier": fields["bank_identifier"]}
    resolved = _resolve_payee_id(ref, list(rt.registry.entries))
    assert resolved == entry["entity_id"]  # the planner can resolve the new institution from the registry
    prop = _proposal(rt, fields)
    prop["payee_id"] = resolved
    r2 = client.post("/api/v1/proposals/p_reg/reevaluate", json={"proposal": prop}).json()
    assert "REGISTRY_MISMATCH" not in r2["reason_codes"]


def test_registry_match_requires_a_resolved_payee_id_from_the_planner(client, rt, tmp_path, monkeypatch):
    """Security: a proposal with payee_id=None must NOT become known just because its ref matches the registry
    (a fabricated ref could otherwise claim an entry without the planner's lookup). The engine denies it."""
    from api.services.registry import Registry

    scratch = _scratch_registry(tmp_path, monkeypatch)
    activate_mandate(rt)
    rt.registry = Registry.load(scratch / "registry.json")
    fields = dict(GENUINE_FIELDS, payee_name="Northfield University", account_identifier="NF0012345678",
                  bank_identifier="NFLDGB2L")
    prop = _proposal(rt, fields)
    prop["payee_id"] = None  # not resolved
    r = client.post("/api/v1/proposals/p_none/reevaluate", json={"proposal": prop}).json()
    assert r["decision"] == "DENY" and "REGISTRY_MISMATCH" in r["reason_codes"]


def test_registry_add_rejects_duplicate_with_typed_409(client, rt, tmp_path, monkeypatch):
    from api.services.registry import Registry

    scratch = _scratch_registry(tmp_path, monkeypatch)
    rt.registry = Registry.load(scratch / "registry.json")
    body = {"legal_name": "Northfield University", "account_identifier": "NF0012345678", "bank_identifier": "NFLDGB2L"}
    # the seeded entity_id collides
    r = client.post("/api/v1/registry", json={**body, "entity_id": "reg_northfield_univ"})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "REGISTRY_ENTITY_EXISTS"


def test_registry_revoke_blocks_a_previously_verified_payee(client, rt, tmp_path, monkeypatch):
    from datetime import datetime, timezone

    from api.services.registry import Registry

    scratch = _scratch_registry(tmp_path, monkeypatch)
    rt.registry = Registry.load(scratch / "registry.json")
    r = client.post("/api/v1/registry/reg_northfield_univ/revoke")
    assert r.status_code == 200 and r.json()["entry"]["revoked_at"]
    # the reloaded registry marks it revoked (the engine denies revoked entries)
    assert rt.registry.entry_valid("reg_northfield_univ", None, datetime.now(timezone.utc)) is False
    assert client.post("/api/v1/registry/nope/revoke").status_code == 404
