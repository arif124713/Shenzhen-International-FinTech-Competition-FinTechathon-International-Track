"""U-ENG-01..12: one test per rule branch (testing.md §2)."""
from __future__ import annotations

from datetime import timedelta

import pytest

from policy_engine import Approval, KeyInfo, action_hash, decide
from policy_engine.tests.factories import (
    NOW,
    UNI_ACCT,
    UNI_BANK,
    UNI_NAME,
    context,
    default_rules,
    make_env,
    mandate_body,
    proposal,
    reader,
    registry_entry,
    sign_mandate,
    tamper,
)

ENV = make_env()


def run(rules=None, prop=None, signed=None, **ctx):
    signed = signed or sign_mandate(ENV, mandate_body(rules))
    return decide(signed, prop or proposal(), context(ENV, **ctx))


def without(*ids):
    return [r for r in default_rules() if r["id"] not in ids]


def test_default_is_allow():
    d = run()
    assert d.decision == "ALLOW" and d.tier == "T2"
    assert d.registry_entry_id == "reg_northfield_univ" and "REGISTRY_MATCH" in d.reason_codes
    assert [t.step for t in d.trace][0] == "integrity"


# ---- U-ENG-01 integrity ----
def test_tampered_mandate_denied():
    signed = sign_mandate(ENV, mandate_body())
    bad = signed.model_copy(update={"body": tamper(signed.body, version=1, owner_id="evil")})
    d = run(signed=bad)
    assert d.decision == "DENY" and d.reason_codes == ("MANDATE_INVALID",)


def test_unknown_rule_type_fails_closed_not_crash():
    rules = default_rules() + [{"id": "R99", "type": "allow_everything"}]
    assert run(rules).reason_codes == ("MANDATE_INVALID",)


# ---- duplicate payment (decision-layer idempotency) ----
def test_duplicate_action_hash_is_denied():
    prop = proposal()
    d = run(prop=prop, paid_action_hashes=(action_hash(prop),))
    assert d.decision == "DENY" and d.reason_codes == ("DUPLICATE_PAYMENT",)
    assert any(t.step == "duplicate" for t in d.trace)


def test_duplicate_check_is_keyed_on_the_action_not_the_proposal_id():
    # a re-submitted invoice gets a new proposal_id but the same action_hash -> still a duplicate
    first = proposal(proposal_id="p1")
    again = proposal(proposal_id="p2")
    assert action_hash(first) == action_hash(again)
    assert run(prop=again, paid_action_hashes=(action_hash(first),)).reason_codes == ("DUPLICATE_PAYMENT",)


def test_a_different_amount_after_a_payment_is_not_a_duplicate():
    first = proposal(amount_minor=90000)
    different = proposal(amount_minor=90001)
    d = run(prop=different, paid_action_hashes=(action_hash(first),))
    assert d.decision != "DENY" or "DUPLICATE_PAYMENT" not in d.reason_codes


def test_no_paid_actions_means_no_duplicate_denial():
    assert run(prop=proposal()).decision == "ALLOW"


def test_superseded_mandate_denied():
    assert run(active_mandate_version=2).reason_codes == ("MANDATE_SUPERSEDED",)


def test_retired_mandate_key_denied():
    d = run(mandate_keys={"mk1": KeyInfo(public_key_b64=ENV.m_pub, status="retired")})
    assert d.reason_codes == ("MANDATE_INVALID",)


# ---- U-ENG-02 anomalies ----
@pytest.mark.parametrize("flag", ["HIDDEN_TEXT", "INSTRUCTION_LIKE_TEXT", "PAYEE_CHANGE_NOTICE"])
def test_baseline_anomalies_denied_even_if_mandate_omits_rule(flag):
    assert run(without("R10"), reader=reader(anomalies=(flag,))).decision == "DENY"
    assert run(without("R10"), detector_flags=(flag,)).decision == "DENY"


def test_mandate_can_block_additional_anomalies_and_none_passes():
    rules = without("R10") + [{"id": "R10", "type": "block_anomalies", "anomalies": ["LOW_IMAGE_QUALITY"]}]
    assert run(rules, reader=reader(anomalies=("LOW_IMAGE_QUALITY",))).decision == "DENY"
    assert run(reader=reader(anomalies=("NONE",))).decision == "ALLOW"


# ---- consistency: planner cannot invent fields ----
def test_proposal_amount_differs_from_document_denied():
    assert run(prop=proposal(amount_minor=95000)).reason_codes == ("PROPOSAL_READER_MISMATCH",)


# ---- U-ENG-03 confidence ----
def test_confidence_boundary():
    assert run(reader=reader(extraction_confidence_bp=8999)).decision == "ESCALATE"
    assert run(reader=reader(extraction_confidence_bp=9000)).decision == "ALLOW"


def test_missing_reader_output_escalates():
    assert run(reader=None).reason_codes == ("READER_OUTPUT_MISSING",)


# ---- U-ENG-04 category ----
def test_category_not_allowed_denied():
    d = run(prop=proposal(category="insurance"), reader=reader(category_guess="insurance"))
    assert d.decision == "DENY" and "CATEGORY_NOT_ALLOWED" in d.reason_codes


# ---- U-ENG-05 registry ----
@pytest.mark.parametrize("field,value", [
    ("name", "Northfield Universitv"), ("account_identifier", "NF0012345679"), ("bank_identifier", "NFLDGB2M"),
    ("name", "Northfіeld University"),          # Cyrillic i (U+0456)
    ("name", "North\u200dfield University"),  # zero-width joiner inserted
])
def test_registry_single_change_denied(field, value):
    ref = {"name": UNI_NAME, "account_identifier": UNI_ACCT, "bank_identifier": UNI_BANK, field: value}
    rd = reader(payee_name=ref["name"], account_identifier=ref["account_identifier"], bank_identifier=ref["bank_identifier"])
    d = run(prop=proposal(payee_ref=ref), reader=rd)
    assert d.decision == "DENY" and "REGISTRY_MISMATCH" in d.reason_codes


def test_fullwidth_digits_normalise_to_registry_value():
    fw = "ＮＦ0012345678"  # full-width N and F: NFKC-equivalent to the registry value
    ref = {"name": UNI_NAME, "account_identifier": fw, "bank_identifier": UNI_BANK}
    rd = reader(account_identifier=fw)
    assert run(prop=proposal(payee_ref=ref), reader=rd).decision == "ALLOW"


def test_registry_unknown_payee_and_bad_signature_and_retired_key():
    assert "REGISTRY_MISMATCH" in run(prop=proposal(payee_id="reg_other")).reason_codes
    forged = registry_entry(ENV).model_copy(update={"signature": "AAAA" + registry_entry(ENV).signature[4:]})
    assert "REGISTRY_SIGNATURE_INVALID" in run(registry=(forged,)).reason_codes
    retired = {"rk1": KeyInfo(public_key_b64=ENV.r_pub, status="retired")}
    assert "REGISTRY_SIGNATURE_INVALID" in run(registry_keys=retired).reason_codes


def test_registry_expired_and_revoked():
    old = registry_entry(ENV, valid_to=(NOW - timedelta(days=1)).isoformat())
    assert "REGISTRY_ENTRY_EXPIRED" in run(registry=(old,)).reason_codes
    rev = registry_entry(ENV, revoked_at=(NOW - timedelta(hours=1)).isoformat())
    assert "REGISTRY_ENTRY_REVOKED" in run(registry=(rev,)).reason_codes


# ---- U-ENG-06 new payee / cooling-off / approvals ----
def new_payee_case(**ctx):
    prop = proposal(category="family_support", payee_id="usr_new", doc_ref=None,
                    payee_ref={"name": "Uncle", "account_identifier": "X1", "bank_identifier": "B1"})
    return run(prop=prop, reader=None, **ctx), prop


def test_new_payee_is_hold_then_escalate_then_allow():
    d, prop = new_payee_case()
    assert d.decision == "HOLD" and d.hold_until == NOW + timedelta(hours=24) and "NEW_PAYEE" in d.reason_codes
    d2, _ = new_payee_case(now=NOW + timedelta(hours=25), hold_started_at=NOW)
    assert d2.decision == "ESCALATE" and d2.required_approvers == ("u_ammu",)
    ap = Approval(approval_id="a1", approver_id="u_ammu", action_hash=action_hash(prop), mandate_version=1,
                  expires_at=NOW + timedelta(hours=24), status="approved")
    d3, _ = new_payee_case(approvals=(ap,))  # approval releases the hold early
    assert d3.decision == "ALLOW" and "APPROVED" in d3.reason_codes


def test_approval_bound_to_exact_action_expiry_and_approver():
    _, prop = new_payee_case()
    base = dict(approval_id="a1", approver_id="u_ammu", action_hash=action_hash(prop), mandate_version=1,
                expires_at=NOW + timedelta(hours=1), status="approved")
    for bad in (dict(action_hash="0" * 64), dict(mandate_version=2), dict(expires_at=NOW - timedelta(seconds=1)),
                dict(approver_id="u_stranger")):
        d, _ = new_payee_case(approvals=(Approval(**{**base, **bad}),))
        assert d.decision == "HOLD", bad
    d, _ = new_payee_case(approvals=(Approval(**{**base, "status": "rejected"}),))
    assert d.decision == "DENY" and "APPROVAL_REJECTED" in d.reason_codes


def test_approval_never_overrides_deny():
    prop = proposal(rail_id="rail_c_card")
    ap = Approval(approval_id="a1", approver_id="u_ammu", action_hash=action_hash(prop), mandate_version=1,
                  expires_at=NOW + timedelta(hours=1), status="approved")
    assert run(prop=prop, approvals=(ap,)).decision == "DENY"


def test_unknown_payee_without_new_payee_rule_is_denied():
    d = run(without("R06", "R07"), prop=proposal(category="family_support", payee_id="usr_new", doc_ref=None), reader=None)
    assert d.reason_codes == ("PAYEE_NOT_ALLOWED",)


# ---- U-ENG-07 caps ----
CAPS = without("R04", "R08")


def test_per_tx_cap_boundary():
    assert run(CAPS, prop=proposal(amount_minor=200000), reader=reader(amount_minor=200000)).decision == "ALLOW"
    d = run(CAPS, prop=proposal(amount_minor=200001), reader=reader(amount_minor=200001))
    assert d.decision == "DENY" and "OVER_CAP" in d.reason_codes


def test_soft_cap_escalates():
    rules = [dict(r, hard=False) if r["id"] == "R03" else r for r in CAPS]
    assert run(rules, prop=proposal(amount_minor=200001), reader=reader(amount_minor=200001)).decision == "ESCALATE"


def test_rolling_cap_uses_ledger_and_window():
    from policy_engine import LedgerEntry
    rules = without("R08")
    inside = LedgerEntry(ts=NOW - timedelta(days=5), amount_minor=450000, currency="USD", category="tuition")
    assert "OVER_CAP" in run(rules, ledger=(inside,)).reason_codes
    outside = LedgerEntry(ts=NOW - timedelta(days=31), amount_minor=450000, currency="USD", category="tuition")
    assert run(rules, ledger=(outside,)).decision == "ALLOW"


def test_cap_currency_mismatch_denied():
    d = run(prop=proposal(currency="GBP"), reader=reader(currency="GBP"))
    assert "CAP_CURRENCY_UNSUPPORTED" in d.reason_codes


# ---- U-ENG-08 escalate_above / U-ENG-09 rail / U-ENG-10 funds ----
def test_escalate_above_boundary():
    assert run(prop=proposal(amount_minor=120000), reader=reader(amount_minor=120000)).decision == "ALLOW"
    d = run(prop=proposal(amount_minor=120001), reader=reader(amount_minor=120001))
    assert d.decision == "ESCALATE" and d.required_approvers == ("u_ammu",)


def test_rail_not_allowed():
    assert "RAIL_NOT_ALLOWED" in run(prop=proposal(rail_id="rail_c_card")).reason_codes


def test_funds_boundary_and_unknown_account():
    assert run(balances={"acc_rafi": 11_000_000}).decision == "ALLOW"
    assert "INSUFFICIENT_FUNDS" in run(balances={"acc_rafi": 10_999_999}).reason_codes
    assert "UNKNOWN_ACCOUNT" in run(balances={}).reason_codes


# ---- U-ENG-11 precedence / U-ENG-12 default deny ----
def test_precedence_deny_beats_hold_beats_escalate():
    prop = proposal(category="family_support", payee_id="usr_new", doc_ref=None, amount_minor=130000,
                    payee_ref={"name": "U", "account_identifier": "X", "bank_identifier": "B"})
    d = run(prop=prop, reader=None)
    assert d.decision == "HOLD" and {"NEW_PAYEE", "ESCALATE_ABOVE", "COOLING_OFF"} <= set(d.reason_codes)
    d2 = run(prop=proposal(**{**prop.model_dump(), "rail_id": "rail_c_card"}), reader=None)
    assert d2.decision == "DENY"


def test_empty_mandate_and_unsupported_action_are_denied():
    assert run([]).decision == "DENY"
    assert "ACTION_NOT_SUPPORTED" in run(prop=proposal(action="convert")).reason_codes
