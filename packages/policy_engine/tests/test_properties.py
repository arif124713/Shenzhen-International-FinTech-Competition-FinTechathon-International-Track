"""P-I1, P-I2, P-I4, P-I5, P-I7: invariants checked with hypothesis (testing.md §2)."""
from __future__ import annotations

from datetime import timedelta

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from policy_engine import LedgerEntry, decide
from policy_engine.decide import norm
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
    sign_mandate,
)

ENV = make_env()
SETTINGS = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
RANK = {"ALLOW": 0, "ESCALATE": 1, "HOLD": 2, "DENY": 3}


def decide_with(rules, prop, rd, **ctx):
    return decide(sign_mandate(ENV, mandate_body(rules)), prop, context(ENV, reader=rd, **ctx))


amounts = st.integers(min_value=1, max_value=300_000)
rails = st.sampled_from(["rail_a_bank", "rail_b_wallet", "rail_c_card", "rail_x"])
cats = st.sampled_from(["tuition", "rent", "family_support", "insurance", "other"])
payees = st.sampled_from(["reg_northfield_univ", "usr_ammu", "usr_new", None])
conf = st.integers(min_value=0, max_value=10000)


@st.composite
def scenario(draw):
    amt, cat, payee, rail = draw(amounts), draw(cats), draw(payees), draw(rails)
    ref = {"name": UNI_NAME, "account_identifier": UNI_ACCT, "bank_identifier": UNI_BANK}
    prop = proposal(amount_minor=amt, category=cat, payee_id=payee, rail_id=rail, payee_ref=ref)
    rd = reader(amount_minor=amt, category_guess=cat, extraction_confidence_bp=draw(conf))
    return prop, rd


@st.composite
def restrictive_rule(draw):
    kind = draw(st.sampled_from(["cap", "escalate", "block", "minconf", "registry"]))
    if kind == "cap":
        return {"id": "X1", "type": "cap", "scope": draw(st.sampled_from(["per_tx", "rolling_7d", "rolling_30d"])),
                "amount_minor": draw(amounts), "currency": "USD", "categories": ["*"]}
    if kind == "escalate":
        return {"id": "X1", "type": "escalate_above", "amount_minor": draw(amounts), "currency": "USD", "approvers": ["u_ammu"]}
    if kind == "block":
        return {"id": "X1", "type": "block_anomalies", "anomalies": ["LOW_IMAGE_QUALITY", "MULTI_PAYEE"]}
    if kind == "minconf":
        return {"id": "X1", "type": "min_confidence", "value_bp": draw(conf)}
    return {"id": "X1", "type": "require_registry_match", "categories": ["*"]}


@SETTINGS
@given(scenario(), restrictive_rule())
def test_I1_adding_a_restrictive_rule_never_relaxes(sc, extra):
    """Permit-list rules (category/payee/rail allow, new_payee, cooling_off) are additive by design and excluded."""
    prop, rd = sc
    before = decide_with(default_rules(), prop, rd)
    after = decide_with(default_rules() + [extra], prop, rd)
    assert RANK[after.decision] >= RANK[before.decision]


@SETTINGS
@given(scenario(), st.randoms(use_true_random=False))
def test_I2_determinism_and_rule_order_independence(sc, rnd):
    prop, rd = sc
    rules = default_rules()
    a = decide_with(rules, prop, rd)
    shuffled = rules[:]; rnd.shuffle(shuffled)
    b = decide_with(shuffled, prop, rd)
    again = decide_with(rules, prop, rd)
    assert a.decision == b.decision and a.reason_codes == b.reason_codes and a.failed_rule_ids == b.failed_rule_ids
    assert a == again


@SETTINGS
@given(st.sampled_from(["name", "account", "bank"]), st.data())
def test_I4_registry_strictness_one_character_change_is_denied(field, data):
    original = {"name": UNI_NAME, "account": UNI_ACCT, "bank": UNI_BANK}[field]
    i = data.draw(st.integers(0, len(original) - 1))
    ch = data.draw(st.characters(blacklist_categories=("Cs", "Cc", "Zs", "Zl", "Zp")))
    mutated = original[:i] + ch + original[i + 1:]
    assume(norm(mutated) != norm(original))
    vals = {"name": UNI_NAME, "account": UNI_ACCT, "bank": UNI_BANK, field: mutated}
    ref = {"name": vals["name"], "account_identifier": vals["account"], "bank_identifier": vals["bank"]}
    rd = reader(payee_name=ref["name"], account_identifier=ref["account_identifier"], bank_identifier=ref["bank_identifier"])
    d = decide_with(default_rules(), proposal(payee_ref=ref), rd)
    assert d.decision == "DENY" and "REGISTRY_MISMATCH" in d.reason_codes


@SETTINGS
@given(st.lists(st.tuples(st.integers(1, 200_000), st.integers(0, 40)), min_size=1, max_size=25))
def test_I5_rolling_cap_integrity_under_split_payments(seq):
    """Executed (ALLOW) amounts inside any 30-day window never exceed the cap, even when split."""
    rules = [r for r in default_rules() if r["id"] not in ("R08",)]  # no escalation: ALLOW is reachable
    cap = 500_000
    ledger: list[LedgerEntry] = []
    day = 0
    for amt, gap in seq:
        day += gap
        now = NOW + timedelta(days=day)
        d = decide(sign_mandate(ENV, mandate_body(rules)), proposal(amount_minor=amt),
                   context(ENV, now=now, reader=reader(amount_minor=amt), ledger=tuple(ledger),
                           registry=(__import__("policy_engine.tests.factories", fromlist=["x"]).registry_entry(ENV),)))
        if d.decision == "ALLOW":
            ledger.append(LedgerEntry(ts=now, amount_minor=amt, currency="USD", category="tuition"))
        window = sum(e.amount_minor for e in ledger if now - timedelta(days=30) < e.ts <= now)
        assert window <= cap


@SETTINGS
@given(scenario())
def test_I7_allow_implies_explicit_permission(sc):
    prop, rd = sc
    d = decide_with(default_rules(), prop, rd)
    if d.decision == "ALLOW":
        assert prop.category in {"tuition", "rent", "family_support"}
        assert prop.payee_id in {"reg_northfield_univ", "usr_ammu"}
        assert prop.rail_id in {"rail_a_bank", "rail_b_wallet"}
