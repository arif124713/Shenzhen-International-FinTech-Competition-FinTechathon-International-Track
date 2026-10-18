"""U-EXEC-01..04, replay, idempotency and the approval flow (testing.md §3, implementation_plan §3.5)."""
from __future__ import annotations

from datetime import timedelta

import pytest
from api.services.executor import ExecRefused
from policy_engine import (
    Approval,
    DecisionToken,
    PayeeRef,
    action_hash,
    canonical_json,
    generate_keypair,
    sign,
)
from policy_engine.tests.factories import proposal, reader

from tests.support import System


def test_allow_executes_once_and_is_audited():
    s = System(); p = proposal()
    d, tok = s.authorize(p)
    assert d.decision == "ALLOW"
    r = s.executor.execute(p, tok)
    assert r.simulated and s.ledger.balances()["acc_rafi"] == 50_000_000 - p.source_debit_minor
    assert [e["event_type"] for e in s.audit.entries] == ["EXEC_OK"] and s.audit.verify() == (True, None)


def test_no_token_forged_expired_and_non_allow_tokens_are_refused():
    s = System(); p = proposal(); _, tok = s.authorize(p)
    for bad, code in [(None, "NO_TOKEN")]:
        with pytest.raises(ExecRefused) as e: s.executor.execute(p, bad)
        assert e.value.code == code
    other_priv, _ = generate_keypair()
    forged = DecisionToken(payload=tok.payload, signature=sign(other_priv, canonical_json(tok.payload)), key_id="ek1")
    with pytest.raises(ExecRefused) as e: s.executor.execute(p, forged)
    assert e.value.code == "BAD_TOKEN_SIGNATURE"
    edited = DecisionToken(payload={**tok.payload, "action_hash": "0" * 64}, signature=tok.signature, key_id="ek1")
    with pytest.raises(ExecRefused) as e: s.executor.execute(p, edited)
    assert e.value.code == "BAD_TOKEN_SIGNATURE"
    s.now += timedelta(minutes=11)
    with pytest.raises(ExecRefused) as e: s.executor.execute(p, tok)
    assert e.value.code == "TOKEN_EXPIRED"
    bad_p = proposal(rail_id="rail_c_card")  # DENY decision still yields a signed token; executor must refuse it
    d, deny_tok = s.authorize(bad_p)
    assert d.decision == "DENY"
    with pytest.raises(ExecRefused) as e: s.executor.execute(bad_p, deny_tok)
    assert e.value.code == "NOT_ALLOW"
    assert s.ledger.balances()["acc_rafi"] == 50_000_000  # nothing moved


@pytest.mark.parametrize("change", [
    dict(payee_id="usr_ammu"), dict(amount_minor=90001), dict(currency="GBP"), dict(rail_id="rail_b_wallet"),
    dict(source_debit_minor=12_000_000), dict(payee_ref=PayeeRef(name="Evil", account_identifier="1", bank_identifier="2")),
])
def test_modified_proposal_cannot_reuse_an_earlier_allow(change):
    s = System(); p = proposal(); _, tok = s.authorize(p)
    with pytest.raises(ExecRefused) as e: s.executor.execute(p.model_copy(update=change), tok)
    assert e.value.code == "ACTION_MISMATCH"
    assert s.ledger.balances()["acc_rafi"] == 50_000_000


def test_replay_executes_exactly_once():
    s = System(); p = proposal(); _, tok = s.authorize(p)
    s.executor.execute(p, tok)
    for _ in range(3):
        with pytest.raises(ExecRefused) as e: s.executor.execute(p, tok)
        assert e.value.code == "TOKEN_REPLAY"
    assert len(s.ledger.rows) == 1


def test_mandate_or_registry_change_between_allow_and_execute_is_refused():
    s = System(); p = proposal(); _, tok = s.authorize(p)
    s.active_version = 2
    with pytest.raises(ExecRefused) as e: s.executor.execute(p, tok)
    assert e.value.code == "MANDATE_CHANGED"
    s.active_version = 1; s.registry_ok = False
    with pytest.raises(ExecRefused) as e: s.executor.execute(p, tok)
    assert e.value.code == "REGISTRY_CHANGED"
    assert not s.ledger.rows
    assert [x["event_type"] for x in s.audit.entries] == ["EXEC_REFUSED", "EXEC_REFUSED"]


def test_ledger_shortfall_after_the_engine_ran_is_refused_and_nothing_moves():
    s = System(balances={"acc_rafi": 50_000_000}); p = proposal(); _, tok = s.authorize(p)
    s.ledger._balances["acc_rafi"] = 1  # state changed after the engine ran
    with pytest.raises(ExecRefused) as e: s.executor.execute(p, tok)
    assert e.value.code == "INSUFFICIENT_FUNDS" and not s.ledger.rows


def test_ledger_idempotency_key_never_double_debits():
    s = System()
    kw = dict(idempotency_key="k", proposal_id="p1", payee_id="x", amount_minor=1, currency="USD", category="tuition",
              source_account="acc_rafi", debit_minor=10, rail_id="r", executed_at=s.now)
    a, b = s.ledger.transfer(**kw), s.ledger.transfer(**kw)
    assert a == b and s.ledger.balances()["acc_rafi"] == 50_000_000 - 10


def test_approval_flow_and_post_approval_tampering():
    s = System()
    p = proposal(amount_minor=130_000, source_debit_minor=15_000_000)
    rd = reader(amount_minor=130_000)
    d, tok = s.authorize(p, reader=rd)
    assert d.decision == "ESCALATE" and d.required_approvers == ("u_ammu",)
    with pytest.raises(ExecRefused) as e: s.executor.execute(p, tok)
    assert e.value.code == "NOT_ALLOW"
    ap = Approval(approval_id="a1", approver_id="u_ammu", action_hash=action_hash(p), mandate_version=1,
                  expires_at=s.now + timedelta(hours=24), status="approved")
    d2, tok2 = s.authorize(p, reader=rd, approvals=(ap,))  # engine re-run with the approval as an input
    assert d2.decision == "ALLOW"
    # beneficiary or amount changed after approval: the approval no longer matches, so no ALLOW is issued
    tampered = p.model_copy(update={"amount_minor": 131_000})
    d3, _ = s.authorize(tampered, reader=reader(amount_minor=131_000), approvals=(ap,))
    assert d3.decision == "ESCALATE"
    # and the ALLOW token for the original cannot be used for the tampered action
    with pytest.raises(ExecRefused) as e: s.executor.execute(tampered, tok2)
    assert e.value.code == "ACTION_MISMATCH"
    assert s.executor.execute(p, tok2).amount_minor == 130_000
