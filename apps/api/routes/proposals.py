"""Proposals: planner -> engine -> signed token -> execute / escalate / hold / block (implementation_plan §5)."""
from __future__ import annotations

import uuid
from datetime import timedelta

from fastapi import APIRouter, HTTPException
from policy_engine import ActionProposal, Context, decide, issue_decision_token
from policy_engine.canonical import action_hash
from pydantic import BaseModel

from ..agents.planner import mandate_summary, plan
from ..services.approvals import create_approval
from ..services.explain import explain
from ..services.mandates import active_signed
from ..services.runtime import get_runtime

router = APIRouter(tags=["proposals"])


class ProposalBody(BaseModel):
    user_request: str
    document_fields: dict | None = None
    source_account: str = "acc_rafi_usd"


@router.post("/proposals")
def create_proposal(body: ProposalBody) -> dict:
    rt = get_runtime()
    signed = active_signed(rt)
    if signed is None:
        raise HTTPException(status_code=409, detail={"code": "NO_ACTIVE_MANDATE"})

    rails = [{"rail_id": c.rail_id, "label": c.label, "supports": list(c.supports), "eta_hours": c.eta_hours}
             for c in rt.ratecards]
    proposal = plan(user_request=body.user_request, reader_fields=body.document_fields,
                    mandate_summary=mandate_summary(signed.body), rails=rails,
                    source_account=body.source_account, complete=rt.planner_client.complete,
                    known_payees=_registry_signed(rt))
    if proposal is None:
        return {"status": "refused", "message": "The request is out of scope or needs more detail."}

    return _evaluate(rt, signed, proposal, reader_fields=body.document_fields)


class RerunBody(BaseModel):
    proposal: dict


@router.post("/proposals/{proposal_id}/reevaluate")
def reevaluate(proposal_id: str, body: RerunBody) -> dict:
    """Re-run the engine (used after a simulated clock advance for a cooling-off hold)."""
    rt = get_runtime()
    signed = active_signed(rt)
    if signed is None:
        raise HTTPException(status_code=409, detail={"code": "NO_ACTIVE_MANDATE"})
    proposal = ActionProposal.model_validate(body.proposal)
    return _evaluate(rt, signed, proposal, proposal_id=proposal_id)


def _approval_summary(proposal: ActionProposal, decision) -> dict:  # type: ignore[no-untyped-def]
    """Only the pre-payment summary fields a guardian may see (testing.md §5, implementation_plan §5).

    The reason text explains *why approval is needed*; informational codes (e.g. the engine's note that a
    detector flag was absent) are excluded so the guardian is not shown a confusing extra sentence.
    """
    why_codes = [c for c in decision.reason_codes if c in {
        "ESCALATE_ABOVE", "LOW_CONFIDENCE", "NEW_PAYEE", "COOLING_OFF", "OVER_SOFT_CAP", "DEADLINE_AT_RISK"}]
    if not why_codes:
        why_codes = [decision.reason_codes[0]] if decision.reason_codes else []
    return {"payee_name": proposal.payee_ref.name, "amount_minor": proposal.amount_minor,
            "currency": proposal.currency, "rail_id": proposal.rail_id,
            "reason": ", ".join(explain(c, "en") for c in why_codes), "expires_hours": 24}


def _reader_output(fields: dict | None):  # type: ignore[no-untyped-def]
    if not fields:
        return None, ()
    from policy_engine import ReaderOutput

    try:
        ro = ReaderOutput.model_validate(fields)
    except Exception:  # noqa: BLE001
        return None, ()
    return ro, tuple(ro.anomalies)


def _registry_signed(rt):  # type: ignore[no-untyped-def]
    return rt.registry.entries


def _evaluate(rt, signed, proposal: ActionProposal, proposal_id: str | None = None,  # type: ignore[no-untyped-def]
              reader_fields: dict | None = None) -> dict:
    reader, flags = _reader_output(reader_fields)
    ctx = Context(
        now=rt.clock(), mandate_keys=rt.mandate_keys, registry_keys=rt.registry.key_infos,
        active_mandate_version=signed.body["version"], ledger=(), balances=rt.ledger.balances(),
        registry=_registry_signed(rt), reader=reader, detector_flags=flags,
        hold_started_at=rt.hold_started_at(proposal.proposal_id),
    )
    decision = decide(signed, proposal, ctx)
    token = issue_decision_token(rt.keys["engine"]["private_b64"], "demo_engine_k1", decision,
                                 nonce=f"n_{uuid.uuid4().hex[:16]}", issued_at=rt.clock(),
                                 expires_at=rt.clock() + timedelta(minutes=10))

    result = _decision_payload(rt, decision, proposal)

    if decision.decision == "ALLOW":
        from ..services.executor import ExecRefused

        try:
            receipt = rt.executor.execute(proposal, token)
            result["status"] = "executed"
            result["receipt"] = {"receipt_id": receipt.receipt_id, "amount_minor": receipt.amount_minor,
                                 "currency": receipt.currency, "simulated": True}
            result["balances"] = rt.ledger.balances()
        except ExecRefused as exc:
            result["status"] = "refused"
            result["exec_code"] = exc.code
    elif decision.decision == "ESCALATE":
        approval = create_approval(action_hash=action_hash(proposal), approver_id="u_ammu", now=rt.clock())
        result["status"] = "needs_approval"
        result["approval"] = {"token": approval.token, "approver_id": approval.approver_id,
                              "expires_at": approval.expires_at.isoformat(),
                              "action_hash": approval.action_hash}
        # Store only the pre-payment summary (the six fields a guardian may see) and the proposal, keyed by
        # the token HASH. The guardian page reads this; Posting still requires the proposal to recompute the
        # action_hash, so nothing here widens authority.
        rt.store_approval(approval.token, _approval_summary(proposal, decision), proposal.model_dump(mode="json"))
        rt.audit.append("api", "APPROVAL_REQUESTED", {"proposal_id": proposal.proposal_id,
                                                      "action_hash": approval.action_hash})
    elif decision.decision == "HOLD":
        result["status"] = "on_hold"
        rt.mark_hold(proposal.proposal_id)  # remember when the cooling-off hold started
    else:
        result["status"] = "blocked"
    return result


def _decision_payload(rt, decision, proposal: ActionProposal) -> dict:  # type: ignore[no-untyped-def]
    return {
        "proposal": proposal.model_dump(mode="json"),
        "decision": decision.decision,
        "tier": decision.tier,
        "reason_codes": list(decision.reason_codes),
        "reasons": [explain(c, "en") for c in decision.reason_codes],
        "failed_rule_ids": list(decision.failed_rule_ids),
        "required_approvers": list(decision.required_approvers),
        "hold_until": decision.hold_until.isoformat() if decision.hold_until else None,
        "deadline_at_risk": decision.deadline_at_risk,
        "trace": [t.model_dump() for t in decision.trace],
        "action_hash": decision.action_hash,
    }


class ApproveBody(BaseModel):
    token: str
    approver_id: str = "u_ammu"
    approve: bool = True
    # Optional: when omitted, the stored proposal for this token is used (still recomputed into action_hash,
    # so authority is unchanged — the approval remains bound to the exact action it was issued for).
    proposal: dict | None = None


@router.get("/approvals/{token}")
def get_approval(token: str) -> dict:
    """Public, token-bound read: returns ONLY the pre-payment summary so the guardian page can render the
    request without copying raw JSON. It never returns the proposal internals or any cryptographic data."""
    rt = get_runtime()
    stored = rt.get_approval(token)
    if stored is None:
        raise HTTPException(status_code=404, detail={"code": "APPROVAL_NOT_FOUND"})
    return {"summary": stored["summary"]}


@router.post("/approvals/decision")
def approval_decision(body: ApproveBody) -> dict:
    rt = get_runtime()
    from policy_engine import Approval
    from pydantic import ValidationError

    # This endpoint is public and token-bound, so malformed input must never crash the app (CLAUDE.md §5:
    # typed problem responses with a stable code, never a stack trace).
    stored = rt.get_approval(body.token) if body.token else None
    proposal_body = body.proposal if body.proposal is not None else (stored or {}).get("proposal")
    if not proposal_body:
        raise HTTPException(status_code=400, detail={"code": "APPROVAL_NOT_FOUND",
                                                     "message": "No payment is bound to this approval link."})
    try:
        proposal = ActionProposal.model_validate(proposal_body)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail={"code": "PROPOSAL_INVALID",
                                                     "message": "The payment details are incomplete or invalid."}) from exc
    if not body.token or not body.approver_id:
        raise HTTPException(status_code=400, detail={"code": "APPROVAL_TOKEN_INVALID"})

    ah = action_hash(proposal)
    status = "approved" if body.approve else "rejected"
    approval = Approval(approval_id=f"a_{uuid.uuid4().hex[:8]}", approver_id=body.approver_id,
                        action_hash=ah, mandate_version=rt._active_version(proposal.payee_id and "m_rafi"),
                        expires_at=rt.clock() + timedelta(hours=24), status=status)
    rt.audit.append("guardian", "APPROVAL_DECISION", {"action_hash": ah, "status": status})

    signed = active_signed(rt)
    if signed is None:
        raise HTTPException(status_code=409, detail={"code": "NO_ACTIVE_MANDATE"})
    ctx = Context(now=rt.clock(), mandate_keys=rt.mandate_keys, registry_keys=rt.registry.key_infos,
                  active_mandate_version=signed.body["version"], ledger=(), balances=rt.ledger.balances(),
                  registry=_registry_signed(rt), approvals=(approval,))
    decision = decide(signed, proposal, ctx)
    token = issue_decision_token(rt.keys["engine"]["private_b64"], "demo_engine_k1", decision,
                                 nonce=f"n_{uuid.uuid4().hex[:16]}", issued_at=rt.clock(),
                                 expires_at=rt.clock() + timedelta(minutes=10))
    result = _decision_payload(rt, decision, proposal)
    if decision.decision == "ALLOW":
        from ..services.executor import ExecRefused

        try:
            receipt = rt.executor.execute(proposal, token)
            result.update(status="executed", receipt={"receipt_id": receipt.receipt_id,
                          "amount_minor": receipt.amount_minor, "currency": receipt.currency, "simulated": True},
                          balances=rt.ledger.balances())
        except ExecRefused as exc:
            result.update(status="refused", exec_code=exc.code)
    else:
        result["status"] = decision.decision.lower()
    return result
