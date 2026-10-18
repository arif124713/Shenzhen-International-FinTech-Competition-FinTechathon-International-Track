"""Signed decision tokens: the only thing the executor accepts (implementation_plan §3.5)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from .canonical import canonical_json
from .models import Decision, Strict
from .signing import sign, verify


class DecisionToken(Strict):
    payload: dict[str, Any]
    signature: str
    key_id: str


def issue_decision_token(private_b64: str, key_id: str, decision: Decision, *, nonce: str,
                         issued_at: datetime, expires_at: datetime) -> DecisionToken:
    """Nonce and timestamps are supplied by the caller (service layer) so this module stays deterministic."""
    payload = {
        "decision": decision.decision,
        "tier": decision.tier,
        "action_hash": decision.action_hash,
        "mandate_id": decision.mandate_id,
        "mandate_version": decision.mandate_version,
        "registry_version": decision.registry_version,
        "registry_entry_id": decision.registry_entry_id,
        "input_hash": decision.input_hash,
        "engine_version": decision.engine_version,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "nonce": nonce,
    }
    return DecisionToken(payload=payload, signature=sign(private_b64, canonical_json(payload)), key_id=key_id)


def verify_decision_token(token: DecisionToken, public_b64: str) -> bool:
    return verify(public_b64, canonical_json(token.payload), token.signature)
