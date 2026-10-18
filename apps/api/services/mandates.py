"""Mandate signing, version management and confirm flow (implementation_plan §4.8).

Prototype uses a server-held per-user demo key after the user confirms the compiled policy; superseded
versions are never valid for new decisions.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from policy_engine import Mandate, SignedMandate, canonical_json, sign

from .runtime import Runtime


class MandateError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def sign_and_activate(rt: Runtime, body: dict[str, Any], *, back_translation: str = "") -> SignedMandate:
    """Validate against the closed rule set, sign with the demo mandate key and make it the active version."""
    body = dict(body)
    mandate_id = body.get("mandate_id", "m_rafi")
    prev = rt.active_mandate(mandate_id)
    body["version"] = (prev["version"] + 1) if prev else 1
    body.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    try:
        Mandate.model_validate(body)
    except Exception as exc:  # noqa: BLE001
        raise MandateError("MANDATE_INVALID") from exc

    signature = sign(rt.keys["mandate"]["private_b64"], canonical_json(body))
    signed = SignedMandate(body=body, signature=signature, signer_key_id="demo_mandate_k1")
    rt.set_active_mandate(mandate_id, body["version"], body, signature, back_translation)
    return signed


def active_signed(rt: Runtime, mandate_id: str = "m_rafi") -> SignedMandate | None:
    m = rt.active_mandate(mandate_id)
    if m is None:
        return None
    return SignedMandate(body=m["body"], signature=m["signature"], signer_key_id="demo_mandate_k1")


def dumps(signed: SignedMandate) -> str:
    return json.dumps({"body": signed.body, "signature": signed.signature, "signer_key_id": signed.signer_key_id})
