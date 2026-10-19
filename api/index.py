"""Vercel Python entrypoint (serverless). Mounts the Mandate FastAPI app at /api.

Vercel's Python runtime imports `app` from this module. The real application lives in
`apps/api/main.py`; we add the repo sub-packages to sys.path here so the serverless environment can import
`api.main`, `policy_engine` and `rail_sim` exactly as the local `make dev` does.

Hosted-demo notes (honest limits):
  - The sandbox runtime keeps in-memory state (mandate, ledger, approvals). Vercel may run several warm
    instances and may cold-start, so a payment does not always see state created in an earlier call. To make
    the link usable immediately we seed a demo mandate on start-up. This is a UI/flow demo, not a durable
    store; the deterministic demo is designed to be reset.
  - Everything is SIMULATED. No real money moves.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _sub in ("packages", "services", "apps", "."):
    _p = str((_ROOT / _sub).resolve())
    if _p not in sys.path:
        sys.path.insert(0, _p)

from api.services.mandates import sign_and_activate  # noqa: E402
from api.services.runtime import get_runtime  # noqa: E402

# Demo ruleset mirroring the seeded demo: tuition/family allowed, tuition needs a verified payee, a hard
# per-transaction cap, escalation above a threshold, new payees need the guardian, and the anomaly floor.
_DEMO_RULES = [
    {"id": "R01", "type": "category_allow", "categories": ["tuition", "family_support"]},
    {"id": "R02", "type": "require_registry_match", "categories": ["tuition"]},
    {"id": "R03", "type": "cap", "scope": "per_tx", "amount_minor": 500000, "currency": "USD",
     "categories": ["*"], "hard": True},
    {"id": "R04", "type": "escalate_above", "amount_minor": 120000, "currency": "USD", "approvers": ["u_ammu"]},
    {"id": "R05", "type": "new_payee", "action": "ESCALATE", "approvers": ["u_ammu"]},
    {"id": "R06", "type": "cooling_off", "applies_to": "new_payee", "hours": 24},
    {"id": "R07", "type": "min_confidence", "value_bp": 9000},
    {"id": "R08", "type": "block_anomalies",
     "anomalies": ["HIDDEN_TEXT", "INSTRUCTION_LIKE_TEXT", "PAYEE_CHANGE_NOTICE"]},
    {"id": "R09", "type": "rail_allow", "rail_ids": ["rail_a_bank", "rail_b_wallet"]},
]


def _seed_demo() -> None:
    """Activate a demo mandate on cold start so the hosted link is immediately usable. Never crashes start-up."""
    try:
        rt = get_runtime()
        if rt.active_mandate("m_rafi") is None:
            sign_and_activate(rt, {
                "mandate_id": "m_rafi", "owner_id": "u_rafi", "base_currency": "BDT",
                "co_signers": [{"id": "u_ammu", "name": "Ammu", "lang": "bn"}],
                "rules": _DEMO_RULES, "created_at": datetime.now(timezone.utc).isoformat(),
            })
    except Exception:  # noqa: BLE001 - a seed failure must not take the whole function down
        pass


_seed_demo()

from api.main import create_app  # noqa: E402

app = create_app()
handler = app  # some Vercel configurations look for `handler`
