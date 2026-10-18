"""Generate the execution-evidence artifacts (testing.md §10, WP-13 item 5).

Runs the deterministic demo flow on a fresh runtime and exports, into docs/execution_evidence/:
  - audit_export.json     (the hash-chained audit log)
  - ledger.csv            (the sandbox ledger rows)
  - checkpoint.json       (the signed head-hash checkpoint)
  - llm_config.md         (the confirmed model IDs, date and reader mode — see remaining_spec §23)

Everything here is SIMULATED and offline (replay LLM). Run: python -m eval.evidence
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path as _Path

_ROOT = _Path(__file__).resolve().parents[1]
for _sub in ("packages", "services", "apps", "."):
    _p = str((_ROOT / _sub).resolve())
    if _p not in sys.path:
        sys.path.insert(0, _p)

from api.services.runtime import reset_runtime  # noqa: E402
from api.settings import settings  # noqa: E402

from eval.fixtures_common import GENUINE_FIELDS as GENUINE  # noqa: E402

# The evidence run uses a deliberately reduced 4-rule mandate (a documented subset of the demo rules):
# tuition/family allowed, registry required for tuition, a hard per-tx cap, and the anomaly security floor.
EVIDENCE_RULES = [
    {"id": "R01", "type": "category_allow", "categories": ["tuition", "family_support"]},
    {"id": "R02", "type": "require_registry_match", "categories": ["tuition"]},
    {"id": "R03", "type": "cap", "scope": "per_tx", "amount_minor": 500000, "currency": "USD",
     "categories": ["*"], "hard": True},
    {"id": "R08", "type": "block_anomalies",
     "anomalies": ["HIDDEN_TEXT", "INSTRUCTION_LIKE_TEXT", "PAYEE_CHANGE_NOTICE"]},
]


def _activate(rt) -> None:  # type: ignore[no-untyped-def]
    from api.services.mandates import sign_and_activate

    sign_and_activate(rt, {
        "mandate_id": "m_rafi", "owner_id": "u_rafi", "base_currency": "BDT",
        "co_signers": [{"id": "u_ammu", "name": "Ammu", "lang": "bn"}],
        "rules": EVIDENCE_RULES,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })


def main() -> None:  # pragma: no cover - evidence generation, run manually / by make
    from api.main import create_app
    from fastapi.testclient import TestClient

    rt = reset_runtime()
    _activate(rt)
    client = TestClient(create_app())
    client.post("/api/v1/proposals", json={"user_request": "pay this invoice", "document_fields": GENUINE})

    out = settings.repo_root / "docs" / "execution_evidence"
    out.mkdir(parents=True, exist_ok=True)

    (out / "audit_export.json").write_text(json.dumps(rt.audit.entries, indent=2), encoding="utf-8")

    with (out / "ledger.csv").open("w", newline="", encoding="utf-8") as fh:
        rows = rt.ledger.rows
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else
                                ["ts", "amount_minor", "currency", "category", "payee_id", "receipt_id"])
        writer.writeheader()
        writer.writerows(rows)

    cp = rt.audit.checkpoint(rt.keys["audit"]["private_b64"], "demo_audit_k1")
    (out / "checkpoint.json").write_text(json.dumps(cp, indent=2), encoding="utf-8")

    (out / "llm_config.md").write_text(
        "# LLM configuration evidence\n\n"
        f"- Confirmed model IDs: reader/planner/compiler = `{settings.llm_model_reader}` (from env; "
        "verify in the official DeepSeek docs before submission).\n"
        f"- Base URL: `{settings.llm_base_url}` (env `LLM_BASE_URL`).\n"
        f"- Provider mode for this evidence run: `{settings.llm_provider}` (replay = offline fixtures).\n"
        "- Temperature: 0. Reasoning/thinking mode: off for extraction and compilation.\n"
        "- Reader mode: determined by the start-up capability probe (`READER_MODE`); text mode is used if "
        "the configured model rejects images. Never crashes on rejection.\n"
        f"- Evidence generated: {datetime.now(timezone.utc).isoformat()}.\n"
        "\n> All calls are simulated/synthetic. No real passport, bank or personal data leaves the machine.\n",
        encoding="utf-8")

    print(json.dumps({"evidence_dir": str(out), "audit_entries": len(rt.audit.entries),
                      "ledger_rows": len(rt.ledger.rows), "head_hash": cp["head_hash"]}, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
