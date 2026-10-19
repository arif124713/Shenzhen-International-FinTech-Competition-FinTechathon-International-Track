"""Live end-to-end reader run over the labelled invoice set (the evidence reviewers asked for).

Unlike the replay benchmark, this calls the configured model for real: for each synthetic invoice it runs the
actual upload -> text layer -> reader path and compares the model's extraction to the gold fields and the
detector flags. It writes `eval/reports/live_reader.json` so a live run can be cited next to the replay report.

Requires a live provider and a key; it FAILS CLOSED (exit 1, no file) if `LLM_PROVIDER=replay` or no key is set,
so a missing run is never mistaken for a passing one.

Run:  LLM_PROVIDER=openai_compat LLM_API_KEY=... python -m eval.live_reader
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path as _Path
from typing import Any

_ROOT = _Path(__file__).resolve().parents[1]
for _sub in ("packages", "services", "apps", "."):
    _p = str((_ROOT / _sub).resolve())
    if _p not in sys.path:
        sys.path.insert(0, _p)

from api.agents.reader import read_document  # noqa: E402
from api.agents.reader.anomalies import detect_metadata_flags, detect_spans, detect_text_flags  # noqa: E402
from api.services.documents import load_document_for_reader  # noqa: E402
from api.settings import settings  # noqa: E402

FIELDS = ("doc_type", "payee_name", "account_identifier", "bank_identifier", "amount_minor", "currency",
          "due_date", "reference", "category_guess")


def run() -> dict[str, Any]:
    if settings.llm_provider == "replay":
        raise SystemExit("LIVE RUN REFUSED: LLM_PROVIDER=replay. Set LLM_PROVIDER=openai_compat and a key.")
    if not settings.llm_api_key:
        raise SystemExit("LIVE RUN REFUSED: no LLM_API_KEY set. This script never falls back to replay.")

    from api.agents.llm import build_client

    complete = build_client(role="reader").complete
    invoices = settings.fixtures_dir / "invoices"
    manifest = json.loads((invoices / "manifest.json").read_text(encoding="utf-8"))

    rows: list[dict[str, Any]] = []
    field_hits = field_total = 0
    for entry in manifest:
        gold = entry["gold"]
        doc = load_document_for_reader(invoices / entry["file"])
        detector_flags = (detect_text_flags(doc.get("text", ""))
                          | detect_metadata_flags(doc.get("metadata"), doc.get("filename"))
                          | detect_spans(doc.get("spans", []))) - {"NONE"}
        try:
            out, union = read_document(doc, complete, detector_spans=doc.get("spans"))
            settled = out.model_dump(mode="json")
            hits = sum(1 for f in FIELDS if settled.get(f) == gold.get(f))
            field_hits += hits
            field_total += len(FIELDS)
            rows.append({"file": entry["file"], "fields_ok": f"{hits}/{len(FIELDS)}",
                         "gold_flags": sorted(gold.get("anomalies") or ()),
                         "detected_flags": sorted(set(union) - {"NONE"}),
                         "detector_flags": sorted(detector_flags)})
        except Exception as exc:  # noqa: BLE001 - a provider failure is recorded, never hidden
            rows.append({"file": entry["file"], "error": f"{type(exc).__name__}: {exc}"})

    report = {
        "mode": settings.llm_provider,
        "model_reader": settings.llm_model_reader,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "documents": len(rows),
        "field_agreement": f"{field_hits}/{field_total}" if field_total else "n/a",
        "rows": rows,
    }
    settings.reports_dir.mkdir(parents=True, exist_ok=True)
    (settings.reports_dir / "live_reader.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":  # pragma: no cover
    print(json.dumps(run(), indent=2))
