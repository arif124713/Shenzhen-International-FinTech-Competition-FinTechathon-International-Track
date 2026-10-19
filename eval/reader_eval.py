"""Reader / detector layer evaluation (the layer the engine-level 0% ASR does NOT cover).

Runs the REAL path on the labelled invoice set (data/fixtures/invoices): upload validation -> text-layer
extraction -> deterministic detectors -> isolated reader (replay fixtures). It reports, per document and in
aggregate:

  - detector flags raised vs the gold flags (the document-level defense, i.e. hidden text / notices caught);
  - detector recall on anomaly-bearing documents;
  - false positives on genuine documents (a benign invoice must raise no blocking flag);
  - field agreement between the reader output and the gold fields.

This is deliberately SEPARATE from the red-team benchmark: the benchmark measures the *engine* given correct
fields; this measures the *front* of the pipeline (parsing + detection + extraction). Offline, replay only.
Run: python -m eval.reader_eval
"""
from __future__ import annotations

import json
import sys
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


def run(*, with_reader: bool = True) -> dict[str, Any]:
    invoices = settings.fixtures_dir / "invoices"
    manifest = json.loads((invoices / "manifest.json").read_text(encoding="utf-8"))
    complete = None
    if with_reader:
        try:
            from api.agents.llm import build_client

            complete = build_client(role="reader").complete
        except Exception:  # noqa: BLE001 - field agreement is optional; detectors are the point
            complete = None

    rows: list[dict[str, Any]] = []
    for entry in manifest:
        gold = entry["gold"]
        doc = load_document_for_reader(invoices / entry["file"])
        detector_flags = (detect_text_flags(doc.get("text", ""))
                          | detect_metadata_flags(doc.get("metadata"), doc.get("filename"))
                          | detect_spans(doc.get("spans", []))) - {"NONE"}
        gold_flags = set(gold.get("anomalies") or ())
        flagged = detector_flags
        if complete is not None:
            _, union = read_document(doc, complete, detector_spans=doc.get("spans"))
            flagged = set(union) - {"NONE"}
        row: dict[str, Any] = {
            "file": entry["file"], "gold_flags": sorted(gold_flags), "detected_flags": sorted(flagged),
            "flag_ok": (gold_flags.issubset(flagged)) if gold_flags else (flagged == set()),
        }
        if complete is not None:
            try:
                out, _ = read_document(doc, complete, detector_spans=doc.get("spans"))
                settled = out.model_dump(mode="json")
                field_ok = sum(1 for f in FIELDS if settled.get(f) == gold.get(f))
                row["field_agreement"] = f"{field_ok}/{len(FIELDS)}"
            except Exception as exc:  # noqa: BLE001 - a missing fixture is reported, not hidden
                row["field_agreement"] = f"n/a ({type(exc).__name__})"
        rows.append(row)

    anomalies_total = sum(1 for r in rows if r["gold_flags"])
    anomalies_caught = sum(1 for r in rows if r["gold_flags"] and r["flag_ok"])
    benign_total = sum(1 for r in rows if not r["gold_flags"])
    benign_clean = sum(1 for r in rows if not r["gold_flags"] and r["flag_ok"])
    return {
        "documents": len(rows),
        "reader_used": complete is not None,
        "detector_recall": {"caught": anomalies_caught, "total": anomalies_total},
        "detector_false_positives": {"clean": benign_clean, "total": benign_total},
        "rows": rows,
    }


if __name__ == "__main__":  # pragma: no cover
    print(json.dumps(run(), indent=2))
